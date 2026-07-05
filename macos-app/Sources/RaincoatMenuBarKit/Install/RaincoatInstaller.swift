import Foundation

// Manages the `raincoat` CLI that ships INSIDE Raincoat.app (Contents/Helpers/raincoat), and
// exposes it on the user's $PATH by symlinking it into /usr/local/bin.
//
// The GUI never needs this — RaincoatLocator already falls back to the bundled copy — but a
// symlink on $PATH lets the user run `raincoat` from Terminal too. /usr/local/bin is on the
// default shell PATH via /etc/paths; it is root-owned on stock macOS, so writing there needs a
// one-time admin authorization (native osascript prompt).
//
// "Managed" install == the exact symlink /usr/local/bin/raincoat -> <this app>/Contents/Helpers
// /raincoat. We only ever create or remove THAT link; a real user install (Homebrew, hand-built,
// a different path) is left untouched and reported as `.installedExternal`.
@MainActor
enum RaincoatInstaller {
    /// A PATH dir present in /etc/paths on every macOS; root-owned, so writes need auth.
    static let installDir = "/usr/local/bin"
    static var installedLinkPath: String { installDir + "/raincoat" }

    enum Status {
        case installedManaged(URL)     // our symlink on $PATH → the bundled binary
        case installedExternal(URL)    // some other raincoat resolves on $PATH (brew, manual)
        case bundledOnly(URL)          // bundled copy exists but nothing is on $PATH
        case missing                   // no bundled copy and nothing on $PATH (un-bundled build)
    }

    enum InstallError: Error, LocalizedError {
        case noBundledBinary
        case cancelled
        case authFailed(String)

        var errorDescription: String? {
            switch self {
            case .noBundledBinary:
                return "This build has no bundled raincoat to install. Run Raincoat from the packaged Raincoat.app."
            case .cancelled:
                return "Authorization was cancelled."
            case .authFailed(let msg):
                return msg.isEmpty ? "The privileged operation failed." : msg
            }
        }
    }

    // MARK: - Status

    static func status() -> Status {
        if let onPath = RaincoatLocator.findOnPath() {
            return isManagedLink(onPath) ? .installedManaged(onPath) : .installedExternal(onPath)
        }
        if let bundled = RaincoatLocator.bundledBinary { return .bundledOnly(bundled) }
        return .missing
    }

    /// True iff `url` is exactly our managed symlink: at installedLinkPath and pointing into
    /// this app's bundle. Deliberately conservative — a foreign raincoat at a different path,
    /// or a /usr/local/bin/raincoat that is a real file (not our symlink), is NOT managed.
    static func isManagedLink(_ url: URL) -> Bool {
        guard url.path == installedLinkPath else { return false }
        guard let dest = try? FileManager.default.destinationOfSymbolicLink(atPath: url.path) else {
            return false   // not a symlink (or unreadable) → a real install, leave it alone
        }
        let destURL = dest.hasPrefix("/")
            ? URL(fileURLWithPath: dest)
            : URL(fileURLWithPath: dest, relativeTo: url.deletingLastPathComponent())
        let bundlePrefix = Bundle.main.bundleURL.standardizedFileURL.path
        return destURL.standardizedFileURL.path.hasPrefix(bundlePrefix)
    }

    // MARK: - Install / uninstall

    /// Symlink the bundled binary into /usr/local/bin (creating the dir if needed). Idempotent:
    /// overwrites an existing managed link, so this doubles as "reinstall" (e.g. after the app
    /// moved). Tries an UNPRIVILEGED symlink first — a Homebrew-style user-owned /usr/local/bin
    /// needs no auth — and only prompts for admin when the write is actually denied.
    @discardableResult
    static func install() throws -> Status {
        guard let src = RaincoatLocator.bundledBinary else { throw InstallError.noBundledBinary }
        if directLink(from: src.path) {
            return status()
        }
        let cmd = "/bin/mkdir -p \(shq(installDir)) && /bin/ln -sf \(shq(src.path)) \(shq(installedLinkPath))"
        try runPrivileged(cmd)
        return status()
    }

    /// Remove our managed symlink. No-op (and never prompts) unless the current install is
    /// `.installedManaged`, so we can never delete a user's real raincoat. Unprivileged when
    /// the dir is user-writable, else escalates.
    @discardableResult
    static func uninstall() throws -> Status {
        guard case .installedManaged = status() else { return status() }
        let fm = FileManager.default
        if fm.isWritableFile(atPath: installDir), (try? fm.removeItem(atPath: installedLinkPath)) != nil {
            return status()
        }
        try runPrivileged("/bin/rm -f \(shq(installedLinkPath))")
        return status()
    }

    /// Best-effort unprivileged symlink (replacing any existing entry). Returns false — so the
    /// caller falls back to privileged auth — when the dir is missing or not user-writable.
    private static func directLink(from src: String) -> Bool {
        let fm = FileManager.default
        guard fm.isWritableFile(atPath: installDir) else { return false }
        try? fm.removeItem(atPath: installedLinkPath)   // `ln -sf` semantics
        do {
            try fm.createSymbolicLink(atPath: installedLinkPath, withDestinationPath: src)
            return true
        } catch {
            return false
        }
    }

    // MARK: - Privileged exec

    // Runs a POSIX shell command as root via the native authorization prompt. Uses an
    // osascript SUBPROCESS (not in-process NSAppleScript) so no Apple-Events entitlement or
    // in-process AppleEvent machinery is involved.
    private static func runPrivileged(_ shellCommand: String) throws {
        let script = "do shell script \(appleQuote(shellCommand)) with administrator privileges"
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        proc.arguments = ["-e", script]
        let errPipe = Pipe()
        proc.standardError = errPipe
        proc.standardOutput = Pipe()
        try proc.run()
        proc.waitUntilExit()
        guard proc.terminationStatus != 0 else { return }

        let msg = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        // osascript reports a cancelled auth prompt as error -128 / "User canceled."
        if msg.contains("-128") || msg.localizedCaseInsensitiveContains("cancel") {
            throw InstallError.cancelled
        }
        throw InstallError.authFailed(msg)
    }

    // MARK: - Quoting helpers

    /// POSIX single-quote: wrap in '…', escaping any embedded ' as '\''.
    private static func shq(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// AppleScript string literal: wrap in "…", escaping \ and ".
    private static func appleQuote(_ s: String) -> String {
        let escaped = s
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        return "\"" + escaped + "\""
    }
}
