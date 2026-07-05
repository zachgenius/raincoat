import AppKit
import Foundation

// Resolves a SearchItem to a concrete argv and spawns `raincoat -- <argv...>`.
//
// For .app bundles it execs the bundle's REAL binary
// (<App>.app/Contents/MacOS/<CFBundleExecutable>) directly, NOT `open -a`: `open`
// re-parents the target under launchd, which escapes the per-process sandbox entirely
// (see docs/GUI-MACOS.md). raincoat then writes its own status file, so the new run
// shows up in the tray with no IPC.
enum LaunchService {
    enum LaunchError: Error, LocalizedError {
        case unresolved
        case raincoatNotFound

        var errorDescription: String? {
            switch self {
            case .unresolved:
                return "Couldn't resolve that item to a runnable command."
            case .raincoatNotFound:
                return "The raincoat binary wasn't found."
            }
        }
    }

    /// Launches `item` under raincoat and records it in recents. Throws on resolution or spawn failure.
    static func launch(_ item: SearchItem) throws {
        guard let argv = resolveArgv(for: item), !argv.isEmpty else { throw LaunchError.unresolved }
        guard let raincoat = RaincoatLocator.find() else { throw LaunchError.raincoatNotFound }

        let process = Process()
        process.executableURL = raincoat
        process.arguments = ["--"] + argv
        // Run detached; raincoat is the sandbox supervisor and owns its own lifecycle/status file.
        try process.run()

        Recents.add(argv.joined(separator: " "))
    }

    /// The argv to hand to `raincoat --`, or nil if the item can't be resolved.
    static func resolveArgv(for item: SearchItem) -> [String]? {
        switch item.kind {
        case .command(let line):
            let tokens = tokenize(line)
            return tokens.isEmpty ? nil : tokens
        case .app(let url):
            guard let exe = executablePath(forBundle: url) else { return nil }
            return [exe]
        }
    }

    /// <App>.app/Contents/MacOS/<CFBundleExecutable>, read from the bundle Info.plist.
    static func executablePath(forBundle appURL: URL) -> String? {
        let plistURL = appURL.appendingPathComponent("Contents/Info.plist")
        if let data = try? Data(contentsOf: plistURL),
           let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
           let exe = plist["CFBundleExecutable"] as? String, !exe.isEmpty {
            let candidate = appURL.appendingPathComponent("Contents/MacOS/\(exe)")
            if FileManager.default.isExecutableFile(atPath: candidate.path) { return candidate.path }
        }
        // Fallback: conventional <AppName>/Contents/MacOS/<AppName>.
        let name = appURL.deletingPathExtension().lastPathComponent
        let fallback = appURL.appendingPathComponent("Contents/MacOS/\(name)")
        return FileManager.default.isExecutableFile(atPath: fallback.path) ? fallback.path : nil
    }

    // Minimal shell-ish tokenizer: whitespace-separated, honoring single/double quotes
    // and backslash escapes so paths with spaces survive.
    static func tokenize(_ line: String) -> [String] {
        var tokens: [String] = []
        var current = ""
        var hasToken = false
        var quote: Character?
        var escaped = false

        for ch in line {
            if escaped {
                current.append(ch); hasToken = true; escaped = false; continue
            }
            if ch == "\\" && quote != "'" {
                escaped = true; hasToken = true; continue
            }
            if let q = quote {
                if ch == q { quote = nil } else { current.append(ch) }
                hasToken = true
                continue
            }
            if ch == "'" || ch == "\"" {
                quote = ch; hasToken = true; continue
            }
            if ch == " " || ch == "\t" {
                if hasToken { tokens.append(current); current = ""; hasToken = false }
                continue
            }
            current.append(ch); hasToken = true
        }
        if hasToken { tokens.append(current) }
        return tokens
    }
}
