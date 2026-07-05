import AppKit
import Foundation

// Headless smoke test for the read-only pipeline (RunStore + Codable + liveness).
// Invoke with `RaincoatMenuBar --selftest`; prints the live runs it would show in the
// tray and exits. Purely a reader — same code path the menu uses, no GUI.
@MainActor
enum SelfTest {
    static func run() {
        let dir = RunPaths.runDirectory
        FileHandle.standardError.write(Data("raincoat selftest — reading \(dir.path)\n".utf8))

        let store = RunStore()
        store.reload()

        print("live runs: \(store.runs.count)")
        for (i, run) in store.runs.enumerated() {
            print("""
            [\(i + 1)] \(run.command)
                \(run.capabilities.summary)
                backend=\(run.backend.isEmpty ? "—" : run.backend) net_mode=\(run.netMode.isEmpty ? "—" : run.netMode)
                supervisor_pid=\(run.supervisorPID) child_pid=\(run.childPID) audit_log=\(run.auditLog.isEmpty ? "—" : run.auditLog)
                notes=\(run.notes)
            """)
        }
    }

    // Reports how the bundled-CLI installer sees the world: bundled path, PATH resolution, and
    // the resulting install Status. No auth prompt, no writes — purely diagnostic.
    static func runInstall() {
        print("bundled binary: \(RaincoatLocator.bundledBinary?.path ?? "none (un-bundled build)")")
        print("on PATH:        \(RaincoatLocator.findOnPath()?.path ?? "not found")")
        print("managed link:   \(RaincoatInstaller.installedLinkPath)")
        print("status:         \(describe(RaincoatInstaller.status()))")
    }

    // Actually performs the install (or uninstall) from the command line, INCLUDING the admin
    // auth dialog when escalation is needed (force it anywhere with
    // RAINCOAT_INSTALL_FORCE_PRIVILEGED=1). Prints the resulting status. Returns an exit code.
    static func runInstallAction(uninstall: Bool) -> Int32 {
        do {
            let result = uninstall ? try RaincoatInstaller.uninstall() : try RaincoatInstaller.install()
            print("\(uninstall ? "uninstall" : "install") OK → \(describe(result))")
            return 0
        } catch RaincoatInstaller.InstallError.cancelled {
            print("cancelled by user")
            return 1
        } catch {
            print("error: \(error.localizedDescription)")
            return 1
        }
    }

    private static func describe(_ status: RaincoatInstaller.Status) -> String {
        switch status {
        case .installedManaged(let u): return "installedManaged(\(u.path))"
        case .installedExternal(let u): return "installedExternal(\(u.path))"
        case .bundledOnly(let u): return "bundledOnly(\(u.path))"
        case .missing: return "missing"
        }
    }

    // Constructs the Preferences window (and exercises LoginItem / RaincoatLocator /
    // KeyCombo) without running the event loop, to confirm nothing throws off-screen.
    static func runPrefs() {
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)

        let controller = PreferencesWindowController(hotKeys: HotKeyManager())
        controller.show()   // builds UI + refresh(): reads status, formats the current combo

        print("preferences window constructed OK")
        print("current hotkey: \(KeyCombo.current.displayString)")
        print("raincoat resolved: \(RaincoatLocator.find()?.path ?? "not found")")
        print("login: bundled=\(LoginItem.isBundled) status=\(String(describing: LoginItem.status))")
    }
}
