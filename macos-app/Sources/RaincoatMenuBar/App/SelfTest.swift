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
