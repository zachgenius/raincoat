import AppKit

// The single public entry point of RaincoatMenuBarKit. Both the SwiftPM executable
// (Sources/RaincoatMenuBar/main.swift) and the Xcode app target (App/main.swift) are
// thin shims that just call this. Everything else in the module stays `internal`.
//
// It handles the headless `--selftest` / `--selftest-prefs` argv modes (reading
// CommandLine.arguments here, not in a shim) and otherwise boots the AppKit app.
// Blocks until the application terminates.
@MainActor
public func runRaincoatMenuBar() {
    // Headless reader smoke test — parse + liveness, no GUI, no run loop.
    if CommandLine.arguments.contains("--selftest") {
        SelfTest.run()
        exit(0)
    }

    // Headless preferences-construction smoke test.
    if CommandLine.arguments.contains("--selftest-prefs") {
        SelfTest.runPrefs()
        exit(0)
    }

    // Headless CLI-install status smoke test (no auth, no GUI).
    if CommandLine.arguments.contains("--selftest-install") {
        SelfTest.runInstall()
        exit(0)
    }

    // Headless install / uninstall of the bundled CLI onto $PATH. Shows the real admin dialog
    // when escalation is needed (RAINCOAT_INSTALL_FORCE_PRIVILEGED=1 forces it).
    if CommandLine.arguments.contains("--install-cli") {
        exit(SelfTest.runInstallAction(uninstall: false))
    }
    if CommandLine.arguments.contains("--uninstall-cli") {
        exit(SelfTest.runInstallAction(uninstall: true))
    }

    let app = NSApplication.shared
    let delegate = AppDelegate()
    app.delegate = delegate
    // Belt-and-suspenders with LSUIElement: never show a Dock icon or main menu.
    app.setActivationPolicy(.accessory)
    app.run()
}
