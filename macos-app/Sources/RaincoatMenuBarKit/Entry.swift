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

    let app = NSApplication.shared
    let delegate = AppDelegate()
    app.delegate = delegate
    // Belt-and-suspenders with LSUIElement: never show a Dock icon or main menu.
    app.setActivationPolicy(.accessory)
    app.run()
}
