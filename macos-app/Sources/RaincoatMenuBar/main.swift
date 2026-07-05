import AppKit

// Entry point. Top-level code in main.swift runs on the main actor under Swift 6, so
// constructing the (MainActor) app objects here is safe. We drive NSApplication
// directly instead of @NSApplicationMain because this is a plain SwiftPM executable.
// Headless reader smoke test — no GUI, no run loop.
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
app.setActivationPolicy(.accessory)
app.run()
