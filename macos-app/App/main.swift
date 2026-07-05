import RaincoatMenuBarKit

// Xcode app-target entry point. Mirrors the SwiftPM executable's main.swift: all behavior
// lives in RaincoatMenuBarKit, consumed here as a local Swift package. Top-level code in a
// file named main.swift runs on the main actor under Swift 6, so calling the @MainActor
// entry point directly is valid.
runRaincoatMenuBar()
