import RaincoatMenuBarKit

// Thin SwiftPM executable. All behavior lives in RaincoatMenuBarKit so the Xcode app
// target can share it via a local-package dependency. Top-level code in main.swift runs
// on the main actor under Swift 6, so calling the @MainActor entry point here is valid.
runRaincoatMenuBar()
