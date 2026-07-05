// swift-tools-version: 6.0
import PackageDescription

// Raincoat menu-bar GUI — a thin, read-only layer over the `raincoat` CLI.
//
// The code lives in a LIBRARY target (RaincoatMenuBarKit) so it can be consumed both by:
//   • the thin SwiftPM executable `RaincoatMenuBar` (below), and
//   • the Xcode app target `Raincoat` (macos-app/Raincoat.xcodeproj, generated from
//     project.yml), which depends on this package as a LOCAL PACKAGE and links the library.
// An app target can't depend on an executable product, hence the split.
//
// The executable stays a menu-bar-only agent: `LSUIElement = true` in Info.plist, embedded
// into `__TEXT,__info_plist` via the -sectcreate linker flags so even the bare
// `.build/**/RaincoatMenuBar` binary is a Dock-less agent. `scripts/make-app-bundle.sh`
// wraps that binary + plist into `Raincoat.app`.
let package = Package(
    name: "RaincoatMenuBar",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(name: "RaincoatMenuBar", targets: ["RaincoatMenuBar"]),
        .library(name: "RaincoatMenuBarKit", targets: ["RaincoatMenuBarKit"]),
    ],
    targets: [
        // All app code. `runRaincoatMenuBar()` is the only public symbol.
        .target(
            name: "RaincoatMenuBarKit",
            path: "Sources/RaincoatMenuBarKit",
            // The plist is embedded via -sectcreate (see below), not compiled as a resource.
            exclude: ["Info.plist"],
            swiftSettings: [
                .swiftLanguageMode(.v6)
            ]
        ),
        // Thin executable: main.swift → runRaincoatMenuBar().
        .executableTarget(
            name: "RaincoatMenuBar",
            dependencies: ["RaincoatMenuBarKit"],
            path: "Sources/RaincoatMenuBar",
            swiftSettings: [
                .swiftLanguageMode(.v6)
            ],
            linkerSettings: [
                // Embed Info.plist so LSUIElement applies to the raw executable too.
                // The path is resolved relative to the package root at link time.
                .unsafeFlags([
                    "-Xlinker", "-sectcreate",
                    "-Xlinker", "__TEXT",
                    "-Xlinker", "__info_plist",
                    "-Xlinker", "Sources/RaincoatMenuBarKit/Info.plist",
                ])
            ]
        ),
    ]
)
