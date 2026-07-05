// swift-tools-version: 6.0
import PackageDescription

// Raincoat menu-bar GUI — a thin, read-only layer over the `raincoat` CLI.
//
// This is a standalone SwiftPM executable (NOT part of the CMake build). It builds a
// menu-bar-only agent app: `LSUIElement = true` in the embedded Info.plist plus a runtime
// `.accessory` activation policy, so it never shows a Dock icon.
//
// The Info.plist is embedded directly into the executable's `__TEXT,__info_plist` section via
// the linker flags below, so even the bare `.build/**/RaincoatMenuBar` binary is treated as an
// agent. `scripts/make-app-bundle.sh` wraps the same binary + plist into `Raincoat.app`.
let package = Package(
    name: "RaincoatMenuBar",
    platforms: [
        .macOS(.v14)
    ],
    targets: [
        .executableTarget(
            name: "RaincoatMenuBar",
            path: "Sources/RaincoatMenuBar",
            // The plist is embedded via -sectcreate, not compiled as a resource.
            exclude: ["Info.plist"],
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
                    "-Xlinker", "Sources/RaincoatMenuBar/Info.plist",
                ])
            ]
        )
    ]
)
