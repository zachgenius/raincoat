import Foundation

// Resolves the `raincoat` binary. Two entry points:
//
//   find()        — full resolution used to actually LAUNCH. Search order:
//                   1. each dir on $PATH
//                   2. /usr/local/bin, /opt/homebrew/bin  (a GUI app's inherited $PATH is
//                      usually minimal, so these common install dirs are checked explicitly)
//                   3. a UserDefaults override path
//                   4. the copy bundled INSIDE Raincoat.app (Contents/Helpers/raincoat)
//                   The bundled fallback (4) is why the GUI works out of the box even before the
//                   user has installed `raincoat` onto their $PATH.
//
//   findOnPath()  — everything EXCEPT the bundled fallback, i.e. a raincoat the user could also
//                   run from a shell. RaincoatInstaller uses it to decide whether `raincoat` is
//                   actually on $PATH (and therefore whether to offer to install it).
enum RaincoatLocator {
    static func find() -> URL? {
        return findOnPath() ?? bundledBinary
    }

    static func findOnPath() -> URL? {
        let fm = FileManager.default

        if let path = ProcessInfo.processInfo.environment["PATH"] {
            for dir in path.split(separator: ":", omittingEmptySubsequences: true) {
                let candidate = URL(fileURLWithPath: String(dir)).appendingPathComponent("raincoat")
                if fm.isExecutableFile(atPath: candidate.path) { return candidate }
            }
        }

        for path in ["/usr/local/bin/raincoat", "/opt/homebrew/bin/raincoat"] {
            if fm.isExecutableFile(atPath: path) { return URL(fileURLWithPath: path) }
        }

        if let override = Defaults.raincoatPath, fm.isExecutableFile(atPath: override) {
            return URL(fileURLWithPath: override)
        }

        return nil
    }

    /// The `raincoat` shipped inside this .app at Contents/Helpers/raincoat, if present and
    /// executable. Nil for a bare `.build/**/RaincoatMenuBar` (no Contents/Helpers), so dev
    /// builds simply have no bundled fallback. Nonisolated: consulted off the main actor by
    /// LaunchService.
    static var bundledBinary: URL? {
        let url = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/raincoat")
        return FileManager.default.isExecutableFile(atPath: url.path) ? url : nil
    }
}
