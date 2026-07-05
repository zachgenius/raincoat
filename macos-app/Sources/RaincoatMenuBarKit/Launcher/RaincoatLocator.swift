import Foundation

// Resolves the `raincoat` binary. Search order matches docs/GUI-MACOS.md:
//   1. each dir on $PATH
//   2. /usr/local/bin, /opt/homebrew/bin  (a GUI app's inherited $PATH is usually minimal,
//      so these common install dirs are checked explicitly)
//   3. a UserDefaults override path (final fallback for non-standard installs)
enum RaincoatLocator {
    static func find() -> URL? {
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
}
