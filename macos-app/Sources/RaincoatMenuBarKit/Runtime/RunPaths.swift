import Foundation

// The one directory this app reads. Mirrors run_status_dir() on the C++ side
// (~/Library/Application Support/Raincoat) plus the "run" subdir.
enum RunPaths {
    static var supportDirectory: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Raincoat", isDirectory: true)
    }

    static var runDirectory: URL {
        supportDirectory.appendingPathComponent("run", isDirectory: true)
    }
}
