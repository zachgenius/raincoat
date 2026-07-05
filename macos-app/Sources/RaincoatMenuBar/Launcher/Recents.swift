import Foundation

// Persisted most-recent-first list of launched command lines (UserDefaults-backed).
enum Recents {
    private static let limit = 50

    static func all() -> [String] { Defaults.recentCommands }

    static func add(_ commandLine: String) {
        let trimmed = commandLine.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        var list = Defaults.recentCommands.filter { $0 != trimmed }
        list.insert(trimmed, at: 0)
        if list.count > limit { list = Array(list.prefix(limit)) }
        Defaults.recentCommands = list
    }
}
