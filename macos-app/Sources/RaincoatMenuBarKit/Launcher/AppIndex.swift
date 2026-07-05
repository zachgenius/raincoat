import AppKit
import Foundation

// Enumerates installed .app bundles from the standard locations. Shallow scan plus a
// single level into non-.app subfolders (e.g. /System/Applications/Utilities). Names
// come from the bundle's display name so results read like Spotlight.
enum AppIndex {
    static func scan() -> [SearchItem] {
        let fm = FileManager.default
        var roots = ["/Applications", "/System/Applications"]
        roots.append(fm.homeDirectoryForCurrentUser.appendingPathComponent("Applications").path)

        var seen = Set<String>()
        var items: [SearchItem] = []
        for root in roots {
            collect(in: root, depth: 0, into: &items, seen: &seen)
        }
        // Alphabetical baseline; the launcher re-ranks by fuzzy score at query time.
        return items.sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
    }

    private static func collect(in dir: String, depth: Int, into items: inout [SearchItem], seen: inout Set<String>) {
        let fm = FileManager.default
        guard let entries = try? fm.contentsOfDirectory(atPath: dir) else { return }
        for entry in entries {
            let full = (dir as NSString).appendingPathComponent(entry)
            if entry.hasSuffix(".app") {
                guard seen.insert(full).inserted else { continue }
                let url = URL(fileURLWithPath: full)
                items.append(SearchItem(title: displayName(for: url), subtitle: full, kind: .app(url)))
            } else if depth == 0 {
                var isDir: ObjCBool = false
                if fm.fileExists(atPath: full, isDirectory: &isDir), isDir.boolValue {
                    collect(in: full, depth: depth + 1, into: &items, seen: &seen)
                }
            }
        }
    }

    static func displayName(for appURL: URL) -> String {
        if let bundle = Bundle(url: appURL) {
            if let name = bundle.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String, !name.isEmpty {
                return name
            }
            if let name = bundle.object(forInfoDictionaryKey: "CFBundleName") as? String, !name.isEmpty {
                return name
            }
        }
        return appURL.deletingPathExtension().lastPathComponent
    }
}
