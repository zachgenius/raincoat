import Foundation

// A single launchable result: either an installed .app bundle or a free-form command.
struct SearchItem: Equatable {
    enum Kind: Equatable {
        case app(URL)
        case command(String)
    }

    let title: String       // display name (bundle display name, or command basename)
    let subtitle: String    // path / provenance
    let kind: Kind
    var recencyBoost: Int = 0   // added to fuzzy score so recent items float up

    static func recent(_ commandLine: String, index: Int, total: Int) -> SearchItem {
        let basename = (commandLine as NSString).lastPathComponent
        return SearchItem(
            title: basename.isEmpty ? commandLine : basename,
            subtitle: "recent · \(commandLine)",
            kind: .command(commandLine),
            recencyBoost: max(1, total - index)
        )
    }
}
