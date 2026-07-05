import AppKit

// Spotlight-style launcher: a floating search panel over installed apps + recent
// commands. Fuzzy-ranks results, and on Enter spawns the selection under raincoat.
@MainActor
final class LauncherController: NSObject, NSTextFieldDelegate, NSTableViewDataSource, NSTableViewDelegate, NSWindowDelegate {
    private let panelWidth: CGFloat = 640
    private let fieldAreaHeight: CGFloat = 52
    private let rowHeight: CGFloat = 42
    private let maxVisibleRows = 8

    private let panel: LauncherPanel
    private let searchField = NSTextField()
    private let tableView = NSTableView()
    private let scrollView = NSScrollView()
    private var scrollHeight: NSLayoutConstraint!

    private var appItems: [SearchItem] = []
    private var indexBuilt = false
    private var results: [SearchItem] = []

    override init() {
        panel = LauncherPanel(
            contentRect: NSRect(x: 0, y: 0, width: panelWidth, height: fieldAreaHeight),
            styleMask: [.borderless, .nonactivatingPanel],
            backing: .buffered,
            defer: false
        )
        super.init()
        configurePanel()
        buildUI()
    }

    // MARK: - Public

    func toggle() {
        if panel.isVisible { hide() } else { show() }
    }

    func show() {
        buildIndexIfNeeded()
        searchField.stringValue = ""
        recomputeResults()
        positionOnActiveScreen()
        panel.makeKeyAndOrderFront(nil)
        panel.makeFirstResponder(searchField)
    }

    func hide() {
        panel.orderOut(nil)
    }

    // MARK: - Panel / UI setup

    private func configurePanel() {
        panel.level = .floating
        panel.isFloatingPanel = true
        panel.hidesOnDeactivate = false
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        panel.isMovableByWindowBackground = false
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .transient]
        panel.delegate = self
    }

    private func buildUI() {
        let container = NSView()
        container.wantsLayer = true
        container.layer?.cornerRadius = 12
        container.layer?.masksToBounds = true

        let effect = NSVisualEffectView()
        effect.material = .popover
        effect.blendingMode = .behindWindow
        effect.state = .active
        effect.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(effect)

        // Search field: large, borderless, no focus ring.
        searchField.translatesAutoresizingMaskIntoConstraints = false
        searchField.font = .systemFont(ofSize: 21, weight: .regular)
        searchField.isBezeled = false
        searchField.isBordered = false
        searchField.drawsBackground = false
        searchField.focusRingType = .none
        searchField.placeholderString = "Search apps and commands…"
        searchField.delegate = self
        searchField.cell?.usesSingleLineMode = true
        searchField.cell?.wraps = false
        searchField.cell?.isScrollable = true
        container.addSubview(searchField)

        let divider = NSBox()
        divider.boxType = .separator
        divider.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(divider)

        // Results table.
        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("main"))
        column.resizingMask = .autoresizingMask
        tableView.addTableColumn(column)
        tableView.headerView = nil
        tableView.backgroundColor = .clear
        tableView.style = .plain
        tableView.rowHeight = rowHeight
        tableView.selectionHighlightStyle = .regular
        tableView.allowsEmptySelection = true
        tableView.allowsMultipleSelection = false
        tableView.refusesFirstResponder = true   // keep keyboard focus in the search field
        tableView.columnAutoresizingStyle = .uniformColumnAutoresizingStyle
        tableView.dataSource = self
        tableView.delegate = self
        tableView.target = self
        tableView.doubleAction = #selector(tableDoubleClicked)

        scrollView.translatesAutoresizingMaskIntoConstraints = false
        scrollView.documentView = tableView
        scrollView.hasVerticalScroller = true
        scrollView.drawsBackground = false
        scrollView.borderType = .noBorder
        scrollView.automaticallyAdjustsContentInsets = false
        container.addSubview(scrollView)

        scrollHeight = scrollView.heightAnchor.constraint(equalToConstant: 0)

        NSLayoutConstraint.activate([
            effect.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            effect.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            effect.topAnchor.constraint(equalTo: container.topAnchor),
            effect.bottomAnchor.constraint(equalTo: container.bottomAnchor),

            searchField.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 18),
            searchField.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -18),
            // Center the field vertically within a fixed-height field area: a single-line
            // NSTextField top-aligns its text, so pinning it to the top left it hugging the top
            // with dead space below. centerY on the field-area midline puts the text in the middle.
            searchField.centerYAnchor.constraint(equalTo: container.topAnchor, constant: fieldAreaHeight / 2),

            divider.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            divider.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            divider.topAnchor.constraint(equalTo: container.topAnchor, constant: fieldAreaHeight),

            scrollView.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            scrollView.topAnchor.constraint(equalTo: divider.bottomAnchor),
            scrollView.bottomAnchor.constraint(equalTo: container.bottomAnchor),
            scrollHeight,
        ])

        panel.contentView = container
    }

    // MARK: - Index & results

    private func buildIndexIfNeeded() {
        guard !indexBuilt else { return }
        appItems = AppIndex.scan()
        indexBuilt = true
    }

    private func recomputeResults() {
        let query = searchField.stringValue.trimmingCharacters(in: .whitespaces)
        let recents = Recents.all()
        let recentItems = recents.enumerated().map { idx, cmd in
            SearchItem.recent(cmd, index: idx, total: recents.count)
        }

        if query.isEmpty {
            // Recents first (already recency-ordered), then apps.
            results = Array((recentItems + appItems).prefix(60))
        } else {
            let candidates = recentItems + appItems
            var scored: [(SearchItem, Int)] = []
            for item in candidates {
                if let s = FuzzyMatcher.score(query: query, candidate: item.title) {
                    scored.append((item, s + item.recencyBoost))
                } else if let s = FuzzyMatcher.score(query: query, candidate: item.subtitle) {
                    scored.append((item, s - 3 + item.recencyBoost))
                }
            }
            results = scored.sorted { $0.1 > $1.1 }.map(\.0)
            results = Array(results.prefix(60))
        }

        tableView.reloadData()
        if !results.isEmpty {
            tableView.selectRowIndexes([0], byExtendingSelection: false)
        }
        updatePanelHeight()
    }

    private func updatePanelHeight() {
        let visible = min(results.count, maxVisibleRows)
        let listHeight = CGFloat(visible) * rowHeight
        scrollHeight.constant = listHeight

        let total = fieldAreaHeight + 1 + listHeight
        var frame = panel.frame
        let top = frame.maxY
        frame.size.height = total
        frame.origin.y = top - total   // keep the top edge pinned as the list grows/shrinks
        panel.setFrame(frame, display: true)
    }

    private func positionOnActiveScreen() {
        let screen = NSScreen.screens.first(where: { $0.frame.contains(NSEvent.mouseLocation) })
            ?? NSScreen.main
            ?? NSScreen.screens.first
        guard let visible = screen?.visibleFrame else { return }

        let height = panel.frame.height
        let x = visible.midX - panelWidth / 2
        // Pin the panel's TOP ~18% below the screen top and let the results grow DOWNWARD, so a
        // tall list never clips above the menu bar (positioning by the bottom origin did). Clamp
        // so the bottom never falls below the visible area either.
        let topY = visible.maxY - visible.height * 0.18
        let y = max(visible.minY, topY - height)
        panel.setFrame(NSRect(x: x, y: y, width: panelWidth, height: height), display: false)
    }

    // MARK: - Launch

    private func launchSelected() {
        let query = searchField.stringValue.trimmingCharacters(in: .whitespaces)
        let row = tableView.selectedRow

        let item: SearchItem
        if row >= 0, row < results.count {
            item = results[row]
        } else if !query.isEmpty {
            item = SearchItem(title: query, subtitle: query, kind: .command(query))
        } else {
            return
        }

        hide()
        do {
            try LaunchService.launch(item)
        } catch {
            presentLaunchError(error)
        }
    }

    private func presentLaunchError(_ error: Error) {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.alertStyle = .warning

        if case LaunchService.LaunchError.raincoatNotFound = error {
            alert.messageText = "Couldn't find the raincoat binary"
            alert.informativeText = """
            Raincoat looked on $PATH, then in /usr/local/bin and /opt/homebrew/bin.

            Install raincoat (e.g. via Homebrew or `make install`), or set an explicit path with:

              defaults write dev.raincoat.menubar raincoat.binaryPath /full/path/to/raincoat
            """
        } else if case LaunchService.LaunchError.appSandboxed = error {
            alert.messageText = "Can't sandbox an App Store app"
            alert.informativeText = error.localizedDescription
        } else {
            alert.messageText = "Couldn't launch under Raincoat"
            alert.informativeText = error.localizedDescription
        }
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    @objc private func tableDoubleClicked() {
        launchSelected()
    }

    private func moveSelection(by delta: Int) {
        guard !results.isEmpty else { return }
        let current = tableView.selectedRow
        let next: Int
        if current < 0 {
            next = delta > 0 ? 0 : results.count - 1
        } else {
            next = max(0, min(results.count - 1, current + delta))
        }
        tableView.selectRowIndexes([next], byExtendingSelection: false)
        tableView.scrollRowToVisible(next)
    }

    // MARK: - NSTextFieldDelegate

    func controlTextDidChange(_ obj: Notification) {
        recomputeResults()
    }

    func control(_ control: NSControl, textView: NSTextView, doCommandBy commandSelector: Selector) -> Bool {
        switch commandSelector {
        case #selector(NSResponder.moveUp(_:)):
            moveSelection(by: -1); return true
        case #selector(NSResponder.moveDown(_:)):
            moveSelection(by: 1); return true
        case #selector(NSResponder.insertNewline(_:)):
            launchSelected(); return true
        case #selector(NSResponder.cancelOperation(_:)):
            hide(); return true
        default:
            return false
        }
    }

    // MARK: - NSTableView data source / delegate

    func numberOfRows(in tableView: NSTableView) -> Int { results.count }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        let id = NSUserInterfaceItemIdentifier("ResultCell")
        let cell = (tableView.makeView(withIdentifier: id, owner: self) as? ResultCellView) ?? {
            let v = ResultCellView(frame: .zero)
            v.identifier = id
            return v
        }()
        let item = results[row]
        cell.configure(title: item.title, subtitle: item.subtitle)
        return cell
    }

    func tableView(_ tableView: NSTableView, shouldSelectRow row: Int) -> Bool { true }

    // MARK: - NSWindowDelegate

    func windowDidResignKey(_ notification: Notification) {
        // Click-away / focus loss dismisses the launcher.
        hide()
    }
}
