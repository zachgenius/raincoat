import AppKit
import Darwin

// The menu-bar tray: an NSStatusItem whose badge is the live-run count and whose
// menu shows one row per live run with a per-capability line and a Kill/Reveal/Copy
// submenu. It is a pure reader; the only signals it ever sends are the explicit,
// user-initiated Kill (SIGTERM to child then supervisor).
@MainActor
final class TrayController: NSObject, NSMenuDelegate {
    /// Invoked when the user picks "Open Launcher…" from the menu.
    var onShowLauncher: (() -> Void)?
    /// Invoked when the user picks "Preferences…" from the menu.
    var onOpenPreferences: (() -> Void)?

    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private let store = RunStore()
    private let menu = NSMenu()
    private var watcher: DirectoryWatcher?

    private static let iconSymbol = "shield.lefthalf.filled"

    func start() {
        menu.delegate = self
        menu.autoenablesItems = false
        statusItem.menu = menu

        configureButton()
        store.reload()
        refreshBadge()

        let w = DirectoryWatcher(url: RunPaths.runDirectory) { [weak self] in
            guard let self else { return }
            self.store.reload()
            self.refreshBadge()
        }
        w.start()
        watcher = w
    }

    // MARK: - Status button

    private func configureButton() {
        guard let button = statusItem.button else { return }
        let image = NSImage(systemSymbolName: Self.iconSymbol, accessibilityDescription: "Raincoat")
            ?? NSImage(systemSymbolName: "umbrella", accessibilityDescription: "Raincoat")
        image?.isTemplate = true
        button.image = image
        button.imagePosition = .imageLeft
        button.toolTip = "Raincoat"
    }

    private func refreshBadge() {
        guard let button = statusItem.button else { return }
        let count = store.runs.count
        button.title = count > 0 ? " \(count)" : ""
        button.toolTip = count == 0
            ? "Raincoat — no sandboxes running"
            : "Raincoat — \(count) sandbox\(count == 1 ? "" : "es") running"
    }

    // MARK: - Menu construction (lazy, on open)

    func menuNeedsUpdate(_ menu: NSMenu) {
        // Fresh read right before display so the menu is never stale.
        store.reload()
        refreshBadge()
        rebuild(menu)
    }

    private func rebuild(_ menu: NSMenu) {
        menu.removeAllItems()

        if store.runs.isEmpty {
            let empty = NSMenuItem(title: "No sandboxes running", action: nil, keyEquivalent: "")
            empty.isEnabled = false
            menu.addItem(empty)
        } else {
            for run in store.runs {
                menu.addItem(makeRunItem(run))
            }
        }

        menu.addItem(.separator())

        let launcher = NSMenuItem(title: "Open Launcher…", action: #selector(openLauncher), keyEquivalent: "")
        launcher.target = self
        menu.addItem(launcher)

        menu.addItem(.separator())

        // Mirror of the Preferences "Start at login" checkbox.
        let login = NSMenuItem(title: "Launch at Login", action: #selector(toggleLoginItem), keyEquivalent: "")
        login.target = self
        login.state = LoginItem.isEnabled ? .on : .off
        login.isEnabled = LoginItem.isBundled
        menu.addItem(login)

        let prefs = NSMenuItem(title: "Preferences…", action: #selector(openPreferences), keyEquivalent: ",")
        prefs.target = self
        menu.addItem(prefs)

        menu.addItem(.separator())

        let quit = NSMenuItem(title: "Quit Raincoat", action: #selector(quit), keyEquivalent: "q")
        quit.target = self
        menu.addItem(quit)
    }

    private func makeRunItem(_ run: RunStatus) -> NSMenuItem {
        let item = NSMenuItem()
        item.attributedTitle = twoLineTitle(command: run.command, detail: run.capabilities.summary)
        item.representedObject = RunBox(run)
        item.submenu = makeSubmenu(for: run)
        return item
    }

    private func twoLineTitle(command: String, detail: String) -> NSAttributedString {
        let para = NSMutableParagraphStyle()
        para.lineSpacing = 1
        para.paragraphSpacing = 1

        let result = NSMutableAttributedString(
            string: truncated(command, max: 60) + "\n",
            attributes: [
                .font: NSFont.menuFont(ofSize: 0),
                .foregroundColor: NSColor.labelColor,
                .paragraphStyle: para,
            ]
        )
        result.append(NSAttributedString(
            string: detail,
            attributes: [
                .font: NSFont.menuFont(ofSize: NSFont.smallSystemFontSize),
                .foregroundColor: NSColor.secondaryLabelColor,
                .paragraphStyle: para,
            ]
        ))
        return result
    }

    private func makeSubmenu(for run: RunStatus) -> NSMenu {
        let sub = NSMenu()
        sub.autoenablesItems = false

        let reveal = NSMenuItem(title: "Reveal Audit Log", action: #selector(revealAuditLog(_:)), keyEquivalent: "")
        reveal.target = self
        reveal.representedObject = RunBox(run)
        reveal.isEnabled = run.auditLogURL != nil
        sub.addItem(reveal)

        let copy = NSMenuItem(title: "Copy Command", action: #selector(copyCommand(_:)), keyEquivalent: "")
        copy.target = self
        copy.representedObject = RunBox(run)
        sub.addItem(copy)

        sub.addItem(.separator())

        // Contextual, honest detail lines (disabled = informational).
        addInfoRow(to: sub, "backend: \(run.backend.isEmpty ? "—" : run.backend)")
        addInfoRow(to: sub, "net_mode: \(run.netMode.isEmpty ? "—" : run.netMode)")
        addInfoRow(to: sub, "supervisor pid: \(run.supervisorPID)  ·  child pid: \(run.childPID)")
        for note in run.notes.prefix(4) {
            addInfoRow(to: sub, "• \(truncated(note, max: 70))")
        }

        sub.addItem(.separator())

        let kill = NSMenuItem(title: "Kill", action: #selector(killRun(_:)), keyEquivalent: "")
        kill.target = self
        kill.representedObject = RunBox(run)
        sub.addItem(kill)

        return sub
    }

    private func addInfoRow(to menu: NSMenu, _ text: String) {
        let item = NSMenuItem(title: text, action: nil, keyEquivalent: "")
        item.isEnabled = false
        menu.addItem(item)
    }

    // MARK: - Actions

    @objc private func revealAuditLog(_ sender: NSMenuItem) {
        guard let run = (sender.representedObject as? RunBox)?.run, let url = run.auditLogURL else { return }
        if FileManager.default.fileExists(atPath: url.path) {
            NSWorkspace.shared.activateFileViewerSelecting([url])
        } else {
            // Log exists in the schema but not on disk yet — reveal the enclosing dir if we can.
            let dir = url.deletingLastPathComponent()
            if FileManager.default.fileExists(atPath: dir.path) {
                NSWorkspace.shared.activateFileViewerSelecting([dir])
            } else {
                NSSound.beep()
            }
        }
    }

    @objc private func copyCommand(_ sender: NSMenuItem) {
        guard let run = (sender.representedObject as? RunBox)?.run else { return }
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(run.command, forType: .string)
    }

    @objc private func killRun(_ sender: NSMenuItem) {
        guard let run = (sender.representedObject as? RunBox)?.run else { return }
        // SIGTERM the child first, then the supervisor (which owns teardown + status file).
        if let child = run.childPidT { _ = kill(child, SIGTERM) }
        if let sup = run.supervisorPidT { _ = kill(sup, SIGTERM) }
        // Refresh promptly; the supervisor's cleanup_root() removes the status file.
        store.reload()
        refreshBadge()
    }

    @objc private func openLauncher() {
        onShowLauncher?()
    }

    @objc private func openPreferences() {
        onOpenPreferences?()
    }

    @objc private func toggleLoginItem() {
        do {
            _ = try LoginItem.setEnabled(!LoginItem.isEnabled)
        } catch {
            NSSound.beep()
            log.error("login item toggle failed: \(String(describing: error), privacy: .public)")
        }
    }

    @objc private func quit() {
        NSApp.terminate(nil)
    }
}

// Boxes a RunStatus value so it can ride in NSMenuItem.representedObject (Any?).
private final class RunBox {
    let run: RunStatus
    init(_ run: RunStatus) { self.run = run }
}

private func truncated(_ s: String, max: Int) -> String {
    guard s.count > max else { return s }
    return String(s.prefix(max - 1)) + "…"
}
