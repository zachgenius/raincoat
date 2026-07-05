import AppKit
import ServiceManagement

// The Preferences window. A single shared instance is owned by AppDelegate; `show()`
// brings it to front. Because the app is LSUIElement/.accessory, AppDelegate flips the
// activation policy to .regular while it's open (so the window can take focus) and this
// controller signals `onClose` to revert to .accessory when it closes.
@MainActor
final class PreferencesWindowController: NSObject, NSWindowDelegate, NSTextFieldDelegate {
    /// Invoked when the window closes, so AppDelegate can restore .accessory policy.
    var onClose: (() -> Void)?

    private let hotKeys: HotKeyManager
    private let window: NSWindow
    private var didCenter = false

    private let recorder: HotKeyRecorderView
    private let hotKeyMessage = PreferencesWindowController.makeHint()

    private let raincoatField = NSTextField()
    private let raincoatStatus = PreferencesWindowController.makeHint()

    private let profileField = NSTextField()
    private let profileStatus = PreferencesWindowController.makeHint()

    private let loginCheckbox = NSButton(checkboxWithTitle: "Launch Raincoat at login", target: nil, action: nil)
    private let loginHint = PreferencesWindowController.makeHint()

    init(hotKeys: HotKeyManager) {
        self.hotKeys = hotKeys
        self.recorder = HotKeyRecorderView(combo: .current)
        self.window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 520, height: 320),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        super.init()
        buildUI()
        wireActions()
    }

    // MARK: - Public

    func show() {
        refresh()
        if !didCenter {
            window.center()
            didCenter = true
        }
        window.makeKeyAndOrderFront(nil)
    }

    // MARK: - UI

    private func buildUI() {
        window.title = "Raincoat Preferences"
        window.isReleasedWhenClosed = false   // AppDelegate keeps the single instance
        window.delegate = self

        recorder.translatesAutoresizingMaskIntoConstraints = false

        let resetButton = NSButton(title: "Use ⌥Space", target: self, action: #selector(resetHotKey))
        resetButton.bezelStyle = .rounded
        resetButton.controlSize = .small

        let hotKeyRow = NSStackView(views: [recorder, resetButton])
        hotKeyRow.orientation = .horizontal
        hotKeyRow.spacing = 8

        configure(field: raincoatField, placeholder: "Auto-discover on $PATH (leave empty)")
        let raincoatBrowse = NSButton(title: "Browse…", target: self, action: #selector(browseRaincoat))
        raincoatBrowse.bezelStyle = .rounded
        let raincoatRow = fieldRow(raincoatField, raincoatBrowse)

        configure(field: profileField, placeholder: "None — raincoat uses its default")
        let profileBrowse = NSButton(title: "Browse…", target: self, action: #selector(browseProfile))
        profileBrowse.bezelStyle = .rounded
        let profileRow = fieldRow(profileField, profileBrowse)

        let grid = NSGridView(views: [
            [label("Global hotkey:"), stackedCell([hotKeyRow, hotKeyMessage])],
            [label("raincoat binary:"), stackedCell([raincoatRow, raincoatStatus])],
            [label("Default profile:"), stackedCell([profileRow, profileStatus])],
            [label("Start at login:"), stackedCell([loginCheckbox, loginHint])],
        ])
        grid.translatesAutoresizingMaskIntoConstraints = false
        grid.rowSpacing = 16
        grid.columnSpacing = 12
        grid.column(at: 0).xPlacement = .trailing
        grid.rowAlignment = .firstBaseline
        for i in 0..<grid.numberOfRows {
            grid.row(at: i).yPlacement = .top
        }

        let container = NSView()
        container.addSubview(grid)
        NSLayoutConstraint.activate([
            grid.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 20),
            grid.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -20),
            grid.topAnchor.constraint(equalTo: container.topAnchor, constant: 20),
            grid.bottomAnchor.constraint(equalTo: container.bottomAnchor, constant: -20),
        ])

        window.contentView = container
        window.layoutIfNeeded()
        window.setContentSize(container.fittingSize)
    }

    private func wireActions() {
        recorder.onCapture = { [weak self] combo in self?.applyHotKey(combo) }
        recorder.onInvalid = { [weak self] in
            self?.setMessage(self?.hotKeyMessage, "Add ⌘, ⌥, or ⌃ to the shortcut.", kind: .warning)
        }
        raincoatField.delegate = self
        profileField.delegate = self
        loginCheckbox.target = self
        loginCheckbox.action = #selector(toggleLogin)
    }

    // MARK: - Refresh (on open)

    private func refresh() {
        recorder.update(to: .current)
        setMessage(hotKeyMessage, "", kind: .info)

        raincoatField.stringValue = Defaults.raincoatPath ?? ""
        refreshRaincoatStatus()

        profileField.stringValue = Defaults.defaultProfilePath ?? ""
        refreshProfileStatus()

        refreshLogin()
    }

    // MARK: - Hotkey

    private func applyHotKey(_ new: KeyCombo) {
        let old = KeyCombo.current
        if hotKeys.rebind(keyCode: new.keyCode, modifiers: new.carbonModifiers) {
            Defaults.hotKeyCode = new.keyCode
            Defaults.hotKeyModifiers = new.carbonModifiers
            recorder.update(to: new)
            setMessage(hotKeyMessage, "Shortcut set to \(new.displayString).", kind: .info)
        } else {
            // Re-registration failed (e.g. combo already claimed) — restore the old binding.
            _ = hotKeys.rebind(keyCode: old.keyCode, modifiers: old.carbonModifiers)
            recorder.update(to: old)
            setMessage(hotKeyMessage, "Couldn't register that shortcut — it may already be in use.", kind: .warning)
        }
    }

    @objc private func resetHotKey() {
        applyHotKey(.defaultCombo)
    }

    // MARK: - raincoat path

    @objc private func browseRaincoat() {
        guard let path = runOpenPanel(chooseDirectories: false, message: "Choose the raincoat executable") else { return }
        raincoatField.stringValue = path
        Defaults.raincoatPath = path
        refreshRaincoatStatus()
    }

    private func refreshRaincoatStatus() {
        if let found = RaincoatLocator.find() {
            setMessage(raincoatStatus, "found ✓  \(found.path)", kind: .ok)
        } else {
            setMessage(raincoatStatus, "not found ✗  (install raincoat or set a path above)", kind: .warning)
        }
    }

    // MARK: - Default profile

    @objc private func browseProfile() {
        guard let path = runOpenPanel(chooseDirectories: false, message: "Choose a raincoat profile") else { return }
        profileField.stringValue = path
        Defaults.defaultProfilePath = path
        refreshProfileStatus()
    }

    private func refreshProfileStatus() {
        guard let path = Defaults.defaultProfilePath else {
            setMessage(profileStatus, "None — launches use raincoat's default profile.", kind: .info)
            return
        }
        if FileManager.default.fileExists(atPath: path) {
            setMessage(profileStatus, "found ✓  passes --profile \(path)", kind: .ok)
        } else {
            setMessage(profileStatus, "not found ✗  \(path)", kind: .warning)
        }
    }

    // MARK: - Start at login

    @objc private func toggleLogin() {
        let wantEnabled = loginCheckbox.state == .on
        do {
            _ = try LoginItem.setEnabled(wantEnabled)
        } catch {
            setMessage(loginHint, "Couldn't update login item: \(error.localizedDescription)", kind: .warning)
        }
        refreshLogin()
    }

    private func refreshLogin() {
        guard LoginItem.isBundled else {
            loginCheckbox.state = .off
            loginCheckbox.isEnabled = false
            setMessage(loginHint, "Only available from the bundled Raincoat.app (not a raw build).", kind: .info)
            return
        }
        loginCheckbox.isEnabled = true

        switch LoginItem.status {
        case .enabled:
            loginCheckbox.state = .on
            setMessage(loginHint, "Raincoat will start automatically at login.", kind: .ok)
        case .requiresApproval:
            loginCheckbox.state = .on
            setMessage(loginHint, "Pending approval — enable in System Settings › General › Login Items.", kind: .warning)
        case .notRegistered:
            loginCheckbox.state = .off
            setMessage(loginHint, "", kind: .info)
        case .notFound:
            loginCheckbox.state = .off
            setMessage(loginHint, "Login service unavailable for this build.", kind: .info)
        @unknown default:
            loginCheckbox.state = .off
            setMessage(loginHint, "", kind: .info)
        }
    }

    // MARK: - NSTextFieldDelegate

    func controlTextDidChange(_ obj: Notification) {
        guard let field = obj.object as? NSTextField else { return }
        if field === raincoatField {
            Defaults.raincoatPath = field.stringValue
            refreshRaincoatStatus()
        } else if field === profileField {
            Defaults.defaultProfilePath = field.stringValue
            refreshProfileStatus()
        }
    }

    // MARK: - NSWindowDelegate

    func windowWillClose(_ notification: Notification) {
        onClose?()
    }

    // MARK: - Helpers

    private enum MessageKind { case info, ok, warning }

    private func setMessage(_ label: NSTextField?, _ text: String, kind: MessageKind) {
        guard let label else { return }
        label.stringValue = text
        switch kind {
        case .info: label.textColor = .secondaryLabelColor
        case .ok: label.textColor = .systemGreen
        case .warning: label.textColor = .systemOrange
        }
    }

    private func runOpenPanel(chooseDirectories: Bool, message: String) -> String? {
        let panel = NSOpenPanel()
        panel.message = message
        panel.canChooseFiles = true
        panel.canChooseDirectories = chooseDirectories
        panel.allowsMultipleSelection = false
        panel.treatsFilePackagesAsDirectories = true
        return panel.runModal() == .OK ? panel.url?.path : nil
    }

    private func configure(field: NSTextField, placeholder: String) {
        field.placeholderString = placeholder
        field.translatesAutoresizingMaskIntoConstraints = false
        field.widthAnchor.constraint(equalToConstant: 300).isActive = true
    }

    private func fieldRow(_ field: NSTextField, _ button: NSButton) -> NSStackView {
        let row = NSStackView(views: [field, button])
        row.orientation = .horizontal
        row.spacing = 8
        return row
    }

    private func label(_ text: String) -> NSTextField {
        let l = NSTextField(labelWithString: text)
        l.font = .systemFont(ofSize: NSFont.systemFontSize)
        return l
    }

    private func stackedCell(_ views: [NSView]) -> NSStackView {
        let stack = NSStackView(views: views)
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 4
        return stack
    }

    private static func makeHint() -> NSTextField {
        let l = NSTextField(labelWithString: "")
        l.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        l.textColor = .secondaryLabelColor
        l.lineBreakMode = .byTruncatingMiddle
        l.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        return l
    }
}
