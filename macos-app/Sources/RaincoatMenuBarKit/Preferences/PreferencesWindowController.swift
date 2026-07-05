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

    private let cliButtonRow = NSStackView()
    private let cliStatus = PreferencesWindowController.makeHint()
    private let cliInstruction = PreferencesWindowController.makeHint()

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

        cliButtonRow.orientation = .horizontal
        cliButtonRow.spacing = 8
        // Persistent one-liner so the buttons are self-explanatory in every state.
        cliInstruction.stringValue = "Puts `raincoat` on your PATH (a symlink in \(RaincoatInstaller.installDir)) so you can run it in Terminal. Uninstall removes only that symlink — never a raincoat you installed yourself."
        cliInstruction.lineBreakMode = .byWordWrapping
        cliInstruction.maximumNumberOfLines = 3
        cliInstruction.preferredMaxLayoutWidth = 320

        let grid = NSGridView(views: [
            [label("Global hotkey:"), stackedCell([hotKeyRow, hotKeyMessage])],
            [label("raincoat binary:"), stackedCell([raincoatRow, raincoatStatus])],
            [label("Command-line tool:"), stackedCell([cliButtonRow, cliStatus, cliInstruction])],
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
        refreshCLIStatus()

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

    // MARK: - Command-line tool (bundled CLI → $PATH)

    // Rebuilds the button row + status line to match the current install state. The buttons
    // shown are contextual: install when only bundled, reinstall/uninstall when managed, etc.
    private func refreshCLIStatus() {
        for view in cliButtonRow.arrangedSubviews { cliButtonRow.removeArrangedSubview(view); view.removeFromSuperview() }

        switch RaincoatInstaller.status() {
        case .installedManaged(let url):
            setMessage(cliStatus, "installed ✓  \(url.path) → bundled copy", kind: .ok)
            addCLIButton("Reinstall", #selector(installCLI))
            addCLIButton("Uninstall", #selector(uninstallCLI))
            addCLIButton("Reveal", #selector(revealCLI))
        case .installedExternal(let url):
            setMessage(cliStatus, "on your PATH ✓  \(url.path)  (your own install — not managed here)", kind: .ok)
            addCLIButton("Reveal", #selector(revealCLI))
        case .bundledOnly:
            setMessage(cliStatus, "bundled with this app, but not on your PATH — install to run `raincoat` in Terminal.", kind: .warning)
            addCLIButton("Install to \(RaincoatInstaller.installDir)", #selector(installCLI))
            addCLIButton("Reveal", #selector(revealCLI))
        case .missing:
            setMessage(cliStatus, "not found — run from Raincoat.app, or install raincoat manually.", kind: .warning)
            addCLIButton("How to Install…", #selector(showInstallHelp))
        }
    }

    private func addCLIButton(_ title: String, _ action: Selector) {
        let button = NSButton(title: title, target: self, action: action)
        button.bezelStyle = .rounded
        button.controlSize = .small
        cliButtonRow.addArrangedSubview(button)
    }

    @objc private func installCLI() {
        do {
            _ = try RaincoatInstaller.install()
        } catch RaincoatInstaller.InstallError.cancelled {
            // User dismissed the auth prompt — leave state as-is, no error.
        } catch {
            presentCLIError("Couldn't install the command-line tool", error)
        }
        refreshCLIStatus()
        refreshRaincoatStatus()
    }

    @objc private func uninstallCLI() {
        do {
            _ = try RaincoatInstaller.uninstall()
        } catch RaincoatInstaller.InstallError.cancelled {
        } catch {
            presentCLIError("Couldn't remove the command-line tool", error)
        }
        refreshCLIStatus()
        refreshRaincoatStatus()
    }

    @objc private func revealCLI() {
        let target = RaincoatLocator.bundledBinary ?? RaincoatLocator.findOnPath()
        guard let url = target else { NSSound.beep(); return }
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }

    @objc private func showInstallHelp() {
        let alert = NSAlert()
        alert.messageText = "Install the raincoat command-line tool"
        alert.informativeText = """
        This build has no bundled copy to install (you're running an unpackaged build).

        Build raincoat from source and put it on your PATH:

          cmake -S . -B build
          cmake --build build -j
          sudo cp build/raincoat /usr/local/bin/

        Or set an explicit path under “raincoat binary” above.
        """
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    private func presentCLIError(_ title: String, _ error: Error) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = title
        alert.informativeText = error.localizedDescription
        alert.addButton(withTitle: "OK")
        alert.runModal()
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
