import AppKit

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private let tray = TrayController()
    private let launcher = LauncherController()
    private let hotKeys = HotKeyManager()
    private var preferences: PreferencesWindowController?

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Belt-and-suspenders with LSUIElement: never show a Dock icon or main menu.
        NSApp.setActivationPolicy(.accessory)

        tray.onShowLauncher = { [weak self] in
            self?.launcher.show()
        }
        tray.onOpenPreferences = { [weak self] in
            self?.showPreferences()
        }
        tray.start()

        hotKeys.register(
            keyCode: Defaults.hotKeyCode,
            modifiers: Defaults.hotKeyModifiers
        ) { [weak self] in
            self?.launcher.toggle()
        }

        maybePromptCLIInstall()
    }

    // First-run check: if the app carries a bundled raincoat that isn't yet on the user's
    // $PATH, offer to install it (so `raincoat` works in Terminal too). Skipped once the user
    // picks "Don't Ask Again", when raincoat is already on $PATH, or for un-bundled dev builds
    // (nothing to install). The GUI itself already works via the bundled fallback either way.
    private func maybePromptCLIInstall() {
        guard !Defaults.cliInstallPromptSuppressed else { return }
        guard case .bundledOnly = RaincoatInstaller.status() else { return }

        let alert = NSAlert()
        alert.messageText = "Install the raincoat command-line tool?"
        alert.informativeText = """
        Raincoat works right now using the copy bundled with this app. To also run \
        `raincoat` from Terminal, install it onto your PATH (a symlink in \
        \(RaincoatInstaller.installDir)). You'll be asked for your password once.

        You can always do this later from Preferences.
        """
        alert.addButton(withTitle: "Install…")
        alert.addButton(withTitle: "Not Now")
        alert.addButton(withTitle: "Don't Ask Again")

        NSApp.activate(ignoringOtherApps: true)
        switch alert.runModal() {
        case .alertFirstButtonReturn:
            do {
                _ = try RaincoatInstaller.install()
            } catch RaincoatInstaller.InstallError.cancelled {
                // Auth dismissed — leave it; they can retry from Preferences.
            } catch {
                let err = NSAlert()
                err.alertStyle = .warning
                err.messageText = "Couldn't install the command-line tool"
                err.informativeText = error.localizedDescription
                err.addButton(withTitle: "OK")
                err.runModal()
            }
        case .alertThirdButtonReturn:
            Defaults.cliInstallPromptSuppressed = true
        default:
            break   // "Not Now" — ask again next launch
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        hotKeys.unregister()
    }

    // Opens the single shared Preferences window. Because this is an .accessory (LSUIElement)
    // app, temporarily become a .regular app so the window can take keyboard focus, and revert
    // to .accessory when it closes.
    private func showPreferences() {
        let controller: PreferencesWindowController
        if let existing = preferences {
            controller = existing
        } else {
            controller = PreferencesWindowController(hotKeys: hotKeys)
            controller.onClose = {
                NSApp.setActivationPolicy(.accessory)
            }
            preferences = controller
        }
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        controller.show()
    }
}
