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
