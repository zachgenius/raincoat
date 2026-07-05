import AppKit

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private let tray = TrayController()
    private let launcher = LauncherController()
    private let hotKeys = HotKeyManager()

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Belt-and-suspenders with LSUIElement: never show a Dock icon or main menu.
        NSApp.setActivationPolicy(.accessory)

        tray.onShowLauncher = { [weak self] in
            self?.launcher.show()
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
}
