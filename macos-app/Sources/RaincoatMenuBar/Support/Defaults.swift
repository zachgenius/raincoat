import Carbon.HIToolbox
import Foundation

// Typed, centralized access to the handful of UserDefaults keys the app persists.
// Nothing here writes sandbox state — these are pure app preferences.
enum Defaults {
    private static var store: UserDefaults { .standard }

    private enum Key {
        static let raincoatPath = "raincoat.binaryPath"
        static let hotKeyCode = "hotkey.keyCode"
        static let hotKeyModifiers = "hotkey.modifiers"
        static let recents = "launcher.recents"
    }

    /// Optional explicit path to the `raincoat` binary, used as a final fallback by RaincoatLocator.
    static var raincoatPath: String? {
        get { (store.string(forKey: Key.raincoatPath)?.trimmingCharacters(in: .whitespaces)).flatMap { $0.isEmpty ? nil : $0 } }
        set { store.set(newValue, forKey: Key.raincoatPath) }
    }

    // Global hotkey. Default ⌥Space (Space = kVK_Space = 49, option = Carbon optionKey).
    static var hotKeyCode: UInt32 {
        get {
            let v = store.object(forKey: Key.hotKeyCode) as? Int
            return UInt32(v ?? kVK_Space)
        }
        set { store.set(Int(newValue), forKey: Key.hotKeyCode) }
    }

    static var hotKeyModifiers: UInt32 {
        get {
            let v = store.object(forKey: Key.hotKeyModifiers) as? Int
            return UInt32(v ?? optionKey)
        }
        set { store.set(Int(newValue), forKey: Key.hotKeyModifiers) }
    }

    /// Recently launched command lines, most-recent-first.
    static var recentCommands: [String] {
        get { store.stringArray(forKey: Key.recents) ?? [] }
        set { store.set(newValue, forKey: Key.recents) }
    }
}
