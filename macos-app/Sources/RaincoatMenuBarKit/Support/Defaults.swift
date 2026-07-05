import Carbon.HIToolbox
import Foundation

// Typed, centralized access to the handful of UserDefaults keys the app persists.
// Nothing here writes sandbox state — these are pure app preferences.
enum Defaults {
    private static var store: UserDefaults { .standard }

    private enum Key {
        static let raincoatPath = "raincoat.binaryPath"
        static let defaultProfile = "raincoat.defaultProfile"
        static let hotKeyCode = "hotkey.keyCode"
        static let hotKeyModifiers = "hotkey.modifiers"
        static let recents = "launcher.recents"
        static let cliInstallPromptSuppressed = "cli.installPromptSuppressed"
    }

    /// Optional explicit path to the `raincoat` binary, used as a final fallback by RaincoatLocator.
    static var raincoatPath: String? {
        get { readTrimmed(Key.raincoatPath) }
        set { writeTrimmed(newValue, forKey: Key.raincoatPath) }
    }

    /// Optional path to a raincoat profile. When set, the launcher passes `--profile <path>`
    /// before `--`. Empty/unset omits it (raincoat uses its own default).
    static var defaultProfilePath: String? {
        get { readTrimmed(Key.defaultProfile) }
        set { writeTrimmed(newValue, forKey: Key.defaultProfile) }
    }

    // Trims whitespace and treats empty as absent, so a blank text field == "not set"
    // and the key is removed rather than left as "".
    private static func readTrimmed(_ key: String) -> String? {
        guard let raw = store.string(forKey: key) else { return nil }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    private static func writeTrimmed(_ value: String?, forKey key: String) {
        let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines)
        if let trimmed, !trimmed.isEmpty {
            store.set(trimmed, forKey: key)
        } else {
            store.removeObject(forKey: key)
        }
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

    /// Set once the user picks "Don't Ask Again" on the first-run CLI-install prompt, so the
    /// app never nags again (they can still install from Preferences).
    static var cliInstallPromptSuppressed: Bool {
        get { store.bool(forKey: Key.cliInstallPromptSuppressed) }
        set { store.set(newValue, forKey: Key.cliInstallPromptSuppressed) }
    }
}
