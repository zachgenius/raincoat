import AppKit
import Carbon.HIToolbox

// A hotkey combination in Carbon terms (RegisterEventHotKey wants a Carbon virtual
// key code + a Carbon modifier mask). Also bridges from a Cocoa NSEvent and renders a
// human display string like "⌥Space" or "⌃⌘K".
struct KeyCombo: Equatable {
    let keyCode: UInt32          // Carbon/HW virtual key code (== NSEvent.keyCode)
    let carbonModifiers: UInt32  // Carbon mask: cmdKey | optionKey | controlKey | shiftKey

    /// The currently-persisted binding.
    static var current: KeyCombo {
        KeyCombo(keyCode: Defaults.hotKeyCode, carbonModifiers: Defaults.hotKeyModifiers)
    }

    /// The default binding, ⌥Space.
    static var defaultCombo: KeyCombo {
        KeyCombo(keyCode: UInt32(kVK_Space), carbonModifiers: UInt32(optionKey))
    }

    // Modifiers that make a shortcut "real" (Shift alone is not enough to register a
    // useful global hotkey and is easy to trigger by accident).
    private static let requiredMask = UInt32(cmdKey | optionKey | controlKey)

    /// Build from a keyDown/keyEquivalent event. Returns nil for a bare key with no
    /// meaningful modifier (⌘/⌥/⌃), i.e. an "obviously bad" combo.
    static func from(event: NSEvent) -> KeyCombo? {
        let mods = carbonModifiers(from: event.modifierFlags)
        guard mods & requiredMask != 0 else { return nil }
        return KeyCombo(keyCode: UInt32(event.keyCode), carbonModifiers: mods)
    }

    static func carbonModifiers(from flags: NSEvent.ModifierFlags) -> UInt32 {
        let f = flags.intersection(.deviceIndependentFlagsMask)
        var m: UInt32 = 0
        if f.contains(.command) { m |= UInt32(cmdKey) }
        if f.contains(.option) { m |= UInt32(optionKey) }
        if f.contains(.control) { m |= UInt32(controlKey) }
        if f.contains(.shift) { m |= UInt32(shiftKey) }
        return m
    }

    /// e.g. "⌥Space", "⌃⌘K". Modifier order matches Apple's (⌃⌥⇧⌘).
    var displayString: String {
        KeyCombo.modifierSymbols(carbonModifiers) + KeyCombo.keyName(for: keyCode)
    }

    /// Just the modifier glyphs (⌃⌥⇧⌘), in Apple order — used for a live "held keys" preview.
    static func modifierSymbols(_ mask: UInt32) -> String {
        var s = ""
        if mask & UInt32(controlKey) != 0 { s += "⌃" }
        if mask & UInt32(optionKey) != 0 { s += "⌥" }
        if mask & UInt32(shiftKey) != 0 { s += "⇧" }
        if mask & UInt32(cmdKey) != 0 { s += "⌘" }
        return s
    }

    // MARK: - Key name table (US-ASCII layout; special keys shown as glyphs)

    static func keyName(for keyCode: UInt32) -> String {
        let code = Int(keyCode)
        if let name = specialKeys[code] { return name }
        if let name = ansiKeys[code] { return name }
        return "key\(keyCode)"
    }

    private static let specialKeys: [Int: String] = [
        kVK_Space: "Space",
        kVK_Return: "↩",
        kVK_ANSI_KeypadEnter: "⌤",
        kVK_Tab: "⇥",
        kVK_Delete: "⌫",
        kVK_ForwardDelete: "⌦",
        kVK_Escape: "⎋",
        kVK_LeftArrow: "←", kVK_RightArrow: "→", kVK_UpArrow: "↑", kVK_DownArrow: "↓",
        kVK_Home: "↖", kVK_End: "↘", kVK_PageUp: "⇞", kVK_PageDown: "⇟",
        kVK_F1: "F1", kVK_F2: "F2", kVK_F3: "F3", kVK_F4: "F4",
        kVK_F5: "F5", kVK_F6: "F6", kVK_F7: "F7", kVK_F8: "F8",
        kVK_F9: "F9", kVK_F10: "F10", kVK_F11: "F11", kVK_F12: "F12",
    ]

    private static let ansiKeys: [Int: String] = [
        kVK_ANSI_A: "A", kVK_ANSI_B: "B", kVK_ANSI_C: "C", kVK_ANSI_D: "D",
        kVK_ANSI_E: "E", kVK_ANSI_F: "F", kVK_ANSI_G: "G", kVK_ANSI_H: "H",
        kVK_ANSI_I: "I", kVK_ANSI_J: "J", kVK_ANSI_K: "K", kVK_ANSI_L: "L",
        kVK_ANSI_M: "M", kVK_ANSI_N: "N", kVK_ANSI_O: "O", kVK_ANSI_P: "P",
        kVK_ANSI_Q: "Q", kVK_ANSI_R: "R", kVK_ANSI_S: "S", kVK_ANSI_T: "T",
        kVK_ANSI_U: "U", kVK_ANSI_V: "V", kVK_ANSI_W: "W", kVK_ANSI_X: "X",
        kVK_ANSI_Y: "Y", kVK_ANSI_Z: "Z",
        kVK_ANSI_0: "0", kVK_ANSI_1: "1", kVK_ANSI_2: "2", kVK_ANSI_3: "3",
        kVK_ANSI_4: "4", kVK_ANSI_5: "5", kVK_ANSI_6: "6", kVK_ANSI_7: "7",
        kVK_ANSI_8: "8", kVK_ANSI_9: "9",
        kVK_ANSI_Minus: "-", kVK_ANSI_Equal: "=",
        kVK_ANSI_LeftBracket: "[", kVK_ANSI_RightBracket: "]",
        kVK_ANSI_Backslash: "\\", kVK_ANSI_Semicolon: ";", kVK_ANSI_Quote: "'",
        kVK_ANSI_Comma: ",", kVK_ANSI_Period: ".", kVK_ANSI_Slash: "/",
        kVK_ANSI_Grave: "`",
    ]
}
