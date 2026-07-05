import Carbon.HIToolbox
import Foundation

// Global hotkey via Carbon RegisterEventHotKey. Chosen deliberately over an NSEvent
// global monitor because it needs NO Accessibility permission. The keycode/modifiers
// are Carbon-flavored (e.g. Space = 49, option = `optionKey`) and persisted in
// UserDefaults so they can be rebound later.
@MainActor
final class HotKeyManager {
    private var hotKeyRef: EventHotKeyRef?
    private var handlerRef: EventHandlerRef?
    private var onTrigger: (() -> Void)?

    // 'RCHK' — a unique signature for our single hotkey.
    private let signature: OSType = 0x5243484B
    private let hotKeyID: UInt32 = 1

    /// Installs the Carbon event handler (once) and registers the given combo.
    /// Returns whether RegisterEventHotKey succeeded.
    @discardableResult
    func register(keyCode: UInt32, modifiers: UInt32, onTrigger: @escaping () -> Void) -> Bool {
        self.onTrigger = onTrigger
        installHandlerIfNeeded()
        return registerHotKey(keyCode: keyCode, modifiers: modifiers)
    }

    /// LIVE re-bind to a new combo, keeping the existing trigger handler installed.
    /// Returns false if the new combo could not be registered (the caller can then
    /// restore the previous binding).
    @discardableResult
    func rebind(keyCode: UInt32, modifiers: UInt32) -> Bool {
        installHandlerIfNeeded()
        return registerHotKey(keyCode: keyCode, modifiers: modifiers)
    }

    func unregister() {
        if let ref = hotKeyRef { UnregisterEventHotKey(ref); hotKeyRef = nil }
        if let ref = handlerRef { RemoveEventHandler(ref); handlerRef = nil }
        onTrigger = nil
    }

    private func installHandlerIfNeeded() {
        guard handlerRef == nil else { return }
        var eventType = EventTypeSpec(
            eventClass: OSType(kEventClassKeyboard),
            eventKind: UInt32(kEventHotKeyPressed)
        )
        let selfPtr = Unmanaged.passUnretained(self).toOpaque()
        InstallEventHandler(
            GetApplicationEventTarget(),
            raincoatHotKeyHandler,
            1,
            &eventType,
            selfPtr,
            &handlerRef
        )
    }

    private func registerHotKey(keyCode: UInt32, modifiers: UInt32) -> Bool {
        if let ref = hotKeyRef { UnregisterEventHotKey(ref); hotKeyRef = nil }
        let id = EventHotKeyID(signature: signature, id: hotKeyID)
        let status = RegisterEventHotKey(
            keyCode,
            modifiers,
            id,
            GetApplicationEventTarget(),
            0,
            &hotKeyRef
        )
        if status != noErr {
            log.error("RegisterEventHotKey failed: \(status)")
            hotKeyRef = nil
            return false
        }
        return true
    }

    fileprivate func fire() {
        onTrigger?()
    }
}

// C callback. Carbon delivers hotkey events on the main run loop, so we are on the
// main thread here and can safely assume MainActor isolation.
private func raincoatHotKeyHandler(
    _ callRef: EventHandlerCallRef?,
    _ event: EventRef?,
    _ userData: UnsafeMutableRawPointer?
) -> OSStatus {
    guard let userData else { return OSStatus(eventNotHandledErr) }
    let manager = Unmanaged<HotKeyManager>.fromOpaque(userData).takeUnretainedValue()
    MainActor.assumeIsolated {
        manager.fire()
    }
    return noErr
}
