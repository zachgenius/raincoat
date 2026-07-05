import AppKit
import Carbon.HIToolbox

// A small click-to-record control for a global hotkey. Click to arm ("Type shortcut…"),
// then the next key combination is captured. Esc cancels; a combo with no ⌘/⌥/⌃ is
// rejected (via KeyCombo.from) and reported through `onInvalid`. The control never
// commits the binding itself — it hands the captured combo to `onCapture` and the owner
// decides whether the live re-bind succeeded, calling `update(to:)` with the final value.
@MainActor
final class HotKeyRecorderView: NSView {
    var onCapture: ((KeyCombo) -> Void)?
    var onInvalid: (() -> Void)?

    private(set) var combo: KeyCombo
    private var isRecording = false
    private let label = NSTextField(labelWithString: "")

    init(combo: KeyCombo) {
        self.combo = combo
        super.init(frame: NSRect(x: 0, y: 0, width: 150, height: 26))
        setup()
        render()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override var intrinsicContentSize: NSSize { NSSize(width: 150, height: 26) }
    override var acceptsFirstResponder: Bool { true }

    /// Set by the owner after deciding whether the re-bind stuck.
    func update(to combo: KeyCombo) {
        self.combo = combo
        stopRecording()
    }

    private func setup() {
        wantsLayer = true
        layer?.cornerRadius = 6
        layer?.borderWidth = 1
        layer?.backgroundColor = NSColor.controlBackgroundColor.cgColor

        label.alignment = .center
        label.translatesAutoresizingMaskIntoConstraints = false
        label.font = .systemFont(ofSize: NSFont.systemFontSize)
        addSubview(label)
        NSLayoutConstraint.activate([
            label.centerXAnchor.constraint(equalTo: centerXAnchor),
            label.centerYAnchor.constraint(equalTo: centerYAnchor),
            widthAnchor.constraint(greaterThanOrEqualToConstant: 150),
            heightAnchor.constraint(equalToConstant: 26),
        ])
    }

    private func render() {
        if isRecording {
            label.stringValue = "Type shortcut…"
            label.textColor = .secondaryLabelColor
            layer?.borderColor = NSColor.keyboardFocusIndicatorColor.cgColor
        } else {
            label.stringValue = combo.displayString
            label.textColor = .labelColor
            layer?.borderColor = NSColor.separatorColor.cgColor
        }
    }

    // MARK: - Recording lifecycle

    override func mouseDown(with event: NSEvent) {
        if isRecording {
            stopRecording()
        } else {
            startRecording()
        }
    }

    private func startRecording() {
        isRecording = true
        window?.makeFirstResponder(self)
        render()
    }

    private func stopRecording() {
        isRecording = false
        render()
    }

    override func resignFirstResponder() -> Bool {
        if isRecording { stopRecording() }
        return super.resignFirstResponder()
    }

    // MARK: - Key capture

    override func keyDown(with event: NSEvent) {
        if isRecording, capture(event) { return }
        super.keyDown(with: event)
    }

    // Catches key equivalents (e.g. ⌘-combinations, Space) before the menu/window consume them.
    override func performKeyEquivalent(with event: NSEvent) -> Bool {
        if isRecording { return capture(event) }
        return super.performKeyEquivalent(with: event)
    }

    override func flagsChanged(with event: NSEvent) {
        if isRecording {
            let mods = KeyCombo.carbonModifiers(from: event.modifierFlags)
            let preview = KeyCombo.modifierSymbols(mods)
            label.stringValue = preview.isEmpty ? "Type shortcut…" : preview + "…"
        }
        super.flagsChanged(with: event)
    }

    /// Returns true when the event was consumed (recording mode swallows everything).
    private func capture(_ event: NSEvent) -> Bool {
        // Esc with no modifiers cancels recording, keeping the current binding.
        if event.keyCode == UInt16(kVK_Escape),
           KeyCombo.carbonModifiers(from: event.modifierFlags) == 0 {
            stopRecording()
            return true
        }
        if let newCombo = KeyCombo.from(event: event) {
            stopRecording()
            onCapture?(newCombo)
        } else {
            NSSound.beep()
            onInvalid?()
            // Stay armed so the user can try a valid combo.
        }
        return true
    }
}
