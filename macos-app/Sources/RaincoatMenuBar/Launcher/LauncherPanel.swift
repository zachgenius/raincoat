import AppKit

// Borderless, non-activating floating panel. A borderless window can't become key
// by default, so we override canBecomeKey to let the search field take input without
// activating the (agent) app.
final class LauncherPanel: NSPanel {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }
}

// A single result row: bold title + dimmed subtitle. Built in code (no xib).
final class ResultCellView: NSTableCellView {
    private let titleLabel = ResultCellView.makeLabel(size: NSFont.systemFontSize, color: .labelColor, bold: false)
    private let subtitleLabel = ResultCellView.makeLabel(size: NSFont.smallSystemFontSize, color: .secondaryLabelColor, bold: false)

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        let stack = NSStackView(views: [titleLabel, subtitleLabel])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 1
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 12),
            stack.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -12),
            stack.centerYAnchor.constraint(equalTo: centerYAnchor),
        ])
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func configure(title: String, subtitle: String) {
        titleLabel.stringValue = title
        subtitleLabel.stringValue = subtitle
    }

    private static func makeLabel(size: CGFloat, color: NSColor, bold: Bool) -> NSTextField {
        let label = NSTextField(labelWithString: "")
        label.font = bold ? .boldSystemFont(ofSize: size) : .systemFont(ofSize: size)
        label.textColor = color
        label.lineBreakMode = .byTruncatingTail
        label.cell?.usesSingleLineMode = true
        return label
    }
}
