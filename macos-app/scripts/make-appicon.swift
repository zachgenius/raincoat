#!/usr/bin/env swift
import AppKit

// One-off placeholder app-icon generator. Draws a 1024×1024 rounded-rect in raincoat-blue
// with a simple white umbrella glyph, into a PNG. The user is expected to replace this with
// real artwork later. Rendered via an offscreen NSBitmapImageRep so it needs no running app.
//
//   swift scripts/make-appicon.swift <out.png>
//
// scripts/build-appicon.sh then downscales this into the AppIcon.appiconset.

let side = 1024
let outPath = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "icon-1024.png"

guard let rep = NSBitmapImageRep(
    bitmapDataPlanes: nil,
    pixelsWide: side, pixelsHigh: side,
    bitsPerSample: 8, samplesPerPixel: 4,
    hasAlpha: true, isPlanar: false,
    colorSpaceName: .deviceRGB,
    bytesPerRow: 0, bitsPerPixel: 0
) else {
    FileHandle.standardError.write(Data("failed to allocate bitmap\n".utf8))
    exit(1)
}

NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)

let S = CGFloat(side)

// Background: rounded rect, raincoat blue.
let inset = S * 0.06
let bgRect = NSRect(x: inset, y: inset, width: S - 2 * inset, height: S - 2 * inset)
let corner = S * 0.225
NSColor(calibratedRed: 0.16, green: 0.42, blue: 0.87, alpha: 1).setFill()
NSBezierPath(roundedRect: bgRect, xRadius: corner, yRadius: corner).fill()

NSColor.white.setFill()
NSColor.white.setStroke()

// Umbrella canopy: a dome (upper semicircle) centered a bit above middle.
let canopyCenter = NSPoint(x: S * 0.5, y: S * 0.585)
let canopyRadius = S * 0.30
let dome = NSBezierPath()
dome.move(to: NSPoint(x: canopyCenter.x - canopyRadius, y: canopyCenter.y))
dome.appendArc(withCenter: canopyCenter, radius: canopyRadius, startAngle: 180, endAngle: 0, clockwise: true)
dome.close()
dome.fill()

// Pole: from the canopy base straight down.
let poleWidth = S * 0.022
let poleTop = canopyCenter.y
let poleBottom = S * 0.245
NSBezierPath(rect: NSRect(x: canopyCenter.x - poleWidth / 2, y: poleBottom, width: poleWidth, height: poleTop - poleBottom)).fill()

// Handle: a J-hook at the bottom of the pole.
let hookRadius = S * 0.045
let hookCenter = NSPoint(x: canopyCenter.x - hookRadius, y: poleBottom)
let hook = NSBezierPath()
hook.lineWidth = poleWidth
hook.lineCapStyle = .round
hook.appendArc(withCenter: hookCenter, radius: hookRadius, startAngle: 0, endAngle: 180, clockwise: true)
hook.stroke()

// Tip ferrule at the very top of the dome.
let tipW = S * 0.014
NSBezierPath(rect: NSRect(x: canopyCenter.x - tipW / 2, y: canopyCenter.y + canopyRadius, width: tipW, height: S * 0.035)).fill()

NSGraphicsContext.restoreGraphicsState()

guard let png = rep.representation(using: .png, properties: [:]) else {
    FileHandle.standardError.write(Data("failed to encode PNG\n".utf8))
    exit(1)
}
do {
    try png.write(to: URL(fileURLWithPath: outPath))
    print("wrote \(outPath) (\(side)×\(side))")
} catch {
    FileHandle.standardError.write(Data("write failed: \(error)\n".utf8))
    exit(1)
}
