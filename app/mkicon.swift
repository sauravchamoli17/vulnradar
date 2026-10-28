import AppKit
import SwiftUI

// Draws the app icon into an .iconset directory.
//
// The mark is the product: a radar sweeping a constellation of dependencies, with one
// blip lit. It avoids the stock-shield cliché and still reads at 16px, where only the
// sweep and the blip survive.

let outputDir = CommandLine.arguments.last ?? "."

/// macOS icons sit inside the canvas, not edge to edge, on a continuous-corner squircle.
func squircle(side: CGFloat) -> CGPath {
    let inset = side * 0.094
    let rect = CGRect(x: inset, y: inset, width: side - inset * 2, height: side - inset * 2)
    return RoundedRectangle(cornerRadius: rect.width * 0.2237, style: .continuous)
        .path(in: rect).cgPath
}

func draw(side: CGFloat) -> NSImage {
    let image = NSImage(size: NSSize(width: side, height: side))
    image.lockFocus()
    guard let ctx = NSGraphicsContext.current?.cgContext else {
        image.unlockFocus()
        return image
    }
    let space = CGColorSpaceCreateDeviceRGB()
    let body = squircle(side: side)

    // Base: near-black with an indigo cast toward the top-left.
    ctx.saveGState()
    ctx.addPath(body)
    ctx.clip()
    let base = CGGradient(colorsSpace: space, colors: [
        CGColor(red: 0.173, green: 0.184, blue: 0.282, alpha: 1),
        CGColor(red: 0.051, green: 0.055, blue: 0.075, alpha: 1)
    ] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(base, start: CGPoint(x: side * 0.15, y: side * 0.95),
                           end: CGPoint(x: side * 0.9, y: side * 0.08), options: [])

    let c = CGPoint(x: side / 2, y: side / 2)
    let r = side * 0.285

    // Radar rings.
    for (index, scale) in [0.42, 0.72, 1.0].enumerated() {
        ctx.setStrokeColor(CGColor(red: 1, green: 1, blue: 1,
                                   alpha: 0.10 + Double(index) * 0.035))
        ctx.setLineWidth(side * 0.0115)
        ctx.addEllipse(in: CGRect(x: c.x - r * scale, y: c.y - r * scale,
                                  width: r * scale * 2, height: r * scale * 2))
        ctx.strokePath()
    }

    // The sweep: a cone of indigo light fading as it trails.
    ctx.saveGState()
    let sweep = CGMutablePath()
    sweep.move(to: c)
    sweep.addArc(center: c, radius: r * 1.06,
                 startAngle: .pi * 0.08, endAngle: .pi * 0.62, clockwise: false)
    sweep.closeSubpath()
    ctx.addPath(sweep)
    ctx.clip()
    let glow = CGGradient(colorsSpace: space, colors: [
        CGColor(red: 0.42, green: 0.45, blue: 0.95, alpha: 0.62),
        CGColor(red: 0.35, green: 0.37, blue: 0.88, alpha: 0.0)
    ] as CFArray, locations: [0, 1])!
    ctx.drawRadialGradient(glow, startCenter: c, startRadius: 0,
                           endCenter: c, endRadius: r * 1.06, options: [])
    ctx.restoreGState()

    // Leading edge of the sweep, the bright line a radar draws.
    ctx.setStrokeColor(CGColor(red: 0.62, green: 0.65, blue: 1, alpha: 0.9))
    ctx.setLineWidth(side * 0.013)
    ctx.setLineCap(.round)
    ctx.move(to: c)
    ctx.addLine(to: CGPoint(x: c.x + cos(.pi * 0.62) * r * 1.02,
                            y: c.y + sin(.pi * 0.62) * r * 1.02))
    ctx.strokePath()

    // Quiet dependencies sitting on the rings.
    let quiet: [(Double, Double)] = [(0.42, 1.30), (0.72, 2.62), (0.72, 5.55), (1.0, 3.95)]
    ctx.setFillColor(CGColor(red: 0.74, green: 0.78, blue: 0.86, alpha: 0.5))
    for (scale, angle) in quiet {
        let p = CGPoint(x: c.x + cos(angle) * r * scale, y: c.y + sin(angle) * r * scale)
        let dot = side * 0.0245
        ctx.fillEllipse(in: CGRect(x: p.x - dot, y: p.y - dot, width: dot * 2, height: dot * 2))
    }

    // The finding: one blip, lit, inside the sweep.
    let blip = CGPoint(x: c.x + cos(.pi * 0.3) * r * 0.72,
                       y: c.y + sin(.pi * 0.3) * r * 0.72)
    let halo = side * 0.085
    let haloGradient = CGGradient(colorsSpace: space, colors: [
        CGColor(red: 0.886, green: 0.333, blue: 0.373, alpha: 0.55),
        CGColor(red: 0.886, green: 0.333, blue: 0.373, alpha: 0.0)
    ] as CFArray, locations: [0, 1])!
    ctx.drawRadialGradient(haloGradient, startCenter: blip, startRadius: 0,
                           endCenter: blip, endRadius: halo, options: [])
    ctx.setFillColor(CGColor(red: 0.925, green: 0.365, blue: 0.408, alpha: 1))
    let br = side * 0.0405
    ctx.fillEllipse(in: CGRect(x: blip.x - br, y: blip.y - br, width: br * 2, height: br * 2))

    ctx.restoreGState()

    // Glass edge: a bright rim along the top, a hairline all round.
    ctx.saveGState()
    ctx.addPath(body)
    ctx.clip()
    let rim = CGGradient(colorsSpace: space, colors: [
        CGColor(red: 1, green: 1, blue: 1, alpha: 0.22),
        CGColor(red: 1, green: 1, blue: 1, alpha: 0.0)
    ] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(rim, start: CGPoint(x: 0, y: side),
                           end: CGPoint(x: 0, y: side * 0.72), options: [])
    ctx.restoreGState()

    ctx.addPath(body)
    ctx.setStrokeColor(CGColor(red: 1, green: 1, blue: 1, alpha: 0.13))
    ctx.setLineWidth(side * 0.004)
    ctx.strokePath()

    image.unlockFocus()
    return image
}

for size in [16, 32, 128, 256, 512, 1024] {
    let image = draw(side: CGFloat(size))
    guard let tiff = image.tiffRepresentation,
          let rep = NSBitmapImageRep(data: tiff),
          let png = rep.representation(using: .png, properties: [:]) else { continue }
    try? png.write(to: URL(fileURLWithPath: "\(outputDir)/icon_\(size)x\(size).png"))
}
