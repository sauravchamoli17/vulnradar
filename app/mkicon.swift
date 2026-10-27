import AppKit

// Renders the app icon into an .iconset directory: a rounded dark tile with a tinted shield.
let outputDir = CommandLine.arguments.last ?? "."

for size in [16, 32, 128, 256, 512, 1024] {
    let side = CGFloat(size)
    let image = NSImage(size: NSSize(width: side, height: side))
    image.lockFocus()

    let tile = NSRect(x: 0, y: 0, width: side, height: side)
        .insetBy(dx: side * 0.055, dy: side * 0.055)
    NSColor(calibratedRed: 0.11, green: 0.12, blue: 0.14, alpha: 1).setFill()
    NSBezierPath(roundedRect: tile, xRadius: side * 0.22, yRadius: side * 0.22).fill()

    let config = NSImage.SymbolConfiguration(pointSize: side * 0.5, weight: .semibold)
    if let symbol = NSImage(systemSymbolName: "shield.lefthalf.filled",
                            accessibilityDescription: nil)?
        .withSymbolConfiguration(config) {
        let tinted = NSImage(size: symbol.size)
        tinted.lockFocus()
        NSColor(calibratedRed: 0.97, green: 0.45, blue: 0.36, alpha: 1).set()
        NSRect(origin: .zero, size: symbol.size).fill(using: .sourceOver)
        symbol.draw(at: .zero, from: .zero, operation: .destinationIn, fraction: 1)
        tinted.unlockFocus()
        tinted.draw(in: NSRect(x: (side - symbol.size.width) / 2,
                               y: (side - symbol.size.height) / 2,
                               width: symbol.size.width, height: symbol.size.height))
    }
    image.unlockFocus()

    guard let tiff = image.tiffRepresentation,
          let rep = NSBitmapImageRep(data: tiff),
          let png = rep.representation(using: .png, properties: [:]) else { continue }
    let path = "\(outputDir)/icon_\(size)x\(size).png"
    try? png.write(to: URL(fileURLWithPath: path))
}
