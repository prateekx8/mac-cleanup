// Draws the original Mac Cleanup app icon (gradient squircle + sparkle) to a 1024px PNG.
// Usage: make_icon <out.png>
import Cocoa

let size: CGFloat = 1024
let img = NSImage(size: NSSize(width: size, height: size))
img.lockFocus()
NSColor.clear.set()
NSRect(x: 0, y: 0, width: size, height: size).fill()

// macOS icon grid: 824px squircle with 100px margin
let body = NSRect(x: 100, y: 100, width: 824, height: 824)
let squircle = NSBezierPath(roundedRect: body, xRadius: 186, yRadius: 186)
NSGraphicsContext.current?.saveGraphicsState()
let shadow = NSShadow()
shadow.shadowColor = NSColor.black.withAlphaComponent(0.35)
shadow.shadowOffset = NSSize(width: 0, height: -14)
shadow.shadowBlurRadius = 28
shadow.set()
NSColor.black.setFill()
squircle.fill()
NSGraphicsContext.current?.restoreGraphicsState()

NSGradient(colors: [NSColor(srgbRed: 0.49, green: 0.36, blue: 1.0, alpha: 1),
                    NSColor(srgbRed: 0.25, green: 0.66, blue: 1.0, alpha: 1),
                    NSColor(srgbRed: 0.18, green: 0.90, blue: 0.77, alpha: 1)])!
    .draw(in: squircle, angle: -45)

// glass sheen on the top half
NSGraphicsContext.current?.saveGraphicsState()
squircle.addClip()
let sheen = NSBezierPath(ovalIn: NSRect(x: -120, y: 520, width: 1264, height: 760))
NSColor.white.withAlphaComponent(0.16).setFill()
sheen.fill()
NSGraphicsContext.current?.restoreGraphicsState()

func sparkle(cx: CGFloat, cy: CGFloat, r: CGFloat, waist: CGFloat) -> NSBezierPath {
    let p = NSBezierPath()
    p.move(to: NSPoint(x: cx, y: cy + r))
    p.curve(to: NSPoint(x: cx + r, y: cy), controlPoint1: NSPoint(x: cx + waist, y: cy + waist), controlPoint2: NSPoint(x: cx + waist, y: cy + waist))
    p.curve(to: NSPoint(x: cx, y: cy - r), controlPoint1: NSPoint(x: cx + waist, y: cy - waist), controlPoint2: NSPoint(x: cx + waist, y: cy - waist))
    p.curve(to: NSPoint(x: cx - r, y: cy), controlPoint1: NSPoint(x: cx - waist, y: cy - waist), controlPoint2: NSPoint(x: cx - waist, y: cy - waist))
    p.curve(to: NSPoint(x: cx, y: cy + r), controlPoint1: NSPoint(x: cx - waist, y: cy + waist), controlPoint2: NSPoint(x: cx - waist, y: cy + waist))
    p.close()
    return p
}

NSGraphicsContext.current?.saveGraphicsState()
let glow = NSShadow()
glow.shadowColor = NSColor.white.withAlphaComponent(0.55)
glow.shadowBlurRadius = 40
glow.set()
NSColor.white.setFill()
sparkle(cx: 470, cy: 470, r: 250, waist: 46).fill()
NSColor.white.withAlphaComponent(0.92).setFill()
sparkle(cx: 700, cy: 700, r: 110, waist: 22).fill()
sparkle(cx: 690, cy: 300, r: 64, waist: 13).fill()
NSGraphicsContext.current?.restoreGraphicsState()
img.unlockFocus()

let rep = NSBitmapImageRep(data: img.tiffRepresentation!)!
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
