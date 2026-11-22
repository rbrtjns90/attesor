import AppKit

let size = 1024
let canvas = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0,
                       space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
func color(_ r: CGFloat, _ g: CGFloat, _ b: CGFloat, _ a: CGFloat = 1) -> CGColor {
    CGColor(red: r, green: g, blue: b, alpha: a)
}
func ellipse(_ x: CGFloat, _ y: CGFloat, _ w: CGFloat, _ h: CGFloat, _ c: CGColor) {
    canvas.setFillColor(c)
    canvas.fillEllipse(in: CGRect(x: x, y: y, width: w, height: h))
}
func tilted(_ x: CGFloat, _ y: CGFloat, _ w: CGFloat, _ h: CGFloat, _ radians: CGFloat, _ c: CGColor) {
    canvas.saveGState()
    canvas.translateBy(x: x, y: y)
    canvas.rotate(by: radians)
    ellipse(-w / 2, -h / 2, w, h, c)
    canvas.restoreGState()
}
let tile = CGPath(roundedRect: CGRect(x: 76, y: 76, width: 872, height: 872),
                  cornerWidth: 198, cornerHeight: 198, transform: nil)
canvas.saveGState()
canvas.addPath(tile)
canvas.clip()
let gradient = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(),
                          colors: [color(0.15, 0.25, 0.44), color(0.32, 0.63, 0.74)] as CFArray,
                          locations: [0, 1])!
canvas.drawLinearGradient(gradient, start: CGPoint(x: 540, y: 100), end: CGPoint(x: 445, y: 940), options: [])
ellipse(204, 201, 616, 91, color(0.08, 0.14, 0.26, 0.24))
let black = color(0.075, 0.10, 0.15)
let white = color(0.98, 0.97, 0.93)
let amber = color(1, 0.68, 0.20)
tilted(328, 283, 183, 84, 0.21, amber)
tilted(696, 283, 183, 84, -0.21, amber)
tilted(313, 477, 123, 276, -0.44, black)
tilted(711, 477, 123, 276, 0.44, black)
ellipse(296, 274, 432, 507, black)
ellipse(334, 305, 356, 384, white)
ellipse(340, 535, 344, 249, black)
ellipse(392, 584, 103, 143, white)
ellipse(529, 584, 103, 143, white)
ellipse(437, 608, 41, 68, black)
ellipse(546, 608, 41, 68, black)
ellipse(439, 646, 13, 19, white)
ellipse(548, 646, 13, 19, white)
ellipse(453, 565, 118, 54, amber)
ellipse(475, 556, 74, 37, color(0.96, 0.53, 0.14))
canvas.restoreGState()
let bitmap = NSBitmapImageRep(cgImage: canvas.makeImage()!)
try bitmap.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
