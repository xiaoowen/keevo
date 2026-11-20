// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// Keevo 标志：盾形与钥匙孔（设计稿"品牌 · 应用图标"方案 A）。几何与应用图标（design/build_icons.py）、
// 扩展的标志（apps/browser-extension/src/brand.ts 的 SHIELD_PATH、KEYHOLE_PATH）相同，都在 20 × 20 的视图框中。

import AppKit
import SwiftUI

enum BrandMark {
    /// 盾形轮廓（SVG：M10 2.6 4.4 4.8v4.4c0 3.6 2.4 6.6 5.6 7.8 3.2-1.2 5.6-4.2 5.6-7.8V4.8L10 2.6Z）。
    static func shield(in rect: CGRect) -> CGPath {
        let p = CGMutablePath()
        let pt = point(in: rect)
        p.move(to: pt(10, 2.6))
        p.addLine(to: pt(4.4, 4.8))
        p.addLine(to: pt(4.4, 9.2))
        p.addCurve(to: pt(10, 17), control1: pt(4.4, 12.8), control2: pt(6.8, 15.8))
        p.addCurve(to: pt(15.6, 9.2), control1: pt(13.2, 15.8), control2: pt(15.6, 12.8))
        p.addLine(to: pt(15.6, 4.8))
        p.closeSubpath()
        return p
    }

    /// 钥匙孔（SVG：圆心 (10, 8.6)、半径 1.4 的圆，加 M9.4 9.4h1.2l.4 2.8H9z）。
    static func keyhole(in rect: CGRect) -> CGPath {
        let p = CGMutablePath()
        let pt = point(in: rect)
        let unit = min(rect.width, rect.height) / 20
        p.addEllipse(in: CGRect(center: pt(10, 8.6), radius: 1.4 * unit))
        p.move(to: pt(9.4, 9.4))
        p.addLine(to: pt(10.6, 9.4))
        p.addLine(to: pt(11, 12.2))
        p.addLine(to: pt(9, 12.2))
        p.closeSubpath()
        return p
    }

    /// 20 × 20 视图框中的点（y 向下，与 SVG 相同）映射到 `rect` 中。
    private static func point(in rect: CGRect) -> (CGFloat, CGFloat) -> CGPoint {
        let unit = min(rect.width, rect.height) / 20
        let ox = rect.midX - 10 * unit
        let oy = rect.midY - 10 * unit
        return { x, y in CGPoint(x: ox + x * unit, y: oy + y * unit) }
    }

    /// 菜单栏图标（模板图像，系统按菜单栏的浅色、深色与选中状态着色）。
    /// 已解锁：实心盾形、镂空钥匙孔；已锁定：盾形轮廓加钥匙孔。
    static func menuBarImage(unlocked: Bool) -> NSImage {
        let size = NSSize(width: 18, height: 18)
        let image = NSImage(size: size, flipped: true) { rect in
            guard let ctx = NSGraphicsContext.current?.cgContext else { return false }
            let box = rect.insetBy(dx: 0.5, dy: 0.5)
            ctx.setFillColor(NSColor.black.cgColor)
            ctx.setStrokeColor(NSColor.black.cgColor)
            if unlocked {
                ctx.addPath(shield(in: box))
                ctx.addPath(keyhole(in: box))
                ctx.fillPath(using: .evenOdd)
            } else {
                ctx.setLineWidth(1.5)
                ctx.setLineJoin(.round)
                ctx.addPath(shield(in: box))
                ctx.strokePath()
                ctx.addPath(keyhole(in: box))
                ctx.fillPath()
            }
            return true
        }
        image.isTemplate = true
        return image
    }
}

private extension CGRect {
    init(center: CGPoint, radius: CGFloat) {
        self.init(x: center.x - radius, y: center.y - radius, width: radius * 2, height: radius * 2)
    }
}

/// 盾形（SwiftUI）。
struct ShieldShape: Shape {
    func path(in rect: CGRect) -> Path { Path(BrandMark.shield(in: rect)) }
}

/// 钥匙孔（SwiftUI）。
struct KeyholeShape: Shape {
    func path(in rect: CGRect) -> Path { Path(BrandMark.keyhole(in: rect)) }
}

/// 应用内标志：品牌色圆角方块中的白色盾形与钥匙孔（设计稿"同一图形用在其他地方 · 应用内标志"）。
struct BrandLogo: View {
    var size: CGFloat = 72

    var body: some View {
        ZStack {
            ShieldShape().stroke(KV.Colors.fgOnAccent, style: StrokeStyle(lineWidth: size * 0.62 / 10, lineJoin: .round))
            KeyholeShape().fill(KV.Colors.fgOnAccent)
        }
        .frame(width: size * 0.62, height: size * 0.62)
        .frame(width: size, height: size)
        .background(KV.Colors.accentFill, in: RoundedRectangle(cornerRadius: size * 0.24, style: .continuous))
        .accessibilityHidden(true)
    }
}
