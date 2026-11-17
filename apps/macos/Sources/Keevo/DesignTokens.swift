// 由 design/build_tokens.py 从 design/tokens/*.json 生成，请勿手改。
// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）

import AppKit
import SwiftUI

/// Keevo 设计令牌（设计系统 v0，见 design/README.md）。
///
/// 颜色随系统外观自动切换：浅色、深色，以及「增强对比度」下的两种高对比外观。
enum KV {
    /// 语义颜色。
    enum Colors {
        /// 内容区、窗口背景
        static let bgCanvas = dynamicColor(light: 0xFFFFFFFF, dark: 0x1C1C1EFF, lightHC: 0xFFFFFFFF, darkHC: 0x000000FF)
        /// 侧边栏、分组背景
        static let bgSurface = dynamicColor(light: 0xF5F5F7FF, dark: 0x161618FF, lightHC: 0xF5F5F7FF, darkHC: 0x0E0E10FF)
        /// 浮层、弹窗、菜单
        static let bgRaised = dynamicColor(light: 0xFFFFFFFF, dark: 0x2C2C2EFF, lightHC: 0xFFFFFFFF, darkHC: 0x2C2C2EFF)
        /// 代码块、秘密值底色
        static let bgSunken = dynamicColor(light: 0xECECEFFF, dark: 0x0E0E10FF, lightHC: 0xECECEFFF, darkHC: 0x0E0E10FF)
        static let bgHover = dynamicColor(light: 0xECECEFFF, dark: 0x2C2C2EFF, lightHC: 0xECECEFFF, darkHC: 0x2C2C2EFF)
        static let bgSelected = dynamicColor(light: 0xD3F4ECFF, dark: 0x0D403BFF, lightHC: 0xD3F4ECFF, darkHC: 0x0D403BFF)
        static let fgPrimary = dynamicColor(light: 0x1C1C1EFF, dark: 0xF5F5F7FF, lightHC: 0x1C1C1EFF, darkHC: 0xFFFFFFFF)
        static let fgSecondary = dynamicColor(light: 0x636366FF, dark: 0xA1A1A6FF, lightHC: 0x48484AFF, darkHC: 0xD2D2D7FF)
        /// 占位符、禁用。不用于正文
        static let fgTertiary = dynamicColor(light: 0x8E8E95FF, dark: 0x7C7C82FF, lightHC: 0x636366FF, darkHC: 0xA1A1A6FF)
        static let fgOnAccent = dynamicColor(light: 0xFFFFFFFF, dark: 0xFFFFFFFF, lightHC: 0xFFFFFFFF, darkHC: 0xFFFFFFFF)
        /// 分隔线（装饰性）
        static let borderSubtle = dynamicColor(light: 0xE3E3E8FF, dark: 0x3A3A3CFF, lightHC: 0xB8B8BFFF, darkHC: 0x636366FF)
        /// 输入框等控件的边界，需 ≥ 3:1
        static let borderControl = dynamicColor(light: 0x8E8E95FF, dark: 0x7C7C82FF, lightHC: 0x636366FF, darkHC: 0xA1A1A6FF)
        /// 主按钮底色，配 fg.on-accent
        static let accentFill = dynamicColor(light: 0x127F71FF, dark: 0x127F71FF, lightHC: 0x0F665BFF, darkHC: 0x127F71FF)
        static let accentFillHover = dynamicColor(light: 0x0F665BFF, dark: 0x0F665BFF, lightHC: 0x0F514AFF, darkHC: 0x0F665BFF)
        /// 品牌色文字、链接、图标
        static let accentFg = dynamicColor(light: 0x0F665BFF, dark: 0x72D4C2FF, lightHC: 0x0F514AFF, darkHC: 0xA8E8DAFF)
        static let accentSubtle = dynamicColor(light: 0xEEFBF8FF, dark: 0x062623FF, lightHC: 0xEEFBF8FF, darkHC: 0x062623FF)
        static let focusRing = dynamicColor(light: 0x1E9C8AFF, dark: 0x3FB9A6FF, lightHC: 0x0F665BFF, darkHC: 0x72D4C2FF)
        static let statusDangerFg = dynamicColor(light: 0xC4321FFF, dark: 0xF07264FF, lightHC: 0x7F2318FF, darkHC: 0xF7A39AFF)
        static let statusDangerBg = dynamicColor(light: 0xFEF2F1FF, dark: 0x3A1A17FF, lightHC: 0xFEF2F1FF, darkHC: 0x3A1A17FF)
        static let statusWarningFg = dynamicColor(light: 0x8A5409FF, dark: 0xF9C259FF, lightHC: 0x6B420CFF, darkHC: 0xF9C259FF)
        static let statusWarningBg = dynamicColor(light: 0xFFF8EBFF, dark: 0x33260EFF, lightHC: 0xFFF8EBFF, darkHC: 0x33260EFF)
        static let statusSuccessFg = dynamicColor(light: 0x227838FF, dark: 0x85D198FF, lightHC: 0x1D5F2FFF, darkHC: 0x85D198FF)
        static let statusSuccessBg = dynamicColor(light: 0xEFFAF1FF, dark: 0x12301AFF, lightHC: 0xEFFAF1FF, darkHC: 0x12301AFF)
        static let statusInfoFg = dynamicColor(light: 0x285FC0FF, dark: 0x8DB8F5FF, lightHC: 0x224D9BFF, darkHC: 0xB9D3FAFF)
        static let statusInfoBg = dynamicColor(light: 0xEFF6FFFF, dark: 0x142540FF, lightHC: 0xEFF6FFFF, darkHC: 0x142540FF)
        static let secretDigit = dynamicColor(light: 0x285FC0FF, dark: 0x8DB8F5FF, lightHC: 0x1B3D7AFF, darkHC: 0xB9D3FAFF)
        static let secretSymbol = dynamicColor(light: 0xC4321FFF, dark: 0xF07264FF, lightHC: 0x7F2318FF, darkHC: 0xF7A39AFF)
        static let shadowColor = dynamicColor(light: 0x0000001F, dark: 0x00000066, lightHC: 0x0000001F, darkHC: 0x00000066)
    }

    /// 本地生成的网站图标底色，配白色文字。
    static let siteColors: [Color] = [
        rgba(0x127F71FF),
        rgba(0x2F6FB8FF),
        rgba(0x7A4FC4FF),
        rgba(0xA83A6BFF),
        rgba(0xB4532AFF),
        rgba(0x8A5A00FF),
        rgba(0x5E6A16FF),
        rgba(0x4A5568FF),
    ]

    /// 间距（pt）。
    enum Space {
        static let s0: CGFloat = 0
        static let s0_5: CGFloat = 2
        static let s1: CGFloat = 4
        static let s1_5: CGFloat = 6
        static let s2: CGFloat = 8
        static let s3: CGFloat = 12
        static let s4: CGFloat = 16
        static let s5: CGFloat = 20
        static let s6: CGFloat = 24
        static let s8: CGFloat = 32
        static let s10: CGFloat = 40
        static let s12: CGFloat = 48
    }

    /// 圆角（pt）。
    enum Radius {
        static let xs: CGFloat = 3
        static let sm: CGFloat = 5
        static let md: CGFloat = 8
        static let lg: CGFloat = 12
        static let xl: CGFloat = 16
        static let full: CGFloat = 999
    }

    /// 字体。macOS 没有动态字体，字号与系统控件保持一致。
    enum Typography {
        static let caption = Font.system(size: 11, weight: .regular)
        static let footnote = Font.system(size: 12, weight: .regular)
        static let body = Font.system(size: 13, weight: .regular)
        static let bodyStrong = Font.system(size: 13, weight: .semibold)
        static let headline = Font.system(size: 15, weight: .semibold)
        static let title = Font.system(size: 20, weight: .semibold)
        static let largeTitle = Font.system(size: 26, weight: .bold)
        static let mono = Font.system(size: 13, weight: .medium, design: .monospaced)
        static let monoLarge = Font.system(size: 18, weight: .medium, design: .monospaced)
        static let largeType = Font.system(size: 28, weight: .medium, design: .monospaced)
    }

    /// 动效。调用方需在「减弱动态效果」开启时改用瞬时变化。
    enum Motion {
        static let fast: Double = 0.12
        static let base: Double = 0.2
        static let slow: Double = 0.32
        static func standard(duration: Double = base) -> Animation {
            .timingCurve(0.2, 0, 0, 1, duration: duration)
        }
    }
}

private func rgba(_ value: UInt32) -> Color {
    Color(nsColor: nsColor(value))
}

private func nsColor(_ value: UInt32) -> NSColor {
    NSColor(
        srgbRed: CGFloat((value >> 24) & 0xFF) / 255,
        green: CGFloat((value >> 16) & 0xFF) / 255,
        blue: CGFloat((value >> 8) & 0xFF) / 255,
        alpha: CGFloat(value & 0xFF) / 255
    )
}

private func dynamicColor(light: UInt32, dark: UInt32, lightHC: UInt32, darkHC: UInt32) -> Color {
    Color(nsColor: NSColor(name: nil) { appearance in
        switch appearance.bestMatch(from: [
            .aqua, .darkAqua, .accessibilityHighContrastAqua, .accessibilityHighContrastDarkAqua,
        ]) {
        case .darkAqua?: return nsColor(dark)
        case .accessibilityHighContrastAqua?: return nsColor(lightHC)
        case .accessibilityHighContrastDarkAqua?: return nsColor(darkHC)
        default: return nsColor(light)
        }
    })
}
