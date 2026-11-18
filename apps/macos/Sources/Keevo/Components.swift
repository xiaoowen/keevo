// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 设计系统 v0 的核心组件（design/README.md）。颜色、间距、圆角、字体一律取自 KV 令牌。

import KeevoKit
import SwiftUI

// MARK: - 网站图标

/// 本地生成的网站图标：首字母 + 按域名选取的颜色。不向任何第三方请求 favicon（docs/ux.md §7）。
///
/// 颜色选择与浏览器扩展共用同一算法（design/README.md「网站图标」）：
/// `key = 去掉 www. 的小写主机名（没有网址时用标题）`，`index = FNV-1a-32(UTF-8(key)) mod 8`。
struct SiteIcon: View {
    let title: String
    let url: String?
    var size: CGFloat = 28

    var body: some View {
        let key = SiteIcon.key(title: title, url: url)
        RoundedRectangle(cornerRadius: size * 0.28, style: .continuous)
            .fill(KV.siteColors[SiteIcon.colorIndex(for: key)])
            .frame(width: size, height: size)
            .overlay {
                Text(SiteIcon.initial(title: title, key: key))
                    .font(.system(size: size * 0.46, weight: .semibold))
                    .foregroundStyle(.white)
            }
            .accessibilityHidden(true)
    }

    static func key(title: String, url: String?) -> String {
        if let url, let host = URL(string: url.contains("://") ? url : "https://\(url)")?.host() {
            let lower = host.lowercased()
            return lower.hasPrefix("www.") ? String(lower.dropFirst(4)) : lower
        }
        return title
    }

    static func colorIndex(for key: String) -> Int {
        var hash: UInt32 = 0x811C_9DC5
        for byte in key.utf8 {
            hash ^= UInt32(byte)
            hash = hash &* 0x0100_0193
        }
        return Int(hash % UInt32(KV.siteColors.count))
    }

    static func initial(title: String, key: String) -> String {
        let source = title.trimmingCharacters(in: .whitespaces).isEmpty ? key : title
        return source.first.map { String($0).uppercased() } ?? "?"
    }
}

// MARK: - 秘密值

/// 秘密值：默认显示为圆点，用户主动显示后才从 Rust 取出明文（docs/ux.md §5、docs/architecture.md §4.2）。
struct SecretText: View {
    let secret: SecretValue
    let revealed: Bool

    var body: some View {
        if revealed {
            Text(secret.expose())
                .font(KV.Typography.mono)
                .foregroundStyle(KV.Colors.fgPrimary)
                .textSelection(.enabled)
        } else {
            Text(String(repeating: "•", count: 10))
                .font(KV.Typography.mono)
                .foregroundStyle(KV.Colors.fgSecondary)
                .accessibilityLabel("已隐藏")
        }
    }
}

/// 字符分类：大字显示与账户密钥显示时，数字与符号用不同颜色，便于手动抄写。
enum CharClass {
    case letter, digit, symbol

    init(_ c: Character) {
        if c.isNumber {
            self = .digit
        } else if c.isLetter {
            self = .letter
        } else {
            self = .symbol
        }
    }

    var color: Color {
        switch self {
        case .letter: KV.Colors.fgPrimary
        case .digit: KV.Colors.secretDigit
        case .symbol: KV.Colors.secretSymbol
        }
    }
}

/// 逐字符分色的等宽文本。
func classifiedText(_ value: String, font: Font) -> Text {
    value.reduce(Text("")) { partial, c in
        partial + Text(String(c)).foregroundColor(CharClass(c).color)
    }
    .font(font)
}

/// 大字显示：每个字符一格，下方标注序号；数字、字母、符号分色（docs/ux.md §5）。
struct LargeTypeView: View {
    let value: String
    @Environment(\.dismiss) private var dismiss

    private let columns = [GridItem(.adaptive(minimum: 44, maximum: 52), spacing: KV.Space.s1)]

    var body: some View {
        VStack(spacing: KV.Space.s4) {
            LazyVGrid(columns: columns, spacing: KV.Space.s2) {
                ForEach(Array(value.enumerated()), id: \.offset) { index, c in
                    VStack(spacing: KV.Space.s0_5) {
                        Text(String(c))
                            .font(KV.Typography.largeType)
                            .foregroundStyle(CharClass(c).color)
                        Text("\(index + 1)")
                            .font(KV.Typography.caption)
                            .foregroundStyle(KV.Colors.fgSecondary)
                    }
                    .frame(minWidth: 44, minHeight: 64)
                    .background(index % 2 == 0 ? KV.Colors.bgSunken : KV.Colors.bgCanvas,
                                in: RoundedRectangle(cornerRadius: KV.Radius.sm))
                }
            }
            HStack(spacing: KV.Space.s4) {
                legend("字母", .letter)
                legend("数字", .digit)
                legend("符号", .symbol)
                Spacer()
                Button("完成") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(KV.Space.s6)
        .frame(minWidth: 520)
        .background(KV.Colors.bgRaised)
    }

    private func legend(_ label: String, _ cls: CharClass) -> some View {
        HStack(spacing: KV.Space.s1) {
            Circle().fill(cls.color).frame(width: 8, height: 8)
            Text(label).font(KV.Typography.footnote).foregroundStyle(KV.Colors.fgSecondary)
        }
    }
}

// MARK: - 提示横幅

/// 三级风险提示（docs/ux.md §5）。信息不只靠颜色传达：每级都有不同的图标。
struct Banner: View {
    enum Kind { case info, success, warning, danger }

    let kind: Kind
    let message: String

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: KV.Space.s2) {
            Image(systemName: icon).foregroundStyle(fg)
            Text(message).font(KV.Typography.footnote).foregroundStyle(fg)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, KV.Space.s3)
        .padding(.vertical, KV.Space.s2)
        .background(bg, in: RoundedRectangle(cornerRadius: KV.Radius.md, style: .continuous))
    }

    private var icon: String {
        switch kind {
        case .info: "info.circle.fill"
        case .success: "checkmark.circle.fill"
        case .warning: "exclamationmark.triangle.fill"
        case .danger: "xmark.octagon.fill"
        }
    }

    private var fg: Color {
        switch kind {
        case .info: KV.Colors.statusInfoFg
        case .success: KV.Colors.statusSuccessFg
        case .warning: KV.Colors.statusWarningFg
        case .danger: KV.Colors.statusDangerFg
        }
    }

    private var bg: Color {
        switch kind {
        case .info: KV.Colors.statusInfoBg
        case .success: KV.Colors.statusSuccessBg
        case .warning: KV.Colors.statusWarningBg
        case .danger: KV.Colors.statusDangerBg
        }
    }
}

// MARK: - 配对码

/// 配对验证码：6 组两位字符，与浏览器扩展中显示的完全一致（spec/ipc.md §4.2）。
struct PairingCode: View {
    let code: String

    var body: some View {
        let groups = stride(from: 0, to: code.count, by: 2).map { i -> String in
            let start = code.index(code.startIndex, offsetBy: i)
            return String(code[start ..< code.index(start, offsetBy: min(2, code.count - i))])
        }
        HStack(spacing: KV.Space.s2) {
            ForEach(Array(groups.enumerated()), id: \.offset) { _, g in
                Text(g)
                    .font(KV.Typography.largeType)
                    .foregroundStyle(KV.Colors.fgPrimary)
                    .padding(.horizontal, KV.Space.s2)
                    .background(KV.Colors.bgSunken, in: RoundedRectangle(cornerRadius: KV.Radius.sm))
            }
        }
        .accessibilityLabel("验证码 \(groups.joined(separator: " "))")
    }
}
