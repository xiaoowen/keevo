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
    var multiline = false
    /// 显示时能否选中文字。详情的字段行双击即复制，关掉选择（否则双击会选中一个词）；历史版本与冲突视图没有
    /// 复制按钮，保留选择。
    var selectable = true

    var body: some View {
        if revealed {
            // 显示时逐字符分色，便于分辨 0/O、1/l 等易混字符（design/README.md"字符分色"）
            let text = classifiedText(secret.expose(), font: KV.Typography.mono)
                .lineLimit(multiline ? nil : 1)
                .fixedSize(horizontal: false, vertical: multiline)
            if selectable {
                text.textSelection(.enabled)
            } else {
                text
            }
        } else {
            Text(String(repeating: "•", count: 10))
                .font(KV.Typography.mono)
                .tracking(1)
                .foregroundStyle(KV.Colors.fgSecondary)
                .accessibilityLabel(tr("已隐藏"))
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
                legend(tr("字母"), .letter)
                legend(tr("数字"), .digit)
                legend(tr("符号"), .symbol)
                Spacer()
                Button(tr("完成")) { dismiss() }.keyboardShortcut(.defaultAction)
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

/// 配对码：6 个词，与浏览器扩展中显示的完全一致（spec/ipc.md §4.2，词表 spec/sas-wordlist-v1.tsv）。
/// 每个词同时显示中文与英文（互为翻译），按从左到右、从上到下的顺序比对。
struct PairingCode: View {
    let words: [SasWord]

    var body: some View {
        Grid(horizontalSpacing: KV.Space.s2, verticalSpacing: KV.Space.s2) {
            ForEach(0 ..< (words.count + 2) / 3, id: \.self) { row in
                GridRow {
                    ForEach(Array(words.enumerated()).filter { $0.offset / 3 == row }, id: \.offset) { index, w in
                        VStack(spacing: 2) {
                            Text("\(index + 1)").font(KV.Typography.caption).foregroundStyle(KV.Colors.fgTertiary)
                            Text(w.zh).font(KV.Typography.title).foregroundStyle(KV.Colors.fgPrimary)
                            Text(w.en).font(KV.Typography.footnote).foregroundStyle(KV.Colors.fgSecondary)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, KV.Space.s2)
                        .background(KV.Colors.bgSunken, in: RoundedRectangle(cornerRadius: KV.Radius.md))
                    }
                }
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(tr("配对码：{}", "\(words.map { UILanguage.current == .en ? $0.en : $0.zh }.joined(separator: tr("、")))"))
    }
}

// MARK: - 按钮

/// 设计稿中的按钮（design/README.md）：主操作为品牌色填充；顶部栏的收藏、编辑、更多、锁定、取消等为无边框按钮
/// （悬停时浅底，设计稿"条目的展示、编辑与新建"）；次要操作为浅底描边；"显示"等行内操作为品牌色文字。
struct KVButtonStyle: ButtonStyle {
    enum Kind { case primary, bordered, secondary, link, danger, toolbar, toolbarAccent }

    var kind: Kind
    var fullWidth = false
    /// 紧凑尺寸：与描边按钮等高（28），用于顶部栏。
    var compact = false

    func makeBody(configuration: Configuration) -> some View {
        StyledButton(configuration: configuration, kind: kind, fullWidth: fullWidth, compact: compact)
    }

    private struct StyledButton: View {
        let configuration: Configuration
        let kind: Kind
        let fullWidth: Bool
        let compact: Bool
        @Environment(\.isEnabled) private var isEnabled
        @ViewState private var hovering = false

        var body: some View {
            label
                .frame(maxWidth: fullWidth ? .infinity : nil)
                .contentShape(Rectangle())
                .opacity(isEnabled ? 1 : 0.45)
                .onHover { hovering = $0 }
        }

        @ViewBuilder
        private var label: some View {
            let pressed = configuration.isPressed
            switch kind {
            case .primary:
                configuration.label
                    .font(KV.Typography.bodyStrong)
                    .foregroundStyle(KV.Colors.fgOnAccent)
                    .padding(.vertical, compact ? KV.Space.s1 : KV.Space.s2)
                    .padding(.horizontal, compact ? KV.Space.s3 : KV.Space.s4)
                    .frame(minHeight: compact ? 28 : nil)
                    .frame(maxWidth: fullWidth ? .infinity : nil)
                    .background(pressed || hovering ? KV.Colors.accentFillHover : KV.Colors.accentFill,
                                in: RoundedRectangle(cornerRadius: compact ? 6 : KV.Radius.md, style: .continuous))
            case .danger:
                configuration.label
                    .font(KV.Typography.bodyStrong)
                    .foregroundStyle(.white)
                    .padding(.vertical, KV.Space.s2)
                    .padding(.horizontal, KV.Space.s4)
                    .frame(maxWidth: fullWidth ? .infinity : nil)
                    .background(KV.Colors.statusDangerFg.opacity(pressed ? 0.85 : 1),
                                in: RoundedRectangle(cornerRadius: KV.Radius.md, style: .continuous))
            case .bordered:
                configuration.label
                    .font(KV.Typography.bodyStrong)
                    .foregroundStyle(KV.Colors.fgPrimary)
                    .padding(.vertical, KV.Space.s1)
                    .padding(.horizontal, KV.Space.s3)
                    .frame(minHeight: 28)
                    .frame(maxWidth: fullWidth ? .infinity : nil)
                    .background(pressed || hovering ? KV.Colors.bgHover : KV.Colors.bgRaised,
                                in: RoundedRectangle(cornerRadius: 6, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: 6, style: .continuous).strokeBorder(KV.Colors.borderControl))
            case .secondary:
                configuration.label
                    .font(KV.Typography.body.weight(.medium))
                    .foregroundStyle(KV.Colors.fgPrimary)
                    .padding(.vertical, KV.Space.s2)
                    .padding(.horizontal, KV.Space.s4)
                    .frame(maxWidth: fullWidth ? .infinity : nil)
                    .background(pressed || hovering ? KV.Colors.bgHover : KV.Colors.bgSurface,
                                in: RoundedRectangle(cornerRadius: KV.Radius.md, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: KV.Radius.md, style: .continuous).strokeBorder(KV.Colors.borderSubtle))
            case .link:
                configuration.label
                    .font(KV.Typography.footnote.weight(.semibold))
                    .foregroundStyle(KV.Colors.accentFg.opacity(pressed ? 0.7 : 1))
                    .padding(KV.Space.s0_5)
            case .toolbar, .toolbarAccent:
                configuration.label
                    .font(kind == .toolbarAccent ? KV.Typography.bodyStrong : KV.Typography.body.weight(.medium))
                    .foregroundStyle(kind == .toolbarAccent ? KV.Colors.accentFg : KV.Colors.fgPrimary)
                    .padding(.horizontal, KV.Space.s2)
                    .frame(minWidth: 28, minHeight: 28)
                    .background(
                        pressed ? KV.Colors.fgPrimary.opacity(0.12) : (hovering ? KV.Colors.bgHover : Color.clear),
                        in: RoundedRectangle(cornerRadius: 6, style: .continuous)
                    )
            }
        }
    }
}

extension ButtonStyle where Self == KVButtonStyle {
    static var kvPrimary: KVButtonStyle { KVButtonStyle(kind: .primary) }
    static var kvBordered: KVButtonStyle { KVButtonStyle(kind: .bordered) }
    static var kvSecondary: KVButtonStyle { KVButtonStyle(kind: .secondary) }
    static var kvLink: KVButtonStyle { KVButtonStyle(kind: .link) }
    static var kvDanger: KVButtonStyle { KVButtonStyle(kind: .danger) }
    /// 顶部栏的无边框按钮：悬停时浅底，按下时加深。
    static var kvToolbar: KVButtonStyle { KVButtonStyle(kind: .toolbar) }
    /// 顶部栏的无边框文字按钮，品牌色（"编辑"）。
    static var kvToolbarAccent: KVButtonStyle { KVButtonStyle(kind: .toolbarAccent) }
}

/// 一组单选行（设置的分类、导入来源、导出格式）：行本身不进入 Tab 顺序，鼠标点击不留焦点框；整组可以获得焦点，
/// 用上下方向键切换选中项。
struct ArrowSelection<Value: Hashable>: ViewModifier {
    let values: [Value]
    let selection: Value
    let select: (Value) -> Void

    func body(content: Content) -> some View {
        content
            .focusable()
            .focusEffectDisabled()
            .onMoveCommand { direction in
                guard let i = values.firstIndex(of: selection) else { return }
                switch direction {
                case .up where i > 0: select(values[i - 1])
                case .down where i + 1 < values.count: select(values[i + 1])
                default: break
                }
            }
    }
}

extension View {
    func arrowSelection<Value: Hashable>(_ values: [Value], selection: Value, select: @escaping (Value) -> Void) -> some View {
        modifier(ArrowSelection(values: values, selection: selection, select: select))
    }
}

/// 只有图标的行内按钮（复制等）：品牌色，悬停时加浅底。
struct IconButton: View {
    let systemImage: String
    let label: String
    var help: String?
    let action: () -> Void
    @ViewState private var hovering = false

    var body: some View {
        Button(action: action) {
            Image(systemName: systemImage)
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(KV.Colors.accentFg)
                .frame(width: 24, height: 24)
                .background(hovering ? KV.Colors.bgHover : .clear, in: RoundedRectangle(cornerRadius: KV.Radius.sm))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .help(help ?? label)
        .accessibilityLabel(label)
    }
}

// MARK: - 搜索框

/// 列表顶部的搜索框（设计稿）：浅灰底、放大镜，有内容时显示清除按钮。
struct KVSearchField: View {
    @Binding var text: String
    let prompt: String
    var focus: FocusState<Bool>.Binding

    var body: some View {
        HStack(spacing: KV.Space.s1_5) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(KV.Colors.fgSecondary)
            TextField(prompt, text: $text)
                .textFieldStyle(.plain)
                .font(KV.Typography.body)
                .focused(focus)
            if !text.isEmpty {
                Button { text = "" } label: {
                    Image(systemName: "xmark.circle.fill").foregroundStyle(KV.Colors.fgTertiary)
                }
                .buttonStyle(.plain)
                .accessibilityLabel(tr("清除搜索"))
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(KV.Colors.bgSunken, in: RoundedRectangle(cornerRadius: KV.Radius.md, style: .continuous))
    }
}

// MARK: - 卡片

/// 字段卡片（设计稿）：细边框、圆角 10，行与行之间是细分隔线（由行自己画，见 `CardRowDivider`）。
struct KVCard<Content: View>: View {
    @ViewBuilder let content: Content

    var body: some View {
        // 底色不用 background(_:in:)：它把圆角作为容器形状传给每一行，行的背景色（悬停、已显示）会各自画成圆角
        VStack(spacing: 0) { content }
            .background(KV.Colors.bgCanvas)
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(KV.Colors.borderSubtle))
    }
}

/// 卡片中行与行之间的分隔线。
struct CardRowDivider: View {
    var body: some View {
        Rectangle().fill(KV.Colors.borderSubtle).frame(height: 1)
    }
}

/// 分组标题（设计稿：13pt、半粗、次要文字色）。
struct GroupTitle: View {
    let text: String

    var body: some View {
        // 分区名可能是模板的默认名称：按界面语言显示
        Text(tr(text))
            .font(KV.Typography.body.weight(.semibold))
            .foregroundStyle(KV.Colors.fgSecondary)
            .accessibilityAddTraits(.isHeader)
    }
}

// MARK: - 标签与徽标

/// 标签胶囊：浅灰底（设计稿"条目的展示、编辑与新建"）。
struct Pill: View {
    let text: String

    var body: some View {
        Text(text)
            .font(KV.Typography.body)
            .foregroundStyle(KV.Colors.fgPrimary)
            .padding(.horizontal, 10)
            .padding(.vertical, 3)
            .background(KV.Colors.bgSunken, in: Capsule())
    }
}

/// 条目中各块的小标签（"网站""标签""附件"）：品牌色小字，与字段行的标签一致。
struct FieldLabel: View {
    let text: String

    var body: some View {
        Text(text)
            .font(KV.Typography.footnote)
            .foregroundStyle(KV.Colors.accentFg)
    }
}

/// 描边徽标（"按域名匹配""秘密"）。
struct OutlineBadge: View {
    let text: String

    var body: some View {
        Text(text)
            .font(KV.Typography.caption)
            .foregroundStyle(KV.Colors.fgSecondary)
            .padding(.horizontal, KV.Space.s2)
            .padding(.vertical, 1)
            .overlay(Capsule().strokeBorder(KV.Colors.borderSubtle))
    }
}

/// 计数徽标（侧边栏）：普通计数为次要文字，需要注意的计数为警示色胶囊。
struct CountBadge: View {
    let count: Int
    var attention = false

    var body: some View {
        if attention {
            Text("\(count)")
                .font(KV.Typography.caption.weight(.semibold))
                .foregroundStyle(KV.Colors.statusWarningFg)
                .padding(.horizontal, 6)
                .padding(.vertical, 1)
                .background(KV.Colors.statusWarningBg, in: Capsule())
        } else {
            Text("\(count)")
                .font(KV.Typography.footnote)
                .foregroundStyle(KV.Colors.fgSecondary)
                .monospacedDigit()
        }
    }
}

// MARK: - 提示条

/// 窗口底部的短暂提示（"已复制 · 90 秒后清除"）。
struct ToastView: View {
    let message: String

    var body: some View {
        HStack(spacing: KV.Space.s2) {
            Image(systemName: "checkmark.circle.fill").foregroundStyle(KV.Colors.statusSuccessFg)
            Text(message).font(KV.Typography.footnote.weight(.medium)).foregroundStyle(KV.Colors.fgPrimary)
        }
        .padding(.horizontal, KV.Space.s4)
        .padding(.vertical, KV.Space.s2)
        .background(KV.Colors.bgRaised, in: Capsule())
        .overlay(Capsule().strokeBorder(KV.Colors.borderSubtle))
        .shadow(color: KV.Colors.shadowColor, radius: 12, y: 4)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.updatesFrequently)
    }
}

// MARK: - 输入框

/// 编辑器中的输入框：无系统边框，浅色描边、圆角 6。
struct KVInputStyle: ViewModifier {
    var mono = false

    func body(content: Content) -> some View {
        content
            .textFieldStyle(.plain)
            .font(mono ? KV.Typography.mono : KV.Typography.body)
            .padding(.horizontal, KV.Space.s2)
            .padding(.vertical, 6)
            .background(KV.Colors.bgCanvas, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 6, style: .continuous).strokeBorder(KV.Colors.borderSubtle))
    }
}

extension View {
    func kvInput(mono: Bool = false) -> some View { modifier(KVInputStyle(mono: mono)) }
    /// 卡片或浅灰块中的无边框输入框（设计稿"条目的展示、编辑与新建"）。
    func kvInline(mono: Bool = false) -> some View {
        textFieldStyle(.plain)
            .font(mono ? KV.Typography.mono : KV.Typography.body)
            .foregroundStyle(KV.Colors.fgPrimary)
    }
}

/// 流式布局：一行放不下时换行（标签）。
struct FlowLayout: Layout {
    var spacing: CGFloat = KV.Space.s1_5

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let rows = arrange(width: proposal.width ?? .infinity, subviews)
        let width = rows.map(\.width).max() ?? 0
        let height = rows.map(\.height).reduce(0, +) + spacing * CGFloat(max(rows.count - 1, 0))
        return CGSize(width: width, height: height)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var y = bounds.minY
        for row in arrange(width: bounds.width, subviews) {
            var x = bounds.minX
            for i in row.indices {
                let size = subviews[i].sizeThatFits(.unspecified)
                subviews[i].place(at: CGPoint(x: x, y: y + (row.height - size.height) / 2), proposal: .unspecified)
                x += size.width + spacing
            }
            y += row.height + spacing
        }
    }

    private struct Row {
        var indices: [Int] = []
        var width: CGFloat = 0
        var height: CGFloat = 0
    }

    private func arrange(width: CGFloat, _ subviews: Subviews) -> [Row] {
        var rows = [Row()]
        for (i, view) in subviews.enumerated() {
            let size = view.sizeThatFits(.unspecified)
            if !rows[rows.count - 1].indices.isEmpty, rows[rows.count - 1].width + spacing + size.width > width {
                rows.append(Row())
            }
            let last = rows.count - 1
            rows[last].width += rows[last].indices.isEmpty ? size.width : size.width + spacing
            rows[last].height = max(rows[last].height, size.height)
            rows[last].indices.append(i)
        }
        return rows
    }
}

/// 只有图标的菜单按钮（"⋯"），悬停时加浅底。
struct IconMenu<Items: View>: View {
    var systemImage = "ellipsis"
    let label: String
    @ViewBuilder let items: Items
    @ViewState private var hovering = false

    var body: some View {
        Menu {
            items
        } label: {
            Image(systemName: systemImage)
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(KV.Colors.fgSecondary)
                .frame(width: 24, height: 24)
                .background(hovering ? KV.Colors.bgHover : .clear, in: RoundedRectangle(cornerRadius: KV.Radius.sm))
                .contentShape(Rectangle())
        }
        .menuStyle(.button)
        .buttonStyle(.plain)
        .menuIndicator(.hidden)
        .fixedSize()
        .onHover { hovering = $0 }
        .help(label)
        .accessibilityLabel(label)
    }
}

/// 带标签的输入框（设计稿"锁屏"）：标签在上，输入框描边、圆角 8，聚焦时品牌色描边。
struct LabeledInput<Field: View>: View {
    let label: String
    var hint: String?
    var focused = false
    @ViewBuilder let field: Field

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label)
                .font(KV.Typography.footnote.weight(.semibold))
                .foregroundStyle(KV.Colors.fgSecondary)
            field
                .textFieldStyle(.plain)
                .font(KV.Typography.body)
                .padding(.horizontal, KV.Space.s3)
                .padding(.vertical, 9)
                .background(KV.Colors.bgCanvas, in: RoundedRectangle(cornerRadius: KV.Radius.md, style: .continuous))
                .overlay(
                    RoundedRectangle(cornerRadius: KV.Radius.md, style: .continuous)
                        .strokeBorder(focused ? KV.Colors.focusRing : KV.Colors.borderControl, lineWidth: focused ? 2 : 1)
                )
            if let hint {
                Text(hint).font(KV.Typography.caption).foregroundStyle(KV.Colors.fgSecondary)
            }
        }
    }
}

/// 页面中央的图标方块（锁屏、引导等）：品牌色浅底，图标为品牌色。
struct HeroIcon: View {
    let systemImage: String
    var tint: Color = KV.Colors.accentFg
    var background: Color = KV.Colors.accentSubtle

    var body: some View {
        Image(systemName: systemImage)
            .font(.system(size: 28, weight: .regular))
            .foregroundStyle(tint)
            .frame(width: 72, height: 72)
            .background(background, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
            .accessibilityHidden(true)
    }
}

/// 带文字的分隔线（"或"）。
struct TextDivider: View {
    let text: String

    var body: some View {
        HStack(spacing: KV.Space.s3) {
            Rectangle().fill(KV.Colors.borderSubtle).frame(height: 1)
            Text(text).font(KV.Typography.footnote).foregroundStyle(KV.Colors.fgTertiary)
            Rectangle().fill(KV.Colors.borderSubtle).frame(height: 1)
        }
    }
}

// MARK: - 设置

/// 设置分组（参考系统设置）：标题、卡片、卡片下方的说明。
struct SettingsSection<Content: View>: View {
    let title: String
    var footer: String?
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: KV.Space.s2) {
            if !title.isEmpty { GroupTitle(text: title) }
            KVCard { content }
            if let footer {
                Text(footer)
                    .font(KV.Typography.footnote)
                    .foregroundStyle(KV.Colors.fgSecondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, KV.Space.s1)
            }
        }
    }
}

/// 设置中的一行：标题与说明在左，控件在右。
struct SettingsRow<Control: View>: View {
    let title: String
    var detail: String?
    /// 说明用品牌色加粗（例如"有新版本"）。
    var emphasizeDetail = false
    @ViewBuilder let control: Control

    var body: some View {
        HStack(spacing: KV.Space.s3) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(KV.Typography.body).foregroundStyle(KV.Colors.fgPrimary)
                if let detail {
                    Text(detail)
                        .font(emphasizeDetail ? KV.Typography.footnote.weight(.semibold) : KV.Typography.footnote)
                        .foregroundStyle(emphasizeDetail ? KV.Colors.accentFg : KV.Colors.fgSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: KV.Space.s3)
            control
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .frame(minHeight: 44)
    }
}

extension View {
    /// 品牌色的小号开关，不显示系统标签（标签由所在的行提供）。
    func kvSwitch(_ label: String) -> some View {
        toggleStyle(.switch)
            .controlSize(.small)
            .tint(KV.Colors.accentFill)
            .labelsHidden()
            .accessibilityLabel(label)
    }
}

/// 分段控件：浅灰底，选中的一段为白色浮起。
struct KVSegmented<Value: Hashable>: View {
    let options: [(Value, String)]
    @Binding var selection: Value

    var body: some View {
        HStack(spacing: 2) {
            ForEach(options, id: \.0) { value, title in
                let selected = value == selection
                Button { selection = value } label: {
                    Text(title)
                        .font(selected ? KV.Typography.bodyStrong : KV.Typography.body)
                        .foregroundStyle(selected ? KV.Colors.fgPrimary : KV.Colors.fgSecondary)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 5)
                        .background {
                            if selected {
                                RoundedRectangle(cornerRadius: 6, style: .continuous)
                                    .fill(KV.Colors.bgRaised)
                                    .shadow(color: KV.Colors.shadowColor, radius: 1, y: 1)
                            }
                        }
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(selected ? .isSelected : [])
            }
        }
        .padding(2)
        .background(KV.Colors.bgSunken, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
    }
}

// MARK: - 口令强度

/// 在后台估计口令强度：输入时不在主线程上计算（个别输入要一两百毫秒），停顿片刻后更新，只采用最后一次输入的
/// 结果（第 24 小时模糊测试的慢输入）。
@MainActor
@Observable
final class StrengthEstimator {
    /// 最近一次估计的结果，以及它对应的口令。
    private(set) var result: PasswordStrengthInfo?
    private(set) var estimatedFor: String?
    private var task: Task<Void, Never>?

    /// 口令改变时调用。空口令立即清空。
    func update(_ password: String, using estimate: @escaping (String) -> PasswordStrengthInfo) {
        task?.cancel()
        guard !password.isEmpty else {
            result = nil
            estimatedFor = password
            return
        }
        task = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(60))
            guard !Task.isCancelled else { return }
            let strength = await Task.detached(priority: .userInitiated) { estimate(password) }.value
            guard !Task.isCancelled else { return }
            self?.result = strength
            self?.estimatedFor = password
        }
    }

    /// 已经算出 `password` 的强度：没有算出之前，依赖强度的判断（能否继续）不放行。
    func isCurrent(for password: String) -> Bool {
        estimatedFor == password
    }

    /// `password` 的强度；还没算出时为 nil（界面显示上一次的结果会误导）。
    func strength(for password: String) -> PasswordStrengthInfo? {
        isCurrent(for: password) ? result : nil
    }
}

// MARK: - 焦点

/// 打开时焦点给容器本身（不画焦点框）。开启全键盘操作时，没有输入框的面板、弹出框会把焦点框放在第一个按钮、
/// 开关或可选择的文字上，而且不随点击移动；用 Tab 才进入其中的控件。Esc 等键盘快捷键照常可用。
private struct ContainerFocus: ViewModifier {
    @FocusState private var focused: Bool

    func body(content: Content) -> some View {
        content
            .focusable()
            .focusEffectDisabled()
            .focused($focused)
            .onAppear { focused = true }
    }
}

extension View {
    /// 见 `ContainerFocus`：用于确认面板、开关列表等没有输入框的容器。
    func kvContainerFocus() -> some View {
        modifier(ContainerFocus())
    }
}

// MARK: - 面板

/// 面板（sheet）的统一框架：标题区（可选图标）、内容、底部按钮靠右。
struct SheetScaffold<Content: View, Footer: View>: View {
    let title: String
    var subtitle: String?
    var systemImage: String?
    var tint: Color = KV.Colors.accentFg
    var width: CGFloat = 480
    /// 底部左侧的说明（例如"41 秒后自动拒绝"）。
    var note: String?
    @ViewBuilder let content: Content
    @ViewBuilder let footer: Footer

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .top, spacing: KV.Space.s3) {
                if let systemImage {
                    Image(systemName: systemImage)
                        .font(.system(size: 18, weight: .medium))
                        .foregroundStyle(tint)
                        .frame(width: 36, height: 36)
                        .background(tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 9, style: .continuous))
                        .accessibilityHidden(true)
                }
                VStack(alignment: .leading, spacing: 3) {
                    Text(title)
                        .font(KV.Typography.headline)
                        .foregroundStyle(KV.Colors.fgPrimary)
                        .fixedSize(horizontal: false, vertical: true)
                    if let subtitle {
                        Text(subtitle)
                            .font(KV.Typography.footnote)
                            .foregroundStyle(KV.Colors.fgSecondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            .padding(.bottom, KV.Space.s4)
            content
            HStack(spacing: KV.Space.s2) {
                if let note {
                    Text(note)
                        .font(KV.Typography.footnote)
                        .foregroundStyle(KV.Colors.fgTertiary)
                        .monospacedDigit()
                }
                Spacer(minLength: 0)
                footer
            }
            .padding(.top, KV.Space.s5)
        }
        .padding(KV.Space.s6)
        .frame(width: width)
        .background(KV.Colors.bgRaised)
    }
}
