// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 详情中的字段（docs/ux.md §2、§5，设计稿"条目的展示、编辑与新建"）：字段卡片中的一行一个字段——标签在上、
// 值在下，操作只在悬停时出现。普通字段、秘密字段、一次性密码（验证码与倒计时环）、键值对、恢复码各有对应的行；
// 网址与备注在卡片下方单独显示。

import AppKit
import KeevoKit
import SwiftUI

/// 字段卡片：一组字段，行与行之间有分隔线。
struct FieldCard: View {
    let itemId: String
    let fields: [FieldEntry]
    let revealed: Set<String>
    let toggle: (String) -> Void
    /// 密码强度：显示在用途为"密码"的那一行右侧。
    var strength: PasswordStrengthInfo?
    let largeType: (String) -> Void

    var body: some View {
        KVCard {
            ForEach(Array(fields.enumerated()), id: \.element.id) { index, field in
                if index > 0 { CardRowDivider() }
                FieldDisplay(
                    itemId: itemId, field: field, revealed: revealed, toggle: toggle,
                    strength: field.purpose == "password" ? strength : nil, largeType: largeType
                )
            }
        }
    }
}

/// 一个字段：按类型选择对应的行。
struct FieldDisplay: View {
    let itemId: String
    let field: FieldEntry
    let revealed: Set<String>
    let toggle: (String) -> Void
    var strength: PasswordStrengthInfo?
    let largeType: (String) -> Void

    var body: some View {
        switch field.kind {
        case "totp":
            OtpRow(itemId: itemId, field: field)
                .contextMenu { ReferenceMenu(itemId: itemId, fieldId: field.id, otp: true) }
        case "kv_list":
            KvRows(itemId: itemId, field: field, revealed: revealed, toggle: toggle)
        case "recovery_codes":
            CodesRows(itemId: itemId, field: field, revealed: revealed, toggle: toggle)
        default:
            FieldRow(
                itemId: itemId,
                field: field,
                revealed: revealed.contains(field.id),
                toggle: { toggle(field.id) },
                strength: strength,
                largeType: { largeType(field.value.expose()) }
            )
            .contextMenu { ReferenceMenu(itemId: itemId, fieldId: field.id) }
        }
    }

    /// 详情中不显示没有内容的字段（编辑器中仍然显示，供填写）。
    static func hasContent(_ field: FieldEntry) -> Bool {
        switch field.kind {
        case "kv_list": !field.kv.isEmpty
        case "recovery_codes": !field.codes.isEmpty
        default: !field.value.isEmpty()
        }
    }
}

/// 条目字段的一行（设计稿"条目的展示、编辑与新建"）：标签在上（品牌色小字），值在下；右侧的附加信息（强度、
/// 倒计时）一直显示，复制、显示等操作只在悬停时出现。`copy` 不为空时双击整行即复制（设计稿"强度、双击复制、
/// 排序与检查更新"）。
struct ItemFieldRow<Value: View, Accessory: View, Actions: View>: View {
    let label: String
    var highlighted = false
    var copy: (() -> Void)?
    @ViewBuilder let value: Value
    @ViewBuilder let accessory: Accessory
    @ViewBuilder let actions: Actions
    @ViewState private var hovering = false

    var body: some View {
        HStack(alignment: .center, spacing: KV.Space.s2) {
            VStack(alignment: .leading, spacing: 2) {
                // 字段名是保险库中的数据：模板的默认名称按界面语言显示
                Text(tr(label))
                    .font(KV.Typography.footnote)
                    .foregroundStyle(KV.Colors.accentFg)
                    .lineLimit(1)
                value
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            accessory
            HStack(spacing: KV.Space.s1) { actions }
                .opacity(hovering ? 1 : 0)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 9)
        .background(highlighted ? KV.Colors.bgSelected : (hovering ? KV.Colors.bgSurface : Color.clear))
        .contentShape(Rectangle())
        .onHover { hovering = $0 }
        .doubleClickToCopy(copy)
    }
}

extension ItemFieldRow where Accessory == EmptyView {
    init(
        label: String,
        highlighted: Bool = false,
        copy: (() -> Void)? = nil,
        @ViewBuilder value: () -> Value,
        @ViewBuilder actions: () -> Actions
    ) {
        self.init(label: label, highlighted: highlighted, copy: copy, value: value, accessory: { EmptyView() }, actions: actions)
    }
}

extension View {
    /// 双击即复制，悬停时提示"双击复制"。`copy` 为空时不改变视图。值不要开启文字选择：双击会被当作选中一个词。
    @ViewBuilder
    func doubleClickToCopy(_ copy: (() -> Void)?) -> some View {
        if let copy {
            self.onTapGesture(count: 2, perform: copy).help(tr("双击复制"))
        } else {
            self
        }
    }
}

extension AppModel {
    /// 复制字段的值（复制按钮与双击）：剪贴板在 Clipboard.clearAfter 秒后清除，底部提示。`itemId` 不为空时记一次
    /// 使用（列表按"使用频率""最近使用"排序）。
    func copyField(label: String, value: String, itemId: String? = nil) {
        Clipboard.copy(value)
        if let itemId { recordUse(itemId: itemId) }
        showToast(tr("已复制{} · {} 秒后清除", "\(tr(label))", "\(Int(Clipboard.clearAfter))"))
    }
}

/// 密码强度的简短标记：文字与小圆环一起表示（不只靠颜色，docs/ux.md §8）。
struct StrengthBadge: View {
    let strength: PasswordStrengthInfo

    var body: some View {
        let (level, label, color) = SecurityText.strengthLabel(strength.score)
        HStack(spacing: KV.Space.s1_5) {
            Text(label)
                .font(KV.Typography.footnote)
                .foregroundStyle(color)
            ZStack {
                Circle().stroke(KV.Colors.borderSubtle, lineWidth: 2.5)
                Circle()
                    .trim(from: 0, to: Double(level) / 4)
                    .stroke(color, style: StrokeStyle(lineWidth: 2.5, lineCap: .round))
                    .rotationEffect(.degrees(-90))
            }
            .frame(width: 14, height: 14)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(tr("强度：{}", "\(label)"))
    }
}

/// 卡片下方的"网站"（设计稿）：每个网址一行链接，悬停时可以复制，双击行的空白处也可以复制。
struct WebsitesBlock: View {
    @Environment(AppModel.self) private var model
    let itemId: String
    let fields: [FieldEntry]

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            ForEach(Array(fields.enumerated()), id: \.element.id) { index, field in
                ItemFieldRow(
                    label: index == 0 ? field.label : "",
                    copy: { model.copyField(label: field.label, value: field.value.expose(), itemId: itemId) }
                ) {
                    if let url = URL(string: field.value.expose()), url.scheme == "https" || url.scheme == "http" {
                        Link(FieldRow.display(url), destination: url)
                            .font(KV.Typography.body)
                            .foregroundStyle(KV.Colors.accentFg)
                            .help(url.absoluteString)
                            .lineLimit(1)
                    } else {
                        Text(field.value.expose())
                            .font(KV.Typography.body)
                            .foregroundStyle(KV.Colors.fgPrimary)
                            .lineLimit(1)
                    }
                } actions: {
                    CopyButton(label: field.label, itemId: itemId) { field.value.expose() }
                }
                .contextMenu { ReferenceMenu(itemId: itemId, fieldId: field.id) }
            }
        }
    }
}

/// 卡片下方的"备注"（设计稿）。
struct NotesBlock: View {
    let field: FieldEntry

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(tr(field.label))
                .font(KV.Typography.footnote)
                .foregroundStyle(KV.Colors.accentFg)
            Text(field.value.expose())
                .font(KV.Typography.body)
                .foregroundStyle(KV.Colors.fgPrimary)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.horizontal, 14)
    }
}

/// 卡片中的一行：标签宽 92，值占满剩余宽度，操作靠右（设计稿）。
struct CardRow<Value: View, Actions: View>: View {
    let label: String
    var labelFont: Font = KV.Typography.footnote
    var labelColor: Color = KV.Colors.fgSecondary
    var labelWidth: CGFloat = 92
    var multiline = false
    var highlighted = false
    /// 不为空时双击整行即复制。
    var copy: (() -> Void)?
    @ViewBuilder let value: Value
    @ViewBuilder let actions: Actions

    var body: some View {
        HStack(alignment: multiline ? .firstTextBaseline : .center, spacing: 10) {
            // 字段名是保险库中的数据：模板的默认名称按界面语言显示
            Text(tr(label))
                .font(labelFont)
                .foregroundStyle(labelColor)
                .frame(width: labelWidth, alignment: .leading)
                .lineLimit(multiline ? nil : 1)
            value
                .frame(maxWidth: .infinity, alignment: .leading)
            HStack(spacing: KV.Space.s1) { actions }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 11)
        .background(highlighted ? KV.Colors.bgSelected : .clear)
        .contentShape(Rectangle())
        .doubleClickToCopy(copy)
    }
}

/// 普通字段与秘密字段。
struct FieldRow: View {
    @Environment(AppModel.self) private var model
    var itemId: String?
    let field: FieldEntry
    let revealed: Bool
    let toggle: () -> Void
    var strength: PasswordStrengthInfo?
    let largeType: () -> Void

    private var multiline: Bool {
        ["multiline", "ssh_private_key"].contains(field.kind) || field.value.expose().contains("\n")
    }

    var body: some View {
        ItemFieldRow(
            label: field.label,
            highlighted: field.concealed && revealed,
            copy: { model.copyField(label: field.label, value: field.value.expose(), itemId: itemId) }
        ) {
            valueView
        } accessory: {
            if let strength { StrengthBadge(strength: strength) }
        } actions: {
            if field.concealed {
                IconButton(
                    systemImage: revealed ? "eye.slash" : "eye",
                    label: revealed ? tr("隐藏") : tr("显示"),
                    help: revealed ? tr("隐藏") : tr("显示（30 秒后自动隐藏）"),
                    action: toggle
                )
                LargeTypeButton(action: largeType)
            }
            CopyButton(label: field.label, itemId: itemId) { field.value.expose() }
        }
    }

    @ViewBuilder
    private var valueView: some View {
        if field.concealed {
            SecretText(secret: field.value, revealed: revealed, multiline: multiline, selectable: false)
        } else if field.kind == "url", let url = URL(string: field.value.expose()),
                  url.scheme == "https" || url.scheme == "http" {
            Link(Self.display(url), destination: url)
                .font(KV.Typography.body)
                .foregroundStyle(KV.Colors.accentFg)
                .help(url.absoluteString)
                .lineLimit(1)
        } else {
            Text(field.value.expose())
                .font(Self.looksLikeKey(field.value.expose()) ? KV.Typography.mono : KV.Typography.body)
                .foregroundStyle(KV.Colors.fgPrimary)
                .lineLimit(multiline ? nil : 1)
                .fixedSize(horizontal: false, vertical: multiline)
        }
    }

    /// 公钥、指纹、PEM 等需要逐字核对的值用等宽字体。
    static func looksLikeKey(_ value: String) -> Bool {
        ["ssh-", "ecdsa-", "SHA256:", "MD5:", "-----BEGIN", "age1"].contains { value.hasPrefix($0) }
    }

    /// 网址的显示：主机名（含非默认端口）加路径，不显示方案与查询。
    static func display(_ url: URL) -> String {
        var host = url.host() ?? url.absoluteString
        if host.hasPrefix("www.") { host.removeFirst(4) }
        if let port = url.port { host += ":\(port)" }
        let path = url.path()
        return path.isEmpty || path == "/" ? host : host + path
    }

    /// 匹配方式（docs/architecture.md §5.3）：默认按可注册域名；IP 地址与 localhost 按主机与端口。
    static func matchMode(_ url: URL) -> String {
        let host = url.host() ?? ""
        let isIP = host.split(separator: ".").count == 4 && host.allSatisfy { $0.isNumber || $0 == "." } || host.contains(":")
        return host == "localhost" || host.hasSuffix(".localhost") || isIP ? tr("按主机与端口匹配") : tr("按域名匹配")
    }
}

/// 复制按钮：只在点击时取出明文（docs/architecture.md §4.2）；复制后提示清除倒计时（docs/ux.md §5）。
struct CopyButton: View {
    @Environment(AppModel.self) private var model
    let label: String
    /// 复制的内容所属的条目：复制时记一次使用。
    var itemId: String?
    let value: () -> String

    var body: some View {
        IconButton(
            systemImage: "doc.on.doc",
            label: tr("复制{}", "\(tr(label))"),
            help: tr("复制（{} 秒后自动清除）", "\(Int(Clipboard.clearAfter))")
        ) {
            model.copyField(label: label, value: value(), itemId: itemId)
        }
    }
}

/// 一次性密码：倒计时环、当前验证码、剩余秒数（设计稿）。到期时重新向 Rust 取码。
struct OtpRow: View {
    @Environment(AppModel.self) private var model
    let itemId: String
    let field: FieldEntry
    @ViewState private var code: OtpCodeEntry?
    @ViewState private var expiresAt = Date.distantPast
    @ViewState private var invalid = false

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let remaining = max(0, expiresAt.timeIntervalSince(context.date))
            ItemFieldRow(
                label: field.label,
                copy: code.flatMap { c in
                    invalid ? nil : { model.copyField(label: field.label, value: c.code.expose(), itemId: itemId) }
                }
            ) {
                if invalid {
                    Text(tr("配置无效，请在编辑器中检查")).font(KV.Typography.footnote).foregroundStyle(KV.Colors.statusDangerFg)
                } else if let code {
                    let seconds = Int(remaining.rounded(.up))
                    HStack(spacing: KV.Space.s2) {
                        Text(Self.grouped(code.code.expose()))
                            .font(.system(size: 16, weight: .medium, design: .monospaced))
                            .tracking(1)
                            .foregroundStyle(KV.Colors.fgPrimary)
                            .accessibilityLabel(tr("验证码 {}", "\(code.code.expose().map(String.init).joined(separator: " "))"))
                        CountdownRing(fraction: remaining / Double(code.period), seconds: seconds)
                        Text("\(seconds)")
                            .font(KV.Typography.footnote)
                            .monospacedDigit()
                            .foregroundStyle(seconds <= 5 ? KV.Colors.statusWarningFg : KV.Colors.fgSecondary)
                            .accessibilityHidden(true)
                    }
                }
            } actions: {
                if let code, !invalid {
                    CopyButton(label: field.label, itemId: itemId) { code.code.expose() }
                }
            }
            .onChange(of: context.date) { refreshIfNeeded(context.date) }
        }
        .onAppear { refreshIfNeeded(.now) }
        .onDisappear { code = nil }
    }

    private func refreshIfNeeded(_ now: Date) {
        guard code == nil || now >= expiresAt, !invalid else { return }
        guard let next = model.otpCode(itemId: itemId, fieldId: field.id) else {
            invalid = true
            return
        }
        code = next
        expiresAt = now.addingTimeInterval(Double(next.remainingMs) / 1000)
    }

    /// 每三位一组，便于读出（"123 456"、"1234 5678"）。
    static func grouped(_ code: String) -> String {
        let size = code.count == 8 ? 4 : 3
        return stride(from: 0, to: code.count, by: size).map { i in
            let start = code.index(code.startIndex, offsetBy: i)
            let end = code.index(start, offsetBy: min(size, code.count - i))
            return String(code[start..<end])
        }.joined(separator: " ")
    }
}

/// 倒计时环（18pt）。剩余时间少于 5 秒时变为警示色；秒数另以文字给出，不只靠颜色（docs/ux.md §8）。
struct CountdownRing: View {
    let fraction: Double
    let seconds: Int

    var body: some View {
        ZStack {
            Circle().stroke(KV.Colors.borderSubtle, lineWidth: 2.5)
            Circle()
                .trim(from: 0, to: max(0, min(1, fraction)))
                .stroke(seconds <= 5 ? KV.Colors.statusWarningFg : KV.Colors.accentFill, style: StrokeStyle(lineWidth: 2.5, lineCap: .round))
                .rotationEffect(.degrees(-90))
        }
        .frame(width: 18, height: 18)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(tr("还剩 {} 秒", "\(seconds)"))
    }
}

/// 键值对（环境变量等）：键为等宽粗体，值为等宽；秘密值默认隐藏，显示时整行高亮，30 秒后自动隐藏。双击一项复制它的值。
struct KvRows: View {
    @Environment(AppModel.self) private var model
    let itemId: String
    let field: FieldEntry
    let revealed: Set<String>
    let toggle: (String) -> Void
    /// 环境变量的分段视图中不显示标题行（标题在卡片外）。
    var showHeader = true

    var body: some View {
        if showHeader {
            CardRow(label: field.label) {
                Text(tr("{} 项", "\(field.kv.count)")).font(KV.Typography.footnote).foregroundStyle(KV.Colors.fgSecondary)
            } actions: {
                CopyEnvButton(field: field)
            }
            CardRowDivider()
        }
        ForEach(Array(field.kv.enumerated()), id: \.offset) { index, entry in
            if index > 0 { CardRowDivider() }
            let key = "\(field.id)/kv/\(index)"
            let shown = revealed.contains(key)
            CardRow(
                label: entry.key,
                labelFont: .system(size: 13, weight: .semibold, design: .monospaced),
                labelColor: KV.Colors.fgPrimary,
                labelWidth: 180,
                highlighted: entry.concealed && shown,
                copy: { model.copyField(label: entry.key, value: entry.value.expose(), itemId: itemId) }
            ) {
                if entry.concealed && !shown {
                    Text(String(repeating: "•", count: 10))
                        .font(KV.Typography.mono)
                        .tracking(1)
                        .foregroundStyle(KV.Colors.fgSecondary)
                        .accessibilityLabel(tr("已隐藏"))
                } else {
                    Text(entry.value.expose())
                        .font(KV.Typography.mono)
                        .foregroundStyle(KV.Colors.fgPrimary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            } actions: {
                if entry.concealed {
                    if shown {
                        Text(tr("已显示 · 30 秒后隐藏"))
                            .font(KV.Typography.caption.weight(.semibold))
                            .foregroundStyle(KV.Colors.accentFg)
                    } else {
                        OutlineBadge(text: tr("秘密"))
                    }
                    Button(shown ? tr("隐藏") : tr("显示")) { toggle(key) }.buttonStyle(.kvLink)
                }
                CopyButton(label: entry.key, itemId: itemId) { entry.value.expose() }
            }
            .contextMenu { ReferenceMenu(itemId: itemId, fieldId: field.id, kvKey: entry.key) }
        }
    }
}

/// 右键菜单："复制 keevo:// 引用"（spec/secret-refs.md §5）。引用不含秘密，可以写进代码与配置。
struct ReferenceMenu: View {
    @Environment(AppModel.self) private var model
    let itemId: String
    let fieldId: String
    var kvKey: String?
    /// 一次性密码：另外提供取当前验证码的引用。
    var otp = false

    var body: some View {
        Button(tr("复制 keevo:// 引用")) { model.copyReference(itemId: itemId, fieldId: fieldId, kvKey: kvKey) }
        if otp {
            Button(tr("复制验证码的 keevo:// 引用")) {
                model.copyReference(itemId: itemId, fieldId: fieldId, kvKey: nil, suffix: "?attribute=otp")
            }
        }
    }
}

/// 把整组键值对复制为 `.env` 格式。
struct CopyEnvButton: View {
    let field: FieldEntry

    var body: some View {
        CopyButton(label: tr("全部变量（.env 格式）")) {
            field.kv.map { "\($0.key)=\($0.value.expose())" }.joined(separator: "\n")
        }
    }
}

/// 环境变量条目（设计稿"开发者条目"）：项目等普通字段在上，各环境（分区）用分段控件切换。
struct EnvironmentView: View {
    let itemId: String
    let groups: [ItemDetailView.FieldGroup]
    let revealed: Set<String>
    let toggle: (String) -> Void
    @ViewState private var selected: String?

    private var environments: [ItemDetailView.FieldGroup] { groups.filter { $0.label != nil } }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            if let base = groups.first(where: { $0.label == nil }) {
                FieldCard(itemId: itemId, fields: base.fields, revealed: revealed, toggle: toggle) { _ in }
            }
            if !environments.isEmpty {
                let current = environments.first { $0.id == selected } ?? environments[0]
                HStack {
                    Picker(tr("环境"), selection: Binding(get: { current.id }, set: { selected = $0 })) {
                        ForEach(environments, id: \.id) { Text($0.label ?? "").tag($0.id) }
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .fixedSize()
                    Spacer()
                    if let kv = current.fields.first(where: { $0.kind == "kv_list" }) {
                        Text(tr("复制为 .env")).font(KV.Typography.footnote).foregroundStyle(KV.Colors.fgSecondary)
                        CopyEnvButton(field: kv)
                    }
                }
                KVCard {
                    ForEach(Array(current.fields.enumerated()), id: \.element.id) { index, field in
                        if index > 0 { CardRowDivider() }
                        if field.kind == "kv_list" {
                            KvRows(itemId: itemId, field: field, revealed: revealed, toggle: toggle, showHeader: false)
                        } else {
                            FieldDisplay(itemId: itemId, field: field, revealed: revealed, toggle: toggle, largeType: { _ in })
                        }
                    }
                }
            }
        }
    }
}

/// 恢复码：逐个标记已使用；剩余少于 3 个时提醒（docs/product.md §5.4）。
struct CodesRows: View {
    @Environment(AppModel.self) private var model
    let itemId: String
    let field: FieldEntry
    let revealed: Set<String>
    let toggle: (String) -> Void

    private var remaining: Int { field.codes.filter { !$0.used }.count }

    var body: some View {
        ItemFieldRow(label: field.label) {
            Text(tr("剩余 {} / {}", "\(remaining)", "\(field.codes.count)"))
                .font(KV.Typography.body)
                .foregroundStyle(remaining < 3 ? KV.Colors.statusWarningFg : KV.Colors.fgPrimary)
        } actions: {
            IconButton(
                systemImage: revealed.contains(field.id) ? "eye.slash" : "eye",
                label: revealed.contains(field.id) ? tr("隐藏") : tr("显示")
            ) { toggle(field.id) }
        }
        if remaining < 3 {
            Banner(kind: .warning, message: tr("恢复码只剩 {} 个，请到网站上重新生成", "\(remaining)"))
                .padding(.horizontal, 14)
                .padding(.bottom, 10)
        }
        ForEach(Array(field.codes.enumerated()), id: \.offset) { index, code in
            CardRowDivider()
            HStack(spacing: 10) {
                // 勾选框只标记"已使用"；代码与行的其余部分双击复制（点代码不再切换勾选，避免双击时勾两次）
                Toggle(isOn: Binding(
                    get: { code.used },
                    set: { model.setCodeUsed(itemId: itemId, field: field, index: index, used: $0) }
                )) {
                    Text(code.used ? tr("标记为未使用") : tr("标记为已使用"))
                }
                .toggleStyle(.checkbox)
                .labelsHidden()
                .help(code.used ? tr("标记为未使用") : tr("标记为已使用"))
                HStack(spacing: 10) {
                    Group {
                        if revealed.contains(field.id) {
                            Text(code.code.expose()).font(KV.Typography.mono).strikethrough(code.used)
                        } else {
                            Text(String(repeating: "•", count: 8)).font(KV.Typography.mono)
                        }
                    }
                    .foregroundStyle(code.used ? KV.Colors.fgTertiary : KV.Colors.fgPrimary)
                    if code.used {
                        Text(tr("已使用")).font(KV.Typography.caption).foregroundStyle(KV.Colors.fgTertiary)
                    }
                    Spacer()
                }
                .contentShape(Rectangle())
                .doubleClickToCopy { model.copyField(label: tr("恢复码"), value: code.code.expose(), itemId: itemId) }
                CopyButton(label: tr("恢复码"), itemId: itemId) { code.code.expose() }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 8)
        }
    }
}
