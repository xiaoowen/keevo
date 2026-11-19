// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 详情中的字段（docs/ux.md §2、§5，设计稿"macOS · 主窗口"）：字段卡片中的一行一个字段——左侧标签、中间值、
// 右侧操作。普通字段、秘密字段、一次性密码（验证码与倒计时环）、网址、键值对、恢复码各有对应的行。

import AppKit
import KeevoKit
import SwiftUI

/// 字段卡片：一组字段，行与行之间有分隔线。
struct FieldCard: View {
    let itemId: String
    let fields: [FieldEntry]
    let revealed: Set<String>
    let toggle: (String) -> Void
    let largeType: (String) -> Void

    var body: some View {
        KVCard {
            ForEach(Array(fields.enumerated()), id: \.element.id) { index, field in
                if index > 0 { CardRowDivider() }
                FieldDisplay(itemId: itemId, field: field, revealed: revealed, toggle: toggle, largeType: largeType)
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
    let largeType: (String) -> Void

    var body: some View {
        switch field.kind {
        case "totp":
            OtpRow(itemId: itemId, field: field)
        case "kv_list":
            KvRows(field: field, revealed: revealed, toggle: toggle)
        case "recovery_codes":
            CodesRows(itemId: itemId, field: field, revealed: revealed, toggle: toggle)
        default:
            FieldRow(
                field: field,
                revealed: revealed.contains(field.id),
                toggle: { toggle(field.id) },
                largeType: { largeType(field.value.expose()) }
            )
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

/// 卡片中的一行：标签宽 92，值占满剩余宽度，操作靠右（设计稿）。
struct CardRow<Value: View, Actions: View>: View {
    let label: String
    var labelFont: Font = KV.Typography.footnote
    var labelColor: Color = KV.Colors.fgSecondary
    var labelWidth: CGFloat = 92
    var multiline = false
    var highlighted = false
    @ViewBuilder let value: Value
    @ViewBuilder let actions: Actions

    var body: some View {
        HStack(alignment: multiline ? .firstTextBaseline : .center, spacing: 10) {
            Text(label)
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
    }
}

/// 普通字段与秘密字段。
struct FieldRow: View {
    let field: FieldEntry
    let revealed: Bool
    let toggle: () -> Void
    let largeType: () -> Void

    private var multiline: Bool {
        ["multiline", "ssh_private_key"].contains(field.kind) || field.value.expose().contains("\n")
    }

    var body: some View {
        CardRow(label: field.label, multiline: multiline, highlighted: field.concealed && revealed) {
            valueView
        } actions: {
            if field.concealed {
                Button(revealed ? "隐藏" : "显示", action: toggle)
                    .buttonStyle(.kvLink)
                    .help(revealed ? "隐藏" : "显示（30 秒后自动隐藏）")
                LargeTypeButton(action: largeType)
            }
            CopyButton(label: field.label) { field.value.expose() }
        }
    }

    @ViewBuilder
    private var valueView: some View {
        if field.concealed {
            SecretText(secret: field.value, revealed: revealed, multiline: multiline)
        } else if field.kind == "url", let url = URL(string: field.value.expose()),
                  url.scheme == "https" || url.scheme == "http" {
            HStack(spacing: KV.Space.s2) {
                Link(Self.display(url), destination: url)
                    .font(KV.Typography.body)
                    .foregroundStyle(KV.Colors.accentFg)
                    .help(url.absoluteString)
                    .lineLimit(1)
                OutlineBadge(text: Self.matchMode(url))
                    .help("填充时按这个方式匹配网址（docs/architecture.md §5.3）")
            }
        } else {
            Text(field.value.expose())
                .font(Self.looksLikeKey(field.value.expose()) ? KV.Typography.mono : KV.Typography.body)
                .foregroundStyle(KV.Colors.fgPrimary)
                .textSelection(.enabled)
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
        return host == "localhost" || host.hasSuffix(".localhost") || isIP ? "按主机与端口匹配" : "按域名匹配"
    }
}

/// 复制按钮：只在点击时取出明文（docs/architecture.md §4.2）；复制后提示清除倒计时（docs/ux.md §5）。
struct CopyButton: View {
    @Environment(AppModel.self) private var model
    let label: String
    let value: () -> String

    var body: some View {
        IconButton(
            systemImage: "doc.on.doc",
            label: "复制\(label)",
            help: "复制（\(Int(Clipboard.clearAfter)) 秒后自动清除）"
        ) {
            Clipboard.copy(value())
            model.showToast("已复制\(label) · \(Int(Clipboard.clearAfter)) 秒后清除")
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
            CardRow(label: field.label) {
                if invalid {
                    Text("配置无效，请在编辑器中检查").font(KV.Typography.footnote).foregroundStyle(KV.Colors.statusDangerFg)
                } else if let code {
                    HStack(spacing: 10) {
                        CountdownRing(fraction: remaining / Double(code.period), seconds: Int(remaining.rounded(.up)))
                        Text(Self.grouped(code.code.expose()))
                            .font(.system(size: 17, weight: .medium, design: .monospaced))
                            .tracking(1)
                            .foregroundStyle(KV.Colors.fgPrimary)
                            .textSelection(.enabled)
                            .accessibilityLabel("验证码 \(code.code.expose().map(String.init).joined(separator: " "))")
                    }
                }
            } actions: {
                if let code, !invalid {
                    let seconds = Int(remaining.rounded(.up))
                    Text("\(seconds) 秒")
                        .font(KV.Typography.footnote)
                        .monospacedDigit()
                        .foregroundStyle(seconds <= 5 ? KV.Colors.statusWarningFg : KV.Colors.fgSecondary)
                        .padding(.trailing, KV.Space.s1)
                    CopyButton(label: field.label) { code.code.expose() }
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
        .accessibilityLabel("还剩 \(seconds) 秒")
    }
}

/// 键值对（环境变量等）：键为等宽粗体，值为等宽；秘密值默认隐藏，显示时整行高亮，30 秒后自动隐藏。
struct KvRows: View {
    let field: FieldEntry
    let revealed: Set<String>
    let toggle: (String) -> Void
    /// 环境变量的分段视图中不显示标题行（标题在卡片外）。
    var showHeader = true

    var body: some View {
        if showHeader {
            CardRow(label: field.label) {
                Text("\(field.kv.count) 项").font(KV.Typography.footnote).foregroundStyle(KV.Colors.fgSecondary)
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
                highlighted: entry.concealed && shown
            ) {
                if entry.concealed && !shown {
                    Text(String(repeating: "•", count: 10))
                        .font(KV.Typography.mono)
                        .tracking(1)
                        .foregroundStyle(KV.Colors.fgSecondary)
                        .accessibilityLabel("已隐藏")
                } else {
                    Text(entry.value.expose())
                        .font(KV.Typography.mono)
                        .foregroundStyle(KV.Colors.fgPrimary)
                        .textSelection(.enabled)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            } actions: {
                if entry.concealed {
                    if shown {
                        Text("已显示 · 30 秒后隐藏")
                            .font(KV.Typography.caption.weight(.semibold))
                            .foregroundStyle(KV.Colors.accentFg)
                    } else {
                        OutlineBadge(text: "秘密")
                    }
                    Button(shown ? "隐藏" : "显示") { toggle(key) }.buttonStyle(.kvLink)
                }
                CopyButton(label: entry.key) { entry.value.expose() }
            }
        }
    }
}

/// 把整组键值对复制为 `.env` 格式。
struct CopyEnvButton: View {
    let field: FieldEntry

    var body: some View {
        CopyButton(label: "全部变量（.env 格式）") {
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
                    Picker("环境", selection: Binding(get: { current.id }, set: { selected = $0 })) {
                        ForEach(environments, id: \.id) { Text($0.label ?? "").tag($0.id) }
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .fixedSize()
                    Spacer()
                    if let kv = current.fields.first(where: { $0.kind == "kv_list" }) {
                        Text("复制为 .env").font(KV.Typography.footnote).foregroundStyle(KV.Colors.fgSecondary)
                        CopyEnvButton(field: kv)
                    }
                }
                KVCard {
                    ForEach(Array(current.fields.enumerated()), id: \.element.id) { index, field in
                        if index > 0 { CardRowDivider() }
                        if field.kind == "kv_list" {
                            KvRows(field: field, revealed: revealed, toggle: toggle, showHeader: false)
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
        CardRow(label: field.label) {
            Text("剩余 \(remaining) / \(field.codes.count)")
                .font(KV.Typography.footnote)
                .foregroundStyle(remaining < 3 ? KV.Colors.statusWarningFg : KV.Colors.fgSecondary)
        } actions: {
            Button(revealed.contains(field.id) ? "隐藏" : "显示") { toggle(field.id) }.buttonStyle(.kvLink)
        }
        if remaining < 3 {
            Banner(kind: .warning, message: "恢复码只剩 \(remaining) 个。请到网站上重新生成一组，并更新这里。")
                .padding(.horizontal, 14)
                .padding(.bottom, 10)
        }
        ForEach(Array(field.codes.enumerated()), id: \.offset) { index, code in
            CardRowDivider()
            HStack(spacing: 10) {
                Toggle(isOn: Binding(
                    get: { code.used },
                    set: { model.setCodeUsed(itemId: itemId, field: field, index: index, used: $0) }
                )) {
                    Group {
                        if revealed.contains(field.id) {
                            Text(code.code.expose()).font(KV.Typography.mono).strikethrough(code.used)
                        } else {
                            Text(String(repeating: "•", count: 8)).font(KV.Typography.mono)
                        }
                    }
                    .foregroundStyle(code.used ? KV.Colors.fgTertiary : KV.Colors.fgPrimary)
                }
                .toggleStyle(.checkbox)
                .help(code.used ? "标记为未使用" : "标记为已使用")
                if code.used {
                    Text("已使用").font(KV.Typography.caption).foregroundStyle(KV.Colors.fgTertiary)
                }
                Spacer()
                CopyButton(label: "恢复码") { code.code.expose() }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 8)
        }
    }
}
