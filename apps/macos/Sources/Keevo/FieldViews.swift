// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 详情中的字段行（docs/ux.md §2、§5）：普通字段、一次性密码（验证码与倒计时环）、键值对、恢复码。

import AppKit
import KeevoKit
import SwiftUI

/// 详情中一个字段的显示：按类型选择对应的行。
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

/// 普通字段：每行带复制按钮，秘密字段另有显示和大字显示按钮。
struct FieldRow: View {
    let field: FieldEntry
    let revealed: Bool
    let toggle: () -> Void
    let largeType: () -> Void

    var body: some View {
        LabeledContent {
            HStack(spacing: KV.Space.s2) {
                if field.concealed {
                    SecretText(secret: field.value, revealed: revealed)
                    Spacer(minLength: 0)
                    Button(revealed ? "隐藏" : "显示", action: toggle)
                        .buttonStyle(.borderless)
                    Button(action: largeType) { Image(systemName: "textformat.size") }
                        .buttonStyle(.borderless)
                        .help("大字显示")
                        .accessibilityLabel("大字显示")
                } else if field.kind == "url", let url = URL(string: field.value.expose()),
                          url.scheme == "https" || url.scheme == "http" {
                    Link(url.absoluteString, destination: url)
                        .font(KV.Typography.body)
                    Spacer(minLength: 0)
                } else {
                    Text(field.value.expose())
                        .font(field.kind == "multiline" ? KV.Typography.body : KV.Typography.body)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .trailing)
                }
                CopyButton(label: field.label) { field.value.expose() }
            }
        } label: {
            Text(field.label)
        }
    }
}

/// 复制按钮：只在点击时取出明文（docs/architecture.md §4.2）。
struct CopyButton: View {
    let label: String
    let value: () -> String

    var body: some View {
        Button { Clipboard.copy(value()) } label: { Image(systemName: "doc.on.doc") }
            .buttonStyle(.borderless)
            .help("复制（\(Int(Clipboard.clearAfter)) 秒后自动清除）")
            .accessibilityLabel("复制\(label)")
    }
}

/// 一次性密码：当前验证码与倒计时环（docs/ux.md §2"TOTP：验证码配倒计时环"）。到期时重新向 Rust 取码。
struct OtpRow: View {
    @Environment(AppModel.self) private var model
    let itemId: String
    let field: FieldEntry
    @ViewState private var code: OtpCodeEntry?
    @ViewState private var expiresAt = Date.distantPast
    @ViewState private var invalid = false

    var body: some View {
        LabeledContent {
            TimelineView(.periodic(from: .now, by: 1)) { context in
                HStack(spacing: KV.Space.s2) {
                    if invalid {
                        Text("配置无效，请在编辑器中检查").foregroundStyle(KV.Colors.statusDangerFg)
                    } else if let code {
                        let remaining = max(0, expiresAt.timeIntervalSince(context.date))
                        Text(Self.grouped(code.code.expose()))
                            .font(KV.Typography.monoLarge)
                            .textSelection(.enabled)
                            .accessibilityLabel("验证码")
                        CountdownRing(fraction: remaining / Double(code.period), seconds: Int(remaining.rounded(.up)))
                        CopyButton(label: field.label) { code.code.expose() }
                    }
                }
                .onChange(of: context.date) { refreshIfNeeded(context.date) }
            }
        } label: {
            Text(field.label)
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

/// 倒计时环。剩余时间少于 5 秒时变为警示色；同时以文字给出秒数，不只靠颜色（docs/ux.md §8）。
struct CountdownRing: View {
    let fraction: Double
    let seconds: Int

    var body: some View {
        ZStack {
            Circle().stroke(KV.Colors.borderSubtle, lineWidth: 3)
            Circle()
                .trim(from: 0, to: max(0, min(1, fraction)))
                .stroke(seconds <= 5 ? KV.Colors.statusWarningFg : KV.Colors.accentFill, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                .rotationEffect(.degrees(-90))
            Text("\(seconds)").font(KV.Typography.caption).monospacedDigit()
        }
        .frame(width: 26, height: 26)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("还剩 \(seconds) 秒")
    }
}

/// 键值对：每项一行，秘密值默认隐藏；另可整体复制为 `.env` 格式。
struct KvRows: View {
    let field: FieldEntry
    let revealed: Set<String>
    let toggle: (String) -> Void

    var body: some View {
        LabeledContent(field.label) {
            CopyButton(label: "全部（.env 格式）") {
                field.kv.map { "\($0.key)=\($0.value.expose())" }.joined(separator: "\n")
            }
            .help("复制为 .env 格式")
        }
        ForEach(Array(field.kv.enumerated()), id: \.offset) { index, entry in
            let key = "\(field.id)/kv/\(index)"
            LabeledContent {
                HStack(spacing: KV.Space.s2) {
                    if entry.concealed {
                        SecretText(secret: entry.value, revealed: revealed.contains(key))
                        Spacer(minLength: 0)
                        Button(revealed.contains(key) ? "隐藏" : "显示") { toggle(key) }
                            .buttonStyle(.borderless)
                    } else {
                        Text(entry.value.expose())
                            .font(KV.Typography.mono)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                    CopyButton(label: entry.key) { entry.value.expose() }
                }
            } label: {
                Text(entry.key).font(KV.Typography.mono).padding(.leading, KV.Space.s3)
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
        LabeledContent(field.label) {
            HStack {
                Text("剩余 \(remaining) / \(field.codes.count)")
                    .foregroundStyle(remaining < 3 ? KV.Colors.statusWarningFg : KV.Colors.fgSecondary)
                Button(revealed.contains(field.id) ? "隐藏" : "显示") { toggle(field.id) }
                    .buttonStyle(.borderless)
            }
        }
        if remaining < 3 {
            Banner(kind: .warning, message: "恢复码只剩 \(remaining) 个。请到网站上重新生成一组，并更新这里。")
        }
        ForEach(Array(field.codes.enumerated()), id: \.offset) { index, code in
            HStack(spacing: KV.Space.s2) {
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
                Text(code.used ? "已使用" : "").font(KV.Typography.caption).foregroundStyle(KV.Colors.fgTertiary)
                Spacer()
                CopyButton(label: "恢复码") { code.code.expose() }
            }
            .padding(.leading, KV.Space.s3)
        }
    }
}
