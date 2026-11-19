// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 安全中心（docs/product.md §5.6，设计稿"macOS · 安全中心"）：8 项检查、条目详情的"安全"区、泄露检查。
// 检查在 Rust 中进行（keevo-core::security）；泄露检查只在用户开启后进行：Swift 只按 SHA-1 前缀查询
// Have I Been Pwned，响应交回 Rust 在本机比对，密码与完整哈希不离开 Rust。

import KeevoKit
import SwiftUI

// MARK: - 模型

extension AppModel {
    /// 稍后重新检查（数据变化、解锁之后）。重复调用只保留最后一次。
    func scheduleSecurityCheck(after delay: Duration = .zero) {
        securityTask?.cancel()
        securityTask = Task { @MainActor in
            if delay > .zero { try? await Task.sleep(for: delay) }
            guard !Task.isCancelled else { return }
            await runSecurityCheck()
        }
    }

    /// 立即检查（在后台线程中进行）。
    func runSecurityCheck() async {
        guard let vault, phase == .unlocked else { return }
        securityChecking = true
        defer { securityChecking = false }
        let report = try? await Task.detached { try vault.runSecurityCheck() }.value
        guard !Task.isCancelled, phase == .unlocked else { return }
        securityReport = report
        securityVersion &+= 1
    }

    func itemSecurity(_ itemId: String) -> ItemSecurity? {
        try? vault?.itemSecurity(itemId: itemId)
    }

    /// "忽略这个条目的提醒" / "恢复提醒"。
    func setSecurityAlerts(itemId: String, enabled: Bool) {
        guard let vault else { return }
        do {
            try vault.setSecurityAlerts(itemId: itemId, enabled: enabled)
            reloadAfterBrowserWrite()
            showToast(enabled ? "已恢复这个条目的提醒" : "已忽略这个条目的提醒")
        } catch {
            report(error)
        }
    }

    /// 开启或关闭泄露检查。开启时立即检查一次。
    func setBreachCheck(enabled: Bool) {
        breachCheckEnabled = enabled
        breachError = nil
        if enabled {
            Task { await runBreachCheck() }
        } else {
            vault?.clearBreachResults()
            scheduleSecurityCheck()
        }
    }

    /// 泄露检查：按前缀查询 Have I Been Pwned（k-匿名，带填充），在 Rust 中比对，然后重新检查。
    func runBreachCheck() async {
        guard let vault, phase == .unlocked, breachCheckEnabled, !breachChecking else { return }
        breachChecking = true
        breachError = nil
        defer { breachChecking = false }
        do {
            let prefixes = try await Task.detached { try vault.prepareBreachCheck() }.value
            try await withThrowingTaskGroup(of: (String, String).self) { group in
                var pending = prefixes[...]
                // 同时最多 4 个请求
                for _ in 0 ..< min(4, pending.count) {
                    let prefix = pending.removeFirst()
                    group.addTask { (prefix, try await Self.fetchRange(prefix)) }
                }
                while let (prefix, body) = try await group.next() {
                    _ = vault.recordBreachRange(prefix: prefix, body: body)
                    if let next = pending.first {
                        pending.removeFirst()
                        group.addTask { (next, try await Self.fetchRange(next)) }
                    }
                }
            }
        } catch {
            breachError = "无法连接 Have I Been Pwned，请稍后重新检查。"
        }
        await runSecurityCheck()
    }

    /// 一个前缀的查询。不带 Cookie 与缓存；User-Agent 只写通用的客户端名。
    nonisolated static func fetchRange(_ prefix: String) async throws -> String {
        guard prefix.count == 5, prefix.allSatisfy(\.isHexDigit),
              let url = URL(string: "https://api.pwnedpasswords.com/range/\(prefix)")
        else { throw URLError(.badURL) }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 15)
        request.setValue("true", forHTTPHeaderField: "Add-Padding")
        request.setValue("Keevo", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await URLSession(configuration: .ephemeral).data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200, let body = String(data: data, encoding: .utf8) else {
            throw URLError(.badServerResponse)
        }
        return body
    }
}

// MARK: - 文字

enum SecurityText {
    static func title(_ check: String) -> String {
        switch check {
        case "weak": "弱密码"
        case "reused": "重复使用"
        case "breached": "已泄露"
        case "missing_totp": "未开启两步验证"
        case "expiring": "即将过期"
        case "insecure_url": "不安全的网址"
        case "outdated_ssh_key": "过时的 SSH 密钥"
        case "few_recovery_codes": "恢复码不足"
        default: check
        }
    }

    static func summary(_ check: String) -> String {
        switch check {
        case "weak": "容易被猜到：常见密码或其变体、过短"
        case "reused": "多个条目使用同一个密码"
        case "breached": "在已知的数据泄露中出现过"
        case "missing_totp": "这些网站支持一次性密码，你还没有保存"
        case "expiring": "30 天内过期或已过期的凭证与令牌"
        case "insecure_url": "保存的网址是 http://"
        case "outdated_ssh_key": "RSA 少于 3072 位、DSA"
        case "few_recovery_codes": "剩余少于 3 个"
        default: ""
        }
    }

    static func advice(_ check: String) -> String {
        switch check {
        case "weak": "用生成器生成随机密码或口令短语。修改后这里自动更新。"
        case "reused": "为每个网站使用不同的密码：一个网站泄露时，其他账户不受影响。修改后这里自动更新。"
        case "breached": "这些密码出现在公开的泄露数据中，攻击者会优先尝试。请尽快在对应网站修改。"
        case "missing_totp": "在网站的安全设置中开启两步验证，并把一次性密码保存到条目中。"
        case "expiring": "在服务商处续期或更换后，更新条目中的过期时间。"
        case "insecure_url": "确认网站是否支持 https://，支持时更新条目中的网址。"
        case "outdated_ssh_key": "生成新的 Ed25519 密钥，并在服务器上替换旧的公钥。"
        case "few_recovery_codes": "在网站上重新生成一组恢复码，并保存到条目中。"
        default: ""
        }
    }

    /// 强度的主要问题（keevo-core::strength::Warning）。
    static func warning(_ code: String?, _ detail: String?) -> String? {
        switch code {
        case "top10": "最常见的 10 个密码之一"
        case "top100": "最常见的 100 个密码之一"
        case "very_common": "非常常见的密码"
        case "similar_to_common": "常见密码 \(detail ?? "") 的变体"
        case "single_word": "只是一个单词"
        case "name": "只是一个人名或姓氏"
        case "common_name": "包含常见的人名或姓氏"
        case "keyboard_row": "键盘上相邻的一排键"
        case "keyboard_pattern": "较短的键盘路径"
        case "repeated_character": "重复的字符"
        case "repeated_pattern": "重复的片段"
        case "sequence": "像 abc、6543 这样的序列"
        case "recent_year": "近年的年份"
        case "date": "日期"
        default: nil
        }
    }

    /// 一个问题的说明（列表中的副标题）。
    static func detail(_ f: SecurityFinding) -> String {
        switch f.check {
        case "weak": warning(f.text.isEmpty ? nil : f.text, f.extra) ?? "容易被猜到"
        case "breached": "在已知泄露中出现过 \(f.number.formatted()) 次"
        case "missing_totp": "\(f.text) 支持一次性密码"
        case "expiring": f.number < 0 ? "\(f.text) · 已过期 \(-f.number) 天" : (f.number == 0 ? "\(f.text) · 今天到期" : "\(f.text) · \(f.number) 天后到期")
        case "insecure_url": f.text
        case "outdated_ssh_key": f.number > 0 ? "RSA \(f.number) 位" : "DSA"
        case "few_recovery_codes": "剩余 \(f.number) 个未使用的恢复码"
        default: f.subtitle
        }
    }

    static func strengthLabel(_ score: UInt8) -> (Int, String, Color) {
        switch score {
        case 0: (1, "很弱", KV.Colors.statusDangerFg)
        case 1: (1, "弱", KV.Colors.statusDangerFg)
        case 2: (2, "一般", KV.Colors.statusWarningFg)
        case 3: (3, "强", KV.Colors.statusSuccessFg)
        default: (4, "很强", KV.Colors.statusSuccessFg)
        }
    }
}

/// 强度条（zxcvbn 的 0–4 分）：四段条、文字与颜色一起表示（docs/ux.md §8）。
struct ScoreMeter: View {
    let strength: PasswordStrengthInfo

    var body: some View {
        let (level, label, color) = SecurityText.strengthLabel(strength.score)
        let reason = SecurityText.warning(strength.warning, strength.warningDetail)
            ?? "约 \(Int(strength.bits.rounded())) 比特熵"
        HStack(spacing: KV.Space.s2) {
            HStack(spacing: 3) {
                ForEach(0 ..< 4, id: \.self) { i in
                    Capsule().fill(i < level ? color : KV.Colors.borderSubtle).frame(width: 18, height: 4)
                }
            }
            Text("\(label) · \(reason)")
                .font(KV.Typography.footnote.weight(.semibold))
                .foregroundStyle(color)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("强度：\(label)，\(reason)")
    }
}

// MARK: - 安全中心

struct SecurityCenterView: View {
    @Environment(AppModel.self) private var model
    @ViewState private var selected: String?
    @ViewState private var confirmingBreach = false

    private var findings: [SecurityFinding] { model.securityReport?.findings ?? [] }

    private func count(_ check: String) -> Int {
        Set(findings.filter { $0.check == check }.map(\.itemId)).count
    }

    /// 默认选中第一个有问题的检查。
    private var current: String {
        selected ?? securityChecks().first { count($0) > 0 } ?? "weak"
    }

    var body: some View {
        VStack(spacing: 0) {
            DetailTopBar {
                if model.securityChecking {
                    ProgressView().controlSize(.small)
                } else if let at = model.securityReport?.checkedAtMs {
                    Text("上次检查：\(ItemDetailView.relative(at))")
                        .font(KV.Typography.footnote)
                        .foregroundStyle(KV.Colors.fgSecondary)
                }
                Button("重新检查") {
                    if model.breachCheckEnabled {
                        Task { await model.runBreachCheck() }
                    } else {
                        model.scheduleSecurityCheck()
                    }
                }
                .buttonStyle(.kvBordered)
                .disabled(model.securityChecking || model.breachChecking)
            }
            ScrollView {
                VStack(alignment: .leading, spacing: KV.Space.s4) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("安全中心").font(KV.Typography.largeTitle).foregroundStyle(KV.Colors.fgPrimary)
                        Text("所有检查都在这台 Mac 上完成。点一项查看涉及的条目。")
                            .font(KV.Typography.body)
                            .foregroundStyle(KV.Colors.fgSecondary)
                    }
                    if model.securityReport == nil {
                        HStack(spacing: KV.Space.s2) {
                            ProgressView().controlSize(.small)
                            Text("正在检查…").font(KV.Typography.body).foregroundStyle(KV.Colors.fgSecondary)
                        }
                    } else {
                        LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 10), count: 4), spacing: 10) {
                            ForEach(securityChecks(), id: \.self) { check in card(check) }
                        }
                    }
                    breachCard
                    if model.securityReport != nil { list(current) }
                }
                .padding(.horizontal, 28)
                .padding(.vertical, 22)
                .frame(maxWidth: 1000, alignment: .leading)
            }
        }
        .sheet(isPresented: $confirmingBreach) {
            BreachCheckConfirmSheet { model.setBreachCheck(enabled: true) }
        }
        .onAppear { if model.securityReport == nil { model.scheduleSecurityCheck() } }
    }

    private func card(_ check: String) -> some View {
        let n = count(check)
        let off = check == "breached" && !(model.securityReport?.breachChecked ?? false)
        let color = off ? KV.Colors.fgTertiary : (n == 0 ? KV.Colors.statusSuccessFg : KV.Colors.statusWarningFg)
        let isSelected = current == check
        return Button { selected = check } label: {
            VStack(alignment: .leading, spacing: 4) {
                HStack(alignment: .firstTextBaseline) {
                    Text(SecurityText.title(check)).font(KV.Typography.bodyStrong).foregroundStyle(KV.Colors.fgPrimary)
                    Spacer(minLength: 4)
                    Text(off ? "—" : "\(n)")
                        .font(.system(size: 20, weight: .bold))
                        .foregroundStyle(color)
                }
                Text(off ? (model.breachCheckEnabled ? (model.breachChecking ? "正在查询…" : "已开启。点「重新检查」查询") : "没有开启。开启后在下方说明") : SecurityText.summary(check))
                    .font(KV.Typography.caption)
                    .foregroundStyle(KV.Colors.fgSecondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .multilineTextAlignment(.leading)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 12)
            .frame(maxWidth: .infinity, minHeight: 92, alignment: .topLeading)
            .background(KV.Colors.bgRaised, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .strokeBorder(isSelected ? KV.Colors.focusRing : KV.Colors.borderSubtle, lineWidth: isSelected ? 2 : 1)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel("\(SecurityText.title(check))，\(off ? "没有开启" : "\(n) 个")")
        .accessibilityAddTraits(isSelected ? .isSelected : [])
    }

    private var breachCard: some View {
        HStack(alignment: .top, spacing: KV.Space.s3) {
            Image(systemName: "globe").foregroundStyle(KV.Colors.fgSecondary).padding(.top, 2)
            VStack(alignment: .leading, spacing: 4) {
                Text("检查已泄露的密码").font(KV.Typography.bodyStrong)
                Text("使用 Have I Been Pwned：只发送每个密码 SHA-1 哈希的前 5 位，在这台 Mac 上比对其余部分；密码与完整哈希不会离开 Keevo。默认关闭。")
                    .font(KV.Typography.footnote)
                    .foregroundStyle(KV.Colors.fgSecondary)
                    .fixedSize(horizontal: false, vertical: true)
                if let error = model.breachError {
                    Text(error).font(KV.Typography.footnote).foregroundStyle(KV.Colors.statusWarningFg)
                } else if model.breachChecking {
                    Text("正在查询…").font(KV.Typography.footnote).foregroundStyle(KV.Colors.fgSecondary)
                }
            }
            Spacer(minLength: KV.Space.s3)
            Toggle("", isOn: Binding(
                get: { model.breachCheckEnabled },
                set: { on in if on { confirmingBreach = true } else { model.setBreachCheck(enabled: false) } }
            ))
            .toggleStyle(.switch)
            .labelsHidden()
            .accessibilityLabel("检查已泄露的密码")
        }
        .padding(14)
        .background(KV.Colors.bgSurface, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(KV.Colors.borderSubtle))
    }

    @ViewBuilder
    private func list(_ check: String) -> some View {
        let shown = findings.filter { $0.check == check }
        VStack(alignment: .leading, spacing: KV.Space.s2) {
            if shown.isEmpty {
                HStack(spacing: KV.Space.s2) {
                    Image(systemName: "checkmark.circle").foregroundStyle(KV.Colors.statusSuccessFg)
                    Text(check == "breached" && !(model.securityReport?.breachChecked ?? false)
                        ? "开启泄露检查后，这里列出出现在已知泄露中的密码。"
                        : "\(SecurityText.title(check))：没有问题。")
                        .font(KV.Typography.body)
                        .foregroundStyle(KV.Colors.fgSecondary)
                }
            } else if check == "reused" {
                let groups = Dictionary(grouping: shown, by: \.group).sorted { $0.key < $1.key }
                ForEach(groups, id: \.key) { _, members in
                    GroupTitle(text: "重复使用 · 这 \(members.count) 个条目使用同一个密码")
                    KVCard { rows(members) }
                }
                note(check)
            } else {
                GroupTitle(text: "\(SecurityText.title(check)) · \(shown.count) 个条目")
                KVCard { rows(shown) }
                note(check)
            }
        }
    }

    @ViewBuilder
    private func rows(_ list: [SecurityFinding]) -> some View {
        ForEach(Array(list.enumerated()), id: \.offset) { index, f in
            if index > 0 { CardRowDivider() }
            HStack(spacing: KV.Space.s3) {
                SiteIcon(title: f.title, url: model.items.first { $0.id == f.itemId }?.urls.first, size: 26)
                VStack(alignment: .leading, spacing: 1) {
                    Text(f.title.isEmpty ? "（无标题）" : f.title).font(KV.Typography.bodyStrong)
                    Text(f.check == "reused" ? f.subtitle : SecurityText.detail(f))
                        .font(KV.Typography.footnote)
                        .foregroundStyle(KV.Colors.fgSecondary)
                        .lineLimit(1)
                }
                Spacer(minLength: KV.Space.s2)
                Button(["weak", "reused", "breached"].contains(f.check) ? "修改密码" : "打开") {
                    model.mainRequest = ["weak", "reused", "breached"].contains(f.check) ? .editItem(f.itemId) : .showItem(f.itemId)
                }
                .buttonStyle(.kvLink)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 9)
        }
    }

    private func note(_ check: String) -> some View {
        Text(SecurityText.advice(check))
            .font(KV.Typography.footnote)
            .foregroundStyle(KV.Colors.fgSecondary)
            .fixedSize(horizontal: false, vertical: true)
    }
}

/// 开启泄露检查前的确认（设计稿）：说明会发送什么、不发送什么。
struct BreachCheckConfirmSheet: View {
    @Environment(\.dismiss) private var dismiss
    let confirm: () -> Void

    var body: some View {
        SheetScaffold(
            title: "开启泄露检查？",
            subtitle: "Keevo 会联网查询 Have I Been Pwned（haveibeenpwned.com）。",
            systemImage: "globe",
            width: 500
        ) {
            VStack(alignment: .leading, spacing: KV.Space.s3) {
                KVCard {
                    CardRow(label: "发送") { Text("每个密码 SHA-1 哈希的前 5 位（k-匿名）").font(KV.Typography.body) } actions: {}
                    CardRowDivider()
                    CardRow(label: "不发送") { Text("密码、完整哈希、用户名与网址").font(KV.Typography.body) } actions: {}
                    CardRowDivider()
                    CardRow(label: "比对") { Text("在这台 Mac 上进行").font(KV.Typography.body) } actions: {}
                    CardRowDivider()
                    CardRow(label: "时机") { Text("开启时与每次「重新检查」，结果只在内存中").font(KV.Typography.body) } actions: {}
                }
                Text("这是 Keevo 少数会主动发起的网络请求之一，可以随时关闭（docs/governance.md §5）。")
                    .font(KV.Typography.footnote)
                    .foregroundStyle(KV.Colors.fgSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        } footer: {
            Button("取消") { dismiss() }
                .buttonStyle(.kvSecondary)
                .keyboardShortcut(.cancelAction)
            Button("开启") {
                confirm()
                dismiss()
            }
            .buttonStyle(.kvPrimary)
        }
    }
}

// MARK: - 条目详情的"安全"区

struct ItemSecuritySection: View {
    @Environment(AppModel.self) private var model
    let itemId: String
    /// 由 ItemDetailView 与详情一起读取（AppModel.itemSecurity）。
    let info: ItemSecurity?
    let edit: () -> Void

    private var hasProblem: Bool {
        guard let info else { return false }
        return (info.strength.map { $0.score <= 2 } ?? false) || !info.reusedWith.isEmpty
            || (info.breachCount ?? 0) > 0 || info.totpDomain != nil || !info.others.isEmpty
    }

    var body: some View {
        Group {
            if let info, info.strength != nil || hasProblem {
                VStack(alignment: .leading, spacing: KV.Space.s2) {
                    GroupTitle(text: "安全")
                    if info.ignored {
                        Banner(kind: .info, message: "已忽略这个条目的提醒：安全中心不再列出它。")
                    }
                    KVCard { rows(info) }
                    if hasProblem || info.ignored {
                        HStack(spacing: KV.Space.s3) {
                            if hasProblem {
                                Button { edit() } label: { Label("生成新密码并修改…", systemImage: "wand.and.stars") }
                                    .buttonStyle(.kvSecondary)
                            }
                            Spacer()
                            Button(info.ignored ? "恢复提醒" : "忽略这个条目的提醒") {
                                model.setSecurityAlerts(itemId: itemId, enabled: info.ignored)
                            }
                            .buttonStyle(.kvLink)
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func rows(_ info: ItemSecurity) -> some View {
        if let s = info.strength {
            CardRow(label: "强度") { ScoreMeter(strength: s) } actions: {}
            CardRowDivider()
            CardRow(label: "重复使用") {
                Text(info.reusedWith.isEmpty ? "没有" : "与" + info.reusedWith.map { "「\($0)」" }.joined() + "使用同一个密码")
                    .font(KV.Typography.body)
                    .foregroundStyle(info.reusedWith.isEmpty ? KV.Colors.statusSuccessFg : KV.Colors.statusWarningFg)
            } actions: {}
            CardRowDivider()
            CardRow(label: "泄露") {
                Group {
                    switch info.breachCount {
                    case nil: Text("没有检查。可以在安全中心开启泄露检查。").foregroundStyle(KV.Colors.fgSecondary)
                    case 0: Text("没有在已知泄露中出现").foregroundStyle(KV.Colors.statusSuccessFg)
                    case let n?: Text("在已知泄露中出现过 \(n.formatted()) 次，请立即修改").foregroundStyle(KV.Colors.statusDangerFg)
                    }
                }
                .font(KV.Typography.body)
            } actions: {}
        }
        if info.totpDomain != nil {
            if info.strength != nil { CardRowDivider() }
            CardRow(label: "两步验证") {
                Text("这个网站支持一次性密码，你还没有保存。")
                    .font(KV.Typography.body)
                    .foregroundStyle(KV.Colors.fgSecondary)
            } actions: {
                Button("添加…") { edit() }.buttonStyle(.kvLink)
            }
        }
        ForEach(Array(info.others.enumerated()), id: \.offset) { index, f in
            if index > 0 || info.strength != nil || info.totpDomain != nil { CardRowDivider() }
            CardRow(label: SecurityText.title(f.check)) {
                Text(SecurityText.detail(f))
                    .font(KV.Typography.body)
                    .foregroundStyle(KV.Colors.statusWarningFg)
            } actions: {}
        }
    }
}
