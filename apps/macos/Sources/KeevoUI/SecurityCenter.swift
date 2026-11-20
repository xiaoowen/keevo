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
            showToast(enabled ? tr("已恢复这个条目的提醒") : tr("已忽略这个条目的提醒"))
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
            breachError = tr("无法连接 Have I Been Pwned，请稍后重新检查。")
        }
        await runSecurityCheck()
    }

    /// 泄露检查共用的会话（不带 Cookie 与缓存）：所有前缀复用同一个连接，网络观察者不能按连接数数出密码个数
    /// （第五轮预审 K16）。
    nonisolated static let breachSession = URLSession(configuration: .ephemeral)

    /// 一个前缀的查询。不带 Cookie 与缓存；User-Agent 只写通用的客户端名。
    nonisolated static func fetchRange(_ prefix: String) async throws -> String {
        guard prefix.count == 5, prefix.allSatisfy(\.isHexDigit),
              let url = URL(string: "https://api.pwnedpasswords.com/range/\(prefix)")
        else { throw URLError(.badURL) }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 15)
        request.setValue("true", forHTTPHeaderField: "Add-Padding")
        request.setValue("Keevo", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await breachSession.data(for: request)
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
        case "weak": tr("弱密码")
        case "reused": tr("重复使用")
        case "breached": tr("已泄露")
        case "missing_totp": tr("未开启两步验证")
        case "expiring": tr("即将过期")
        case "insecure_url": tr("不安全的网址")
        case "outdated_ssh_key": tr("过时的 SSH 密钥")
        case "few_recovery_codes": tr("恢复码不足")
        default: check
        }
    }

    static func summary(_ check: String) -> String {
        switch check {
        case "weak": tr("容易被猜到：常见密码或其变体、过短")
        case "reused": tr("多个条目使用同一个密码")
        case "breached": tr("在已知的数据泄露中出现过")
        case "missing_totp": tr("这些网站支持一次性密码，你还没有保存")
        case "expiring": tr("30 天内过期或已过期的凭证与令牌")
        case "insecure_url": tr("保存的网址是 http://")
        case "outdated_ssh_key": tr("RSA 少于 3072 位、DSA")
        case "few_recovery_codes": tr("剩余少于 3 个")
        default: ""
        }
    }

    static func advice(_ check: String) -> String {
        switch check {
        case "weak": tr("用生成器生成随机密码或口令短语。修改后这里自动更新。")
        case "reused": tr("为每个网站使用不同的密码：一个网站泄露时，其他账户不受影响。修改后这里自动更新。")
        case "breached": tr("这些密码出现在公开的泄露数据中，攻击者会优先尝试。请尽快在对应网站修改。")
        case "missing_totp": tr("在网站的安全设置中开启两步验证，并把一次性密码保存到条目中。")
        case "expiring": tr("在服务商处续期或更换后，更新条目中的过期时间。")
        case "insecure_url": tr("确认网站是否支持 https://，支持时更新条目中的网址。")
        case "outdated_ssh_key": tr("生成新的 Ed25519 密钥，并在服务器上替换旧的公钥。")
        case "few_recovery_codes": tr("在网站上重新生成一组恢复码，并保存到条目中。")
        default: ""
        }
    }

    /// 强度的主要问题（keevo-core::strength::Warning）。
    static func warning(_ code: String?, _ detail: String?) -> String? {
        switch code {
        case "top10": tr("最常见的 10 个密码之一")
        case "top100": tr("最常见的 100 个密码之一")
        case "very_common": tr("非常常见的密码")
        case "similar_to_common": tr("常见密码 {} 的变体", "\(detail ?? "")")
        case "single_word": tr("只是一个单词")
        case "name": tr("只是一个人名或姓氏")
        case "common_name": tr("包含常见的人名或姓氏")
        case "keyboard_row": tr("键盘上相邻的一排键")
        case "keyboard_pattern": tr("较短的键盘路径")
        case "repeated_character": tr("重复的字符")
        case "repeated_pattern": tr("重复的片段")
        case "sequence": tr("像 abc、6543 这样的序列")
        case "recent_year": tr("近年的年份")
        case "date": tr("日期")
        default: nil
        }
    }

    /// 一个问题的说明（列表中的副标题）。
    static func detail(_ f: SecurityFinding) -> String {
        switch f.check {
        case "weak": warning(f.text.isEmpty ? nil : f.text, f.extra) ?? tr("容易被猜到")
        case "breached": tr("在已知泄露中出现过 {} 次", "\(f.number.formatted())")
        case "missing_totp": tr("{} 支持一次性密码", "\(f.text)")
        case "expiring": f.number < 0 ? tr("{} · 已过期 {} 天", "\(f.text)", "\(-f.number)") : (f.number == 0 ? tr("{} · 今天到期", "\(f.text)") : tr("{} · {} 天后到期", "\(f.text)", "\(f.number)"))
        case "insecure_url": f.text
        case "outdated_ssh_key": f.number > 0 ? tr("RSA {} 位", "\(f.number)") : "DSA"
        case "few_recovery_codes": tr("剩余 {} 个未使用的恢复码", "\(f.number)")
        default: f.subtitle
        }
    }

    static func strengthLabel(_ score: UInt8) -> (Int, String, Color) {
        switch score {
        case 0: (1, tr("很弱"), KV.Colors.statusDangerFg)
        case 1: (1, tr("弱"), KV.Colors.statusDangerFg)
        case 2: (2, tr("一般"), KV.Colors.statusWarningFg)
        case 3: (3, tr("强"), KV.Colors.statusSuccessFg)
        default: (4, tr("很强"), KV.Colors.statusSuccessFg)
        }
    }
}

/// 强度条（zxcvbn 的 0–4 分）：四段条、文字与颜色一起表示（docs/ux.md §8）。
struct ScoreMeter: View {
    let strength: PasswordStrengthInfo

    var body: some View {
        let (level, label, color) = SecurityText.strengthLabel(strength.score)
        let reason = SecurityText.warning(strength.warning, strength.warningDetail)
            ?? tr("约 {} 比特熵", "\(Int(strength.bits.rounded()))")
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
        .accessibilityLabel(tr("强度：{}，{}", "\(label)", "\(reason)"))
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
                    Text(tr("上次检查：{}", "\(ItemDetailView.relative(at))"))
                        .font(KV.Typography.footnote)
                        .foregroundStyle(KV.Colors.fgSecondary)
                }
                Button(tr("重新检查")) {
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
                        Text(tr("安全中心")).font(KV.Typography.largeTitle).foregroundStyle(KV.Colors.fgPrimary)
                        Text(tr("所有检查都在这台 Mac 上完成。点一项查看涉及的条目。"))
                            .font(KV.Typography.body)
                            .foregroundStyle(KV.Colors.fgSecondary)
                    }
                    if model.securityReport == nil {
                        HStack(spacing: KV.Space.s2) {
                            ProgressView().controlSize(.small)
                            Text(tr("正在检查…")).font(KV.Typography.body).foregroundStyle(KV.Colors.fgSecondary)
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
                Text(off ? (model.breachCheckEnabled ? (model.breachChecking ? tr("正在查询…") : tr("已开启。点「重新检查」查询")) : tr("没有开启。开启后在下方说明")) : SecurityText.summary(check))
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
        .accessibilityLabel(tr("{}，{}", "\(SecurityText.title(check))", "\(off ? tr("没有开启") : tr("{} 个", "\(n)"))"))
        .accessibilityAddTraits(isSelected ? .isSelected : [])
    }

    private var breachCard: some View {
        HStack(alignment: .top, spacing: KV.Space.s3) {
            Image(systemName: "globe").foregroundStyle(KV.Colors.fgSecondary).padding(.top, 2)
            VStack(alignment: .leading, spacing: 4) {
                Text(tr("检查已泄露的密码")).font(KV.Typography.bodyStrong)
                Text(tr("使用 Have I Been Pwned：只发送每个密码 SHA-1 哈希的前 5 位，在这台 Mac 上比对其余部分；密码与完整哈希不会离开 Keevo。默认关闭。"))
                    .font(KV.Typography.footnote)
                    .foregroundStyle(KV.Colors.fgSecondary)
                    .fixedSize(horizontal: false, vertical: true)
                if let error = model.breachError {
                    Text(error).font(KV.Typography.footnote).foregroundStyle(KV.Colors.statusWarningFg)
                } else if model.breachChecking {
                    Text(tr("正在查询…")).font(KV.Typography.footnote).foregroundStyle(KV.Colors.fgSecondary)
                }
            }
            Spacer(minLength: KV.Space.s3)
            Toggle("", isOn: Binding(
                get: { model.breachCheckEnabled },
                set: { on in if on { confirmingBreach = true } else { model.setBreachCheck(enabled: false) } }
            ))
            .toggleStyle(.switch)
            .labelsHidden()
            .accessibilityLabel(tr("检查已泄露的密码"))
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
                        ? tr("开启泄露检查后，这里列出出现在已知泄露中的密码。")
                        : tr("{}：没有问题。", "\(SecurityText.title(check))"))
                        .font(KV.Typography.body)
                        .foregroundStyle(KV.Colors.fgSecondary)
                }
            } else if check == "reused" {
                let groups = Dictionary(grouping: shown, by: \.group).sorted { $0.key < $1.key }
                ForEach(groups, id: \.key) { _, members in
                    GroupTitle(text: tr("重复使用 · 这 {} 个条目使用同一个密码", "\(members.count)"))
                    KVCard { rows(members) }
                }
                note(check)
            } else {
                GroupTitle(text: tr("{} · {} 个条目", "\(SecurityText.title(check))", "\(shown.count)"))
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
                    Text(f.title.isEmpty ? tr("（无标题）") : f.title).font(KV.Typography.bodyStrong)
                    Text(f.check == "reused" ? f.subtitle : SecurityText.detail(f))
                        .font(KV.Typography.footnote)
                        .foregroundStyle(KV.Colors.fgSecondary)
                        .lineLimit(1)
                }
                Spacer(minLength: KV.Space.s2)
                Button(["weak", "reused", "breached"].contains(f.check) ? tr("修改密码") : tr("打开")) {
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
            title: tr("开启泄露检查？"),
            subtitle: tr("Keevo 会联网查询 Have I Been Pwned（haveibeenpwned.com）。"),
            systemImage: "globe",
            width: 500
        ) {
            VStack(alignment: .leading, spacing: KV.Space.s3) {
                KVCard {
                    CardRow(label: tr("发送"), multiline: true) {
                        Text(tr("每个密码 SHA-1 哈希的前 5 位（k-匿名），另加随机的伪前缀")).font(KV.Typography.body).fixedSize(horizontal: false, vertical: true)
                    } actions: {}
                    CardRowDivider()
                    CardRow(label: tr("不发送")) { Text(tr("密码、完整哈希、用户名与网址")).font(KV.Typography.body) } actions: {}
                    CardRowDivider()
                    // 第五轮预审 K16：k-匿名挡不住的元数据，开启前说清楚（docs/governance.md §5）
                    CardRow(label: tr("仍会暴露"), multiline: true) {
                        Text(tr("保险库中不同密码的大致数量（以 64 个为一档），以及两次检查之间是否有密码改过"))
                            .font(KV.Typography.body)
                            .fixedSize(horizontal: false, vertical: true)
                    } actions: {}
                    CardRowDivider()
                    CardRow(label: tr("比对")) { Text(tr("在这台 Mac 上进行")).font(KV.Typography.body) } actions: {}
                    CardRowDivider()
                    CardRow(label: tr("不检查")) { Text(tr("已忽略提醒的条目")).font(KV.Typography.body) } actions: {}
                    CardRowDivider()
                    CardRow(label: tr("时机")) { Text(tr("开启时与每次「重新检查」，结果只在内存中")).font(KV.Typography.body) } actions: {}
                }
                Text(tr("这是 Keevo 少数会主动发起的网络请求之一，可以随时关闭（docs/governance.md §5）。"))
                    .font(KV.Typography.footnote)
                    .foregroundStyle(KV.Colors.fgSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        } footer: {
            Button(tr("取消")) { dismiss() }
                .buttonStyle(.kvSecondary)
                .keyboardShortcut(.cancelAction)
            Button(tr("开启")) {
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
                    GroupTitle(text: tr("安全"))
                    if info.ignored {
                        Banner(kind: .info, message: tr("已忽略这个条目的提醒：安全中心不再列出它。"))
                    }
                    KVCard { rows(info) }
                    if hasProblem || info.ignored {
                        HStack(spacing: KV.Space.s3) {
                            if hasProblem {
                                Button { edit() } label: { Label(tr("生成新密码并修改…"), systemImage: "wand.and.stars") }
                                    .buttonStyle(.kvSecondary)
                            }
                            Spacer()
                            Button(info.ignored ? tr("恢复提醒") : tr("忽略这个条目的提醒")) {
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
            CardRow(label: tr("强度")) { ScoreMeter(strength: s) } actions: {}
            CardRowDivider()
            CardRow(label: tr("重复使用")) {
                Text(info.reusedWith.isEmpty ? tr("没有") : tr("与") + info.reusedWith.map { tr("「{}」", "\($0)") }.joined() + tr("使用同一个密码"))
                    .font(KV.Typography.body)
                    .foregroundStyle(info.reusedWith.isEmpty ? KV.Colors.statusSuccessFg : KV.Colors.statusWarningFg)
            } actions: {}
            CardRowDivider()
            CardRow(label: tr("泄露")) {
                Group {
                    switch info.breachCount {
                    case nil: Text(tr("没有检查。可以在安全中心开启泄露检查。")).foregroundStyle(KV.Colors.fgSecondary)
                    case 0: Text(tr("没有在已知泄露中出现")).foregroundStyle(KV.Colors.statusSuccessFg)
                    case let n?: Text(tr("在已知泄露中出现过 {} 次，请立即修改", "\(n.formatted())")).foregroundStyle(KV.Colors.statusDangerFg)
                    }
                }
                .font(KV.Typography.body)
            } actions: {}
        }
        if info.totpDomain != nil {
            if info.strength != nil { CardRowDivider() }
            CardRow(label: tr("两步验证")) {
                Text(tr("这个网站支持一次性密码，你还没有保存。"))
                    .font(KV.Typography.body)
                    .foregroundStyle(KV.Colors.fgSecondary)
            } actions: {
                Button(tr("添加…")) { edit() }.buttonStyle(.kvLink)
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
