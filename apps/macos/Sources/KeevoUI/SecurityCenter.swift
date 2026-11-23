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

    /// 这一类检查是否开启（"检查项"中的开关）。"已泄露"就是泄露检查的开关。
    func checkEnabled(_ check: String) -> Bool {
        check == "breached" ? breachCheckEnabled : !disabledChecks.contains(check)
    }

    func setCheck(_ check: String, enabled: Bool) {
        if enabled { disabledChecks.remove(check) } else { disabledChecks.insert(check) }
    }

    /// 开启的检查发现的问题：卡片、列表与侧边栏的数字都只算这些。
    var visibleFindings: [SecurityFinding] {
        (securityReport?.findings ?? []).filter { checkEnabled($0.check) }
    }

    /// 有问题的条目数（只算开启的检查）。
    var visibleAffectedItems: Int { Set(visibleFindings.map(\.itemId)).count }

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
                    // 格式不对的响应不算查过（第五轮评审 L7）：整次检查报告失败，结果不显示为"没有泄露"
                    guard vault.recordBreachRange(prefix: prefix, body: body) else {
                        throw URLError(.cannotParseResponse)
                    }
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
        // 带填充的响应约 30–40 KB；远超这个大小的不是正常响应
        guard (response as? HTTPURLResponse)?.statusCode == 200, data.count <= 1 << 20,
              let body = String(data: data, encoding: .utf8)
        else {
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
        // 有具体问题时（如"常见密码"）跟在级别后面，否则只显示级别
        let reason = SecurityText.warning(strength.warning, strength.warningDetail)
        HStack(spacing: KV.Space.s2) {
            HStack(spacing: 3) {
                ForEach(0 ..< 4, id: \.self) { i in
                    Capsule().fill(i < level ? color : KV.Colors.borderSubtle).frame(width: 18, height: 4)
                }
            }
            Text(reason.map { "\(label) · \($0)" } ?? label)
                .font(KV.Typography.footnote.weight(.semibold))
                .foregroundStyle(color)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(reason.map { tr("强度：{}，{}", "\(label)", "\($0)") } ?? tr("强度：{}", "\(label)"))
    }
}

// MARK: - 安全中心

struct SecurityCenterView: View {
    @Environment(AppModel.self) private var model
    @ViewState private var selected: String?
    @ViewState private var confirmingBreach = false
    @ViewState private var showingChecks = false

    private var findings: [SecurityFinding] { model.visibleFindings }
    private var enabledChecks: [String] { securityChecks().filter(model.checkEnabled) }
    private var disabledCount: Int { securityChecks().count - enabledChecks.count }

    private func count(_ check: String) -> Int {
        Set(findings.filter { $0.check == check }.map(\.itemId)).count
    }

    /// 默认选中第一个有问题的检查；选中的检查被关闭后改选其他的。
    private var current: String? {
        if let selected, model.checkEnabled(selected) { return selected }
        return enabledChecks.first { count($0) > 0 } ?? enabledChecks.first
    }

    var body: some View {
        VStack(spacing: 0) {
            DetailTopBar {
                if model.securityChecking || model.breachChecking {
                    ProgressView().controlSize(.small)
                } else if let at = model.securityReport?.checkedAtMs {
                    Text(tr("{}检查过", "\(ItemDetailView.relative(at))"))
                        .font(KV.Typography.footnote)
                        .foregroundStyle(KV.Colors.fgSecondary)
                }
                Button {
                    if model.breachCheckEnabled {
                        Task { await model.runBreachCheck() }
                    } else {
                        model.scheduleSecurityCheck()
                    }
                } label: {
                    Label(tr("重新检查"), systemImage: "arrow.clockwise")
                }
                .buttonStyle(.kvToolbar)
                .disabled(model.securityChecking || model.breachChecking)
                Button { showingChecks.toggle() } label: {
                    Label(tr("检查项"), systemImage: "slider.horizontal.3")
                }
                .buttonStyle(.kvToolbar)
                .popover(isPresented: $showingChecks, arrowEdge: .bottom) {
                    SecurityChecksPopover {
                        showingChecks = false
                        confirmingBreach = true
                    }
                }
            }
            ScrollView {
                VStack(alignment: .leading, spacing: KV.Space.s4) {
                    Text(tr("安全中心")).font(KV.Typography.largeTitle).foregroundStyle(KV.Colors.fgPrimary)
                    if let error = model.breachError {
                        Banner(kind: .warning, message: error)
                    }
                    if model.securityReport == nil {
                        HStack(spacing: KV.Space.s2) {
                            ProgressView().controlSize(.small)
                            Text(tr("正在检查…")).font(KV.Typography.body).foregroundStyle(KV.Colors.fgSecondary)
                        }
                    } else {
                        LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 10), count: 4), spacing: 10) {
                            ForEach(enabledChecks, id: \.self) { check in card(check) }
                            if disabledCount > 0 { disabledTile }
                        }
                        if let current { list(current) }
                    }
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

    /// 卡片只有名称与数字，说明放在悬停提示里（设计稿）。
    private func card(_ check: String) -> some View {
        let n = count(check)
        // 泄露检查开启后还没有查询完：数字未知
        let pending = check == "breached" && !(model.securityReport?.breachChecked ?? false)
        let color = pending ? KV.Colors.fgTertiary : (n == 0 ? KV.Colors.statusSuccessFg : KV.Colors.statusWarningFg)
        let isSelected = current == check
        return Button { selected = check } label: {
            HStack(alignment: .firstTextBaseline) {
                Text(SecurityText.title(check)).font(KV.Typography.bodyStrong).foregroundStyle(KV.Colors.fgPrimary)
                Spacer(minLength: 4)
                Text(pending ? "—" : "\(n)")
                    .font(.system(size: 20, weight: .bold))
                    .foregroundStyle(color)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(isSelected ? KV.Colors.accentSubtle : KV.Colors.bgRaised, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .strokeBorder(isSelected ? KV.Colors.focusRing : KV.Colors.borderSubtle, lineWidth: isSelected ? 2 : 1)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .focusable(false)
        .help(pending ? tr("正在查询…") : SecurityText.summary(check))
        .accessibilityLabel(tr("{}，{}", "\(SecurityText.title(check))", "\(pending ? tr("正在查询") : tr("{} 个", "\(n)"))"))
        .accessibilityAddTraits(isSelected ? .isSelected : [])
    }

    /// 卡片区末尾的虚线格"已关闭 N 项"：点它打开检查项。
    private var disabledTile: some View {
        Button { showingChecks = true } label: {
            Label(tr("已关闭 {} 项", "\(disabledCount)"), systemImage: "slider.horizontal.3")
                .font(KV.Typography.body)
                .foregroundStyle(KV.Colors.fgSecondary)
                .padding(.horizontal, 14)
                .padding(.vertical, 12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .overlay(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .strokeBorder(KV.Colors.borderControl, style: StrokeStyle(lineWidth: 1, dash: [4, 3]))
                )
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .focusable(false)
    }

    @ViewBuilder
    private func list(_ check: String) -> some View {
        let shown = findings.filter { $0.check == check }
        VStack(alignment: .leading, spacing: KV.Space.s2) {
            if shown.isEmpty {
                HStack(spacing: KV.Space.s2) {
                    Image(systemName: "checkmark.circle").foregroundStyle(KV.Colors.statusSuccessFg)
                    Text(check == "breached" && !(model.securityReport?.breachChecked ?? false) ? tr("正在查询…") : tr("没有问题"))
                        .font(KV.Typography.body)
                        .foregroundStyle(KV.Colors.fgSecondary)
                }
            } else if check == "reused" {
                let groups = Dictionary(grouping: shown, by: \.group).sorted { $0.key < $1.key }
                ForEach(groups, id: \.key) { _, members in
                    GroupTitle(text: tr("这 {} 个条目使用同一个密码", "\(members.count)"))
                    KVCard { rows(members) }
                }
            } else {
                GroupTitle(text: tr("{} · {}", "\(SecurityText.title(check))", "\(shown.count)"))
                KVCard { rows(shown) }
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
                .buttonStyle(.kvToolbarAccent)
                Menu {
                    Button(tr("忽略这个条目的提醒")) { model.setSecurityAlerts(itemId: f.itemId, enabled: false) }
                } label: {
                    Image(systemName: "ellipsis").font(.system(size: 13, weight: .medium))
                }
                .menuStyle(.button)
                .buttonStyle(.kvToolbar)
                .menuIndicator(.hidden)
                .fixedSize()
                .accessibilityLabel(tr("更多操作"))
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 8)
        }
    }
}

/// "检查项"的弹出面板（设计稿）：每一类检查一个开关。打开"已泄露"即开启泄露检查，先确认会发送什么。
struct SecurityChecksPopover: View {
    @Environment(AppModel.self) private var model
    /// 打开"已泄露"：关闭面板，弹出确认。
    let requestBreach: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(tr("检查项"))
                .font(KV.Typography.bodyStrong)
                .padding(.horizontal, 16)
                .padding(.top, 12)
                .padding(.bottom, 6)
            ForEach(securityChecks(), id: \.self) { check in
                Toggle(isOn: Binding(
                    get: { model.checkEnabled(check) },
                    set: { on in
                        if check == "breached" {
                            if on { requestBreach() } else { model.setBreachCheck(enabled: false) }
                        } else {
                            model.setCheck(check, enabled: on)
                        }
                    }
                )) {
                    VStack(alignment: .leading, spacing: 1) {
                        Text(SecurityText.title(check)).font(KV.Typography.body)
                        if check == "breached" {
                            Text(tr("联网检查，只发送哈希的前 5 位"))
                                .font(KV.Typography.caption)
                                .foregroundStyle(KV.Colors.fgSecondary)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .toggleStyle(.switch)
                .controlSize(.small)
                .padding(.horizontal, 16)
                .padding(.vertical, 6)
            }
        }
        .padding(.bottom, 8)
        .frame(width: 300)
        // 否则焦点框一直停在第一个开关上
        .kvContainerFocus()
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
                Text(tr("可以随时在「检查项」中关闭"))
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

    /// 只列出开启的检查发现的问题（设计稿：强度显示在密码一行，没有问题时不显示这一区）。
    private func problems(_ info: ItemSecurity) -> [(title: String, detail: String, fix: Bool)] {
        var out: [(String, String, Bool)] = []
        if model.checkEnabled("weak"), let s = info.strength, s.score <= 2 {
            out.append((SecurityText.title("weak"), SecurityText.warning(s.warning, s.warningDetail) ?? tr("容易被猜到"), true))
        }
        if model.checkEnabled("reused"), !info.reusedWith.isEmpty {
            out.append((SecurityText.title("reused"), tr("与") + info.reusedWith.map { tr("「{}」", "\($0)") }.joined() + tr("使用同一个密码"), true))
        }
        if model.checkEnabled("breached"), let n = info.breachCount, n > 0 {
            out.append((SecurityText.title("breached"), tr("在已知泄露中出现过 {} 次", "\(n.formatted())"), true))
        }
        if model.checkEnabled("missing_totp"), let domain = info.totpDomain {
            out.append((SecurityText.title("missing_totp"), tr("{} 支持一次性密码", "\(domain)"), false))
        }
        for f in info.others where model.checkEnabled(f.check) {
            out.append((SecurityText.title(f.check), SecurityText.detail(f), false))
        }
        return out
    }

    var body: some View {
        if let info {
            let list = problems(info)
            if info.ignored {
                HStack(spacing: KV.Space.s2) {
                    Text(tr("已忽略这个条目的安全提醒"))
                        .font(KV.Typography.footnote)
                        .foregroundStyle(KV.Colors.fgSecondary)
                    Button(tr("恢复提醒")) { model.setSecurityAlerts(itemId: itemId, enabled: true) }
                        .buttonStyle(.kvLink)
                }
                .padding(.horizontal, 14)
            } else if !list.isEmpty {
                VStack(alignment: .leading, spacing: KV.Space.s2) {
                    KVCard {
                        ForEach(Array(list.enumerated()), id: \.offset) { index, p in
                            if index > 0 { CardRowDivider() }
                            ItemFieldRow(label: p.title) {
                                Text(p.detail)
                                    .font(KV.Typography.body)
                                    .foregroundStyle(KV.Colors.statusWarningFg)
                                    .fixedSize(horizontal: false, vertical: true)
                            } actions: {}
                        }
                    }
                    HStack(spacing: KV.Space.s3) {
                        if list.contains(where: \.fix) {
                            Button { edit() } label: { Label(tr("生成新密码并修改…"), systemImage: "wand.and.stars") }
                                .buttonStyle(.kvToolbarAccent)
                        } else if info.totpDomain != nil, model.checkEnabled("missing_totp") {
                            Button(tr("添加一次性密码…")) { edit() }.buttonStyle(.kvToolbarAccent)
                        }
                        Spacer()
                        Button(tr("忽略这个条目的提醒")) { model.setSecurityAlerts(itemId: itemId, enabled: false) }
                            .buttonStyle(.kvLink)
                    }
                }
            }
        }
    }
}
