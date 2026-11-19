// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 首次使用（docs/ux.md §3.1，设计稿"macOS · 首次使用（完整流程）与主密码练习"）：
// 欢迎（三项承诺，创建或导入）→ ① 主密码（实时强度，推荐生成的口令短语）→ ② 应急包（PDF：保存或打印，勾选后继续）
// → ③ Touch ID → ④ 连接浏览器 → ⑤ 完成页三个下一步。之后第 3 天、第 7 天与每月提醒练习一次主密码。
// 应急包也可以在"设置 → 安全"中重新保存（先重新验证）。

import AppKit
import CoreImage.CIFilterBuiltins
import KeevoKit
import PDFKit
import SwiftUI

/// 首次使用的步骤。账户在"主密码"一步之后创建，之后的步骤记在偏好中：中途锁定或退出后，解锁时接着进行。
enum OnboardingStep: String {
    case welcome, password, kit, touchID, browser, done

    /// 圆点进度中的位置（欢迎页不显示）。
    var index: Int? {
        switch self {
        case .welcome: nil
        case .password: 0
        case .kit: 1
        case .touchID: 2
        case .browser: 3
        case .done: 4
        }
    }
}

// MARK: - 模型

extension AppModel {
    private static let onboardingKey = "onboarding.step"

    /// 账户创建之后、首次使用完成之前的步骤（中途锁定或退出时，解锁后接着进行）。
    var savedOnboardingStep: OnboardingStep? {
        get { UserDefaults.standard.string(forKey: Self.onboardingKey).flatMap(OnboardingStep.init(rawValue:)) }
        set { UserDefaults.standard.set(newValue?.rawValue, forKey: Self.onboardingKey) }
    }

    func goToOnboarding(_ step: OnboardingStep) {
        onboardingStep = step
        if step != .welcome, step != .password { savedOnboardingStep = step }
    }

    /// 完成首次使用。`then` 为完成页上选择的下一步。
    func finishOnboarding(then next: MainRequestAfterOnboarding? = nil) {
        onboardingStep = nil
        savedOnboardingStep = nil
        pendingSecretKey = nil
        PracticeSchedule.start()
        switch next {
        case .importData: showingImport = true
        case .browser: openSettings(page: .browser)
        case .sshAgent: openSettings(page: .developer)
        case nil: break
        }
    }

    func openSettings(page: SettingsView.Page) {
        requestedSettingsPage = page
        NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
    }
}

/// 完成页的三个下一步。
enum MainRequestAfterOnboarding { case importData, browser, sshAgent }

// MARK: - 外框

struct OnboardingFlow: View {
    @Environment(AppModel.self) private var model
    /// 主密码只在流程中短暂保留：开启 Touch ID 时还要用一次，之后清除。
    @ViewState private var password = ""

    var body: some View {
        let step = model.onboardingStep ?? .welcome
        ZStack(alignment: .top) {
            KV.Colors.bgCanvas.ignoresSafeArea()
            if let index = step.index {
                StepDots(active: index, total: 5).padding(.top, 18)
            }
            ScrollView {
                VStack(spacing: 20) {
                    switch step {
                    case .welcome: WelcomeStep()
                    case .password: PasswordStep(password: $password)
                    case .kit: KitStep()
                    case .touchID: TouchIDStep(password: $password)
                    case .browser: BrowserStep()
                    case .done: DoneStep()
                    }
                }
                .frame(width: 400)
                .padding(.top, 52)
                .padding(.bottom, 32)
                .frame(maxWidth: .infinity)
            }
        }
        .onChange(of: step) { if step == .done || step == .browser { password = "" } }
    }
}

struct StepDots: View {
    let active: Int
    let total: Int

    var body: some View {
        HStack(spacing: 6) {
            ForEach(0 ..< total, id: \.self) { i in
                Capsule()
                    .fill(i <= active ? KV.Colors.accentFill : KV.Colors.borderSubtle)
                    .frame(width: i == active ? 18 : 6, height: 6)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("第 \(active + 1) 步，共 \(total) 步")
    }
}

private struct Headline: View {
    let title: String
    let subtitle: String

    var body: some View {
        VStack(spacing: 8) {
            Text(title)
                .font(.system(size: 24, weight: .bold))
                .foregroundStyle(KV.Colors.fgPrimary)
                .accessibilityAddTraits(.isHeader)
            Text(subtitle)
                .font(KV.Typography.body)
                .foregroundStyle(KV.Colors.fgSecondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

// MARK: - 欢迎

private struct WelcomeStep: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        HeroIcon(systemImage: "key.horizontal.fill", tint: KV.Colors.fgOnAccent, background: KV.Colors.accentFill)
        Headline(title: "欢迎使用 Keevo", subtitle: "开源、只在你的设备上的密码管理器。")
        VStack(alignment: .leading, spacing: 12) {
            promise("internaldrive", "数据只保存在这台 Mac 上", "加密后存放在本机，Keevo 没有服务器。")
            promise("eye.slash", "没有人能读取，包括我们", "只有你的主密码与这台 Mac 上的账户密钥能解开它。")
            promise("chevron.left.forwardslash.chevron.right", "代码完全开源", "任何人都可以检查 Keevo 是否如实做到这些。")
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(KV.Colors.bgSurface, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        VStack(spacing: 8) {
            Button("创建新的保险库") {
                model.importAfterOnboarding = false
                model.goToOnboarding(.password)
            }
            .buttonStyle(KVButtonStyle(kind: .primary, fullWidth: true))
            .keyboardShortcut(.defaultAction)
            Button("从其他密码管理器导入") {
                // 导入需要先有保险库：设置主密码后，完成页直接打开导入
                model.importAfterOnboarding = true
                model.goToOnboarding(.password)
            }
            .buttonStyle(KVButtonStyle(kind: .secondary, fullWidth: true))
        }
        Text("加入已有账户（在多台设备间同步）将在后续版本提供。")
            .font(KV.Typography.footnote)
            .foregroundStyle(KV.Colors.fgTertiary)
    }

    private func promise(_ symbol: String, _ title: String, _ detail: String) -> some View {
        HStack(alignment: .top, spacing: KV.Space.s3) {
            Image(systemName: symbol)
                .font(.system(size: 14, weight: .medium))
                .foregroundStyle(KV.Colors.accentFg)
                .frame(width: 22)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(KV.Typography.bodyStrong).foregroundStyle(KV.Colors.fgPrimary)
                Text(detail).font(KV.Typography.footnote).foregroundStyle(KV.Colors.fgSecondary)
            }
        }
        .accessibilityElement(children: .combine)
    }
}

// MARK: - ① 主密码

/// 主密码的要求：至少 10 个字符，强度至少"一般"（不是常见密码或其简单变体）。
enum MasterPasswordRule {
    static let minLength = 10

    static func problem(_ password: String, strength: PasswordStrengthInfo?) -> String? {
        if password.count < minLength { return "至少 \(minLength) 个字符" }
        if let s = strength, s.score < 2 {
            return SecurityText.warning(s.warning, s.warningDetail).map { "太容易猜到：\($0)" } ?? "太容易猜到，换一个更长、更随机的"
        }
        return nil
    }
}

/// 强度条：四段与文字（docs/ux.md §8：颜色之外还有文字）。
struct MasterStrengthMeter: View {
    let strength: PasswordStrengthInfo?

    var body: some View {
        let (level, label, color) = strength.map { SecurityText.strengthLabel($0.score) } ?? (0, "", KV.Colors.fgTertiary)
        HStack(spacing: 6) {
            ForEach(0 ..< 4, id: \.self) { i in
                Capsule().fill(i < level ? color : KV.Colors.bgSunken).frame(height: 4)
            }
            Text(label)
                .font(KV.Typography.footnote.weight(.semibold))
                .foregroundStyle(color)
                .frame(minWidth: 28, alignment: .trailing)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(label.isEmpty ? "强度：未输入" : "强度：\(label)")
    }
}

private struct PasswordStep: View {
    @Environment(AppModel.self) private var model
    @Binding var password: String
    @ViewState private var confirm = ""
    @ViewState private var reveal = false
    /// 由生成器生成时的熵（比特）；手动输入或修改后为 nil。
    @ViewState private var generatedBits: Double?
    @ViewState private var generatedValue = ""
    @FocusState private var focus: Field?

    private enum Field { case password, confirm }

    private var strength: PasswordStrengthInfo? { password.isEmpty ? nil : passwordStrength(password: password) }
    private var problem: String? { MasterPasswordRule.problem(password, strength: strength) }
    private var canContinue: Bool { problem == nil && confirm == password && !model.busy }

    var body: some View {
        Headline(title: "设置主密码", subtitle: "它是打开保险库的唯一钥匙。建议用几个随机的词组成一句话。")
        VStack(alignment: .leading, spacing: 10) {
            LabeledInput(label: "主密码", focused: focus == .password) {
                HStack {
                    Group {
                        if reveal {
                            TextField("", text: $password)
                        } else {
                            SecureField("", text: $password)
                        }
                    }
                    .focused($focus, equals: .password)
                    .font(reveal ? KV.Typography.mono : KV.Typography.body)
                    Button { reveal.toggle() } label: {
                        Image(systemName: reveal ? "eye.slash" : "eye").foregroundStyle(KV.Colors.fgSecondary)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(reveal ? "隐藏主密码" : "显示主密码")
                }
            }
            MasterStrengthMeter(strength: strength)
            Text(detail)
                .font(KV.Typography.caption)
                .foregroundStyle(problem != nil && !password.isEmpty ? KV.Colors.statusWarningFg : KV.Colors.fgSecondary)
            Button { generate() } label: { Label("换一个生成的口令短语", systemImage: "wand.and.stars") }
                .buttonStyle(.kvLink)
            LabeledInput(label: "再输入一次", hint: confirm.isEmpty || confirm == password ? nil : "两次输入不一致", focused: focus == .confirm) {
                SecureField("", text: $confirm)
                    .focused($focus, equals: .confirm)
                    .onSubmit(create)
            }
        }
        Banner(kind: .warning, message: "忘记主密码、同时丢失应急包时，数据将无法恢复。没有人能帮你重置，包括 Keevo。")
        Button(action: create) {
            HStack(spacing: KV.Space.s2) {
                if model.busy { ProgressView().controlSize(.small).tint(.white) }
                Text(model.busy ? "正在创建保险库…" : "继续")
            }
        }
        .buttonStyle(KVButtonStyle(kind: .primary, fullWidth: true))
        .keyboardShortcut(.defaultAction)
        .disabled(!canContinue)
        HStack {
            Button("返回") { model.goToOnboarding(.welcome) }.buttonStyle(.kvLink)
        }
        ErrorText()
            .onAppear { focus = .password }
            .onChange(of: password) { if password != generatedValue { generatedBits = nil } }
    }

    private var detail: String {
        if password.isEmpty { return "至少 \(MasterPasswordRule.minLength) 个字符；推荐使用生成的口令短语。" }
        if let bits = generatedBits { return "约 \(Int(bits.rounded())) 比特熵 · 4 个随机单词" }
        if let problem { return problem }
        return "约 \(Int((strength?.bits ?? 0).rounded())) 比特熵"
    }

    private func generate() {
        guard let g = try? generatePassword(recipe: .passphrase(words: 4, separator: "-", capitalize: false, includeNumber: false)) else { return }
        generatedValue = g.value.expose()
        password = generatedValue
        generatedBits = g.entropyBits
        reveal = true
        confirm = ""
        focus = .confirm
    }

    private func create() {
        guard canContinue else { return }
        Task {
            await model.createAccount(password: password)
            if model.phase == .unlocked { model.goToOnboarding(.kit) }
        }
    }
}

// MARK: - ② 应急包

private struct KitStep: View {
    @Environment(AppModel.self) private var model
    @ViewState private var saved = false
    @ViewState private var asking = false

    var body: some View {
        Headline(title: "保存你的应急包", subtitle: "在新设备上登录、或从备份恢复时，需要主密码和账户密钥。")
        if let key = model.pendingSecretKey {
            KitPreview(secretKey: key.expose())
            KitActions(secretKey: key, accountId: model.accountId)
        } else {
            // 中途锁定或退出过：内存中的账户密钥已清除，验证后重新取出
            Banner(kind: .info, message: "为了安全，Keevo 锁定时清除了内存中的账户密钥。验证身份后重新显示。")
            Button("显示应急包…") { asking = true }
                .buttonStyle(KVButtonStyle(kind: .secondary, fullWidth: true))
        }
        VStack(alignment: .leading, spacing: 8) {
            NumberedStep(n: 1, text: "打印出来，或抄写账户密钥。")
            NumberedStep(n: 2, text: "和主密码分开存放在安全的地方。")
            NumberedStep(n: 3, text: "不要存进其他云端笔记或截图。保存的 PDF 打印后请删除。")
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        Toggle("我已妥善保存应急包", isOn: $saved)
            .toggleStyle(.checkbox)
            .font(KV.Typography.body)
            .frame(maxWidth: .infinity, alignment: .leading)
        Button("继续") { model.goToOnboarding(model.touchIDAvailable ? .touchID : .browser) }
            .buttonStyle(KVButtonStyle(kind: .primary, fullWidth: true))
            .keyboardShortcut(.defaultAction)
            .disabled(!saved || model.pendingSecretKey == nil)
            .sheet(isPresented: $asking) {
                ReverifySheet(title: "显示应急包", message: "请先确认是你本人。", confirmTitle: "显示") { password in
                    await model.revealEmergencyKit(password: password)
                }
            }
    }
}

struct NumberedStep: View {
    let n: Int
    let text: String

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: KV.Space.s2) {
            Text("\(n)")
                .font(KV.Typography.caption.weight(.semibold))
                .foregroundStyle(KV.Colors.accentFg)
                .frame(width: 18, height: 18)
                .background(KV.Colors.accentSubtle, in: Circle())
            Text(text).font(KV.Typography.body).foregroundStyle(KV.Colors.fgPrimary)
        }
    }
}

/// 应急包的预览（设计稿）：二维码、名称、内容与账户密钥。
struct KitPreview: View {
    let secretKey: String

    var body: some View {
        HStack(spacing: 14) {
            if let qr = EmergencyKit.qrImage(secretKey) {
                Image(nsImage: qr)
                    .interpolation(.none)
                    .resizable()
                    .frame(width: 64, height: 64)
                    .accessibilityHidden(true)
            }
            VStack(alignment: .leading, spacing: 4) {
                Text("Keevo 应急包 · PDF").font(KV.Typography.bodyStrong)
                Text("账户密钥、二维码、账户 ID 与主密码书写处")
                    .font(KV.Typography.footnote)
                    .foregroundStyle(KV.Colors.fgSecondary)
                // 数字与字母分色，便于抄写（docs/ux.md §5）
                classifiedText(secretKey, font: KV.Typography.mono)
                    .font(KV.Typography.mono)
                    .textSelection(.enabled)
            }
            Spacer(minLength: 0)
        }
        .padding(14)
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .strokeBorder(KV.Colors.borderControl, style: StrokeStyle(lineWidth: 1, dash: [4, 3]))
        )
    }
}

/// 保存 PDF 与打印。
struct KitActions: View {
    @Environment(AppModel.self) private var model
    let secretKey: SecretValue
    let accountId: String

    var body: some View {
        HStack(spacing: 8) {
            Button { save() } label: { Label("保存 PDF…", systemImage: "arrow.down.doc") }
                .buttonStyle(KVButtonStyle(kind: .secondary, fullWidth: true))
            Button { print() } label: { Label("打印…", systemImage: "printer") }
                .buttonStyle(KVButtonStyle(kind: .secondary, fullWidth: true))
        }
    }

    private var pdf: Data {
        EmergencyKit.pdf(secretKey: secretKey.expose(), accountId: accountId, created: Date())
    }

    private func save() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "Keevo 应急包.pdf"
        panel.allowedContentTypes = [.pdf]
        panel.message = "PDF 中有账户密钥。打印或存到 U 盘后，请删除电脑上的这份。"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try pdf.write(to: url, options: [.atomic, .completeFileProtection])
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            model.showToast("已保存应急包")
        } catch {
            model.errorMessage = "无法保存：\(error.localizedDescription)"
        }
    }

    private func print() {
        guard let doc = PDFDocument(data: pdf) else { return }
        let info = NSPrintInfo.shared.copy() as? NSPrintInfo ?? NSPrintInfo.shared
        info.jobDisposition = .spool
        guard let op = doc.printOperation(for: info, scalingMode: .pageScaleToFit, autoRotate: true) else { return }
        op.jobTitle = "Keevo 应急包"
        op.run()
    }
}

// MARK: - ③ Touch ID

private struct TouchIDStep: View {
    @Environment(AppModel.self) private var model
    @Binding var password: String

    var body: some View {
        HeroIcon(systemImage: "touchid")
        Headline(title: "用 Touch ID 解锁", subtitle: "平时用指纹解锁，不必每次输入主密码。")
        VStack(alignment: .leading, spacing: 8) {
            Text("以下情况仍需输入主密码：").font(KV.Typography.footnote.weight(.semibold))
            Group {
                Text("· Mac 重启后的第一次解锁")
                Text("· 超过 \(model.passwordIntervalDays) 天没有输入过主密码")
                Text("· 指纹有变化，或连续 3 次未能识别")
            }
            .font(KV.Typography.footnote)
            .foregroundStyle(KV.Colors.fgSecondary)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(KV.Colors.bgSurface, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        VStack(spacing: 8) {
            Button { enable() } label: { Label("开启 Touch ID", systemImage: "touchid") }
                .buttonStyle(KVButtonStyle(kind: .primary, fullWidth: true))
                .keyboardShortcut(.defaultAction)
                .disabled(model.busy || password.isEmpty)
            Button("以后再说") { model.goToOnboarding(.browser) }
                .buttonStyle(KVButtonStyle(kind: .secondary, fullWidth: true))
        }
        if password.isEmpty {
            Text("可以在「设置 → 安全」中开启。").font(KV.Typography.footnote).foregroundStyle(KV.Colors.fgSecondary)
        }
        ErrorText()
    }

    private func enable() {
        let pw = password
        Task {
            if await model.enableTouchID(password: pw) {
                password = ""
                model.goToOnboarding(.browser)
            }
        }
    }
}

// MARK: - ④ 连接浏览器

private struct BrowserStep: View {
    @Environment(AppModel.self) private var model
    @ViewState private var message: String?

    private struct Browser: Identifiable {
        let id: String
        let name: String
        let supported: Bool
    }

    private static let candidates = [
        Browser(id: "com.google.Chrome", name: "Google Chrome", supported: true),
        Browser(id: "com.microsoft.edgemac", name: "Microsoft Edge", supported: false),
        Browser(id: "com.brave.Browser", name: "Brave", supported: false),
    ]

    private var installed: [Browser] {
        Self.candidates.filter { NSWorkspace.shared.urlForApplication(withBundleIdentifier: $0.id) != nil }
    }

    var body: some View {
        HeroIcon(systemImage: "puzzlepiece.extension")
        Headline(title: "连接浏览器", subtitle: "安装 Keevo 扩展后，在网页上一键填充、保存新的登录。")
        if installed.isEmpty {
            Banner(kind: .info, message: "这台 Mac 上没有找到 Chrome。安装 Chrome 后，可以在「设置 → 浏览器」中连接。")
        } else {
            KVCard {
                ForEach(Array(installed.enumerated()), id: \.element.id) { index, b in
                    if index > 0 { CardRowDivider() }
                    row(b)
                }
            }
        }
        if let message { Banner(kind: .warning, message: message) }
        Text("扩展装好后会请求与 Keevo 配对：核对 6 个词即可。")
            .font(KV.Typography.footnote)
            .foregroundStyle(KV.Colors.fgSecondary)
        VStack(spacing: 8) {
            Button("继续") { model.goToOnboarding(.done) }
                .buttonStyle(KVButtonStyle(kind: .primary, fullWidth: true))
                .keyboardShortcut(.defaultAction)
            Button("跳过") { model.goToOnboarding(.done) }.buttonStyle(.kvLink)
        }
        // 扩展装好后会自动发起配对：每两秒刷新一次连接状态
        .task {
            while !Task.isCancelled {
                model.refreshBrowserPairings()
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }

    private func row(_ b: Browser) -> some View {
        let connected = model.browserPairings.contains { $0.browser == b.id }
        let state = !b.supported ? "已安装 · 稍后支持" : (connected ? "已安装 · 扩展已连接" : "已安装 · 扩展未连接")
        return HStack(spacing: 10) {
            Image(systemName: "globe").font(.system(size: 16)).foregroundStyle(KV.Colors.fgSecondary)
            VStack(alignment: .leading, spacing: 1) {
                Text(b.name).font(KV.Typography.bodyStrong)
                Text(state).font(KV.Typography.footnote).foregroundStyle(connected ? KV.Colors.statusSuccessFg : KV.Colors.fgSecondary)
            }
            Spacer()
            if b.supported, !connected {
                Button("安装扩展") { install() }.buttonStyle(.kvBordered)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }

    private func install() {
        do {
            try NativeHostManifest.install()
        } catch {
            message = "这个构建无法连接浏览器（需要打包后的 Keevo.app）。可以稍后在「设置 → 浏览器」中连接。"
            return
        }
        if let id = browserExtensionId(), let url = URL(string: "https://chromewebstore.google.com/detail/\(id)") {
            NSWorkspace.shared.open(url)
        }
    }
}

// MARK: - ⑤ 完成

private struct DoneStep: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        HeroIcon(systemImage: "checkmark", tint: KV.Colors.fgOnAccent, background: KV.Colors.statusSuccessFg)
        Headline(title: "一切就绪", subtitle: "保险库已经准备好。接下来可以：")
        KVCard {
            next("square.and.arrow.down", "导入其他密码管理器的数据", "1Password、Bitwarden、浏览器导出的文件", .importData)
            CardRowDivider()
            next("puzzlepiece.extension", "在浏览器中使用", "填充、保存与生成密码", .browser)
            CardRowDivider()
            next("terminal", "设置 SSH Agent", "让 ssh 与 git 使用保险库中的密钥", .sshAgent)
        }
        Button("开始使用") { model.finishOnboarding(then: model.importAfterOnboarding ? .importData : nil) }
            .buttonStyle(KVButtonStyle(kind: .primary, fullWidth: true))
            .keyboardShortcut(.defaultAction)
    }

    private func next(_ symbol: String, _ title: String, _ detail: String, _ action: MainRequestAfterOnboarding) -> some View {
        Button { model.finishOnboarding(then: action) } label: {
            HStack(spacing: 12) {
                Image(systemName: symbol)
                    .font(.system(size: 15))
                    .foregroundStyle(KV.Colors.accentFg)
                    .frame(width: 32, height: 32)
                    .background(KV.Colors.accentSubtle, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                VStack(alignment: .leading, spacing: 1) {
                    Text(title).font(KV.Typography.bodyStrong).foregroundStyle(KV.Colors.fgPrimary)
                    Text(detail).font(KV.Typography.footnote).foregroundStyle(KV.Colors.fgSecondary)
                }
                Spacer()
                Image(systemName: "chevron.right").font(.system(size: 11, weight: .semibold)).foregroundStyle(KV.Colors.fgTertiary)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 12)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

// MARK: - 应急包 PDF

enum EmergencyKit {
    /// 账户密钥的二维码（纠错等级 M）。内容只有账户密钥本身。
    static func qrImage(_ text: String, scale: CGFloat = 8) -> NSImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: scale, y: scale)) else { return nil }
        let rep = NSCIImageRep(ciImage: output)
        let image = NSImage(size: rep.size)
        image.addRepresentation(rep)
        return image
    }

    /// A4 一页的 PDF。只在内存中生成，由用户选择保存或打印。
    @MainActor
    static func pdf(secretKey: String, accountId: String, created: Date) -> Data {
        let size = CGSize(width: 595, height: 842)
        let page = KitPage(secretKey: secretKey, accountId: accountId, created: created)
            .frame(width: size.width, height: size.height)
            .environment(\.colorScheme, .light)
        let renderer = ImageRenderer(content: page)
        let data = NSMutableData()
        renderer.render { _, render in
            var box = CGRect(origin: .zero, size: size)
            guard let consumer = CGDataConsumer(data: data as CFMutableData),
                  let ctx = CGContext(consumer: consumer, mediaBox: &box, [
                      kCGPDFContextTitle as String: "Keevo 应急包",
                      kCGPDFContextCreator as String: "Keevo",
                  ] as CFDictionary)
            else { return }
            ctx.beginPDFPage(nil)
            render(ctx)
            ctx.endPDFPage()
            ctx.closePDF()
        }
        return data as Data
    }
}

/// 应急包的一页（打印用：白底黑字，不随深色模式变化）。
private struct KitPage: View {
    let secretKey: String
    let accountId: String
    let created: Date

    private let ink = Color.black
    private let gray = Color(white: 0.4)
    private let line = Color(white: 0.75)

    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            HStack(alignment: .firstTextBaseline) {
                Text("Keevo 应急包").font(.system(size: 26, weight: .bold))
                Text("Emergency Kit").font(.system(size: 14)).foregroundStyle(gray)
                Spacer()
                Text("创建于 \(created.formatted(.dateTime.year().month().day()))").font(.system(size: 11)).foregroundStyle(gray)
            }
            Text("在新设备上登录、或从备份恢复时，需要下面的账户密钥和你的主密码。打印出来，和主密码分开存放在安全的地方。Keevo 不保存它们，丢失后没有人能帮你恢复数据。")
                .font(.system(size: 12))
                .fixedSize(horizontal: false, vertical: true)
            VStack(alignment: .leading, spacing: 16) {
                // 账户密钥独占一行，绝不截断
                field("账户密钥（Secret Key）") {
                    Text(secretKey)
                        .font(.system(size: 18, weight: .semibold, design: .monospaced))
                        .lineLimit(1)
                        .fixedSize()
                }
                HStack(alignment: .bottom, spacing: 20) {
                    VStack(alignment: .leading, spacing: 14) {
                        field("账户 ID") {
                            Text(accountId).font(.system(size: 10, design: .monospaced)).foregroundStyle(gray).fixedSize()
                        }
                        Text("账户密钥中没有字母 I、L、O、U：看起来像 0 或 1 的字符都是数字。")
                            .font(.system(size: 10))
                            .foregroundStyle(gray)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer(minLength: 0)
                    if let qr = EmergencyKit.qrImage(secretKey, scale: 10) {
                        VStack(spacing: 4) {
                            Image(nsImage: qr).interpolation(.none).resizable().frame(width: 110, height: 110)
                            Text("扫描以输入账户密钥").font(.system(size: 9)).foregroundStyle(gray)
                        }
                    }
                }
            }
            .padding(18)
            .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(ink, lineWidth: 1.5))
            field("主密码（可选，自己决定是否写在这里）") {
                VStack(spacing: 26) {
                    Rectangle().fill(line).frame(height: 1)
                    Rectangle().fill(line).frame(height: 1)
                }
                .padding(.top, 22)
            }
            Text("如果把主密码写在这页纸上，请把它当作保险库本身来保管。")
                .font(.system(size: 10))
                .foregroundStyle(gray)
            VStack(alignment: .leading, spacing: 8) {
                Text("怎样保管").font(.system(size: 13, weight: .semibold))
                ForEach(Array(["打印出来，或抄写账户密钥。", "和主密码分开存放在安全的地方，例如家里的抽屉。", "不要存进其他云端笔记或截图；保存的 PDF 打印后请删除。"].enumerated()), id: \.offset) { i, s in
                    Text("\(i + 1). \(s)").font(.system(size: 11))
                }
            }
            Spacer()
            Text("Keevo · 开源、只在你的设备上的密码管理器").font(.system(size: 9)).foregroundStyle(gray)
        }
        .foregroundStyle(ink)
        .padding(48)
        .background(Color.white)
    }

    private func field(_ label: String, @ViewBuilder content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label).font(.system(size: 10, weight: .semibold)).foregroundStyle(gray)
            content()
        }
    }
}

// MARK: - 重新保存应急包（设置 → 安全）

extension AppModel {
    var accountId: String { (try? vault?.accountId()) ?? "" }

    /// 验证身份后取出账户密钥（重新保存应急包）。
    func revealEmergencyKit(password: String?) async -> Bool {
        guard let vault else { return false }
        do {
            pendingSecretKey = try await Task.detached { try vault.emergencyKitSecretKey(password: password) }.value
            errorMessage = nil
            return true
        } catch KeevoError.Cancelled {
            return false
        } catch {
            errorMessage = Self.describe(error)
            return false
        }
    }
}

/// 设置中重新保存应急包。
struct EmergencyKitSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        SheetScaffold(
            title: "应急包",
            subtitle: "在新设备上登录、或从备份恢复时，需要主密码和账户密钥。",
            systemImage: "lifepreserver",
            width: 500
        ) {
            VStack(alignment: .leading, spacing: KV.Space.s3) {
                if let key = model.pendingSecretKey {
                    KitPreview(secretKey: key.expose())
                    KitActions(secretKey: key, accountId: model.accountId)
                }
                Text("保存的 PDF 中有账户密钥：打印或存到 U 盘后，请删除电脑上的这份。")
                    .font(KV.Typography.footnote)
                    .foregroundStyle(KV.Colors.fgSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        } footer: {
            Button("完成") { dismiss() }
                .buttonStyle(.kvPrimary)
                .keyboardShortcut(.defaultAction)
        }
        .onDisappear { model.pendingSecretKey = nil }
    }
}

// MARK: - 主密码练习

/// 练习的时间表：账户创建后第 3 天、第 7 天，之后每 30 天一次。只在开启了 Touch ID 时提醒。
enum PracticeSchedule {
    private static let startKey = "practice.start"
    private static let countKey = "practice.count"
    private static let lastKey = "practice.last"
    static let offKey = "practice.off"
    private static let day: TimeInterval = 86_400

    /// 开始计时（完成首次使用时；老用户第一次运行到这里时）。
    static func start(now: Date = Date()) {
        let d = UserDefaults.standard
        if d.object(forKey: startKey) == nil { d.set(now, forKey: startKey) }
    }

    static var enabled: Bool {
        get { !UserDefaults.standard.bool(forKey: offKey) }
        set { UserDefaults.standard.set(!newValue, forKey: offKey) }
    }

    static func nextDue() -> Date? {
        let d = UserDefaults.standard
        guard let start = d.object(forKey: startKey) as? Date else { return nil }
        switch d.integer(forKey: countKey) {
        case 0: return start.addingTimeInterval(3 * day)
        case 1: return start.addingTimeInterval(7 * day)
        default: return ((d.object(forKey: lastKey) as? Date) ?? start).addingTimeInterval(30 * day)
        }
    }

    static func due(now: Date = Date()) -> Bool {
        enabled && (nextDue().map { now >= $0 } ?? false)
    }

    /// 练习过或跳过：进入下一次。
    static func record(now: Date = Date()) {
        let d = UserDefaults.standard
        d.set(d.integer(forKey: countKey) + 1, forKey: countKey)
        d.set(now, forKey: lastKey)
    }
}

extension AppModel {
    /// 解锁之后：到了练习的时间、并且平时用 Touch ID 解锁时，提醒练习一次主密码。
    func schedulePracticeReminder() {
        guard isBackground else { return }
        PracticeSchedule.start()
        guard touchIDEnabled, PracticeSchedule.due(), onboardingStep == nil else { return }
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(1.5))
            if phase == .unlocked { showingPractice = true }
        }
    }

    /// 核对主密码（只在本机核对）。
    func practice(password: String) async -> Bool {
        guard let vault else { return false }
        do {
            try await Task.detached { try vault.reverify(password: password) }.value
            errorMessage = nil
            PracticeSchedule.record()
            showToast("主密码正确")
            return true
        } catch KeevoError.WrongCredentials {
            errorMessage = "主密码不正确，再试一次。如果想不起来，请用应急包中的信息，并尽快在「设置 → 安全」中修改主密码。"
            return false
        } catch {
            errorMessage = Self.describe(error)
            return false
        }
    }
}

struct PracticeSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @ViewState private var password = ""
    @ViewState private var working = false

    var body: some View {
        SheetScaffold(
            title: "练习一次主密码",
            subtitle: "你最近一直用 Touch ID 解锁。输入一次主密码，确认自己还记得它。",
            systemImage: "key",
            width: 460
        ) {
            VStack(alignment: .leading, spacing: KV.Space.s3) {
                LabeledInput(label: "主密码", focused: true) {
                    SecureField("", text: $password).onSubmit(check)
                }
                Text("只在这台 Mac 上核对，不会保存。第 3 天、第 7 天，之后每月提醒一次。")
                    .font(KV.Typography.footnote)
                    .foregroundStyle(KV.Colors.fgSecondary)
                ErrorText()
                Button("不再提醒") {
                    PracticeSchedule.enabled = false
                    dismiss()
                }
                .buttonStyle(.kvLink)
            }
        } footer: {
            Button("跳过") {
                PracticeSchedule.record()
                dismiss()
            }
            .buttonStyle(.kvSecondary)
            .keyboardShortcut(.cancelAction)
            if working { ProgressView().controlSize(.small) }
            Button("核对", action: check)
                .buttonStyle(.kvPrimary)
                .keyboardShortcut(.defaultAction)
                .disabled(password.isEmpty || working)
        }
        .onDisappear { model.errorMessage = nil }
    }

    private func check() {
        guard !password.isEmpty, !working else { return }
        working = true
        Task {
            if await model.practice(password: password) { dismiss() }
            password = ""
            working = false
        }
    }
}
