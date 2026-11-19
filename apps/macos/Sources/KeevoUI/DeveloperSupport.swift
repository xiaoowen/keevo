// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 开发者能力（spec/cli.md、spec/ssh-agent.md、spec/secret-refs.md）：命令行工具与 SSH 的原生确认界面、
// "设置 → 开发者"、条目详情中的 SSH Agent 卡片、导入私钥、写入 ~/.ssh/config、配置 Git 提交签名。

import AppKit
import KeevoKit
import SwiftUI
import UniformTypeIdentifiers

/// 谁在等待解锁（锁屏上说明）。
enum UnlockWaiter {
    case cli, ssh

    var text: String {
        switch self {
        case .cli: "命令行工具正在等待解锁。解锁后会继续执行。"
        case .ssh: "SSH 正在等待解锁。解锁后会继续连接。"
        }
    }
}

/// 一次终端会话授权（spec/cli.md §5）。
struct CliAuthorizationRequest: Identifiable {
    let id = UUID()
    let origin: RequestOrigin
    let deadline: Date
    let answer: (Bool) -> Void
}

/// 一次 SSH 签名授权（spec/ssh-agent.md §4.3）。
struct SshAuthorizationRequest: Identifiable {
    let id = UUID()
    let request: SshSignRequest
    let deadline: Date
    let answer: (Bool) -> Void
}

/// Rust 服务调用的原生确认界面：在服务的工作线程中阻塞，直到用户回答或超时。
final class DeveloperPromptBridge: DeveloperPrompt, @unchecked Sendable {
    private weak var model: AppModel?

    init(model: AppModel) {
        self.model = model
    }

    func unlockRequested(reason: String) {
        DispatchQueue.main.async { [weak self] in
            guard let model = self?.model, model.phase == .locked else { return }
            model.unlockWaiter = reason == "ssh" ? .ssh : .cli
            NSApp.activate()
            NSApp.windows.first { $0.isVisible || $0.isMiniaturized }?.makeKeyAndOrderFront(nil)
        }
    }

    func authorizeCli(origin: RequestOrigin, timeoutMs: UInt64) -> Bool {
        presentAndWait(model: model, timeoutMs: timeoutMs) { deadline, answer in
            .cli(CliAuthorizationRequest(origin: origin, deadline: deadline, answer: answer))
        }
    }

    func authorizeSsh(request: SshSignRequest, timeoutMs: UInt64) -> Bool {
        presentAndWait(model: model, timeoutMs: timeoutMs) { deadline, answer in
            .ssh(SshAuthorizationRequest(request: request, deadline: deadline, answer: answer))
        }
    }

    func sshSigned(request: SshSignRequest) {
        // 解锁期间自动签名的密钥：给出一个短暂提示，让每次使用都可见
        guard request.policy == "unlocked" else { return }
        DispatchQueue.main.async { [weak self] in
            self?.model?.showToast("已用「\(request.keyTitle)」签名（\(request.origin.app ?? request.origin.parentName)）")
        }
    }

    func lockedByCli() {
        DispatchQueue.main.async { [weak self] in
            self?.model?.lock()
        }
    }
}

// MARK: - 模型

extension AppModel {
    /// 启动命令行工具的服务；按设置开启 SSH Agent。没有从打包的应用运行时启动失败，其余功能不受影响。
    func startDeveloperServices() {
        guard isBackground, let vault else { return }
        do {
            try vault.startDeveloperServices(prompt: developerPrompt)
            developerServiceError = nil
        } catch {
            developerServiceError = Self.describe(error)
            return
        }
        if sshAgentEnabled { applySshAgent(enabled: true) }
        sshAgent = vault.sshAgentInfo()
    }

    func applySshAgent(enabled: Bool) {
        guard let vault else { return }
        do {
            sshAgent = try vault.setSshAgentEnabled(enabled: enabled)
            sshAgentError = nil
        } catch {
            sshAgentError = Self.describe(error)
            sshAgent = vault.sshAgentInfo()
        }
    }

    func refreshDeveloper() {
        guard let vault else { return }
        cliSessions = vault.cliSessions()
        sshKeys = (try? vault.sshKeys()) ?? []
        sshAgent = vault.sshAgentInfo()
    }

    func revokeCliSession(_ id: String) {
        vault?.revokeCliSession(id: id)
        refreshDeveloper()
    }

    func setSshPolicy(itemId: String, policy: String?) {
        guard let vault else { return }
        do {
            try vault.setSshAgentPolicy(itemId: itemId, policy: policy)
            reloadAfterBrowserWrite()
            refreshDeveloper()
        } catch {
            report(error)
        }
    }

    func generateSshKey(itemId: String) {
        guard let vault else { return }
        do {
            let fingerprint = try vault.generateSshKey(itemId: itemId)
            reloadAfterBrowserWrite()
            refreshDeveloper()
            showToast("已生成 Ed25519 密钥 \(fingerprint.prefix(16))…")
        } catch {
            report(error)
        }
    }

    /// 导入私钥。返回给人看的错误；成功时为 `nil`。
    func importSshKey(itemId: String, text: String) -> String? {
        guard let vault else { return "Keevo 已锁定" }
        do {
            _ = try vault.importSshPrivateKey(itemId: itemId, text: text)
            reloadAfterBrowserWrite()
            refreshDeveloper()
            return nil
        } catch KeevoError.SshKey(let code, let detail) {
            return Self.sshKeyProblem(code: code, detail: detail)
        } catch {
            return Self.describe(error)
        }
    }

    static func sshKeyProblem(code: String, detail: String = "") -> String {
        switch code {
        case "encrypted": "这把私钥有口令保护。请先在终端运行 ssh-keygen -p -f <私钥文件> 去掉口令，再导入；导入后私钥由保险库加密保存。"
        case "pem": "这是 PEM 格式的私钥。请先在终端运行 ssh-keygen -p -f <私钥文件> 转换为 OpenSSH 格式，再导入。"
        case "unsupported": "暂不支持\(detail.isEmpty ? "这种" : "「\(detail)」")算法。目前 SSH Agent 只支持 Ed25519。"
        case "missing": "还没有私钥：生成新的密钥或导入现有私钥。"
        case "multiple": "这个条目中有多个私钥字段，Agent 不知道用哪一个。请删除多余的。"
        default: "无法识别的私钥。请粘贴以 -----BEGIN OPENSSH PRIVATE KEY----- 开头的完整内容。"
        }
    }

    /// 复制字段的 `keevo://` 引用（spec/secret-refs.md §5）。引用不含秘密，按普通文本复制。
    func copyReference(itemId: String, fieldId: String, kvKey: String?, suffix: String = "") {
        guard let vault else { return }
        do {
            let reference = try vault.secretReference(itemId: itemId, fieldId: fieldId, kvKey: kvKey) + suffix
            let pb = NSPasteboard.general
            pb.clearContents()
            pb.setString(reference, forType: .string)
            showToast("已复制引用")
        } catch {
            report(error)
        }
    }

    /// 在确认界面中验证身份：Touch ID（`password` 为 `nil`）或主密码。成功时返回 `nil`，否则返回给人看的原因
    /// （用户取消时为空字符串）。
    func verifyIdentity(password: String?) async -> String? {
        guard let vault else { return "Keevo 已锁定" }
        do {
            try await Task.detached { try vault.reverify(password: password) }.value
            return nil
        } catch KeevoError.Cancelled {
            return ""
        } catch {
            return Self.describe(error)
        }
    }

    /// 应用包内的命令行工具。不是从打包的应用运行时为 `nil`。
    var bundledCliURL: URL? {
        let url = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/keevo")
        return FileManager.default.isExecutableFile(atPath: url.path) ? url : nil
    }
}

// MARK: - 确认界面

/// 身份验证：Touch ID，或者没有启用时输入主密码。
private struct IdentityCheck: View {
    @Environment(AppModel.self) private var model
    @Binding var password: String
    let error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: KV.Space.s2) {
            if !model.touchIDUsable {
                LabeledInput(label: "主密码", hint: "确认是你本人") {
                    SecureField("", text: $password)
                }
            }
            if let error, !error.isEmpty {
                Banner(kind: .danger, message: error)
            }
        }
    }
}

/// 按钮区：拒绝与允许同等样式，回车不会放行（与浏览器的确认界面一致）。
private struct AuthorizeButtons: View {
    @Environment(AppModel.self) private var model
    let password: String
    let busy: Bool
    let deny: () -> Void
    let allow: () -> Void

    var body: some View {
        Button("拒绝", action: deny)
            .buttonStyle(.kvSecondary)
            .keyboardShortcut(.cancelAction)
        Button(action: allow) {
            if model.touchIDUsable {
                Label("用 Touch ID 允许", systemImage: "touchid")
            } else {
                Text("允许")
            }
        }
        .buttonStyle(.kvSecondary)
        .disabled(busy || (!model.touchIDUsable && password.isEmpty))
    }
}

private func originRows(_ origin: RequestOrigin) -> some View {
    Group {
        if let app = origin.app {
            CardRow(label: "应用") { Text(app).font(KV.Typography.body) } actions: {}
            CardRowDivider()
        }
        CardRow(label: "命令", multiline: true) {
            Text(origin.command)
                .font(KV.Typography.mono)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        } actions: {}
        CardRowDivider()
        CardRow(label: "启动者", multiline: true) {
            Text(origin.parentCommand.map { "\(origin.parentName)（\($0)）" } ?? origin.parentName)
                .font(KV.Typography.body)
                .fixedSize(horizontal: false, vertical: true)
        } actions: {}
    }
}

/// 命令行工具的终端会话授权（spec/cli.md §5）。
struct CliAuthorizationSheet: View {
    @Environment(AppModel.self) private var model
    let request: CliAuthorizationRequest
    @ViewState private var password = ""
    @ViewState private var error: String?
    @ViewState private var busy = false

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let left = max(0, Int(request.deadline.timeIntervalSince(context.date).rounded(.up)))
            SheetScaffold(
                title: "允许命令行工具访问 Keevo？",
                subtitle: request.origin.inTerminal
                    ? "「\(request.origin.app ?? "终端")」中的一个终端会话请求读取保险库。"
                    : "「\(request.origin.app ?? request.origin.parentName)」请求读取保险库。",
                systemImage: "terminal",
                width: 520,
                note: "\(left) 秒后自动拒绝"
            ) {
                VStack(alignment: .leading, spacing: KV.Space.s3) {
                    KVCard { originRows(request.origin) }
                    Text("允许后，这个终端会话闲置 10 分钟内不再询问（最长 12 小时），锁定 Keevo 时失效，也可以在「设置 → 开发者」中撤销。如果你没有运行 keevo，请选择「拒绝」。")
                        .font(KV.Typography.footnote)
                        .foregroundStyle(KV.Colors.fgSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                    IdentityCheck(password: $password, error: error)
                }
            } footer: {
                AuthorizeButtons(password: password, busy: busy) { answer(false) } allow: { allow() }
            }
            .onChange(of: left) { if left == 0, model.browserDialog?.id == request.id { model.browserDialog = nil } }
        }
    }

    private func allow() {
        busy = true
        Task {
            let problem = await model.verifyIdentity(password: model.touchIDUsable ? nil : password)
            busy = false
            if let problem {
                error = problem
            } else {
                answer(true)
            }
        }
    }

    private func answer(_ accepted: Bool) {
        request.answer(accepted && Date() < request.deadline)
        model.browserDialog = nil
    }
}

/// SSH 签名授权（spec/ssh-agent.md §4.3）。
struct SshSignSheet: View {
    @Environment(AppModel.self) private var model
    let request: SshAuthorizationRequest
    @ViewState private var password = ""
    @ViewState private var error: String?
    @ViewState private var busy = false

    private var r: SshSignRequest { request.request }

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let left = max(0, Int(request.deadline.timeIntervalSince(context.date).rounded(.up)))
            SheetScaffold(
                title: "允许使用 SSH 密钥「\(r.keyTitle)」？",
                subtitle: "「\(r.origin.app ?? r.origin.parentName)」中的 ssh 请求用这把密钥签名。",
                systemImage: "key.horizontal",
                tint: r.forwarded ? KV.Colors.statusDangerFg : KV.Colors.accentFg,
                width: 540,
                note: "\(left) 秒后自动拒绝"
            ) {
                VStack(alignment: .leading, spacing: KV.Space.s3) {
                    if r.forwarded {
                        Banner(kind: .danger, message: "这个请求来自转发的 agent：一台远程主机正在使用你的密钥登录别处。除非你刚刚在远程主机上运行了 ssh 或 git，否则请拒绝。")
                    }
                    KVCard {
                        CardRow(label: "密钥", multiline: true) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(r.keyTitle).font(KV.Typography.bodyStrong)
                                Text(r.fingerprint).font(KV.Typography.mono).foregroundStyle(KV.Colors.fgSecondary)
                            }
                        } actions: {}
                        CardRowDivider()
                        originRows(r.origin)
                        if let host = r.hostFingerprint {
                            CardRowDivider()
                            CardRow(label: "目标主机", multiline: true) {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(host).font(KV.Typography.mono)
                                    Text(r.hostVerified ? "主机密钥已验证" : "主机密钥的算法无法验证，仅供参考")
                                        .font(KV.Typography.caption)
                                        .foregroundStyle(r.hostVerified ? KV.Colors.statusSuccessFg : KV.Colors.fgSecondary)
                                }
                            } actions: {}
                        }
                    }
                    Text(r.policy == "session" && !r.forwarded
                        ? "允许后，同一会话闲置 10 分钟内使用这把密钥不再询问，锁定时失效。"
                        : "这把密钥设置为每次使用都确认。可以在「设置 → 开发者」中修改。")
                        .font(KV.Typography.footnote)
                        .foregroundStyle(KV.Colors.fgSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                    IdentityCheck(password: $password, error: error)
                }
            } footer: {
                AuthorizeButtons(password: password, busy: busy) { answer(false) } allow: { allow() }
            }
            .onChange(of: left) { if left == 0, model.browserDialog?.id == request.id { model.browserDialog = nil } }
        }
    }

    private func allow() {
        busy = true
        Task {
            let problem = await model.verifyIdentity(password: model.touchIDUsable ? nil : password)
            busy = false
            if let problem {
                error = problem
            } else {
                answer(true)
            }
        }
    }

    private func answer(_ accepted: Bool) {
        request.answer(accepted && Date() < request.deadline)
        model.browserDialog = nil
    }
}

// MARK: - 策略

/// SSH Agent 策略的选项（spec/ssh-agent.md §4.1）。
enum AgentPolicyChoice: String, CaseIterable, Identifiable {
    case off, ask, session, unlocked
    var id: String { rawValue }

    var title: String {
        switch self {
        case .off: "不在 Agent 中提供"
        case .ask: "每次使用都确认"
        case .session: "每个会话确认一次"
        case .unlocked: "解锁期间自动使用"
        }
    }

    init(_ policy: String?) {
        self = policy.flatMap(AgentPolicyChoice.init(rawValue:)) ?? .off
    }

    var policy: String? { self == .off ? nil : rawValue }
}

private struct PolicyPicker: View {
    @Environment(AppModel.self) private var model
    let key: SshKeyInfo

    var body: some View {
        Picker("SSH Agent", selection: Binding(
            get: { AgentPolicyChoice(key.policy) },
            set: { model.setSshPolicy(itemId: key.itemId, policy: $0.policy) }
        )) {
            ForEach(AgentPolicyChoice.allCases) { Text($0.title).tag($0) }
        }
        .pickerStyle(.menu)
        .labelsHidden()
        .fixedSize()
        .disabled(key.problem != nil)
    }
}

// MARK: - 条目详情中的 SSH Agent 卡片

/// SSH 密钥条目的详情：Agent 策略、生成或导入私钥（spec/ssh-agent.md §3、§4.1）。
struct SshKeyAgentCard: View {
    @Environment(AppModel.self) private var model
    let itemId: String
    @ViewState private var importing = false
    @ViewState private var confirmRegenerate = false

    private var key: SshKeyInfo? { model.sshKeys.first { $0.itemId == itemId } }

    var body: some View {
        VStack(alignment: .leading, spacing: KV.Space.s2) {
            GroupTitle(text: "SSH Agent")
            KVCard {
                if let key {
                    CardRow(label: "使用方式") {
                        if let problem = key.problem {
                            Text(AppModel.sshKeyProblem(code: problem))
                                .font(KV.Typography.footnote)
                                .foregroundStyle(KV.Colors.statusWarningFg)
                                .fixedSize(horizontal: false, vertical: true)
                        } else {
                            PolicyPicker(key: key)
                        }
                    } actions: {}
                    if key.problem == nil, !(model.sshAgent?.running ?? false) {
                        CardRowDivider()
                        CardRow(label: "") {
                            Text("SSH Agent 没有开启。在「设置 → 开发者」中开启后，ssh 与 git 才能使用这把密钥。")
                                .font(KV.Typography.footnote)
                                .foregroundStyle(KV.Colors.fgSecondary)
                                .fixedSize(horizontal: false, vertical: true)
                        } actions: {}
                    }
                }
                CardRowDivider()
                HStack(spacing: KV.Space.s4) {
                    if key?.problem == "missing" {
                        Button { model.generateSshKey(itemId: itemId) } label: {
                            Label("生成新的 Ed25519 密钥", systemImage: "wand.and.stars")
                        }
                    } else {
                        Button { confirmRegenerate = true } label: {
                            Label("重新生成…", systemImage: "arrow.triangle.2.circlepath")
                        }
                    }
                    Button { importing = true } label: { Label("导入私钥…", systemImage: "square.and.arrow.down") }
                    if let line = key?.publicKey {
                        Button {
                            let pb = NSPasteboard.general
                            pb.clearContents()
                            pb.setString(line, forType: .string)
                            model.showToast("已复制公钥")
                        } label: { Label("复制公钥", systemImage: "doc.on.doc") }
                    }
                    Spacer(minLength: 0)
                }
                .buttonStyle(.kvLink)
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
            }
        }
        .onAppear { model.refreshDeveloper() }
        .onChange(of: model.dataVersion) { model.refreshDeveloper() }
        .sheet(isPresented: $importing) { ImportSshKeySheet(itemId: itemId) }
        .confirmationDialog("生成新的密钥替换现在的私钥？", isPresented: $confirmRegenerate) {
            Button("生成并替换", role: .destructive) { model.generateSshKey(itemId: itemId) }
            Button("取消", role: .cancel) {}
        } message: {
            Text("旧的私钥会留在这个条目的历史中。已添加了旧公钥的服务器（如 GitHub）需要换成新的公钥。")
        }
    }
}

/// 导入私钥：粘贴或从文件读取（spec/ssh-agent.md §3）。
struct ImportSshKeySheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let itemId: String
    @ViewState private var text = ""
    @ViewState private var error: String?

    var body: some View {
        SheetScaffold(
            title: "导入 SSH 私钥",
            subtitle: "粘贴私钥文件的内容（以 -----BEGIN OPENSSH PRIVATE KEY----- 开头），或从文件读取。导入后私钥由保险库加密保存，原文件可以删除。",
            systemImage: "square.and.arrow.down",
            width: 560
        ) {
            VStack(alignment: .leading, spacing: KV.Space.s3) {
                TextEditor(text: $text)
                    .font(KV.Typography.mono)
                    .frame(height: 180)
                    .scrollContentBackground(.hidden)
                    .padding(KV.Space.s2)
                    .background(KV.Colors.bgSunken, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                    .accessibilityLabel("私钥")
                Button { chooseFile() } label: { Label("从文件读取…", systemImage: "folder") }
                    .buttonStyle(.kvLink)
                if let error {
                    Banner(kind: .danger, message: error)
                }
            }
        } footer: {
            Button("取消") { dismiss() }
                .buttonStyle(.kvSecondary)
                .keyboardShortcut(.cancelAction)
            Button("导入") {
                if let problem = model.importSshKey(itemId: itemId, text: text) {
                    error = problem
                } else {
                    text = ""
                    dismiss()
                }
            }
            .buttonStyle(.kvPrimary)
            .disabled(text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
        .onDisappear { text = "" }
    }

    private func chooseFile() {
        let panel = NSOpenPanel()
        panel.showsHiddenFiles = true
        panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh")
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url,
              let data = try? Data(contentsOf: url), data.count < 64 * 1024,
              let content = String(data: data, encoding: .utf8)
        else { return }
        text = content
    }
}

// MARK: - 设置 → 开发者

struct DeveloperSettings: View {
    @Environment(AppModel.self) private var model
    @ViewState private var installMessage: String?
    @ViewState private var configuringSsh = false
    @ViewState private var configuringGit = false

    var body: some View {
        @Bindable var model = model
        VStack(alignment: .leading, spacing: KV.Space.s5) {
            SettingsSection(
                title: "命令行工具",
                footer: "keevo 不保存任何密钥，每次都向 Keevo 请求。第一次在某个终端会话中使用时，需要在 Keevo 中确认。"
            ) {
                SettingsRow(
                    title: "keevo",
                    detail: model.bundledCliURL.map { "安装后可在终端中运行 keevo read、keevo run 等命令。位于 \($0.path)" }
                        ?? "从打包的 Keevo.app 运行时可用（scripts/package-macos.sh）。"
                ) {
                    Button("安装到 ~/.local/bin") { installCli() }
                        .buttonStyle(.kvBordered)
                        .disabled(model.bundledCliURL == nil)
                }
            }
            if let installMessage {
                Banner(kind: .info, message: installMessage)
            }
            if let error = model.developerServiceError {
                Banner(kind: .warning, message: "命令行工具的服务没有启动：\(error)")
            }
            SettingsSection(title: "已授权的终端会话") {
                if model.cliSessions.isEmpty {
                    SettingsRow(title: "没有已授权的终端会话", detail: "授权在闲置 10 分钟后或锁定时失效。") { EmptyView() }
                } else {
                    ForEach(Array(model.cliSessions.enumerated()), id: \.element.id) { index, s in
                        if index > 0 { CardRowDivider() }
                        SettingsRow(
                            title: "\(s.origin.app ?? s.origin.parentName) · \(s.origin.command)",
                            detail: "授权于 \(Self.minutes(s.ageSecs)) 前 · 闲置 \(Self.minutes(s.idleSecs))"
                        ) {
                            Button("撤销") { model.revokeCliSession(s.id) }
                                .buttonStyle(.kvBordered)
                        }
                    }
                }
            }
            SettingsSection(
                title: "SSH Agent",
                footer: "开启后，ssh 与 git 可以使用保险库中的 SSH 密钥签名，私钥不离开 Keevo。只提供在下面开启了的密钥，不接受 ssh-add 添加的外部密钥。"
            ) {
                SettingsRow(
                    title: "开启 SSH Agent",
                    detail: model.sshAgent?.running == true ? model.sshAgent?.socketPath : "关闭时不监听任何 socket。"
                ) {
                    Toggle("开启 SSH Agent", isOn: Binding(
                        get: { model.sshAgentEnabled },
                        set: { on in
                            model.sshAgentEnabled = on
                            model.applySshAgent(enabled: on)
                        }
                    ))
                    .kvSwitch("开启 SSH Agent")
                    .disabled(model.developerServiceError != nil)
                }
                if model.sshAgent?.running == true {
                    CardRowDivider()
                    SettingsRow(
                        title: "SSH 配置",
                        detail: "在 ~/.ssh/config 中把 IdentityAgent 指向 \(Self.tilde(model.sshAgent?.linkPath ?? ""))"
                    ) {
                        Button("配置…") { configuringSsh = true }.buttonStyle(.kvBordered)
                    }
                    CardRowDivider()
                    SettingsRow(title: "Git 提交签名", detail: "用保险库中的 SSH 密钥签名提交（gpg.format = ssh）。") {
                        Button("配置…") { configuringGit = true }.buttonStyle(.kvBordered)
                    }
                }
            }
            if let error = model.sshAgentError {
                Banner(kind: .danger, message: "SSH Agent 无法启动：\(error)")
            }
            if let problem = model.sshAgent?.linkProblem {
                Banner(kind: .warning, message: "便捷路径没有创建：\(problem)。可以直接使用 \(model.sshAgent?.socketPath ?? "")。")
            }
            SettingsSection(title: "SSH 密钥") {
                if model.phase != .unlocked {
                    SettingsRow(title: "解锁 Keevo 之后才能查看。") { EmptyView() }
                } else if model.sshKeys.isEmpty {
                    SettingsRow(title: "还没有 SSH 密钥", detail: "新建一个「SSH 密钥」条目即可生成 Ed25519 密钥。") { EmptyView() }
                } else {
                    ForEach(Array(model.sshKeys.enumerated()), id: \.element.itemId) { index, key in
                        if index > 0 { CardRowDivider() }
                        SettingsRow(
                            title: key.title,
                            detail: key.problem.map { AppModel.sshKeyProblem(code: $0) } ?? key.fingerprint
                        ) {
                            PolicyPicker(key: key)
                        }
                    }
                }
            }
        }
        .onAppear { model.refreshDeveloper() }
        .sheet(isPresented: $configuringSsh) { SshConfigSheet() }
        .sheet(isPresented: $configuringGit) { GitSigningSheet() }
    }

    static func minutes(_ secs: UInt64) -> String {
        secs < 60 ? "不到 1 分钟" : "\(secs / 60) 分钟"
    }

    static func tilde(_ path: String) -> String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return path.hasPrefix(home) ? "~" + path.dropFirst(home.count) : path
    }

    static var localBin: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".local/bin", isDirectory: true)
    }

    /// 在 ~/.local/bin 中创建 keevo 与 keevo-ssh-sign 两个软链，指向应用包内的命令行工具。
    private func installCli() {
        guard let cli = model.bundledCliURL else { return }
        let fm = FileManager.default
        do {
            try fm.createDirectory(at: Self.localBin, withIntermediateDirectories: true)
            for name in ["keevo", "keevo-ssh-sign"] {
                let link = Self.localBin.appendingPathComponent(name)
                if let existing = try? fm.destinationOfSymbolicLink(atPath: link.path) {
                    if existing == cli.path { continue }
                    try fm.removeItem(at: link)
                } else if fm.fileExists(atPath: link.path) {
                    installMessage = "\(link.path) 已存在且不是软链，没有改动。"
                    return
                }
                try fm.createSymbolicLink(at: link, withDestinationURL: cli)
            }
            installMessage = "已安装到 ~/.local/bin。如果终端找不到 keevo，把 export PATH=\"$HOME/.local/bin:$PATH\" 加到 ~/.zshrc。"
        } catch {
            installMessage = "安装失败：\(error.localizedDescription)"
        }
    }
}

/// 写入 ~/.ssh/config：先显示改动，确认后才写入，原文件备份（docs/ux.md §3.6）。
struct SshConfigSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @ViewState private var message: String?

    private var configURL: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh/config")
    }

    private var agentPath: String { DeveloperSettings.tilde(model.sshAgent?.linkPath ?? sshAgentLinkPath()) }

    private var addition: String {
        "# Keevo SSH Agent（由 Keevo 添加）\nHost *\n  IdentityAgent \"\(agentPath)\"\n"
    }

    private var existing: String { (try? String(contentsOf: configURL, encoding: .utf8)) ?? "" }

    private var alreadyConfigured: Bool { existing.contains(agentPath) }

    var body: some View {
        SheetScaffold(
            title: "配置 ~/.ssh/config",
            subtitle: "在文件开头加入下面几行，让 ssh 经 Keevo 的 Agent 使用密钥。原文件会备份为 config.keevo-backup。",
            systemImage: "doc.badge.gearshape",
            width: 560
        ) {
            VStack(alignment: .leading, spacing: KV.Space.s3) {
                if alreadyConfigured {
                    Banner(kind: .success, message: "已经配置好了。")
                }
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(Array(addition.split(separator: "\n", omittingEmptySubsequences: false).enumerated()), id: \.offset) { _, line in
                            Text("+ \(line)")
                                .font(KV.Typography.mono)
                                .foregroundStyle(KV.Colors.statusSuccessFg)
                        }
                        ForEach(Array(existing.split(separator: "\n", omittingEmptySubsequences: false).prefix(12).enumerated()), id: \.offset) { _, line in
                            Text("  \(line)")
                                .font(KV.Typography.mono)
                                .foregroundStyle(KV.Colors.fgSecondary)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(KV.Space.s3)
                }
                .frame(height: 200)
                .background(KV.Colors.bgSunken, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                if let message {
                    Banner(kind: .danger, message: message)
                }
            }
        } footer: {
            Button("取消") { dismiss() }
                .buttonStyle(.kvSecondary)
                .keyboardShortcut(.cancelAction)
            Button("写入") { write() }
                .buttonStyle(.kvPrimary)
                .disabled(alreadyConfigured)
        }
    }

    private func write() {
        let fm = FileManager.default
        let dir = configURL.deletingLastPathComponent()
        do {
            try fm.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let old = existing
            if fm.fileExists(atPath: configURL.path) {
                let backup = dir.appendingPathComponent("config.keevo-backup")
                try? fm.removeItem(at: backup)
                try fm.copyItem(at: configURL, to: backup)
            }
            try (addition + "\n" + old).write(to: configURL, atomically: true, encoding: .utf8)
            try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: configURL.path)
            model.showToast("已写入 ~/.ssh/config")
            dismiss()
        } catch {
            message = "写入失败：\(error.localizedDescription)"
        }
    }
}

/// 配置 Git 提交签名：执行前显示将运行的命令（docs/ux.md §3.6 第 4 步）。
struct GitSigningSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @ViewState private var selected: String?
    @ViewState private var output: String?

    private var usable: [SshKeyInfo] { model.sshKeys.filter { $0.publicKey != nil && $0.policy != nil } }
    private var key: SshKeyInfo? { usable.first { $0.itemId == selected } ?? usable.first }
    private var signer: URL { DeveloperSettings.localBin.appendingPathComponent("keevo-ssh-sign") }
    private var signerInstalled: Bool { FileManager.default.isExecutableFile(atPath: signer.path) }

    private var commands: [[String]] {
        guard let key, let line = key.publicKey else { return [] }
        return [
            ["config", "--global", "gpg.format", "ssh"],
            ["config", "--global", "user.signingkey", "key::\(line)"],
            ["config", "--global", "gpg.ssh.program", signer.path],
            ["config", "--global", "commit.gpgsign", "true"],
        ]
    }

    var body: some View {
        SheetScaffold(
            title: "配置 Git 提交签名",
            subtitle: "Git 会经 Keevo 的 SSH Agent 用所选的密钥签名提交。将运行下面的命令（修改 ~/.gitconfig）。",
            systemImage: "signature",
            width: 600
        ) {
            VStack(alignment: .leading, spacing: KV.Space.s3) {
                if usable.isEmpty {
                    Banner(kind: .warning, message: "还没有在 Agent 中开启的 SSH 密钥。先在「设置 → 开发者 → SSH 密钥」中为一把密钥选择使用方式。")
                } else {
                    Picker("密钥", selection: Binding(get: { key?.itemId }, set: { selected = $0 })) {
                        ForEach(usable, id: \.itemId) { Text($0.title).tag(String?.some($0.itemId)) }
                    }
                    .pickerStyle(.menu)
                    .fixedSize()
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(Array(commands.enumerated()), id: \.offset) { _, args in
                            Text("git " + args.map { $0.contains(" ") ? "\"\($0)\"" : $0 }.joined(separator: " "))
                                .font(KV.Typography.mono)
                                .textSelection(.enabled)
                                .lineLimit(2)
                                .truncationMode(.middle)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(KV.Space.s3)
                    .background(KV.Colors.bgSunken, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                    if !signerInstalled {
                        Banner(kind: .warning, message: "还没有安装命令行工具：先在「设置 → 开发者 → 命令行工具」中安装，签名程序 keevo-ssh-sign 随之安装。")
                    }
                }
                if let output {
                    Banner(kind: .danger, message: output)
                }
            }
        } footer: {
            Button("取消") { dismiss() }
                .buttonStyle(.kvSecondary)
                .keyboardShortcut(.cancelAction)
            Button("运行") { run() }
                .buttonStyle(.kvPrimary)
                .disabled(commands.isEmpty || !signerInstalled)
        }
    }

    private func run() {
        for args in commands {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/git")
            p.arguments = args
            let err = Pipe()
            p.standardError = err
            do {
                try p.run()
                p.waitUntilExit()
            } catch {
                output = "无法运行 git：\(error.localizedDescription)"
                return
            }
            if p.terminationStatus != 0 {
                let text = String(data: err.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
                output = "git \(args.joined(separator: " ")) 失败：\(text)"
                return
            }
        }
        model.showToast("已配置 Git 提交签名")
        dismiss()
    }
}
