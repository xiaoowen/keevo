// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 浏览器扩展支持（spec/ipc.md）：Vault Service 的原生确认界面、"设置 → 浏览器"、Chrome 的 host 清单。

import AppKit
import KeevoKit
import SwiftUI

/// 一次待确认的配对（spec/ipc.md §4.2 第 5 步）。
struct PairingRequest: Identifiable {
    let id = UUID()
    let words: [SasWord]
    let name: String
    let browser: String
    let deadline: Date
    let answer: (Bool) -> Void
}

/// 一次等待授权的填充（spec/ipc.md §5.2 第 1 条）。
struct FillAuthorizationRequest: Identifiable {
    let id = UUID()
    let request: BrowserFillRequest
    let deadline: Date
    let answer: (Bool) -> Void
}

/// 一次等待确认的密码更新（spec/ipc.md §5.5）。
struct UpdateConfirmationRequest: Identifiable {
    let id = UUID()
    let request: BrowserUpdateRequest
    /// 新密码与保存的不同。
    let changed: Bool
    let deadline: Date
    let answer: (Bool) -> Void
}

/// 当前显示的确认界面。浏览器的配对、填充授权、密码更新，以及命令行工具与 SSH 的授权共用一个 sheet，逐个显示。
enum BrowserPromptItem: Identifiable {
    case pairing(PairingRequest)
    case fill(FillAuthorizationRequest)
    case update(UpdateConfirmationRequest)
    case cli(CliAuthorizationRequest)
    case ssh(SshAuthorizationRequest)

    var id: UUID {
        switch self {
        case .pairing(let r): r.id
        case .fill(let r): r.id
        case .update(let r): r.id
        case .cli(let r): r.id
        case .ssh(let r): r.id
        }
    }
}

/// 显示一个确认界面并等待回答（在服务的工作线程中调用）。同一时间只显示一个：后到的请求排队，到截止时间仍未
/// 轮到即按拒绝处理。截止时间到：关闭界面并按拒绝处理（spec/ipc.md §4.2 第 7 步、§5.2 第 1 条，spec/cli.md §5）。
func presentAndWait(
    model: AppModel?,
    timeoutMs: UInt64,
    make: (Date, @escaping (Bool) -> Void) -> BrowserPromptItem
) -> Bool {
    let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000)
    let until = DispatchTime.now() + .milliseconds(Int(min(timeoutMs, 60_000)))
    guard PromptSlot.semaphore.wait(timeout: until) == .success else { return false }
    defer { PromptSlot.semaphore.signal() }
    let answered = DispatchSemaphore(value: 0)
    let lock = NSLock()
    var result = false
    let item = make(deadline) { accepted in
        lock.withLock { result = accepted }
        answered.signal()
    }
    DispatchQueue.main.async { [weak model] in
        if case .pairing = item { model?.pairingNotice = nil }
        model?.browserDialog = item
        NSApp.activate()
    }
    guard answered.wait(timeout: until) == .success else {
        DispatchQueue.main.async { [weak model] in
            if model?.browserDialog?.id == item.id { model?.browserDialog = nil }
        }
        return false
    }
    return lock.withLock { result }
}

/// 全部确认界面共用的排队信号量。
enum PromptSlot {
    static let semaphore = DispatchSemaphore(value: 1)
}

/// 因频率限制被暂停的配对（spec/ipc.md §5.2 第 3 条）。
struct PausedPairing: Identifiable {
    let id: String
    let name: String
    let browser: String
}

/// Rust 服务调用的原生确认界面。这些方法在服务的工作线程中调用，阻塞到用户回答或超时为止；
/// 界面只出现在 Keevo.app 中，扩展与网页无法伪造（spec/ipc.md §5.2 第 4 条）。
final class BrowserPromptBridge: BrowserPrompt, @unchecked Sendable {
    private weak var model: AppModel?

    init(model: AppModel) {
        self.model = model
    }

    func pairingStarted(browser: String) {
        DispatchQueue.main.async { [weak self] in
            self?.model?.pairingNotice = browser
            NSApp.requestUserAttention(.informationalRequest)
        }
    }

    func confirmPairing(words: [SasWord], name: String, browser: String, timeoutMs: UInt64) -> Bool {
        ask(timeoutMs: timeoutMs) { deadline, answer in
            .pairing(PairingRequest(words: words, name: name, browser: browser, deadline: deadline, answer: answer))
        }
    }

    func authorizeFill(request: BrowserFillRequest, timeoutMs: UInt64) -> Bool {
        let accepted = ask(timeoutMs: timeoutMs) { deadline, answer in
            .fill(FillAuthorizationRequest(request: request, deadline: deadline, answer: answer))
        }
        if accepted {
            // 授权由 Rust 在这里返回之后写入；稍后刷新"设置 → 浏览器"的列表
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
                self?.model?.refreshBrowserPairings()
            }
        }
        return accepted
    }

    func confirmUpdate(request: BrowserUpdateRequest, changed: Bool, timeoutMs: UInt64) -> Bool {
        let accepted = ask(timeoutMs: timeoutMs) { deadline, answer in
            .update(UpdateConfirmationRequest(request: request, changed: changed, deadline: deadline, answer: answer))
        }
        if accepted {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
                self?.model?.reloadAfterBrowserWrite()
            }
        }
        return accepted
    }

    func queriesLimited(pairingId: String, name: String, browser: String) {
        DispatchQueue.main.async { [weak self] in
            self?.model?.browserWarning =
                "「\(name)」（\(browserName(browser))）在 10 分钟内查询了太多不同的网站，已暂时停止回答它的查询。如果不是你在操作，请在「设置 → 浏览器」中解除配对。"
            NSApp.requestUserAttention(.criticalRequest)
        }
    }

    func loginSaved(pairingName: String, browser: String, title: String) {
        DispatchQueue.main.async { [weak self] in
            self?.model?.browserNotice = "「\(pairingName)」（\(browserName(browser))）保存了新的登录「\(title)」。"
            self?.model?.reloadAfterBrowserWrite()
        }
    }

    func fillPaused(pairingId: String, name: String, browser: String) {
        DispatchQueue.main.async { [weak self] in
            self?.model?.pausedPairing = PausedPairing(id: pairingId, name: name, browser: browser)
            self?.model?.refreshBrowserPairings()
            NSApp.requestUserAttention(.criticalRequest)
        }
    }

    private func ask(timeoutMs: UInt64, make: (Date, @escaping (Bool) -> Void) -> BrowserPromptItem) -> Bool {
        presentAndWait(model: model, timeoutMs: timeoutMs, make: make)
    }
}

/// 浏览器确认对话框中的条目（图标、标题、用户名）。
private struct PromptItemRow: View {
    let title: String
    let username: String
    let url: String?

    var body: some View {
        HStack(spacing: KV.Space.s3) {
            SiteIcon(title: title, url: url, size: 32)
            VStack(alignment: .leading, spacing: 2) {
                Text(title.isEmpty ? "（无标题）" : title)
                    .font(KV.Typography.bodyStrong)
                    .foregroundStyle(KV.Colors.fgPrimary)
                if !username.isEmpty {
                    Text(username).font(KV.Typography.footnote).foregroundStyle(KV.Colors.fgSecondary)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .accessibilityElement(children: .combine)
    }
}

/// 配对确认：比对两边显示的短认证串（spec/ipc.md §4.2）。
/// 浏览器确认对话框都没有默认按钮、两个按钮同等样式：回车不会误放行，界面也不引导用户点"允许"。
struct PairingConfirmSheet: View {
    @Environment(AppModel.self) private var model
    let request: PairingRequest

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let left = max(0, Int(request.deadline.timeIntervalSince(context.date).rounded(.up)))
            SheetScaffold(
                title: "浏览器请求配对",
                subtitle: "「\(request.name)」（\(browserName(request.browser))）请求连接 Keevo。",
                systemImage: "puzzlepiece.extension",
                width: 500,
                note: "\(left) 秒后自动拒绝"
            ) {
                VStack(alignment: .leading, spacing: KV.Space.s3) {
                    Text("请逐个确认扩展弹窗中的 6 个词与下面完全一致，顺序也要相同。")
                        .font(KV.Typography.body)
                        .foregroundStyle(KV.Colors.fgPrimary)
                        .fixedSize(horizontal: false, vertical: true)
                    PairingCode(words: request.words)
                    Text("如果不一致，或者你没有在扩展中发起配对，请选择「不一致」。配对后，这个扩展可以在你授权的网站上取用密码。")
                        .font(KV.Typography.footnote)
                        .foregroundStyle(KV.Colors.fgSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } footer: {
                Button("不一致") { answer(false) }
                    .buttonStyle(.kvSecondary)
                    .keyboardShortcut(.cancelAction)
                Button("一致，确认配对") { answer(true) }
                    .buttonStyle(.kvSecondary)
            }
            .onChange(of: left) { if left == 0, model.browserDialog?.id == request.id { model.browserDialog = nil } }
        }
    }

    private func answer(_ accepted: Bool) {
        // 截止时间之后的确认一律按拒绝处理（Rust 端也会再检查一次）
        request.answer(accepted && Date() < request.deadline)
        model.browserDialog = nil
    }
}

/// 填充授权：某个配对第一次为某个条目在某个站点取用凭据（spec/ipc.md §5.2 第 1 条）。
/// 显示规范化后的站点、条目标题与用户名、发起请求的配对。默认按钮不是"允许"，回车不会误放行。
struct FillAuthorizationSheet: View {
    @Environment(AppModel.self) private var model
    let request: FillAuthorizationRequest

    private var r: BrowserFillRequest { request.request }

    /// 站点的主机部分，作为最醒目的一行：用户据此判断是不是自己正在访问的网站。
    private var host: String {
        r.site.split(separator: "://", maxSplits: 1).last.map(String.init) ?? r.site
    }

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let left = max(0, Int(request.deadline.timeIntervalSince(context.date).rounded(.up)))
            SheetScaffold(
                title: "允许扩展在这个网站上填充？",
                subtitle: "「\(r.pairingName)」（\(browserName(r.browser))）请求在下面这个网站上填充登录信息。",
                systemImage: "key.viewfinder",
                width: 500,
                note: "\(left) 秒后自动拒绝"
            ) {
                VStack(alignment: .leading, spacing: KV.Space.s3) {
                    KVCard {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("网站")
                                .font(KV.Typography.caption)
                                .foregroundStyle(KV.Colors.fgSecondary)
                            Text(host)
                                .font(KV.Typography.title)
                                .foregroundStyle(KV.Colors.fgPrimary)
                                .textSelection(.enabled)
                            Text(r.site)
                                .font(KV.Typography.mono)
                                .foregroundStyle(KV.Colors.fgSecondary)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 14)
                        .padding(.vertical, 12)
                        .background(KV.Colors.bgSurface)
                        .accessibilityElement(children: .combine)
                        .accessibilityLabel("网站 \(r.site)")
                        CardRowDivider()
                        PromptItemRow(title: r.title, username: r.username, url: r.site)
                    }
                    Text("这是这个扩展第一次在这个网站上使用这个条目。允许后不再询问，可在「设置 → 浏览器」中撤销。如果你没有在浏览器中点击填充，或者网站不是你正在访问的那个，请选择「拒绝」。")
                        .font(KV.Typography.footnote)
                        .foregroundStyle(KV.Colors.fgSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } footer: {
                Button("拒绝") { answer(false) }
                    .buttonStyle(.kvSecondary)
                    .keyboardShortcut(.cancelAction)
                Button("允许") { answer(true) }
                    .buttonStyle(.kvSecondary)
            }
            .onChange(of: left) { if left == 0, model.browserDialog?.id == request.id { model.browserDialog = nil } }
        }
    }

    private func answer(_ accepted: Bool) {
        request.answer(accepted && Date() < request.deadline)
        model.browserDialog = nil
    }
}

/// 密码更新：扩展请求覆盖已有登录的密码（spec/ipc.md §5.5）。每次都要确认；旧密码留在条目的历史中。
struct UpdateConfirmationSheet: View {
    @Environment(AppModel.self) private var model
    let request: UpdateConfirmationRequest

    private var r: BrowserUpdateRequest { request.request }

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let left = max(0, Int(request.deadline.timeIntervalSince(context.date).rounded(.up)))
            SheetScaffold(
                title: "更新这个登录的密码？",
                subtitle: "「\(r.pairingName)」（\(browserName(r.browser))）在 \(r.site) 上提交了新密码。",
                systemImage: "key.horizontal",
                width: 500,
                note: "\(left) 秒后自动拒绝"
            ) {
                VStack(alignment: .leading, spacing: KV.Space.s3) {
                    KVCard {
                        PromptItemRow(title: r.title, username: r.username, url: r.site)
                    }
                    if !request.changed {
                        Banner(kind: .info, message: "新密码与保存的相同，确认后不会有任何改动。")
                    }
                    Text("旧密码会保留在这个条目的历史中，可以随时恢复。如果你没有在这个网站上修改密码，请选择「不更新」。")
                        .font(KV.Typography.footnote)
                        .foregroundStyle(KV.Colors.fgSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } footer: {
                Button("不更新") { answer(false) }
                    .buttonStyle(.kvSecondary)
                    .keyboardShortcut(.cancelAction)
                Button("更新密码") { answer(true) }
                    .buttonStyle(.kvSecondary)
            }
            .onChange(of: left) { if left == 0, model.browserDialog?.id == request.id { model.browserDialog = nil } }
        }
    }

    private func answer(_ accepted: Bool) {
        request.answer(accepted && Date() < request.deadline)
        model.browserDialog = nil
    }
}

extension BrowserAuthorization {
    var key: String { itemId + "\n" + site }
}

func browserName(_ id: String) -> String {
    switch id {
    case "com.google.Chrome": "Google Chrome"
    case "com.microsoft.edgemac": "Microsoft Edge"
    case "com.brave.Browser": "Brave"
    default: id
    }
}

/// Chrome 的 native messaging host 清单（spec/ipc.md §3.2）：host 位于应用包内，只允许 Keevo 扩展连接。
enum NativeHostManifest {
    static var directory: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Google/Chrome/NativeMessagingHosts", isDirectory: true)
    }

    static var file: URL { directory.appendingPathComponent(browserHostName() + ".json") }

    /// 应用包内的 host。不是从打包的 Keevo.app 运行时为 `nil`。
    static var hostBinary: URL? {
        let url = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/keevo-native-host")
        return FileManager.default.isExecutableFile(atPath: url.path) ? url : nil
    }

    /// 已安装，且指向这个应用包里的 host。
    static var installed: Bool {
        guard let data = try? Data(contentsOf: file),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let path = json["path"] as? String
        else { return false }
        return path == hostBinary?.path
    }

    enum InstallError: Error {
        case notBundled
        case noExtensionId
    }

    static func install() throws {
        guard let host = hostBinary else { throw InstallError.notBundled }
        guard let extensionId = browserExtensionId() else { throw InstallError.noExtensionId }
        let manifest: [String: Any] = [
            "name": browserHostName(),
            "description": "Keevo",
            "path": host.path,
            "type": "stdio",
            "allowed_origins": ["chrome-extension://\(extensionId)/"],
        ]
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let data = try JSONSerialization.data(withJSONObject: manifest, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        try data.write(to: file, options: .atomic)
    }

    static func uninstall() throws {
        if FileManager.default.fileExists(atPath: file.path) {
            try FileManager.default.removeItem(at: file)
        }
    }
}

/// "设置 → 浏览器"：已配对的扩展、解除配对、Chrome 支持。
struct BrowserSettings: View {
    @Environment(AppModel.self) private var model
    @ViewState private var revoking: BrowserPairing?
    @ViewState private var installMessage: String?
    @ViewState private var installed = NativeHostManifest.installed

    var body: some View {
        VStack(alignment: .leading, spacing: KV.Space.s5) {
            SettingsSection(
                title: "Chrome",
                footer: "扩展第一次连接时，需要在 Keevo 中核对 6 个词并确认配对。"
            ) {
                SettingsRow(title: "连接 Keevo 扩展", detail: "Chrome 中的 Keevo 扩展通过本机的安全通道连接 Keevo，不经过网络。") {
                    if installed {
                        HStack(spacing: KV.Space.s2) {
                            Label("已安装", systemImage: "checkmark.circle.fill")
                                .font(KV.Typography.footnote.weight(.semibold))
                                .foregroundStyle(KV.Colors.statusSuccessFg)
                            Button("卸载") { run { try NativeHostManifest.uninstall() } }
                                .buttonStyle(.kvBordered)
                        }
                    } else {
                        Button("安装") { run { try NativeHostManifest.install() } }
                            .buttonStyle(KVButtonStyle(kind: .primary, compact: true))
                    }
                }
            }
            if let installMessage {
                Banner(kind: .danger, message: installMessage)
            }
            if let error = model.browserServiceError {
                Banner(kind: .warning, message: "浏览器服务没有启动：\(error)")
            }
            SettingsSection(title: "已配对的扩展") {
                if model.phase != .unlocked {
                    SettingsRow(title: "解锁 Keevo 之后才能查看。") { EmptyView() }
                } else if model.browserPairings.isEmpty {
                    SettingsRow(title: "还没有配对的扩展", detail: "在 Chrome 的 Keevo 扩展中点「连接 Keevo」开始配对。") { EmptyView() }
                } else {
                    ForEach(Array(model.browserPairings.enumerated()), id: \.element.id) { index, p in
                        if index > 0 { CardRowDivider() }
                        pairingRow(p)
                    }
                }
            }
            if model.pendingRevocationWarning {
                Banner(kind: .warning, message: "有撤销没能写入数据库，重启 Keevo 后可能失效。下次解锁时会自动重试。")
            }
            if model.authorizationRevokeWarning {
                Banner(kind: .warning, message: "撤销授权没能写入数据库，重启 Keevo 后这项授权可能恢复。请稍后再试一次。")
            }
        }
        .onAppear { model.refreshBrowserPairings() }
        .sheet(item: Binding(get: { revoking.map(RevokeItem.init) }, set: { if $0 == nil { revoking = nil } })) { item in
            ReverifySheet(
                title: "解除「\(item.pairing.name)」的配对",
                message: "解除后，这个扩展立即断开，不能再取用任何密码。请先确认是你本人。",
                confirmTitle: "解除配对",
                destructive: true
            ) { password in
                await model.revokeBrowserPairing(id: item.pairing.id, password: password)
            }
        }
    }

    private func pairingRow(_ p: BrowserPairing) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: KV.Space.s3) {
                Image(systemName: "puzzlepiece.extension.fill")
                    .font(.system(size: 14))
                    .foregroundStyle(KV.Colors.accentFg)
                    .frame(width: 32, height: 32)
                    .background(KV.Colors.accentSubtle, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: KV.Space.s2) {
                        Text(p.name.isEmpty ? "（未命名）" : p.name)
                            .font(KV.Typography.bodyStrong)
                            .foregroundStyle(KV.Colors.fgPrimary)
                        if p.paused {
                            Text("已暂停")
                                .font(KV.Typography.caption.weight(.semibold))
                                .foregroundStyle(KV.Colors.statusWarningFg)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 1)
                                .background(KV.Colors.statusWarningBg, in: Capsule())
                        }
                    }
                    Text("\(browserName(p.browser)) · 配对于 \(Date(timeIntervalSince1970: TimeInterval(p.pairedAtMs) / 1000).formatted(date: .abbreviated, time: .shortened))")
                        .font(KV.Typography.footnote)
                        .foregroundStyle(KV.Colors.fgSecondary)
                }
                Spacer(minLength: KV.Space.s2)
                if p.paused {
                    Button("恢复") { model.resumeBrowserPairing(id: p.id) }
                        .buttonStyle(.kvBordered)
                }
                Button("解除配对…") { revoking = p }
                    .buttonStyle(.kvBordered)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            AuthorizationList(pairing: p)
        }
    }

    private func run(_ body: () throws -> Void) {
        do {
            try body()
            installMessage = nil
        } catch NativeHostManifest.InstallError.notBundled {
            installMessage = "请从打包的 Keevo.app 运行（scripts/package-macos.sh），host 位于应用包内。"
        } catch NativeHostManifest.InstallError.noExtensionId {
            installMessage = "这个构建没有编译进扩展 ID。"
        } catch {
            installMessage = "写入 host 清单失败：\(error.localizedDescription)"
        }
        installed = NativeHostManifest.installed
    }
}

/// 一个配对已授权的网站（spec/ipc.md §5.2 第 2 条）：可逐项撤销。撤销只会减少权限，不需要重新验证。
private struct AuthorizationList: View {
    @Environment(AppModel.self) private var model
    let pairing: BrowserPairing
    @ViewState private var expanded = false

    var body: some View {
        let items = model.browserAuthorizations[pairing.id] ?? []
        if !items.isEmpty {
            VStack(alignment: .leading, spacing: 0) {
                Button { withAnimation(.easeOut(duration: 0.15)) { expanded.toggle() } } label: {
                    HStack(spacing: KV.Space.s1) {
                        Image(systemName: "chevron.right")
                            .font(.system(size: 9, weight: .bold))
                            .rotationEffect(.degrees(expanded ? 90 : 0))
                        Text("已授权的网站（\(items.count)）")
                    }
                    .font(KV.Typography.footnote.weight(.semibold))
                    .foregroundStyle(KV.Colors.fgSecondary)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .padding(.leading, 58)
                .padding(.bottom, KV.Space.s2)
                .accessibilityValue(expanded ? "已展开" : "已收起")
                if expanded {
                    ForEach(items, id: \.key) { a in
                        HStack(spacing: KV.Space.s2) {
                            SiteIcon(title: a.title ?? a.site, url: a.site, size: 20)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(a.title ?? "（条目已删除）").font(KV.Typography.body)
                                Text("\(a.site) · \(Date(timeIntervalSince1970: TimeInterval(a.grantedAtMs) / 1000).formatted(date: .abbreviated, time: .shortened))")
                                    .font(KV.Typography.caption)
                                    .foregroundStyle(KV.Colors.fgSecondary)
                            }
                            Spacer()
                            Button("撤销") {
                                model.revokeBrowserAuthorization(pairingId: pairing.id, itemId: a.itemId, site: a.site)
                            }
                            .buttonStyle(.kvLink)
                        }
                        .padding(.leading, 58)
                        .padding(.trailing, 14)
                        .padding(.vertical, 5)
                    }
                    Spacer().frame(height: KV.Space.s2)
                }
            }
        }
    }
}

private struct RevokeItem: Identifiable {
    let pairing: BrowserPairing
    var id: String { pairing.id }
}

/// 敏感操作之前重新验证：Touch ID 或主密码（docs/ux.md §5"重新验证"）。`action` 收到 `nil` 表示用 Touch ID。
struct ReverifySheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let title: String
    let message: String
    var confirmTitle = "确认"
    var destructive = false
    let action: (String?) async -> Bool
    @ViewState private var password = ""

    var body: some View {
        SheetScaffold(
            title: title,
            subtitle: message,
            systemImage: "person.badge.shield.checkmark",
            tint: destructive ? KV.Colors.statusDangerFg : KV.Colors.accentFg,
            width: 440
        ) {
            VStack(alignment: .leading, spacing: KV.Space.s3) {
                if model.touchIDUsable {
                    Button {
                        Task { if await action(nil) { dismiss() } }
                    } label: {
                        Label("用 Touch ID 确认", systemImage: "touchid")
                    }
                    .buttonStyle(KVButtonStyle(kind: .secondary, fullWidth: true))
                    .disabled(model.busy)
                    TextDivider(text: "或输入主密码")
                }
                LabeledInput(label: "主密码") {
                    SecureField("", text: $password).onSubmit(confirm)
                }
                ErrorText()
            }
        } footer: {
            Button("取消") { dismiss() }
                .buttonStyle(.kvSecondary)
                .keyboardShortcut(.cancelAction)
            Button(confirmTitle, action: confirm)
                .buttonStyle(KVButtonStyle(kind: destructive ? .danger : .primary))
                .keyboardShortcut(.defaultAction)
                .disabled(password.isEmpty || model.busy)
        }
    }

    private func confirm() {
        guard !password.isEmpty, !model.busy else { return }
        Task { if await action(password) { dismiss() } }
    }
}
