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

/// 一次等待授权的填充（spec/ipc.md §5.2 第 1 条）：拒绝、只允许这个网站，或这个扩展在所有网站上都不再询问。
struct FillAuthorizationRequest: Identifiable {
    let id = UUID()
    let request: BrowserFillRequest
    let deadline: Date
    let answer: (BrowserFillDecision) -> Void
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

/// 一次等待允许的搜索：这次解锁中第一次搜索全部条目（spec/ipc.md §5.6）。
struct SearchAuthorizationRequest: Identifiable {
    let id = UUID()
    let request: BrowserSearchRequest
    let deadline: Date
    let answer: (Bool) -> Void
}

/// 当前显示的确认界面。浏览器的配对、填充授权、密码更新、搜索，以及命令行工具与 SSH 的授权共用一个 sheet，逐个显示。
enum BrowserPromptItem: Identifiable {
    case pairing(PairingRequest)
    case fill(FillAuthorizationRequest)
    case update(UpdateConfirmationRequest)
    case search(SearchAuthorizationRequest)
    case cli(CliAuthorizationRequest)
    case ssh(SshAuthorizationRequest)

    var id: UUID {
        switch self {
        case .pairing(let r): r.id
        case .fill(let r): r.id
        case .update(let r): r.id
        case .search(let r): r.id
        case .cli(let r): r.id
        case .ssh(let r): r.id
        }
    }
}

/// 回到发起请求的浏览器（扩展弹窗随之重新打开，spec/ipc.md §5.6）。只激活与配对记录中相同的浏览器。
@MainActor
func returnToBrowser(_ bundleID: String) {
    NSRunningApplication.runningApplications(withBundleIdentifier: bundleID).first?.activate()
}

/// 把主窗口带到前台。
@MainActor
func showMainWindow() {
    NSApp.activate()
    NSApp.windows.first { $0.isVisible || $0.isMiniaturized }?.makeKeyAndOrderFront(nil)
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
        // 确认界面是主窗口上的 sheet：主窗口被关闭或最小化时，先打开或还原它，否则界面无处显示、到期按拒绝处理
        model?.showMainWindow()
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

    func authorizeFill(request: BrowserFillRequest, timeoutMs: UInt64) -> BrowserFillDecision {
        // 通用的等待只带回"是否允许"；允许的方式（这个网站或所有网站）另外记下
        let lock = NSLock()
        var decision = BrowserFillDecision.deny
        let accepted = ask(timeoutMs: timeoutMs) { deadline, answer in
            .fill(FillAuthorizationRequest(request: request, deadline: deadline) { d in
                lock.withLock { decision = d }
                answer(d != .deny)
            })
        }
        let result = accepted ? lock.withLock { decision } : .deny
        if result != .deny {
            // 授权由 Rust 在这里返回之后写入；稍后刷新"设置 → 浏览器"的列表
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
                self?.model?.refreshBrowserPairings()
            }
        }
        return result
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
                tr("「{}」（{}）在 10 分钟内查询了太多不同的网站，已暂时停止回答它的查询。如果不是你在操作，请在「设置 → 浏览器」中解除配对。", "\(name)", "\(browserName(browser))")
            NSApp.requestUserAttention(.criticalRequest)
        }
    }

    func loginSaved(pairingName: String, browser: String, title: String) {
        DispatchQueue.main.async { [weak self] in
            self?.model?.browserNotice = tr("「{}」（{}）保存了新的登录「{}」。", "\(pairingName)", "\(browserName(browser))", "\(title)")
            self?.model?.reloadAfterBrowserWrite()
        }
    }

    func authorizeSearch(request: BrowserSearchRequest, timeoutMs: UInt64) -> Bool {
        let accepted = ask(timeoutMs: timeoutMs) { deadline, answer in
            .search(SearchAuthorizationRequest(request: request, deadline: deadline, answer: answer))
        }
        if accepted {
            // 用户是在浏览器里点的搜索：允许后回到浏览器，扩展会重新打开弹窗显示结果
            DispatchQueue.main.async { returnToBrowser(request.browser) }
        }
        return accepted
    }

    func openRequested(pairingName: String, browser: String, itemId: String?) {
        DispatchQueue.main.async { [weak self] in
            guard let model = self?.model else { return }
            showMainWindow()
            if let itemId, model.phase == .unlocked { model.mainRequest = .showItem(itemId) }
        }
    }

    func browserUnlockRequested(pairingName: String, browser: String) {
        DispatchQueue.main.async { [weak self] in
            guard let model = self?.model, model.phase == .locked else { return }
            model.unlockWaiter = .browser(name: pairingName, bundleID: browser, since: Date())
            // 用户刚在扩展弹窗里点了"解锁"：来到前台；可以用 Touch ID 时直接请求验证
            showMainWindow()
            if model.touchIDUsable { Task { await model.unlockWithTouchID() } }
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
                Text(title.isEmpty ? tr("（无标题）") : title)
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
                title: tr("浏览器请求配对"),
                subtitle: tr("「{}」（{}）请求连接 Keevo。", "\(request.name)", "\(browserName(request.browser))"),
                systemImage: "puzzlepiece.extension",
                width: 500,
                note: tr("{} 秒后自动拒绝", "\(left)")
            ) {
                VStack(alignment: .leading, spacing: KV.Space.s3) {
                    Text(tr("请逐个确认扩展弹窗中的 6 个词与下面完全一致，顺序也要相同。"))
                        .font(KV.Typography.body)
                        .foregroundStyle(KV.Colors.fgPrimary)
                        .fixedSize(horizontal: false, vertical: true)
                    PairingCode(words: request.words)
                    Text(tr("如果不一致，或者你没有在扩展中发起配对，请选择「不一致」。配对后，这个扩展可以在你授权的网站上取用密码。"))
                        .font(KV.Typography.footnote)
                        .foregroundStyle(KV.Colors.fgSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } footer: {
                Button(tr("不一致")) { answer(false) }
                    .buttonStyle(.kvSecondary)
                    .keyboardShortcut(.cancelAction)
                Button(tr("一致，确认配对")) { answer(true) }
                    .buttonStyle(.kvSecondary)
            }
            .onChange(of: left) { if left == 0, model.browserDialog?.id == request.id { model.browserDialog = nil } }
        }
        .kvContainerFocus()
    }

    private func answer(_ accepted: Bool) {
        // 截止时间之后的确认一律按拒绝处理（Rust 端也会再检查一次）
        request.answer(accepted && Date() < request.deadline)
        model.browserDialog = nil
    }
}

/// 填充授权：某个配对第一次为某个条目在某个站点取用凭据（spec/ipc.md §5.2 第 1 条）。
/// 显示规范化后的站点、条目标题与用户名、发起请求的配对。可以只允许这个网站，或让这个扩展在所有网站上都不再询问。
/// 没有默认按钮，回车不会误放行；Esc 等于拒绝。
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
                title: tr("允许扩展在这个网站上填充？"),
                subtitle: tr("「{}」（{}）请求在下面这个网站上填充登录信息。", "\(r.pairingName)", "\(browserName(r.browser))"),
                systemImage: "key.viewfinder",
                width: 500,
                note: tr("{} 秒后自动拒绝", "\(left)")
            ) {
                VStack(alignment: .leading, spacing: KV.Space.s3) {
                    KVCard {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(tr("网站"))
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
                        .accessibilityLabel(tr("网站 {}", "\(r.site)"))
                        CardRowDivider()
                        PromptItemRow(title: r.title, username: r.username, url: r.site)
                    }
                    Text(tr("选「所有网站」后，这个扩展以后填充都不再询问，可在「设置 → 浏览器」中改回。没有在浏览器中点击填充时，请选择「拒绝」。"))
                        .font(KV.Typography.footnote)
                        .foregroundStyle(KV.Colors.fgSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } footer: {
                Button(tr("拒绝")) { answer(.deny) }
                    .buttonStyle(.kvSecondary)
                    .keyboardShortcut(.cancelAction)
                Button(tr("仅这个网站")) { answer(.thisSite) }
                    .buttonStyle(.kvSecondary)
                Button(tr("所有网站")) { answer(.allSites) }
                    .buttonStyle(.kvSecondary)
            }
            .onChange(of: left) { if left == 0, model.browserDialog?.id == request.id { model.browserDialog = nil } }
        }
        .kvContainerFocus()
    }

    private func answer(_ decision: BrowserFillDecision) {
        // 截止时间之后的回答一律按拒绝处理（Rust 端也会再检查一次）
        request.answer(Date() < request.deadline ? decision : .deny)
        model.browserDialog = nil
    }
}

/// 搜索全部条目：这次解锁中第一次（spec/ipc.md §5.6）。显示搜索词，让用户核对是不是自己刚输入的；
/// 允许后到下次锁定前不再询问。与其他浏览器确认一样没有默认按钮。
struct SearchAuthorizationSheet: View {
    @Environment(AppModel.self) private var model
    let request: SearchAuthorizationRequest

    private var r: BrowserSearchRequest { request.request }

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let left = max(0, Int(request.deadline.timeIntervalSince(context.date).rounded(.up)))
            SheetScaffold(
                title: tr("允许扩展搜索全部条目？"),
                subtitle: tr("「{}」（{}）请求在保险库的全部条目中搜索。", "\(r.pairingName)", "\(browserName(r.browser))"),
                systemImage: "magnifyingglass",
                width: 500,
                note: tr("{} 秒后自动拒绝", "\(left)")
            ) {
                VStack(alignment: .leading, spacing: KV.Space.s3) {
                    KVCard {
                        CardRow(label: tr("搜索内容")) {
                            Text(r.query).font(KV.Typography.mono).textSelection(.enabled)
                        } actions: {}
                        CardRowDivider()
                        CardRow(label: tr("返回")) { Text(tr("匹配条目的标题与用户名，不含密码")).font(KV.Typography.body) } actions: {}
                        CardRowDivider()
                        CardRow(label: tr("有效期")) { Text(tr("到 Keevo 下次锁定")).font(KV.Typography.body) } actions: {}
                    }
                    Text(tr("其他网站的条目只能在 Keevo 中打开，不能在扩展里填充。如果你没有在扩展中搜索，请选择「拒绝」。"))
                        .font(KV.Typography.footnote)
                        .foregroundStyle(KV.Colors.fgSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } footer: {
                Button(tr("拒绝")) { answer(false) }
                    .buttonStyle(.kvSecondary)
                    .keyboardShortcut(.cancelAction)
                Button(tr("允许")) { answer(true) }
                    .buttonStyle(.kvSecondary)
            }
            .onChange(of: left) { if left == 0, model.browserDialog?.id == request.id { model.browserDialog = nil } }
        }
        .kvContainerFocus()
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
                title: tr("更新这个登录的密码？"),
                subtitle: tr("「{}」（{}）在 {} 上提交了新密码。", "\(r.pairingName)", "\(browserName(r.browser))", "\(r.site)"),
                systemImage: "key.horizontal",
                width: 500,
                note: tr("{} 秒后自动拒绝", "\(left)")
            ) {
                VStack(alignment: .leading, spacing: KV.Space.s3) {
                    KVCard {
                        PromptItemRow(title: r.title, username: r.username, url: r.site)
                    }
                    if !request.changed {
                        Banner(kind: .info, message: tr("新密码与保存的相同，确认后不会有任何改动。"))
                    }
                    Text(tr("旧密码会保留在这个条目的历史中，可以随时恢复。如果你没有在这个网站上修改密码，请选择「不更新」。"))
                        .font(KV.Typography.footnote)
                        .foregroundStyle(KV.Colors.fgSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } footer: {
                Button(tr("不更新")) { answer(false) }
                    .buttonStyle(.kvSecondary)
                    .keyboardShortcut(.cancelAction)
                Button(tr("更新密码")) { answer(true) }
                    .buttonStyle(.kvSecondary)
            }
            .onChange(of: left) { if left == 0, model.browserDialog?.id == request.id { model.browserDialog = nil } }
        }
        .kvContainerFocus()
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

/// 安装 Chrome 扩展的三步（设计稿"Alpha 安装后的问题"）：Alpha 版的扩展没有上架 Chrome 应用商店，从发布页下载后以
/// "加载已解压的扩展程序"安装（docs/alpha/install.md §4）。引导与"设置 → 浏览器"共用。
struct ChromeExtensionSteps: View {
    @ViewState private var copied = false

    /// 这个版本的发布页：扩展与应用同一个版本。
    static var releaseURL: URL? {
        URL(string: "https://github.com/\(UpdateChecker.repository)/releases/tag/v\(keevoVersion())")
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            step(1, tr("从发布页下载 {}，解压到长期保留的位置（例如\"应用程序\"文件夹旁）。Chrome 从这个文件夹加载扩展，删除或移动它，扩展就会失效。", "Keevo-\(keevoVersion())-chrome-extension.zip")) {
                if let url = Self.releaseURL {
                    Button(tr("打开发布页")) { NSWorkspace.shared.open(url) }.buttonStyle(.kvLink)
                }
            }
            step(2, tr("在 Chrome 中打开 chrome://extensions，打开右上角的\"开发者模式\"，点\"加载已解压的扩展程序\"，选择解压后的文件夹。")) {
                Button(copied ? tr("已复制") : tr("复制地址")) { copyAddress() }.buttonStyle(.kvLink)
            }
            step(3, tr("点 Chrome 工具栏中的 Keevo 图标，选\"与 Keevo 配对\"，核对两边的 6 个词。")) { EmptyView() }
        }
    }

    private func step<Action: View>(_ n: Int, _ text: String, @ViewBuilder action: () -> Action) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: KV.Space.s2) {
            Text("\(n)")
                .font(KV.Typography.caption.weight(.semibold))
                .foregroundStyle(KV.Colors.accentFg)
                .frame(width: 18, height: 18)
                .background(KV.Colors.accentSubtle, in: Circle())
            VStack(alignment: .leading, spacing: 4) {
                Text(text)
                    .font(KV.Typography.body)
                    .foregroundStyle(KV.Colors.fgPrimary)
                    .fixedSize(horizontal: false, vertical: true)
                action()
            }
        }
    }

    /// Keevo 打不开 chrome:// 地址，只能复制给用户粘贴。地址不是秘密，不按秘密的方式处理剪贴板。
    private func copyAddress() {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString("chrome://extensions", forType: .string)
        copied = true
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(2))
            copied = false
        }
    }
}

extension AppModel {
    /// 已配对的 Chrome 扩展（Keevo 看不到 Chrome 装了什么，扩展的状态以配对为准）。
    var chromePairings: [BrowserPairing] { browserPairings.filter { $0.browser == "com.google.Chrome" } }
}

/// "设置 → 浏览器"（设计稿"Alpha 安装后的问题"）：扩展是否配对、是否允许扩展连接（本机通道）、安装步骤、
/// 已配对的扩展与解除配对。
struct BrowserSettings: View {
    @Environment(AppModel.self) private var model
    @ViewState private var revoking: BrowserPairing?
    @ViewState private var installMessage: String?
    @ViewState private var installed = NativeHostManifest.installed

    var body: some View {
        VStack(alignment: .leading, spacing: KV.Space.s5) {
            SettingsSection(
                title: "Chrome",
                footer: tr("扩展第一次连接时，需要在 Keevo 中核对 6 个词并确认配对。")
            ) {
                extensionRow
                CardRowDivider()
                SettingsRow(
                    title: tr("允许扩展连接 Keevo"),
                    detail: tr("在 Chrome 中登记本机通道，扩展经它连接 Keevo，不经过网络。")
                ) {
                    Toggle(tr("允许扩展连接 Keevo"), isOn: Binding(
                        get: { installed },
                        set: { on in run { try on ? NativeHostManifest.install() : NativeHostManifest.uninstall() } }
                    ))
                    .kvSwitch(tr("允许扩展连接 Keevo"))
                }
            }
            if let installMessage {
                Banner(kind: .danger, message: installMessage)
            }
            if let error = model.browserServiceError {
                Banner(kind: .warning, message: tr("浏览器服务没有启动：{}", "\(error)"))
            }
            // 配对之后收起
            if model.phase == .unlocked, model.chromePairings.isEmpty {
                SettingsSection(title: tr("安装 Chrome 扩展")) {
                    ChromeExtensionSteps()
                        .padding(.horizontal, 14)
                        .padding(.vertical, 12)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            SettingsSection(title: tr("已配对的扩展")) {
                if model.phase != .unlocked {
                    SettingsRow(title: tr("解锁 Keevo 之后才能查看。")) { EmptyView() }
                } else if model.browserPairings.isEmpty {
                    SettingsRow(title: tr("还没有配对的扩展"), detail: tr("在 Chrome 中点 Keevo 扩展的图标，选「与 Keevo 配对」。")) { EmptyView() }
                } else {
                    ForEach(Array(model.browserPairings.enumerated()), id: \.element.id) { index, p in
                        if index > 0 { CardRowDivider() }
                        pairingRow(p)
                    }
                }
            }
            if model.pendingRevocationWarning {
                Banner(kind: .warning, message: tr("有撤销没能写入数据库，重启 Keevo 后可能失效。下次解锁时会自动重试。"))
            }
            if model.fillScopeSaveFailed {
                Banner(kind: .warning, message: tr("填充确认的设置没能保存，请稍后再试一次。"))
            }
            if model.authorizationRevokeWarning {
                Banner(kind: .warning, message: tr("撤销授权没能写入数据库，重启 Keevo 后这项授权可能恢复。请稍后再试一次。"))
            }
        }
        .onAppear { model.refreshBrowserPairings() }
        // 扩展装好后会自动发起配对：设置页开着时定时刷新，配对后状态随之更新
        .task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(2))
                model.refreshBrowserPairings()
            }
        }
        .sheet(item: Binding(get: { revoking.map(RevokeItem.init) }, set: { if $0 == nil { revoking = nil } })) { item in
            ReverifySheet(
                title: tr("解除「{}」的配对", "\(item.pairing.name)"),
                message: tr("解除后，这个扩展立即断开，不能再取用任何密码。请先确认是你本人。"),
                confirmTitle: tr("解除配对"),
                destructive: true
            ) { password in
                await model.revokeBrowserPairing(id: item.pairing.id, password: password)
            }
        }
    }

    /// "Keevo 扩展"：按是否配对显示（Keevo 看不到 Chrome 装了什么）。
    @ViewBuilder
    private var extensionRow: some View {
        let paired = model.chromePairings
        if model.phase != .unlocked {
            SettingsRow(title: tr("Keevo 扩展"), detail: tr("解锁 Keevo 之后才能查看。")) { EmptyView() }
        } else if paired.isEmpty {
            SettingsRow(title: tr("Keevo 扩展"), detail: tr("还没有配对")) {
                Text(tr("未配对"))
                    .font(KV.Typography.footnote.weight(.semibold))
                    .foregroundStyle(KV.Colors.statusWarningFg)
            }
        } else {
            SettingsRow(
                title: tr("Keevo 扩展"),
                detail: tr("已配对：{}", paired.map { $0.name.isEmpty ? tr("（未命名）") : $0.name }.joined(separator: tr("、")))
            ) {
                Label(tr("已配对"), systemImage: "checkmark.circle.fill")
                    .font(KV.Typography.footnote.weight(.semibold))
                    .foregroundStyle(KV.Colors.statusSuccessFg)
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
                        Text(p.name.isEmpty ? tr("（未命名）") : p.name)
                            .font(KV.Typography.bodyStrong)
                            .foregroundStyle(KV.Colors.fgPrimary)
                        if p.paused {
                            Text(tr("已暂停"))
                                .font(KV.Typography.caption.weight(.semibold))
                                .foregroundStyle(KV.Colors.statusWarningFg)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 1)
                                .background(KV.Colors.statusWarningBg, in: Capsule())
                        }
                    }
                    Text(tr("{} · 配对于 {}", "\(browserName(p.browser))", "\(Date(timeIntervalSince1970: TimeInterval(p.pairedAtMs) / 1000).formatted(date: .abbreviated, time: .shortened))"))
                        .font(KV.Typography.footnote)
                        .foregroundStyle(KV.Colors.fgSecondary)
                }
                Spacer(minLength: KV.Space.s2)
                if p.paused {
                    Button(tr("恢复")) { model.resumeBrowserPairing(id: p.id) }
                        .buttonStyle(.kvBordered)
                }
                Button(tr("解除配对…")) { revoking = p }
                    .buttonStyle(.kvBordered)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            CardRowDivider().padding(.leading, 58)
            HStack(spacing: KV.Space.s2) {
                Text(tr("填充确认")).font(KV.Typography.body)
                Spacer(minLength: KV.Space.s2)
                Picker(tr("填充确认"), selection: Binding(
                    get: { p.fillAllSites },
                    set: { model.setBrowserFillAllSites(id: p.id, enabled: $0) }
                )) {
                    Text(tr("逐个网站确认")).tag(false)
                    Text(tr("所有网站都不再确认")).tag(true)
                }
                .pickerStyle(.menu)
                .labelsHidden()
                .fixedSize()
            }
            .padding(.leading, 58)
            .padding(.trailing, 14)
            .padding(.vertical, 8)
            if p.fillAllSites {
                Text(tr("这个扩展在任何网站上填充都不再询问。"))
                    .font(KV.Typography.footnote)
                    .foregroundStyle(KV.Colors.fgSecondary)
                    .padding(.leading, 58)
                    .padding(.trailing, 14)
                    .padding(.bottom, KV.Space.s3)
            } else {
                AuthorizationList(pairing: p)
            }
        }
    }

    private func run(_ body: () throws -> Void) {
        do {
            try body()
            installMessage = nil
        } catch NativeHostManifest.InstallError.notBundled {
            installMessage = tr("请从打包的 Keevo.app 运行（scripts/package-macos.sh），host 位于应用包内。")
        } catch NativeHostManifest.InstallError.noExtensionId {
            installMessage = tr("这个构建没有编译进扩展 ID。")
        } catch {
            installMessage = tr("写入 host 清单失败：{}", "\(error.localizedDescription)")
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
                        Text(tr("已授权的网站（{}）", "\(items.count)"))
                    }
                    .font(KV.Typography.footnote.weight(.semibold))
                    .foregroundStyle(KV.Colors.fgSecondary)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .padding(.leading, 58)
                .padding(.bottom, KV.Space.s2)
                .accessibilityValue(expanded ? tr("已展开") : tr("已收起"))
                if expanded {
                    ForEach(items, id: \.key) { a in
                        HStack(spacing: KV.Space.s2) {
                            SiteIcon(title: a.title ?? a.site, url: a.site, size: 20)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(a.title ?? tr("（条目已删除）")).font(KV.Typography.body)
                                Text("\(a.site) · \(Date(timeIntervalSince1970: TimeInterval(a.grantedAtMs) / 1000).formatted(date: .abbreviated, time: .shortened))")
                                    .font(KV.Typography.caption)
                                    .foregroundStyle(KV.Colors.fgSecondary)
                            }
                            Spacer()
                            Button(tr("撤销")) {
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
    var confirmTitle = tr("确认")
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
                        Label(tr("用 Touch ID 确认"), systemImage: "touchid")
                    }
                    .buttonStyle(KVButtonStyle(kind: .secondary, fullWidth: true))
                    .disabled(model.busy)
                    TextDivider(text: tr("或输入主密码"))
                }
                LabeledInput(label: tr("主密码")) {
                    SecureField("", text: $password).onSubmit(confirm)
                }
                ErrorText()
            }
        } footer: {
            Button(tr("取消")) { dismiss() }
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
