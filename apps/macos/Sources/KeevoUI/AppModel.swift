// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）

import AppKit
import CoreGraphics
import Foundation
import KeevoKit
import Observation

/// 应用状态。所有耗时的 Rust 调用（Argon2id 约 1 秒、Touch ID 等待用户）都放到后台执行，界面保持响应。
@MainActor
@Observable
final class AppModel {
    enum Phase {
        case onboarding
        /// Secure Enclave 暂时不可用，无法打开数据库（spec/crypto.md §8.7）。
        case unavailable
        case locked
        case unlocked
    }

    private(set) var phase: Phase = .onboarding
    private(set) var busy = false
    var errorMessage: String?
    /// 新建账户后只展示一次的账户密钥（句柄，显示时才取出明文）。
    var pendingSecretKey: SecretValue?
    /// 解锁时发现 KDF 参数异常地高，等待用户确认（spec/crypto.md §5.3）。
    var pendingKdf: KdfInfo?
    private(set) var vaults: [VaultEntry] = []
    private(set) var items: [ItemEntry] = []

    /// 记下条目被使用了一次（在 Keevo 或快速访问中复制），并就地更新列表中的使用次数与最近使用（列表排序），
    /// 不重新读取全部条目。写入失败不影响复制本身。
    func recordUse(itemId: String) {
        guard (try? vault?.recordItemUse(itemId: itemId)) != nil,
              let index = items.firstIndex(where: { $0.id == itemId }) else { return }
        items[index].useCount += 1
        items[index].lastUsedMs = UInt64(max(0, Date().timeIntervalSince1970 * 1000))
    }
    /// 每次条目数据变化时加 1。详情等视图据此重新读取。
    private(set) var dataVersion = 0

    /// 安全中心最近一次的检查结果（docs/product.md §5.6），锁定时丢弃。
    var securityReport: SecurityReport?
    /// 正在检查。
    var securityChecking = false
    /// 泄露检查的状态：正在查询、上次失败的原因。
    var breachChecking = false
    var breachError: String?
    /// 用户开启了泄露检查（Have I Been Pwned，默认关闭，docs/governance.md §5）。只记偏好，不记结果。
    var breachCheckEnabled = UserDefaults.standard.bool(forKey: "security.breachCheck") {
        didSet { UserDefaults.standard.set(breachCheckEnabled, forKey: "security.breachCheck") }
    }
    /// 关闭的检查项（安全中心的"检查项"，设计稿"安全中心：可以关闭的检查项"）。只存在这台 Mac 上，不随保险库同步；
    /// "已泄露"不在其中，它对应 `breachCheckEnabled`。
    var disabledChecks = Set(UserDefaults.standard.stringArray(forKey: "security.disabledChecks") ?? []) {
        didSet {
            UserDefaults.standard.set(disabledChecks.sorted(), forKey: "security.disabledChecks")
            securityVersion &+= 1
        }
    }
    /// 每次检查结果更新时加 1。详情的"安全"区据此重新读取。
    var securityVersion = 0
    @ObservationIgnored var securityTask: Task<Void, Never>?

    /// 每天自动备份（docs/product.md §5.7，默认开启）。
    var autoBackupEnabled = UserDefaults.standard.object(forKey: "backup.auto") as? Bool ?? true {
        didSet { UserDefaults.standard.set(autoBackupEnabled, forKey: "backup.auto") }
    }
    /// 用户选择的备份文件夹；`nil` 为默认的 `~/Library/Application Support/Keevo/backups`。
    var customBackupFolder = UserDefaults.standard.string(forKey: "backup.folder") {
        didSet { UserDefaults.standard.set(customBackupFolder, forKey: "backup.folder") }
    }
    /// 保留的份数。
    var backupKeep = UserDefaults.standard.object(forKey: "backup.keep") as? Int ?? 30 {
        didSet { UserDefaults.standard.set(backupKeep, forKey: "backup.keep") }
    }
    /// 备份文件夹中的备份，新的在前。
    var backups: [BackupInfo] = []
    /// 上次自动备份失败的原因（例如外部硬盘没有连接）。
    var backupError: String?
    /// 首次使用进行到哪一步（docs/ux.md §3.1）；`nil` 为不在首次使用中。
    var onboardingStep: OnboardingStep?
    /// 欢迎页选了"从其他密码管理器导入"：完成后直接打开导入。
    var importAfterOnboarding = false
    /// 请设置窗口显示的页面（完成页的"在浏览器中使用"等）。
    var requestedSettingsPage: SettingsView.Page?
    /// 主密码练习（docs/ux.md §3.1 第 8 条）。
    var showingPractice = false
    /// 在菜单栏显示 Keevo（默认开启）。
    static let menuBarKey = "menuBar.enabled"
    var menuBarEnabled = UserDefaults.standard.object(forKey: AppModel.menuBarKey) as? Bool ?? true {
        didSet { UserDefaults.standard.set(menuBarEnabled, forKey: Self.menuBarKey) }
    }
    /// 快速访问：每次打开加 1（重置搜索）；快捷键被其他应用占用。
    var quickAccessSession = 0
    var quickAccessShortcutTaken = false
    /// 打开主窗口（主窗口关闭后由快速访问与菜单栏使用）。
    @ObservationIgnored var openMainWindow: (() -> Void)?
    /// 导入向导与导出（「文件 → 导入…」「文件 → 导出…」）。
    var showingImport = false
    var showingExport = false
    /// 锁屏上显示一次的说明（例如"已从备份恢复"），解锁后清除。
    var lockNotice: String?
    @ObservationIgnored var backupTimer: Task<Void, Never>?

    /// 有浏览器正在请求配对（spec/ipc.md §4.2 第 8 步：每次尝试都对用户可见）。值为浏览器标识。
    var pairingNotice: String?
    /// 浏览器写入保险库的提示（spec/ipc.md §5.5：每次保存都对用户可见）。
    var browserNotice: String?
    /// 菜单栏命令对主窗口的请求（新建、生成密码、搜索）。
    var mainRequest: MainRequest?
    /// 正在编辑的条目（编辑器打开期间）。主窗口据此锁住侧边栏与列表。
    var editingItem: String?
    /// 窗口底部的短暂提示（例如"已复制"）。
    private(set) var toast: String?
    @ObservationIgnored private var toastTask: Task<Void, Never>?

    func showToast(_ message: String) {
        toast = message
        toastTask?.cancel()
        toastTask = Task { @MainActor in
            try? await Task.sleep(for: .seconds(2))
            if !Task.isCancelled { self.toast = nil }
        }
    }
    /// 浏览器的异常行为（spec/ipc.md §5.2：查询过于频繁）。用户关闭前一直显示。
    var browserWarning: String?
    /// 当前显示的浏览器确认界面（配对或填充授权）。
    var browserDialog: BrowserPromptItem?
    /// 因频率限制被暂停、等待用户处理的配对（spec/ipc.md §5.2 第 3 条）。
    var pausedPairing: PausedPairing?
    /// 已配对的浏览器扩展。
    private(set) var browserPairings: [BrowserPairing] = []
    /// 每个配对已授权的网站，按配对 ID。
    private(set) var browserAuthorizations: [String: [BrowserAuthorization]] = [:]
    /// 撤销授权没能写入数据库。
    private(set) var authorizationRevokeWarning = false
    /// "填充确认"的设置没能保存（已锁定或写入数据库失败）。
    private(set) var fillScopeSaveFailed = false
    /// 浏览器服务没有启动的原因。
    private(set) var browserServiceError: String?
    /// 有撤销没能写入数据库（spec/ipc.md §4.4）。
    private(set) var pendingRevocationWarning = false
    @ObservationIgnored private lazy var browserPrompt = BrowserPromptBridge(model: self)

    // MARK: 开发者（spec/cli.md、spec/ssh-agent.md）

    @ObservationIgnored lazy var developerPrompt = DeveloperPromptBridge(model: self)
    /// 命令行工具的服务没有启动的原因。
    var developerServiceError: String?
    /// SSH Agent 的状态。
    var sshAgent: SshAgentInfo?
    /// SSH Agent 没有启动的原因。
    var sshAgentError: String?
    /// 已授权的终端会话。
    var cliSessions: [CliSessionInfo] = []
    /// SSH 密钥条目在 Agent 中的状态。
    var sshKeys: [SshKeyInfo] = []
    /// 命令行工具或 SSH 正在等待解锁（锁屏上说明）。
    var unlockWaiter: UnlockWaiter?
    /// 最近的 SSH 签名（只在内存中，锁定时清空）：让每次使用都可见，包括"解锁期间自动"的密钥。
    var recentSshUse: [SshUseRecord] = []
    /// SSH Agent 是否开启（记在本机，默认关闭，spec/ssh-agent.md §1）。
    var sshAgentEnabled: Bool {
        didSet { UserDefaults.standard.set(sshAgentEnabled, forKey: Self.sshAgentKey) }
    }
    static let sshAgentKey = "sshAgentEnabled"

    /// 本机没有可用的账户密钥，解锁时需要用户从应急包输入。
    private(set) var needsSecretKey = false
    /// 上一次解锁因主密码（或账户密钥）不正确而失败：锁屏在输入框下说明，不用横幅。编辑输入时清除。
    var wrongCredentials = false
    /// 解锁失败的次数：锁屏据此让输入框抖动一次。
    private(set) var failedUnlocks = 0
    /// Touch ID 已启用且未失效。
    private(set) var touchIDEnabled = false
    /// 此时不能用 Touch ID 的原因；为 `nil` 时可以用 Touch ID 解锁（docs/ux.md §3.2）。
    private(set) var passwordReason: PasswordReasonKind? = .notEnabled
    /// 必须重新输入主密码的间隔天数。
    private(set) var passwordIntervalDays: UInt8 = 14

    /// 闲置多少分钟后自动锁定（docs/ux.md §3.8）。
    var autoLockMinutes: Int {
        didSet { UserDefaults.standard.set(autoLockMinutes, forKey: Self.autoLockKey) }
    }
    static let autoLockChoices = [1, 2, 5, 10, 15, 30, 60]
    private static let autoLockKey = "autoLockMinutes"

    /// 不允许 Keevo 的窗口被截屏或屏幕共享（docs/ux.md §5，可选，默认关闭）。
    var hideFromScreenCapture: Bool {
        didSet {
            UserDefaults.standard.set(hideFromScreenCapture, forKey: Self.hideFromCaptureKey)
            NSApp.windows.forEach(applyCapturePolicy)
        }
    }
    private static let hideFromCaptureKey = "hideFromScreenCapture"

    private(set) var vault: KeevoVault?
    private let dbPath: String
    private let localDir: String
    private let enclave: SecureEnclaveProvider
    private var observers: [NSObjectProtocol] = []
    private var idleTimer: Timer?
    /// 本次锁定期间是否已经自动弹出过 Touch ID。系统的 Touch ID 提示关闭时，应用会再次变为活跃；
    /// 不加限制的话，用户点了取消就会再弹一次，没完没了。
    private var autoPrompted = false

    /// 正式应用：数据目录在 `~/Library/Application Support/Keevo`（ADR-0003）。
    convenience init() {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Keevo", isDirectory: true)
        self.init(dataDirectory: support, enclave: SecureEnclaveBridge(touchIDReason: tr("解锁 Keevo")), background: true)
    }

    /// `dataDirectory`：数据库与本机密钥目录（spec/crypto.md §8.7）。`background` 为 `false` 时不监听系统锁定、
    /// 不启动闲置计时与浏览器服务（截图程序用）。
    init(dataDirectory support: URL, enclave: SecureEnclaveProvider, background: Bool) {
        self.enclave = enclave
        self.background = background
        let stored = UserDefaults.standard.integer(forKey: Self.autoLockKey)
        autoLockMinutes = Self.autoLockChoices.contains(stored) ? stored : 10
        hideFromScreenCapture = UserDefaults.standard.bool(forKey: Self.hideFromCaptureKey)
        sshAgentEnabled = UserDefaults.standard.bool(forKey: Self.sshAgentKey)

        try? FileManager.default.createDirectory(
            at: support, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]
        )
        dbPath = support.appendingPathComponent("vault.sqlite").path
        defaultBackupFolder = support.appendingPathComponent("backups", isDirectory: true).path
        // 上次运行留下的附件预览
        try? FileManager.default.removeItem(at: support.appendingPathComponent("preview", isDirectory: true))
        localDir = support.appendingPathComponent("local", isDirectory: true).path
        if FileManager.default.fileExists(atPath: dbPath) {
            open(reenrolling: false)
        } else {
            onboardingStep = .welcome
        }
        if background {
            observeSystemLockEvents()
            startIdleTimer()
            registerQuickAccessShortcut()
        }
    }

    private let background: Bool
    /// 默认的备份文件夹（数据目录下的 backups）。
    let defaultBackupFolder: String
    /// 是否为正式运行（监听系统事件、启动本地服务）；截图程序中为 `false`。
    var isBackground: Bool { background }

    /// Touch ID 在这台 Mac 上是否可用（登记了指纹）。
    var touchIDAvailable: Bool { SecureEnclaveBridge.touchIDAvailable }

    /// 此时能否用 Touch ID 解锁。
    var touchIDUsable: Bool { touchIDEnabled && passwordReason == nil }

    private var environment: LocalEnvironment { .thisMac(localDir: localDir, enclave: enclave) }

    // MARK: - 打开

    /// 打开数据库。Secure Enclave 暂时不可用时进入 `.unavailable`，什么都不改变。
    func open(reenrolling: Bool) {
        errorMessage = nil
        do {
            vault = reenrolling
                ? try openVaultReenrolling(path: dbPath, local: environment)
                : try openVault(path: dbPath, local: environment)
            refreshLocalState()
            phase = .locked
            startBrowserService()
            startDeveloperServices()
            if background { startAutoBackup() }
        } catch KeevoError.EnclaveUnavailable {
            phase = .unavailable
        } catch {
            phase = .unavailable
            report(error)
        }
    }

    // MARK: - 账户与解锁

    func createAccount(password: String) async {
        await run {
            let (path, env) = (self.dbPath, self.environment)
            let account = try await Task.detached {
                try KeevoKit.createAccount(path: path, password: password, local: env)
            }.value
            self.vault = account.vault
            self.pendingSecretKey = account.secretKey
            try self.didUnlock()
            self.startBrowserService()
            self.startDeveloperServices()
        }
    }

    /// 解锁。`secretKey` 为空时只用主密码，账户密钥取自本机包裹。主密码不正确、需要账户密钥时不设错误信息，
    /// 由锁屏就地说明（设计稿"锁屏改版"）。
    func unlock(password: String, secretKey: String) async {
        guard let vault else { return }
        let manual = secretKey.trimmingCharacters(in: .whitespaces)
        wrongCredentials = false
        await run {
            do {
                try await Task.detached {
                    if manual.isEmpty {
                        try vault.unlockWithPassword(password: password)
                    } else {
                        try vault.unlock(password: password, secretKey: manual)
                    }
                }.value
            } catch KeevoError.WrongCredentials {
                self.wrongCredentials = true
                self.failedUnlocks += 1
                return
            } catch KeevoError.SecretKeyRequired {
                // 锁屏随之显示账户密钥输入框与原因
                self.needsSecretKey = true
                return
            } catch KeevoError.KdfNeedsConfirmation {
                self.pendingKdf = try? vault.kdfParams()
                return
            }
            try self.didUnlock()
        }
    }

    /// 用户确认了异常的 KDF 参数之后解锁。确认的必须正是此刻的参数，否则不执行派生。
    func unlockConfirmingKdf(password: String, secretKey: String, confirmed: KdfInfo) async {
        guard let vault else { return }
        pendingKdf = nil
        let manual = secretKey.trimmingCharacters(in: .whitespaces)
        wrongCredentials = false
        await run {
            do {
                try await Task.detached {
                    try vault.unlockConfirmingKdf(
                        password: password, secretKey: manual.isEmpty ? nil : manual, confirmed: confirmed
                    )
                }.value
            } catch KeevoError.WrongCredentials {
                self.wrongCredentials = true
                self.failedUnlocks += 1
                return
            }
            try self.didUnlock()
        }
    }

    /// 用 Touch ID 解锁。用户取消时不显示错误。
    func unlockWithTouchID() async {
        guard let vault, touchIDUsable, !busy else { return }
        await run {
            defer { self.refreshLocalState() }
            do {
                try await Task.detached { try vault.unlockWithTouchId() }.value
            } catch KeevoError.Cancelled {
                return
            }
            try self.didUnlock()
        }
    }

    /// 应用回到前台时：锁定且可以用 Touch ID，就直接弹出 Touch ID（docs/ux.md §3.2"默认用 Touch ID"）。
    func appDidBecomeActive() {
        guard phase == .locked, !autoPrompted else { return }
        refreshLocalState()
        guard touchIDUsable else { return }
        autoPrompted = true
        Task { await unlockWithTouchID() }
    }

    /// 启用 Touch ID：需要再输入一次主密码。
    func enableTouchID(password: String) async -> Bool {
        guard let vault else { return false }
        var ok = false
        await run {
            try await Task.detached { try vault.enableTouchId(password: password) }.value
            self.refreshLocalState()
            ok = true
        }
        return ok
    }

    /// 关闭 Touch ID：先重新验证（docs/ux.md §5）。`password` 为 `nil` 时用 Touch ID 验证。用户取消时不显示错误。
    func disableTouchID(password: String?) async -> Bool {
        guard let vault else { return false }
        var ok = false
        await run {
            defer { self.refreshLocalState() }
            do {
                try await Task.detached { try vault.disableTouchId(password: password) }.value
            } catch KeevoError.Cancelled {
                return
            }
            ok = true
        }
        return ok
    }

    func setPasswordInterval(days: UInt8) {
        guard let vault else { return }
        perform {
            try vault.setPasswordIntervalDays(days: days)
            self.refreshLocalState()
        }
    }

    // MARK: - 浏览器扩展

    /// 启动浏览器扩展的本地服务（spec/ipc.md）。没有从打包的应用运行时（未编译进 host 的 cdhash）启动失败，
    /// 应用其余功能不受影响。
    private func startBrowserService() {
        guard background, let vault else { return }
        do {
            _ = try vault.startBrowserService(prompt: browserPrompt)
            browserServiceError = nil
        } catch {
            browserServiceError = Self.describe(error)
        }
    }

    /// 浏览器保存或更新了条目：刷新列表与授权。
    func reloadAfterBrowserWrite() {
        guard phase == .unlocked else { return }
        try? reload()
        refreshBrowserPairings()
    }

    func refreshBrowserPairings() {
        browserPairings = vault?.browserPairings() ?? []
        var authorizations: [String: [BrowserAuthorization]] = [:]
        for p in browserPairings {
            authorizations[p.id] = (try? vault?.browserAuthorizations(pairingId: p.id)) ?? []
        }
        browserAuthorizations = authorizations
    }

    /// 撤销一项站点授权：之后这个扩展再在该网站上使用该条目，需要重新确认。
    func revokeBrowserAuthorization(pairingId: String, itemId: String, site: String) {
        guard let vault else { return }
        let persisted = (try? vault.revokeBrowserAuthorization(pairingId: pairingId, itemId: itemId, site: site)) ?? false
        authorizationRevokeWarning = !persisted
        refreshBrowserPairings()
    }

    /// 填充确认：逐个网站确认，或这个扩展在所有网站上都不再询问（spec/ipc.md §5.2 第 1 条）。
    /// 改回逐个网站确认后，之前逐项授权的网站仍然有效。
    func setBrowserFillAllSites(id: String, enabled: Bool) {
        fillScopeSaveFailed = !((try? vault?.setBrowserFillAllSites(pairingId: id, enabled: enabled)) ?? false)
        refreshBrowserPairings()
    }

    /// 用户确认后恢复被暂停的配对（spec/ipc.md §5.2 第 3 条）。
    func resumeBrowserPairing(id: String) {
        try? vault?.resumeBrowserPairing(pairingId: id)
        if pausedPairing?.id == id { pausedPairing = nil }
        refreshBrowserPairings()
    }

    /// 解除配对：先重新验证（docs/ux.md §5），再删除记录并立即断开（spec/ipc.md §4.4）。
    func revokeBrowserPairing(id: String, password: String?) async -> Bool {
        guard let vault else { return false }
        var ok = false
        await run {
            do {
                try await Task.detached { try vault.reverify(password: password) }.value
            } catch KeevoError.Cancelled {
                return
            }
            let persisted = try vault.revokeBrowserPairing(id: id)
            self.pendingRevocationWarning = !persisted
            self.refreshBrowserPairings()
            ok = true
        }
        return ok
    }

    /// 锁定：Rust 端清除全部密钥，界面同时丢弃所有已解密的数据。
    func lock() {
        vault?.lock()
        wrongCredentials = false
        vaults = []
        items = []
        sshKeys = []
        cliSessions = []
        recentSshUse = []
        browserPairings = []
        browserAuthorizations = [:]
        browserDialog = nil
        pausedPairing = nil
        securityTask?.cancel()
        securityReport = nil
        showingImport = false
        showingExport = false
        showingPractice = false
        onboardingStep = nil
        clearPreviews()
        breachChecking = false
        pendingSecretKey = nil
        pendingKdf = nil
        dataVersion &+= 1
        Clipboard.clearIfOwned()
        if vault != nil {
            phase = .locked
            autoPrompted = false
            refreshLocalState()
        }
    }

    private func didUnlock() throws {
        lockNotice = nil
        // 首次使用中途锁定或退出过：接着进行
        if onboardingStep == nil, let saved = savedOnboardingStep { onboardingStep = saved }
        refreshLocalState()
        try reload()
        phase = .unlocked
        // 扩展弹窗里点了"解锁"：2 分钟内解锁就回到那个浏览器，扩展会重新打开弹窗（spec/ipc.md §5.6）
        if case .browser(_, let bundleID, let since) = unlockWaiter, Date().timeIntervalSince(since) < 120 {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { returnToBrowser(bundleID) }
        }
        unlockWaiter = nil
        refreshDeveloper()
        schedulePracticeReminder()
    }

    private func refreshLocalState() {
        guard let vault else { return }
        needsSecretKey = !vault.hasLocalSecretKey()
        touchIDEnabled = vault.touchIdEnabled()
        passwordReason = vault.touchIDBlocker()
        passwordIntervalDays = (try? vault.passwordIntervalDays()) ?? 14
    }

    // MARK: - 自动锁定

    /// 闲置检测：按整个系统的最后一次键盘、鼠标或触控板输入计时，而不只看 Keevo 的窗口。
    private func startIdleTimer() {
        idleTimer = Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                // 首次使用期间不因闲置锁定（保险库还是空的；睡眠与锁屏照常锁定）
                guard let self, self.phase == .unlocked, !self.busy, self.onboardingStep == nil else { return }
                if Self.systemIdleSeconds() >= TimeInterval(self.autoLockMinutes * 60) {
                    self.lock()
                }
            }
        }
    }

    static func systemIdleSeconds() -> TimeInterval {
        guard let anyInput = CGEventType(rawValue: UInt32.max) else { return 0 }
        return CGEventSource.secondsSinceLastEventType(.combinedSessionState, eventType: anyInput)
    }

    /// 系统睡眠、屏幕锁定、屏幕保护程序启动或切换用户时自动锁定（docs/ux.md §3.8）。
    private func observeSystemLockEvents() {
        let workspace = NSWorkspace.shared.notificationCenter
        for name in [NSWorkspace.willSleepNotification, NSWorkspace.screensDidSleepNotification,
                     NSWorkspace.sessionDidResignActiveNotification] {
            observers.append(workspace.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.lock() }
            })
        }
        for name in ["com.apple.screenIsLocked", "com.apple.screensaver.didstart"] {
            observers.append(DistributedNotificationCenter.default().addObserver(
                forName: Notification.Name(name), object: nil, queue: .main
            ) { [weak self] _ in
                MainActor.assumeIsolated { self?.lock() }
            })
        }
        observers.append(NotificationCenter.default.addObserver(
            forName: NSApplication.didBecomeActiveNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.appDidBecomeActive() }
        })
        // 新打开的窗口与弹出的面板都要套用截屏设置
        for name in [NSWindow.didBecomeKeyNotification, NSWindow.didBecomeMainNotification] {
            observers.append(NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main) { [weak self] note in
                MainActor.assumeIsolated {
                    if let window = note.object as? NSWindow { self?.applyCapturePolicy(window) }
                }
            })
        }
    }

    private func applyCapturePolicy(_ window: NSWindow) {
        window.sharingType = hideFromScreenCapture ? .none : .readOnly
    }

    // MARK: - 条目

    @discardableResult
    func createLogin(vaultId: String, title: String, username: String, password: String, url: String) -> String? {
        guard let vault else { return nil }
        var id: String?
        perform {
            id = try vault.createLogin(
                vaultId: vaultId,
                input: LoginInput(title: title, username: username, password: password, url: url)
            )
            try self.reload()
        }
        return id
    }

    /// 按类型模板新建条目，返回条目 ID（docs/product.md §5.3）。
    func createItem(vaultId: String, itemType: String, preset: String?, title: String) -> String? {
        guard let vault else { return nil }
        var id: String?
        perform {
            id = try vault.createItem(vaultId: vaultId, itemType: itemType, preset: preset, title: title)
            try self.reload()
        }
        return id
    }

    /// 搜索（过滤语法见 keevo-core::search），返回按相关度排序的条目 ID。出错时返回空列表。
    func search(_ query: String) -> [String] {
        guard let vault else { return [] }
        return (try? vault.search(query: query)) ?? []
    }

    /// 一次性密码字段此刻的验证码。
    func otpCode(itemId: String, fieldId: String) -> OtpCodeEntry? {
        try? vault?.otpCode(itemId: itemId, fieldId: fieldId)
    }

    /// 把恢复码标记为已使用或未使用：重写整个恢复码列表（spec/vault-format.md §2.3）。
    func setCodeUsed(itemId: String, field: FieldEntry, index: Int, used: Bool) {
        let codes = field.codes.enumerated().map { i, c in
            CodeInput(code: c.code.expose(), used: i == index ? used : c.used)
        }
        mutate { try $0.updateItem(itemId: itemId, edits: [.setFieldCodes(fieldId: field.id, codes: codes)]) }
    }

    func detail(of itemId: String) -> ItemDetail? {
        guard let vault else { return nil }
        do {
            return try vault.item(itemId: itemId)
        } catch KeevoError.NotFound {
            return nil
        } catch {
            report(error)
            return nil
        }
    }

    /// 保存编辑。错误交给调用方展示（编辑界面需要区分"过大"与"需要重建"）。
    /// `force` 时即使没有编辑也写入一个收敛修订，用于确认撤销删除等状态（spec/revisions.md §5.4）。
    func update(itemId: String, edits: [ItemEdit], force: Bool = false) throws {
        guard let vault, !edits.isEmpty || force else { return }
        do {
            try vault.updateItem(itemId: itemId, edits: edits)
        } catch KeevoError.Locked {
            lock()
            throw KeevoError.Locked
        }
        try reload()
    }

    func setFavorite(itemId: String, _ favorite: Bool) {
        mutate { try $0.updateItem(itemId: itemId, edits: [.setFavorite(favorite: favorite)]) }
    }

    func trash(itemId: String) {
        mutate { try $0.trashItem(itemId: itemId) }
    }

    func restore(itemId: String) {
        mutate { try $0.restoreItem(itemId: itemId) }
    }

    func purge(itemId: String) {
        mutate { try $0.purgeItem(itemId: itemId) }
    }

    func history(of itemId: String) -> [HistoryItem] {
        guard let vault else { return [] }
        do {
            return try vault.history(itemId: itemId)
        } catch {
            report(error)
            return []
        }
    }

    func revisionFields(itemId: String, revId: String) -> [FieldEntry]? {
        try? vault?.revisionFields(itemId: itemId, revId: revId)
    }

    func restoreVersion(itemId: String, revId: String) {
        mutate { try $0.restoreVersion(itemId: itemId, revId: revId) }
    }

    func resolveConflict(itemId: String, key: String, revId: String) {
        mutate { try $0.resolveConflict(itemId: itemId, key: key, revId: revId) }
    }

    /// 重建为新条目（spec/revisions.md §7.1），返回新条目的 ID。
    func rebuild(itemId: String) throws -> String? {
        guard let vault else { return nil }
        let result = try vault.rebuildItem(itemId: itemId, drop: [])
        try reload()
        if !result.skippedAttachments.isEmpty {
            // 内容已损坏、读不出的附件没有保留：告诉用户是哪些（第五轮评审问题 5）
            showToast(tr("有 {} 个附件已损坏，没有保留：{}", "\(result.skippedAttachments.count)", result.skippedAttachments.joined(separator: tr("、"))))
        }
        return result.itemId
    }

    // MARK: - 内部

    private func mutate(_ body: (KeevoVault) throws -> Void) {
        guard let vault else { return }
        perform {
            try body(vault)
            try self.reload()
        }
    }

    private func reload() throws {
        guard let vault else { return }
        vaults = try vault.vaults()
        items = try vault.items()
        // 排序键：汉字转为拼音后与拉丁字母混排（"阿里云"排在"Apple ID"旁边）。转换较慢，只在数据变化时算一次
        var keys = sortKeys
        for item in items where keys[item.title] == nil {
            keys[item.title] = Self.sortKey(item.title)
        }
        sortKeys = keys
        dataVersion &+= 1
        // 数据变化后稍等片刻再重新检查（连续编辑时只检查一次）
        scheduleSecurityCheck(after: .seconds(1))
    }

    /// 标题 → 排序键（拼音，小写）。
    private(set) var sortKeys: [String: String] = [:]

    static func sortKey(_ title: String) -> String {
        let latin = title.applyingTransform(.mandarinToLatin, reverse: false) ?? title
        return (latin.applyingTransform(.stripDiacritics, reverse: false) ?? latin).lowercased()
    }

    private func run(_ body: @escaping () async throws -> Void) async {
        busy = true
        errorMessage = nil
        defer { busy = false }
        do {
            try await body()
        } catch {
            report(error)
        }
    }

    private func perform(_ body: () throws -> Void) {
        do {
            try body()
        } catch {
            report(error)
        }
    }

    func report(_ error: Error) {
        if case KeevoError.Locked = error {
            lock()
            return
        }
        errorMessage = Self.describe(error)
    }

    static func describe(_ error: Error) -> String {
        guard let error = error as? KeevoError else { return tr("发生了意外错误。") }
        switch error {
        case .WrongCredentials:
            return tr("主密码或账户密钥不正确。")
        case .SecretKeyRequired:
            return tr("这台 Mac 上没有可用的账户密钥（例如数据是从别处恢复的）。请从应急包中输入账户密钥，之后只需主密码。")
        case .TouchIdUnavailable:
            return tr("现在不能使用 Touch ID，请输入主密码。")
        case .AuthenticationFailed:
            return tr("Touch ID 未能识别指纹。")
        case .EnclaveUnavailable:
            return tr("Secure Enclave 暂时不可用，请稍后重试。")
        case .Cancelled:
            return tr("已取消。")
        case .InvalidSecretKey(let code) where code == "checksum_mismatch":
            return tr("账户密钥校验失败，请检查是否有输错的字符。")
        case .InvalidSecretKey:
            return tr("账户密钥格式不正确，应形如 K1-XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX。")
        case .Tampered:
            return tr("数据似乎被篡改或损坏了，Keevo 已阻止打开它。你可以从历史版本恢复。")
        case .Locked:
            return tr("保险库已锁定。")
        case .DeveloperServiceUnavailable(let reason) where reason.contains("cdhash was not compiled in"):
            return tr("请从打包的 Keevo.app 运行（scripts/package-macos.sh），命令行工具与 SSH Agent 才能使用。")
        case .DeveloperServiceUnavailable(let reason):
            return tr("无法启动：{}", "\(reason)")
        case .SshKey(let code, let detail):
            return sshKeyProblem(code: code, detail: detail)
        case .Backup(let code) where code == "other_account":
            return tr("这份备份属于另一个 Keevo 账户，不能用来恢复这个保险库。")
        case .Backup(let code) where code == "newer_version":
            return tr("这份备份来自更新版本的 Keevo，请先更新 Keevo。")
        case .Backup:
            return tr("这不是 Keevo 备份文件，或者文件已损坏。")
        case .KdfNeedsConfirmation:
            return tr("这个保险库的解锁参数异常地高，可能被篡改过。为安全起见，Keevo 没有自动解锁。")
        case .ItemTooLarge:
            return tr("这个条目合并其他设备的内容后过大，无法保存。请先处理冲突或删除部分字段。")
        case .ItemNeedsRebuild:
            return tr("这个条目合并其他设备的内容后超出了上限，只能查看。可以把它重建为一个新条目后继续编辑。")
        case .NotFound:
            return tr("这个条目已不存在。")
        case .BrowserServiceUnavailable(let reason) where reason.contains("cdhash"):
            return tr("这个构建没有编译进 native host 的 cdhash，请用 scripts/package-macos.sh 打包后运行。")
        case .BrowserServiceUnavailable(let reason):
            return tr("浏览器服务无法启动（{}）。", "\(reason)")
        default:
            return tr("操作失败：{}", "\(error)")
        }
    }

    /// 解锁界面说明为什么这次需要主密码（docs/ux.md §2"锁屏"）。没有启用 Touch ID 时不说明。
    var passwordReasonText: String? {
        guard touchIDEnabled || passwordReason == .invalidated else { return nil }
        switch passwordReason {
        case .restarted: return tr("Mac 重启后需要输入一次主密码，之后可以用 Touch ID。")
        case .intervalElapsed: return tr("距上次输入主密码已超过 {} 天，请输入一次主密码。", "\(passwordIntervalDays)")
        case .tooManyFailures: return tr("Touch ID 连续多次未能识别，请输入主密码。")
        case .invalidated: return tr("Touch ID 已失效（例如指纹有变化）。输入主密码后会自动恢复。")
        case .notEnabled, nil: return nil
        }
    }
}

/// 剪贴板：标记为隐藏/临时内容，90 秒后若内容仍是 Keevo 写入的值则清除（docs/ux.md §5）。
enum Clipboard {
    private static var ownedChangeCount: Int?
    static let clearAfter: TimeInterval = 90

    @MainActor
    static func copy(_ value: String) {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.declareTypes([.string, .init("org.nspasteboard.ConcealedType"), .init("org.nspasteboard.TransientType")], owner: nil)
        pb.setString(value, forType: .string)
        pb.setString("", forType: .init("org.nspasteboard.ConcealedType"))
        pb.setString("", forType: .init("org.nspasteboard.TransientType"))
        let count = pb.changeCount
        ownedChangeCount = count
        DispatchQueue.main.asyncAfter(deadline: .now() + clearAfter) {
            MainActor.assumeIsolated {
                if NSPasteboard.general.changeCount == count { clearIfOwned() }
            }
        }
    }

    @MainActor
    static func clearIfOwned() {
        guard let owned = ownedChangeCount, NSPasteboard.general.changeCount == owned else { return }
        NSPasteboard.general.clearContents()
        ownedChangeCount = nil
    }
}
