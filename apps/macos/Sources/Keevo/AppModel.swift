// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）

import AppKit
import Foundation
import KeevoKit
import Observation

/// 应用状态。所有耗时的 Rust 调用（Argon2id 约 1 秒）都放到后台执行，界面保持响应。
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
    /// 新建账户后只展示一次的账户密钥。
    var pendingSecretKey: String?
    private(set) var vaults: [VaultEntry] = []
    private(set) var items: [ItemEntry] = []

    /// 本机没有可用的账户密钥，解锁时需要用户从应急包输入。
    private(set) var needsSecretKey = false
    /// Touch ID 已启用且未失效。
    private(set) var touchIDEnabled = false

    private var vault: KeevoVault?
    private let dbPath: String
    private let localDir: String
    private let enclave = SecureEnclaveBridge(touchIDReason: "解锁 Keevo")
    private var observers: [NSObjectProtocol] = []

    init() {
        // 数据目录（ADR-0003）：数据库与本机密钥目录（spec/crypto.md §8.7）
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Keevo", isDirectory: true)
        try? FileManager.default.createDirectory(
            at: support, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]
        )
        dbPath = support.appendingPathComponent("vault.sqlite").path
        localDir = support.appendingPathComponent("local", isDirectory: true).path
        if FileManager.default.fileExists(atPath: dbPath) {
            open(reenrolling: false)
        }
        observeSystemLockEvents()
    }

    /// Touch ID 在这台 Mac 上是否可用（登记了指纹）。
    var touchIDAvailable: Bool { SecureEnclaveBridge.touchIDAvailable }

    // MARK: - 打开

    /// 打开数据库。Secure Enclave 暂时不可用时进入 `.unavailable`，什么都不改变。
    func open(reenrolling: Bool) {
        errorMessage = nil
        do {
            let opened = reenrolling
                ? try openVaultReenrolling(path: dbPath, localDir: localDir, enclave: enclave)
                : try openVault(path: dbPath, localDir: localDir, enclave: enclave)
            vault = opened
            refreshLocalState()
            phase = .locked
        } catch KeevoError.EnclaveUnavailable {
            phase = .unavailable
        } catch {
            phase = .unavailable
            report(error)
        }
    }

    // MARK: - 账户

    func createAccount(password: String) async {
        await run {
            let (path, localDir, enclave) = (self.dbPath, self.localDir, self.enclave)
            let account = try await Task.detached {
                try KeevoKit.createAccount(path: path, password: password, localDir: localDir, enclave: enclave)
            }.value
            self.vault = account.vault
            self.pendingSecretKey = account.secretKey
            self.refreshLocalState()
            try self.reload()
            self.phase = .unlocked
        }
    }

    /// 解锁。`secretKey` 为空时只用主密码，账户密钥取自本机包裹。
    func unlock(password: String, secretKey: String) async {
        guard let vault else { return }
        let manual = secretKey.trimmingCharacters(in: .whitespaces)
        await run {
            do {
                try await Task.detached {
                    if manual.isEmpty {
                        try vault.unlockWithPassword(password: password)
                    } else {
                        try vault.unlock(password: password, secretKey: manual)
                    }
                }.value
            } catch KeevoError.SecretKeyRequired {
                self.needsSecretKey = true
                throw KeevoError.SecretKeyRequired
            }
            try self.didUnlock()
        }
    }

    /// 用 Touch ID 解锁。用户取消时不显示错误。
    func unlockWithTouchID() async {
        guard let vault, touchIDEnabled else { return }
        await run {
            do {
                try await Task.detached { try vault.unlockWithTouchId() }.value
            } catch KeevoError.Cancelled {
                return
            } catch KeevoError.TouchIdUnavailable {
                self.refreshLocalState()
                throw KeevoError.TouchIdUnavailable
            }
            try self.didUnlock()
        }
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

    func disableTouchID() {
        guard let vault else { return }
        perform {
            try vault.disableTouchId()
            self.refreshLocalState()
        }
    }

    /// 锁定：Rust 端清除全部密钥，界面同时丢弃所有已解密的数据。
    func lock() {
        vault?.lock()
        vaults = []
        items = []
        pendingSecretKey = nil
        Clipboard.clearIfOwned()
        if vault != nil { phase = .locked }
    }

    private func didUnlock() throws {
        refreshLocalState()
        try reload()
        phase = .unlocked
    }

    private func refreshLocalState() {
        guard let vault else { return }
        needsSecretKey = !vault.hasLocalSecretKey()
        touchIDEnabled = vault.touchIdEnabled()
    }

    // MARK: - 条目

    func createLogin(vaultId: String, title: String, username: String, password: String, url: String) {
        guard let vault else { return }
        perform {
            _ = try vault.createLogin(
                vaultId: vaultId,
                input: LoginInput(title: title, username: username, password: password, url: url)
            )
            try self.reload()
        }
    }

    func fields(of itemId: String) -> [FieldEntry] {
        guard let vault else { return [] }
        do {
            return try vault.fields(itemId: itemId)
        } catch {
            report(error)
            return []
        }
    }

    func trash(itemId: String) {
        guard let vault else { return }
        perform {
            try vault.trashItem(itemId: itemId)
            try self.reload()
        }
    }

    // MARK: - 内部

    private func reload() throws {
        guard let vault else { return }
        vaults = try vault.vaults()
        items = try vault.items()
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

    private func report(_ error: Error) {
        if case KeevoError.Locked = error {
            lock()
            return
        }
        errorMessage = Self.describe(error)
    }

    static func describe(_ error: Error) -> String {
        guard let error = error as? KeevoError else { return "发生了意外错误。" }
        switch error {
        case .WrongCredentials:
            return "主密码或账户密钥不正确。"
        case .SecretKeyRequired:
            return "这台 Mac 上没有可用的账户密钥（例如数据是从别处恢复的）。请从应急包中输入账户密钥，之后只需主密码。"
        case .TouchIdUnavailable:
            return "Touch ID 已失效（例如指纹有变化）。请输入主密码解锁，Touch ID 会随后自动恢复。"
        case .EnclaveUnavailable:
            return "Secure Enclave 暂时不可用，请稍后重试。"
        case .Cancelled:
            return "已取消。"
        case .InvalidSecretKey(let code) where code == "checksum_mismatch":
            return "账户密钥校验失败，请检查是否有输错的字符。"
        case .InvalidSecretKey:
            return "账户密钥格式不正确，应形如 K1-XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX。"
        case .Tampered:
            return "数据似乎被篡改或损坏了，Keevo 已阻止打开它。"
        case .Locked:
            return "保险库已锁定。"
        case .KdfNeedsConfirmation:
            return "这个保险库的解锁参数异常地高，可能被篡改过。为安全起见，Keevo 没有自动解锁。"
        case .ItemTooLarge:
            return "这个条目合并其他设备的内容后过大，无法保存。请先处理冲突或删除部分字段。"
        case .ItemNeedsRebuild:
            return "这个条目合并其他设备的内容后超出了上限，只能查看和导出。可以把它重建为一个新条目后继续编辑。"
        default:
            return "操作失败：\(error)"
        }
    }

    /// 系统睡眠、屏幕锁定或切换用户时自动锁定（docs/ux.md §3.8）。
    private func observeSystemLockEvents() {
        let workspace = NSWorkspace.shared.notificationCenter
        for name in [NSWorkspace.willSleepNotification, NSWorkspace.screensDidSleepNotification,
                     NSWorkspace.sessionDidResignActiveNotification] {
            observers.append(workspace.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.lock() }
            })
        }
        observers.append(DistributedNotificationCenter.default().addObserver(
            forName: Notification.Name("com.apple.screenIsLocked"), object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.lock() }
        })
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
