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

    private var vault: KeevoVault?
    private let dbPath: String
    private var observers: [NSObjectProtocol] = []

    init() {
        // M0 空壳：存放在 Application Support。M1 改为 App Group 容器（docs/architecture.md §4.3）
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Keevo-M0", isDirectory: true)
        try? FileManager.default.createDirectory(at: support, withIntermediateDirectories: true)
        dbPath = support.appendingPathComponent("vault.sqlite").path

        if FileManager.default.fileExists(atPath: dbPath), let opened = try? openVault(path: dbPath) {
            vault = opened
            phase = .locked
        }
        observeSystemLockEvents()
    }

    // MARK: - 账户

    func createAccount(password: String) async {
        await run {
            let path = self.dbPath
            let account = try await Task.detached { try KeevoKit.createAccount(path: path, password: password) }.value
            self.vault = account.vault
            self.pendingSecretKey = account.secretKey
            try self.reload()
            self.phase = .unlocked
        }
    }

    func unlock(password: String, secretKey: String) async {
        guard let vault else { return }
        await run {
            try await Task.detached { try vault.unlock(password: password, secretKey: secretKey) }.value
            try self.reload()
            self.phase = .unlocked
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
