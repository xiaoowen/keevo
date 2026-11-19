// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// `keevo-smoke --browser-service <网址>`：为打包产物的真实浏览器测试（apps/browser-extension/test/packaged.mjs）
// 提供 Vault Service。与 Keevo.app 链接同一份 Rust 静态库，因此同样只接受 cdhash 编译进来的 native host
// （spec/ipc.md §3.1）。
//
// - 在临时目录新建账户，添加一个网址为 <网址> 的登录；
// - 经 FFI 启动浏览器服务（socket 位于 $HOME 下，测试把 HOME 指向临时目录）；
// - 配对、填充授权、密码更新一律自动同意，并把每个事件打印为一行 "EVENT …"，供测试核对；
// - 打印 READY，读到标准输入结束时退出。

import CryptoKit
import Foundation
import KeevoKit

/// 自动同意的确认界面：把事件写到标准输出。
final class AutoBrowserPrompt: BrowserPrompt, @unchecked Sendable {
    private func emit(_ line: String) {
        print("EVENT \(line)")
        fflush(stdout)
    }

    func pairingStarted(browser: String) {
        emit("pairing_started \(browser)")
    }

    func confirmPairing(words: [SasWord], name: String, browser: String, timeoutMs: UInt64) -> Bool {
        emit("confirm_pairing \(name) \(words.map(\.zh).joined(separator: " "))")
        return true
    }

    func authorizeFill(request: BrowserFillRequest, timeoutMs: UInt64) -> Bool {
        emit("authorize_fill \(request.site) \(request.title)")
        return true
    }

    func fillPaused(pairingId: String, name: String, browser: String) {
        emit("fill_paused \(name)")
    }

    func confirmUpdate(request: BrowserUpdateRequest, changed: Bool, timeoutMs: UInt64) -> Bool {
        emit("confirm_update \(request.site) \(changed)")
        return true
    }

    func loginSaved(pairingName: String, browser: String, title: String) {
        emit("login_saved \(title)")
    }

    func queriesLimited(pairingId: String, name: String, browser: String) {
        emit("queries_limited \(name)")
    }
}

func runBrowserServiceIfRequested() -> Int32? {
    let args = CommandLine.arguments
    guard args.count == 3, args[1] == "--browser-service" else { return nil }
    let localURL = args[2]
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("keevo-browser-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: dir) }
    do {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let enclave: SecureEnclaveProvider = SecureEnclave.isAvailable
            && ProcessInfo.processInfo.environment["KEEVO_SMOKE_SOFTWARE_ENCLAVE"] != "1"
            ? SecureEnclaveBridge(touchIDReason: "Keevo 浏览器测试")
            : SoftwareEnclave()
        let created = try createAccount(
            path: dir.appendingPathComponent("vault.sqlite").path,
            password: "浏览器测试的主密码",
            local: .thisMac(localDir: dir.appendingPathComponent("local").path, enclave: enclave)
        )
        let vault = created.vault
        let vaultId = try vault.vaults()[0].id
        _ = try vault.createLogin(
            vaultId: vaultId,
            input: LoginInput(title: "本地开发（打包测试）", username: "admin", password: "packaged-pass", url: localURL)
        )
        _ = try vault.startBrowserService(prompt: AutoBrowserPrompt())
        print("READY")
        fflush(stdout)
        while readLine() != nil {}
        return 0
    } catch {
        print("ERROR \(error)")
        fflush(stdout)
        return 1
    }
}
