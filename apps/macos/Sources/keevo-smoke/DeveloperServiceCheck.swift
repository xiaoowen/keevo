// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// `keevo-smoke --developer-service`：为打包产物的命令行工具与 SSH Agent 测试（scripts/package-macos.sh --verify）
// 提供服务。与 Keevo.app 链接同一份 Rust 静态库，因此同样只接受 cdhash 编译进来的 keevo（spec/cli.md §2）。
//
// - 在临时目录新建账户，添加一个登录与一把 Ed25519 SSH 密钥（Agent 策略为"解锁期间自动"）；
// - 经 FFI 启动命令行工具的服务与 SSH Agent（socket 位于 $HOME 下，测试把 HOME 指向临时目录）；
// - 会话授权与签名确认一律自动同意，并把每个事件打印为一行 "EVENT …"；
// - 打印 "VAULT <保险库名>" 与 READY，读到标准输入结束时退出。

import Foundation
import KeevoKit

final class AutoDeveloperPrompt: DeveloperPrompt, @unchecked Sendable {
    private func emit(_ line: String) {
        print("EVENT \(line)")
        fflush(stdout)
    }

    func unlockRequested(reason: String) { emit("unlock_requested \(reason)") }

    func authorizeCli(origin: RequestOrigin, timeoutMs: UInt64) -> Bool {
        emit("authorize_cli \(origin.command)")
        return true
    }

    func authorizeSsh(request: SshSignRequest, timeoutMs: UInt64) -> Bool {
        emit("authorize_ssh \(request.keyTitle)")
        return true
    }

    func sshSigned(request: SshSignRequest) { emit("ssh_signed \(request.keyTitle)") }

    func lockedByCli() { emit("locked_by_cli") }
}

func runDeveloperServiceIfRequested() -> Int32? {
    let args = CommandLine.arguments
    guard args.count == 2, args[1] == "--developer-service" else { return nil }
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("keevo-dev-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: dir) }
    do {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let created = try createAccount(
            path: dir.appendingPathComponent("vault.sqlite").path,
            password: "命令行测试的主密码",
            local: .thisMac(localDir: dir.appendingPathComponent("local").path, enclave: SoftwareEnclave())
        )
        let vault = created.vault
        let info = try vault.vaults()[0]
        _ = try vault.createLogin(
            vaultId: info.id,
            input: LoginInput(title: "打包测试", username: "admin", password: "packaged-cli-pass", url: "https://example.com")
        )
        let key = try vault.createItem(vaultId: info.id, itemType: "ssh_key", preset: nil, title: "打包测试密钥")
        _ = try vault.generateSshKey(itemId: key)
        try vault.setSshAgentPolicy(itemId: key, policy: "unlocked")
        try vault.startDeveloperServices(prompt: AutoDeveloperPrompt())
        let agent = try vault.setSshAgentEnabled(enabled: true)
        guard agent.running else {
            print("ERROR ssh agent not running")
            return 1
        }
        print("VAULT \(info.name)")
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
