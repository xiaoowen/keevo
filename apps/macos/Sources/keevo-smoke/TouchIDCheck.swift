// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// Touch ID 实测（需要用户在场，不在 CI 中运行）。每一步的操作说明直接显示在系统的 Touch ID 提示里。
//
//   keevo-smoke --touch-id                    解锁、取消、指纹不匹配、恢复
//   keevo-smoke --touch-id-locked             锁屏期间使用 Secure Enclave 密钥报什么错
//   keevo-smoke --touch-id-change prepare DIR 指纹变化前：建立启用了 Touch ID 的保险库
//   keevo-smoke --touch-id-change check DIR   指纹变化后：确认 Touch ID 失效、主密码解锁后自动恢复
//
// 结果用于技术验证记录（docs/spikes/2026-11-18-secure-enclave-without-team.md）。

import Foundation
import KeevoKit

private let checkPassword = "touch-id 实测 correct horse"

private struct Step {
    var passed = 0
    var failed = 0

    mutating func expect(_ ok: Bool, _ message: String, detail: String? = nil) {
        if ok { passed += 1 } else { failed += 1 }
        print("  \(ok ? "✓" : "✗") \(message)\(detail.map { "（\($0)）" } ?? "")")
    }
}

private func outcome(_ body: () throws -> Void) -> String {
    do {
        try body()
        return "成功"
    } catch let error as KeevoError {
        return "\(error)"
    } catch {
        return "意外错误 \(error)"
    }
}

private func makeVault(dir: URL, enclave: SecureEnclaveBridge, touchID: Bool) throws -> KeevoVault {
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let local = LocalEnvironment.thisMac(localDir: dir.appendingPathComponent("local").path, enclave: enclave)
    let account = try createAccount(
        path: dir.appendingPathComponent("vault.sqlite").path, password: checkPassword, local: local
    )
    if touchID {
        try account.vault.enableTouchId(password: checkPassword)
    }
    return account.vault
}

private func reopen(dir: URL, enclave: SecureEnclaveBridge) throws -> KeevoVault {
    let local = LocalEnvironment.thisMac(localDir: dir.appendingPathComponent("local").path, enclave: enclave)
    return try openVault(path: dir.appendingPathComponent("vault.sqlite").path, local: local)
}

/// 解锁、取消、指纹不匹配、恢复。
private func checkPrompts() throws -> Step {
    var step = Step()
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("keevo-touchid-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: dir) }
    let enclave = SecureEnclaveBridge(touchIDReason: "")
    let vault = try makeVault(dir: dir, enclave: enclave, touchID: true)
    step.expect(vault.touchIdEnabled(), "启用 Touch ID（不弹出提示）")
    vault.lock()

    func attempt(_ n: Int, _ instruction: String) -> String {
        print("第 \(n) 步（共 4 步）：\(instruction)")
        enclave.touchIDReason = "第 \(n) 步：\(instruction)"
        vault.lock()
        return outcome { try vault.unlockWithTouchId() }
    }

    let r1 = attempt(1, "请用已登记的手指验证")
    step.expect(r1 == "成功" && vault.isUnlocked(), "已登记的手指：解锁", detail: r1)

    let r2 = attempt(2, "请点「取消」")
    step.expect(r2 == "\(KeevoError.Cancelled)", "取消：什么都不改变", detail: enclave.lastFailureDescription ?? r2)
    step.expect(vault.touchIdEnabled() && vault.touchIDBlocker() == nil, "取消后 Touch ID 仍可用")

    let r3 = attempt(3, "请用没有登记的手指（或指关节）按，直到提示消失")
    step.expect(
        r3 == "\(KeevoError.AuthenticationFailed)", "指纹不匹配：计入失败次数",
        detail: enclave.lastFailureDescription ?? r3
    )
    step.expect(vault.touchIdEnabled(), "指纹不匹配不等于失效")

    let r4 = attempt(4, "请用已登记的手指验证")
    step.expect(r4 == "成功", "再次用已登记的手指：解锁", detail: r4)
    step.expect(vault.touchIDBlocker() == nil, "成功后失败次数清零")
    return step
}

/// 锁屏期间：不要求用户在场的 Secure Enclave 密钥报什么错，Keevo 是否"什么都不改变"。
private func checkLockedScreen() throws -> Step {
    var step = Step()
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("keevo-locked-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: dir) }
    let enclave = SecureEnclaveBridge(touchIDReason: "")
    let vault = try makeVault(dir: dir, enclave: enclave, touchID: false)
    vault.lock()
    print("请在 10 秒内锁定屏幕（⌃⌘Q），保持锁定约 20 秒后再解锁。之后这里会打印结果。")
    Thread.sleep(forTimeInterval: 10)
    var seen: [String: Int] = [:]
    let deadline = Date().addingTimeInterval(30)
    while Date() < deadline {
        let opened = outcome { _ = try reopen(dir: dir, enclave: enclave) }
        let key = opened == "成功" ? "打开数据库：成功" : "打开数据库：\(opened)；\(enclave.lastFailureDescription ?? "")"
        seen[key, default: 0] += 1
        Thread.sleep(forTimeInterval: 2)
    }
    for (result, count) in seen.sorted(by: { $0.key < $1.key }) {
        print("  · \(result) × \(count)")
    }
    let afterward = try reopen(dir: dir, enclave: enclave)
    step.expect(afterward.hasLocalSecretKey(), "解锁屏幕后，本机的账户密钥仍可用（锁屏期间没有误判失效）")
    let unlocked = outcome { try afterward.unlockWithPassword(password: checkPassword) }
    step.expect(unlocked == "成功", "只用主密码解锁", detail: unlocked)
    return step
}

/// 指纹变化前后。
private func checkFingerprintChange(phase: String, dir: URL) throws -> Step {
    var step = Step()
    let enclave = SecureEnclaveBridge(touchIDReason: "Keevo 实测：请用已登记的手指验证")
    if phase == "prepare" {
        let vault = try makeVault(dir: dir, enclave: enclave, touchID: true)
        vault.lock()
        let r = outcome { try vault.unlockWithTouchId() }
        step.expect(r == "成功", "指纹变化前：Touch ID 解锁", detail: r)
        print("下一步：在「系统设置 › 触控 ID 与密码」中添加或删除一个指纹，然后运行 check。")
        return step
    }
    let vault = try reopen(dir: dir, enclave: enclave)
    let r = outcome { try vault.unlockWithTouchId() }
    step.expect(
        r == "\(KeevoError.TouchIdUnavailable)", "指纹变化后：Touch ID 失效",
        detail: "\(r)；\(enclave.lastFailureDescription ?? "无原始错误")"
    )
    step.expect(vault.touchIDBlocker() == .invalidated, "解锁界面说明原因：Touch ID 已失效")
    let p = outcome { try vault.unlockWithPassword(password: checkPassword) }
    step.expect(p == "成功" && vault.touchIdEnabled(), "主密码解锁后自动重新包裹", detail: p)
    vault.lock()
    let again = outcome { try vault.unlockWithTouchId() }
    step.expect(again == "成功", "之后 Touch ID 恢复可用", detail: again)
    try? FileManager.default.removeItem(at: dir)
    return step
}

/// 处理 `--touch-id*` 参数；没有这些参数时返回 `nil`，继续运行普通冒烟测试。
func runTouchIDCheckIfRequested() -> Int32? {
    let args = CommandLine.arguments
    guard let mode = args.dropFirst().first, mode.hasPrefix("--touch-id") else { return nil }
    guard SecureEnclaveBridge.touchIDAvailable else {
        print("这台 Mac 没有可用的 Touch ID，或还没有登记指纹。")
        return 1
    }
    do {
        let step: Step
        switch mode {
        case "--touch-id":
            step = try checkPrompts()
        case "--touch-id-locked":
            step = try checkLockedScreen()
        case "--touch-id-change" where args.count == 4 && ["prepare", "check"].contains(args[2]):
            step = try checkFingerprintChange(phase: args[2], dir: URL(fileURLWithPath: args[3]))
        default:
            print("用法：keevo-smoke --touch-id | --touch-id-locked | --touch-id-change prepare|check <目录>")
            return 2
        }
        print(step.failed == 0 ? "全部通过（\(step.passed) 项）" : "失败 \(step.failed) 项")
        return step.failed == 0 ? 0 : 1
    } catch {
        print("意外错误：\(error)")
        return 1
    }
}
