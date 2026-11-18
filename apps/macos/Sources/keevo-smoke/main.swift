// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）
//
// 端到端冒烟测试：经 UniFFI 从 Swift 调用 Rust 核心，覆盖 M0 退出标准
// "创建 → 锁定 → 解锁 → 读写条目"，并验证重新打开数据库后数据完整；
// 以及 M1.1 的条目详情、批量编辑、历史与恢复、回收站与永久删除；
// 本机密钥包裹使用本机真实的 Secure Enclave（不要求用户在场的用途，不会弹出提示）；
// 没有 Secure Enclave 的机器（CI 的虚拟机）改用只存在于本测试中的软件实现。

import CryptoKit
import Foundation
import KeevoKit

if let code = runTouchIDCheckIfRequested() ?? runDlopenCheckIfRequested() {
    exit(code)
}

var failures = 0

func check(_ condition: @autoclosure () throws -> Bool, _ message: String) {
    do {
        if try condition() {
            print("  ✓ \(message)")
            return
        }
        print("  ✗ \(message)")
    } catch {
        print("  ✗ \(message)：意外错误 \(error)")
    }
    failures += 1
}

func expectError(_ message: String, _ body: () throws -> Void, matches: (KeevoError) -> Bool) {
    do {
        try body()
        print("  ✗ \(message)：没有报错")
        failures += 1
    } catch let error as KeevoError where matches(error) {
        print("  ✓ \(message)")
    } catch {
        print("  ✗ \(message)：错误类型不符 \(error)")
        failures += 1
    }
}

let dir = FileManager.default.temporaryDirectory.appendingPathComponent("keevo-smoke-\(UUID().uuidString)")
try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
defer { try? FileManager.default.removeItem(at: dir) }
let db = dir.appendingPathComponent("vault.sqlite").path
let localDir = dir.appendingPathComponent("local").path
/// 没有 Secure Enclave 时（CI 的虚拟机）使用的软件实现：密钥以原始字节作为 blob。
/// 只用于冒烟测试，不随应用发布，因此不提供 Secure Enclave 的任何保护。
final class SoftwareEnclave: SecureEnclaveProvider, @unchecked Sendable {
    func createKey(purpose: UInt8) throws -> EnclaveKeyData {
        let key = P256.KeyAgreement.PrivateKey()
        return EnclaveKeyData(blob: key.rawRepresentation, publicKey: key.publicKey.x963Representation)
    }

    func agreeEphemeral(publicKey: Data) throws -> EphemeralAgreementData {
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: publicKey)
        let eph = P256.KeyAgreement.PrivateKey()
        let shared = try eph.sharedSecretFromKeyAgreement(with: peer)
        return EphemeralAgreementData(ephemeralPublic: eph.publicKey.x963Representation, shared: shared.withUnsafeBytes { Data($0) })
    }

    func agree(purpose: UInt8, keyBlob: Data, ephemeralPublic: Data) throws -> Data {
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublic)
        let key = try P256.KeyAgreement.PrivateKey(rawRepresentation: keyBlob)
        return try key.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Data($0) }
    }
}

/// `KEEVO_SMOKE_SOFTWARE_ENCLAVE=1` 强制使用软件实现，用于在本机验证 CI 走的路径。
let useSecureEnclave = SecureEnclave.isAvailable
    && ProcessInfo.processInfo.environment["KEEVO_SMOKE_SOFTWARE_ENCLAVE"] != "1"
let enclave: SecureEnclaveProvider = useSecureEnclave
    ? SecureEnclaveBridge(touchIDReason: "Keevo 冒烟测试")
    : SoftwareEnclave()
let password = "主密码 correct horse battery"

print("Keevo 冒烟测试（Swift → UniFFI → Rust）")

// 第一阶段放在单独的作用域里：离开作用域时第一个实例被释放。同一数据库同时只能有一个打开者
// （spec/revisions.md §7.2），重新打开之前必须先关闭。
let secretKey: String
let itemId: String
do {
    let created = try createAccount(path: db, password: password, local: .thisMac(localDir: localDir, enclave: enclave))
    let vault = created.vault
    check(vault.isUnlocked(), "创建账户后处于解锁状态")
    check(created.secretKey.hasPrefix("K1-") && created.secretKey.count == 34, "账户密钥为 K1- 显示格式")

    let personal = try vault.vaults()
    check(personal.count == 1 && personal[0].name == "个人", "默认保险库为「个人」")

    itemId = try vault.createLogin(
        vaultId: personal[0].id,
        input: LoginInput(title: "GitHub", username: "octocat", password: "s3cret-🔐", url: "https://github.com")
    )

    vault.lock()
    check(!vault.isUnlocked(), "锁定后处于锁定状态")
    expectError("锁定后无法读取条目", { _ = try vault.items() }) { if case .Locked = $0 { return true }; return false }
    expectError("错误的主密码无法解锁", { try vault.unlock(password: "wrong", secretKey: created.secretKey) }) {
        if case .WrongCredentials = $0 { return true }; return false
    }
    expectError("格式错误的账户密钥被识别", { try vault.unlock(password: password, secretKey: "K1-0000") }) {
        if case .InvalidSecretKey(let code) = $0 { return code == "wrong_length" }; return false
    }
    secretKey = created.secretKey
}

// 模拟应用重启：重新打开数据库文件，并用小写形式输入账户密钥
let reopened = try openVault(path: db, local: .thisMac(localDir: localDir, enclave: enclave))
check(!reopened.isUnlocked(), "重新打开后处于锁定状态")
try reopened.unlock(password: password, secretKey: secretKey.lowercased())
check(reopened.isUnlocked(), "用主密码与账户密钥解锁")

let items = try reopened.items()
check(items.count == 1 && items[0].title == "GitHub" && items[0].subtitle == "octocat", "条目概要正确")
let fields = try reopened.fields(itemId: itemId)
check(fields.contains { $0.concealed && $0.value == "s3cret-🔐" }, "密码字段可读且默认隐藏")
check(fields.contains { $0.kind == "url" && $0.value == "https://github.com" }, "网址字段可读")

try reopened.renameItem(itemId: itemId, title: "GitHub（工作）")
check(try reopened.items().first?.title == "GitHub（工作）", "修改标题后读回新值")

// M1.1：详情与批量编辑
let password0 = fields.first { $0.purpose == "password" }
check(password0 != nil, "密码字段带有自动填充用途")
try reopened.updateItem(itemId: itemId, edits: [
    .setFavorite(favorite: true),
    .addTag(tag: "work"),
    .setFieldValue(fieldId: password0?.id ?? "", value: "n3w-🔑"),
    .addField(kind: "text", label: "备注", purpose: nil, value: "多行\n备注"),
])
let detail = try reopened.item(itemId: itemId)
check(detail.favorite && detail.tags == ["work"] && detail.fields.count == 4, "一次写入应用多个编辑")
check(detail.fields.contains { $0.id == password0?.id && $0.value == "n3w-🔑" }, "字段值已修改")
check(detail.conflicts.isEmpty && detail.headCount == 1 && !detail.resurrected, "没有冲突与并发头")
expectError("不支持的字段类型被拒绝", {
    try reopened.updateItem(itemId: itemId, edits: [.addField(kind: "file", label: "x", purpose: nil, value: "")])
}) { if case .InvalidInput = $0 { return true }; return false }

// 历史与恢复到此版本
let history = try reopened.history(itemId: itemId)
check(history.count == 3 && history.last?.title == "GitHub", "历史从新到旧列出每次写入")
let firstRev = history.last?.revId ?? ""
check(try reopened.revisionFields(itemId: itemId, revId: firstRev).contains { $0.value == "s3cret-🔐" }, "可查看旧版本的字段")
try reopened.restoreVersion(itemId: itemId, revId: firstRev)
let restored = try reopened.item(itemId: itemId)
check(restored.title == "GitHub" && restored.tags.isEmpty && restored.fields.count == 3, "恢复到此版本")

// 回收站与永久删除
try reopened.trashItem(itemId: itemId)
check(try reopened.item(itemId: itemId).trashed, "移入回收站")
try reopened.restoreItem(itemId: itemId)
check(try !reopened.item(itemId: itemId).trashed, "从回收站恢复")
try reopened.purgeItem(itemId: itemId)
expectError("永久删除后读不到", { _ = try reopened.item(itemId: itemId) }) {
    if case .NotFound = $0 { return true }; return false
}
check(try reopened.items().isEmpty, "列表中不再出现")
check(try reopened.kdfParams().memoryKib > 0, "可读出 KDF 参数")

// M1.1：本机密钥包裹（spec/crypto.md §8.7），使用真实的 Secure Enclave
print(useSecureEnclave ? "本机密钥包裹（Secure Enclave）" : "本机密钥包裹（软件实现：本机没有 Secure Enclave，或已指定）")
let db2 = dir.appendingPathComponent("vault2.sqlite").path
let local2 = dir.appendingPathComponent("local2").path
let fm = FileManager.default

func currentGeneration() throws -> String {
    let n = try String(contentsOfFile: local2 + "/current", encoding: .utf8)
    return local2 + "/gen-" + n
}

func corrupt(_ file: String) throws {
    let path = try currentGeneration() + "/" + file
    var data = try Data(contentsOf: URL(fileURLWithPath: path))
    data[data.count / 2] ^= 0x01
    try data.write(to: URL(fileURLWithPath: path))
}

let secretKey2: String
do {
    let created = try createAccount(path: db2, password: password, local: .thisMac(localDir: local2, enclave: enclave))
    secretKey2 = created.secretKey
    check(created.vault.hasLocalSecretKey(), "新建账户后账户密钥已包裹到本机")
    check(!created.vault.touchIdEnabled(), "Touch ID 默认未启用")
}
do {
    let vault = try openVault(path: db2, local: .thisMac(localDir: local2, enclave: enclave))
    try vault.unlockWithPassword(password: password)
    check(vault.isUnlocked(), "重新打开后只用主密码解锁")
    vault.lock()
    expectError("只用主密码时，主密码错误被识别", { try vault.unlockWithPassword(password: "wrong") }) {
        if case .WrongCredentials = $0 { return true }; return false
    }
    let gen = try currentGeneration()
    let dirMode = (try fm.attributesOfItem(atPath: local2)[.posixPermissions] as? Int) ?? 0
    let fileModes = try ["02.key", "02.wrap", "04.key", "04.wrap"].map {
        (try fm.attributesOfItem(atPath: gen + "/" + $0)[.posixPermissions] as? Int) ?? 0
    }
    check(dirMode == 0o700 && fileModes.allSatisfy { $0 == 0o600 }, "本机密钥目录 0700、文件 0600")
    let wrapSize = (try fm.attributesOfItem(atPath: gen + "/02.wrap")[.size] as? Int) ?? 0
    check(wrapSize == 123, "账户密钥的包裹为 123 字节")
}

// 本机密钥目录丢失（相当于把数据库恢复到另一台 Mac）
try fm.removeItem(atPath: local2)
do {
    let vault = try openVault(path: db2, local: .thisMac(localDir: local2, enclave: enclave))
    check(!vault.hasLocalSecretKey(), "本机密钥丢失后需要账户密钥")
    expectError("只用主密码时要求账户密钥", { try vault.unlockWithPassword(password: password) }) {
        if case .SecretKeyRequired = $0 { return true }; return false
    }
    try vault.unlock(password: password, secretKey: secretKey2)
    check(vault.hasLocalSecretKey(), "输入账户密钥解锁后补登")
}
do {
    let vault = try openVault(path: db2, local: .thisMac(localDir: local2, enclave: enclave))
    try vault.unlockWithPassword(password: password)
    check(vault.isUnlocked(), "补登之后只用主密码解锁")
}

// 损坏的 blob：真实的 Secure Enclave 报告"失效"，而不是"暂时不可用"（软件实现中表现为解包认证失败）
try corrupt("02.key")
do {
    let vault = try openVault(path: db2, local: .thisMac(localDir: local2, enclave: enclave))
    expectError("账户密钥的 blob 损坏时要求账户密钥", { try vault.unlockWithPassword(password: password) }) {
        if case .SecretKeyRequired = $0 { return true }; return false
    }
    try vault.unlock(password: password, secretKey: secretKey2)
    check(vault.hasLocalSecretKey(), "重新包裹账户密钥")
}
try corrupt("04.key")
do {
    let vault = try openVault(path: db2, local: .thisMac(localDir: local2, enclave: enclave))
    check(!vault.hasLocalSecretKey(), "设备标记的 blob 损坏时重新登记本机，其余包裹随之作废")
    try vault.unlock(password: password, secretKey: secretKey2)
    check(vault.hasLocalSecretKey(), "重新登记后补登账户密钥")
}

if failures > 0 {
    print("失败 \(failures) 项")
    exit(1)
}
print("全部通过")
