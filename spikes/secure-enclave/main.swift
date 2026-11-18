// 技术验证：不绑定任何 Apple 开发者团队时，Secure Enclave 与钥匙串能做什么（ADR-0003）。
//
//   swiftc -O spikes/secure-enclave/main.swift -o /tmp/keevo-se-spike
//   codesign -s - -f /tmp/keevo-se-spike        # 临时签名，没有 Team ID、没有任何 entitlement
//   /tmp/keevo-se-spike
//
// 不会弹出任何认证提示：需要用户在场的密钥只创建、不使用。钥匙串中的测试项写入后立即删除。

import CryptoKit
import Foundation
import LocalAuthentication
import Security

var failures = 0
func report(_ id: String, _ name: String, _ ok: Bool, _ detail: String) {
    print("[\(id)] \(ok ? "通过" : "失败") \(name)：\(detail)")
    if !ok { failures += 1 }
}

// 1. 环境
let la = LAContext()
var laError: NSError?
let biometryReady = la.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &laError)
print("[环境] SecureEnclave.isAvailable = \(SecureEnclave.isAvailable)；biometryType = \(la.biometryType.rawValue)；"
      + "生物识别可用 = \(biometryReady)\(laError.map { "（\($0.code) \($0.localizedDescription)）" } ?? "")")

// 2. Touch ID 解锁的包裹方式：SE 密钥协商 + HKDF + AES-GCM 包裹 32 字节的 AUK，SE 密钥以 blob 形式存成普通文件
do {
    let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey()
    let blob = seKey.dataRepresentation
    let auk = SymmetricKey(size: .bits256)
    // 包裹：临时密钥与 SE 公钥协商
    let eph = P256.KeyAgreement.PrivateKey()
    let wrapKey = try eph.sharedSecretFromKeyAgreement(with: seKey.publicKey)
        .hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(), sharedInfo: Data("keevo/v1/se-wrap".utf8), outputByteCount: 32)
    let sealed = try AES.GCM.seal(auk.withUnsafeBytes { Data($0) }, using: wrapKey)
    // 解包：只凭 blob 恢复 SE 密钥
    let restored = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob)
    let unwrapKey = try restored.sharedSecretFromKeyAgreement(with: eph.publicKey)
        .hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(), sharedInfo: Data("keevo/v1/se-wrap".utf8), outputByteCount: 32)
    let opened = try AES.GCM.open(sealed, using: unwrapKey)
    report("2", "SE 密钥包裹与解包 AUK（blob 存成文件，不用钥匙串）", opened == auk.withUnsafeBytes { Data($0) },
           "blob \(blob.count) 字节")
} catch { report("2", "SE 密钥包裹与解包 AUK", false, "\(error)") }

// 3. M2 的设备签名密钥：SE 签名密钥，不需要用户在场
do {
    let key = try SecureEnclave.P256.Signing.PrivateKey()
    let msg = Data("segment".utf8)
    let sig = try key.signature(for: msg)
    report("3", "SE 签名密钥（设备签名，M2）", key.publicKey.isValidSignature(sig, for: msg), "签名可验证")
} catch { report("3", "SE 签名密钥", false, "\(error)") }

// 4–5. 需要用户在场的 SE 密钥（只创建，使用时才会弹出认证）
for (id, name, flags) in [("4", "userPresence（Touch ID 或登录密码）", SecAccessControlCreateFlags([.privateKeyUsage, .userPresence])),
                          ("5", "biometryCurrentSet（仅 Touch ID，指纹变化即失效）", SecAccessControlCreateFlags([.privateKeyUsage, .biometryCurrentSet]))] {
    var err: Unmanaged<CFError>?
    guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &err) else {
        report(id, name, false, "访问控制创建失败"); continue
    }
    do {
        let k = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: ac)
        report(id, name, true, "创建成功（blob \(k.dataRepresentation.count) 字节）")
    } catch {
        let enrolled = biometryReady ? "" : "；本机未登记指纹，生物识别类访问控制无法创建，与团队无关"
        report(id, name, id == "5" && !biometryReady, "\((error as NSError).code) \(error.localizedDescription)\(enrolled)")
    }
}

// 6. 数据保护钥匙串：需要 keychain-access-groups 权限（团队签发），预期失败
func keychainAdd(_ dataProtection: Bool) -> OSStatus {
    var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                            kSecAttrService as String: "app.keevo.se-spike",
                            kSecAttrAccount as String: UUID().uuidString,
                            kSecValueData as String: Data("x".utf8)]
    if dataProtection { q[kSecUseDataProtectionKeychain as String] = true }
    let st = SecItemAdd(q as CFDictionary, nil)
    if st == errSecSuccess { SecItemDelete(q as CFDictionary) }
    return st
}
let dp = keychainAdd(true)
report("6", "数据保护钥匙串不可用（预期）", dp == errSecMissingEntitlement, "OSStatus \(dp)")
// 7. 传统登录钥匙串：不需要权限
let legacy = keychainAdd(false)
report("7", "登录钥匙串可用", legacy == errSecSuccess, "OSStatus \(legacy)")

print(failures == 0 ? "全部符合预期" : "\(failures) 项不符合预期")
exit(failures == 0 ? 0 : 1)
