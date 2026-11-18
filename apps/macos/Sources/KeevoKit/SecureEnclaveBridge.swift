// SPDX-License-Identifier: GPL-3.0-or-later（附加 App Store 许可，见仓库根目录 LICENSE）

import CryptoKit
import CryptoTokenKit
import Foundation
import LocalAuthentication
import Security

/// 用 CryptoKit 实现 Rust 核心需要的 Secure Enclave 操作（`spec/crypto.md` §8.7"分工"）。
///
/// 这里只做密钥协商：被包裹的材料（AUK、账户密钥、设备 ID）不经过 Swift。协商结果只能解开对应的那一份包裹，
/// 交给 Rust 之后即丢弃。
///
/// 错误分为四类（§8.7"失败与恢复"），分类依据见 `docs/spikes/2026-11-18-secure-enclave-without-team.md`：
/// - **取消**：用户取消。什么都不改变。
/// - **未通过**：指纹不匹配（`authenticationFailed`）。计入连续失败次数，3 次后必须输入主密码。
/// - **失效**：只在能确定材料本身已坏时报告——blob 无法解析（CryptoTokenKit `corruptedData`、`objectNotFound`），
///   公钥无效（`CryptoKitError`）。Touch ID（0x01）例外：它失效的代价只是"用主密码解锁并重新包裹"，
///   因此其余无法确定的错误也按失效处理。
/// - **暂时不可用**：其余一切，包括无法弹出认证界面、锁屏。什么都不改变，以免误换设备 ID。
public final class SecureEnclaveBridge: SecureEnclaveProvider, @unchecked Sendable {
    private let lock = NSLock()
    private var reason: String
    private var lastFailure: String?

    public init(touchIDReason: String) {
        reason = touchIDReason
    }

    /// Touch ID 提示中显示的原因。
    public var touchIDReason: String {
        get { lock.withLock { reason } }
        set { lock.withLock { reason = newValue } }
    }

    /// 最近一次失败的原始错误（域与错误码，不含任何秘密），用于诊断与实测（技术验证记录）。
    public var lastFailureDescription: String? {
        lock.withLock { lastFailure }
    }

    /// 本机是否可以启用 Touch ID（有 Secure Enclave，且登记了指纹）。
    public static var touchIDAvailable: Bool {
        guard SecureEnclave.isAvailable else { return false }
        var error: NSError?
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    public func createKey(purpose: UInt8) throws -> EnclaveKeyData {
        guard SecureEnclave.isAvailable else { throw EnclaveFailure.Unavailable }
        var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        if purpose == Self.aukPurpose {
            flags.insert(.biometryCurrentSet)
        }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error
        ) else {
            throw EnclaveFailure.Unavailable
        }
        do {
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
            return EnclaveKeyData(blob: key.dataRepresentation, publicKey: key.publicKey.x963Representation)
        } catch {
            // 创建失败不涉及已有材料：一律按暂时不可用（例如没有登记指纹），不让核心层丢弃任何东西
            throw EnclaveFailure.Unavailable
        }
    }

    public func agreeEphemeral(publicKey: Data) throws -> EphemeralAgreementData {
        let peer: P256.KeyAgreement.PublicKey
        do {
            peer = try P256.KeyAgreement.PublicKey(x963Representation: publicKey)
        } catch {
            throw EnclaveFailure.Unusable
        }
        let ephemeral = P256.KeyAgreement.PrivateKey()
        do {
            let shared = try ephemeral.sharedSecretFromKeyAgreement(with: peer)
            return EphemeralAgreementData(
                ephemeralPublic: ephemeral.publicKey.x963Representation,
                shared: shared.withUnsafeBytes { Data($0) }
            )
        } catch {
            throw EnclaveFailure.Unusable
        }
    }

    public func agree(purpose: UInt8, keyBlob: Data, ephemeralPublic: Data) throws -> Data {
        let peer: P256.KeyAgreement.PublicKey
        do {
            peer = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublic)
        } catch {
            throw EnclaveFailure.Unusable
        }
        let context = LAContext()
        context.localizedReason = touchIDReason
        lock.withLock { lastFailure = nil }
        do {
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: keyBlob, authenticationContext: context
            )
            let shared = try key.sharedSecretFromKeyAgreement(with: peer)
            return shared.withUnsafeBytes { Data($0) }
        } catch {
            let ns = error as NSError
            let failure = Self.classify(error, purpose: purpose)
            lock.withLock { lastFailure = "\(ns.domain) \(ns.code) → \(failure)" }
            throw failure
        }
    }

    private static let aukPurpose: UInt8 = 0x01

    static func classify(_ error: Error, purpose: UInt8) -> EnclaveFailure {
        let unknown: EnclaveFailure = purpose == aukPurpose ? .Unusable : .Unavailable
        if error is CryptoKitError {
            return .Unusable
        }
        let ns = error as NSError
        switch ns.domain {
        case LAError.errorDomain:
            switch LAError.Code(rawValue: ns.code) {
            case .userCancel, .appCancel, .systemCancel, .userFallback:
                return .Cancelled
            case .authenticationFailed:
                return .Failed
            case .notInteractive, .biometryLockout, .biometryDisconnected, .biometryNotPaired, .invalidContext:
                return .Unavailable
            default:
                return unknown
            }
        case TKError.errorDomain:
            switch TKError.Code(rawValue: ns.code) {
            case .corruptedData, .objectNotFound, .badParameter:
                return .Unusable
            case .canceledByUser:
                return .Cancelled
            default:
                return unknown
            }
        case NSOSStatusErrorDomain:
            switch OSStatus(ns.code) {
            case errSecUserCanceled:
                return .Cancelled
            case errSecInteractionNotAllowed:
                return .Unavailable
            case errSecItemNotFound, errSecDecode:
                return .Unusable
            default:
                return unknown
            }
        default:
            return unknown
        }
    }
}

public extension LocalEnvironment {
    /// 这台 Mac 的本机环境：本机密钥目录、Secure Enclave 与本次开机的标识。
    static func thisMac(localDir: String, enclave: SecureEnclaveProvider) -> LocalEnvironment {
        LocalEnvironment(localDir: localDir, bootSession: Self.bootSession, enclave: enclave)
    }

    /// 本次开机的标识（`kern.bootsessionuuid`），每次开机都不同。取不到时为空字符串，
    /// 核心层因此一直按"重启之后"处理，要求先输入主密码。
    static var bootSession: String {
        var size = 0
        guard sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) == 0, size > 0, size <= 128 else { return "" }
        var buffer = [CChar](repeating: 0, count: size)
        guard sysctlbyname("kern.bootsessionuuid", &buffer, &size, nil, 0) == 0 else { return "" }
        return String(cString: buffer)
    }
}
