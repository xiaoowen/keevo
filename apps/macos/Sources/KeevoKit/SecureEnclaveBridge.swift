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
/// 错误分为三类（§8.7"失败与恢复"），分类依据见 `docs/spikes/2026-11-18-secure-enclave-without-team.md`：
/// - **取消**：用户取消、认证失败次数用尽。什么都不改变。
/// - **失效**：只在能确定材料本身已坏时报告——blob 无法解析（CryptoTokenKit `corruptedData`、`objectNotFound`），
///   公钥无效（`CryptoKitError`）。Touch ID（0x01）例外：它失效的代价只是"用主密码解锁并重新包裹"，
///   因此其余无法确定的错误也按失效处理。
/// - **暂时不可用**：其余一切，包括无法弹出认证界面、锁屏。什么都不改变，以免误换设备 ID。
public final class SecureEnclaveBridge: SecureEnclaveProvider, @unchecked Sendable {
    /// Touch ID 提示中显示的原因。
    private let touchIDReason: String

    public init(touchIDReason: String) {
        self.touchIDReason = touchIDReason
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
        do {
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: keyBlob, authenticationContext: context
            )
            let shared = try key.sharedSecretFromKeyAgreement(with: peer)
            return shared.withUnsafeBytes { Data($0) }
        } catch {
            throw Self.classify(error, purpose: purpose)
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
            case .userCancel, .appCancel, .systemCancel, .userFallback, .authenticationFailed:
                return .Cancelled
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
