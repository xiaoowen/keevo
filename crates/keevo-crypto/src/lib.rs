//! Keevo 的密码学边界。
//!
//! 本 crate 实现 `spec/crypto.md` v0.1，是整个 workspace 中**唯一**允许直接依赖密码学原语库的
//! crate（由 `scripts/check-crypto-deps.py` 在 CI 中检查）。
//!
//! # 设计约束
//!
//! - 所有密钥类型在释放时清零，并且不实现 `Debug`、`Display`、`Clone` 或任何序列化接口，
//!   在编译期杜绝密钥被打印、记录或意外复制。
//! - 公开 API 中的 nonce 只能随机生成；固定 nonce 仅在本 crate 的单元测试中可用。
//! - 错误类型不携带任何秘密数据。
//! - 只使用 `spec/crypto.md` §3 列出的原语。
//!
//! # 主要入口
//!
//! - [`AccountSecretKey`]：账户密钥（Secret Key）的生成、显示与解析。
//! - [`KdfParams`]：Argon2id 参数，带硬编码的上下限。
//! - [`derive_account_unlock_key`]：双因子密钥派生（2SKD），得到 AUK。
//! - [`AccountKeyset`]：账户密钥集，由 AUK 封装。
//! - [`seal`] / [`open`]：加密信封；[`SymmetricKey::wrap_key`] / [`SymmetricKey::unwrap_key`]：密钥包裹。
//! - [`Handshake`] / [`Transport`]：本地 IPC 的 Noise 握手与传输加密（`spec/ipc.md`）。
//! - [`openssh_decrypt`]：导入有口令保护的 OpenSSH 私钥（`spec/ssh-agent.md` §3）。

mod ed25519;
mod envelope;
mod error;
mod hkdf;
mod id;
mod kdf;
mod key;
mod keyset;
mod local_record;
mod local_wrap;
mod noise;
mod openssh;
mod padding;
mod random;
mod secret_key;
mod totp;
mod two_skd;

#[cfg(test)]
mod ipc_vectors;
#[cfg(test)]
mod kat;
#[cfg(test)]
mod vectors;

pub use ed25519::{
    ED25519_PUBLIC_LEN, ED25519_SEED_LEN, ED25519_SIGNATURE_LEN, Ed25519SigningKey, ed25519_verify,
};
pub use envelope::{
    AAD_LEN, AadContext, HEADER_LEN, MAX_ENVELOPE_LEN, MAX_PLAINTEXT_LEN, MIN_ENVELOPE_LEN,
    ObjectType, Part, envelope_key_id, open, seal,
};
pub use error::{CryptoError, Result, SecretKeyError};
pub use id::{Id128, KeyId};
pub use kdf::KdfParams;
pub use key::SymmetricKey;
pub use keyset::AccountKeyset;
pub use local_record::{MAX_LOCAL_RECORD_LEN, open_local_record, seal_local_record};
pub use local_wrap::{
    EPH_PUB_LEN, LocalAgreement, LocalPurpose, LocalWrapHeader, MAX_LOCAL_WRAP_LEN, SHARED_LEN,
    unwrap_auk, unwrap_device_marker, unwrap_secret_key, unwrap_service_static, wrap_auk,
    wrap_device_marker, wrap_secret_key, wrap_service_static,
};
pub use noise::{
    Handshake, MAX_NOISE_MESSAGE, PAIR_NONCE_LEN, StaticKeypair, Transport, pairing_commitment,
    pairing_nonce,
};
pub use openssh::{OPENSSH_CIPHER_BLOCK, OPENSSH_CIPHERS, OPENSSH_MAX_ROUNDS, openssh_decrypt};
pub use random::random_below;

/// SHA-256。只用于非秘密值（例如 SSH 公钥指纹，`spec/ssh-agent.md` §3）。
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    hkdf::sha256(&[data])
}
pub use secret_key::AccountSecretKey;
pub use totp::{MAX_OTP_SECRET_LEN, OTP_DIGITS, OtpAlgorithm, OtpKey};
pub use two_skd::{MAX_PASSWORD_LEN, derive_account_unlock_key};

/// 解密后的明文。离开作用域时自动清零整个缓冲区（包括未使用的容量）。
pub type SecretBytes = zeroize::Zeroizing<Vec<u8>>;
