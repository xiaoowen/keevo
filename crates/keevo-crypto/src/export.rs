//! Keevo 加密导出文件（`spec/export.md`）：用导出密码保护的一个文件，可以在另一台 Mac 或另一个账户中导入。
//!
//! ```text
//! magic "KEEVOEXP" (8) || version 0x01 (1) || KdfParams (29, spec/crypto.md §5.1) || nonce (24) || 密文与标签
//! ```
//! 密钥 = HKDF-SHA256(Argon2id(NFKD(导出密码), KdfParams), salt = 空, info = "keevo/v1/export")；
//! 算法 XChaCha20-Poly1305，AAD 为密文之前的全部字节。导出密码与主密码无关。

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::SecretBytes;
use crate::envelope::TAG_LEN;
use crate::error::{CryptoError, Result};
use crate::hkdf::hkdf_sha256;
use crate::kdf::KdfParams;
use crate::random;
use crate::two_skd::normalize_password;

/// 文件开头的标记。
pub const EXPORT_MAGIC: &[u8; 8] = b"KEEVOEXP";
const VERSION: u8 = 0x01;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = 8 + 1 + KdfParams::ENCODED_LEN + NONCE_LEN;
const INFO: &[u8] = b"keevo/v1/export";
/// 明文的长度上限：256 MiB。
pub const MAX_EXPORT_LEN: usize = 256 * 1024 * 1024;

fn cipher(password: &str, params: &KdfParams) -> Result<XChaCha20Poly1305> {
    let normalized = normalize_password(password)?;
    let k = params.argon2id(normalized.as_bytes())?;
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf_sha256(k.as_ref(), &[], INFO, key.as_mut())?;
    XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| CryptoError::Malformed)
}

/// 用导出密码加密。`params` 通常为 [`KdfParams::generate_default`]。耗时约一秒，应在后台线程调用。
///
/// # Errors
/// 口令为空或过长、明文超过 [`MAX_EXPORT_LEN`]、随机数或 KDF 失败。
pub fn seal_export(password: &str, params: &KdfParams, plaintext: &[u8]) -> Result<Vec<u8>> {
    if plaintext.len() > MAX_EXPORT_LEN {
        return Err(CryptoError::TooLarge);
    }
    let nonce: [u8; NONCE_LEN] = random::array()?;
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(EXPORT_MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&params.encode());
    header.extend_from_slice(&nonce);
    let mut buf = Zeroizing::new(plaintext.to_vec());
    cipher(password, params)?
        .encrypt_in_place(&XNonce::from(nonce), &header, &mut *buf)
        .map_err(|_| CryptoError::TooLarge)?;
    let mut out = header;
    out.extend_from_slice(&buf);
    Ok(out)
}

/// 文件是否以 Keevo 导出文件的标记开头（不验证其余部分）。
#[must_use]
pub fn is_export(data: &[u8]) -> bool {
    data.starts_with(EXPORT_MAGIC)
}

/// 用导出密码解密。KDF 参数超出本机自动执行预算时拒绝（防止恶意文件耗尽内存）。
///
/// # Errors
/// - 不是导出文件或长度不对：[`CryptoError::Malformed`]；版本不支持：[`CryptoError::UnsupportedVersion`]；
/// - KDF 参数越界：[`CryptoError::KdfAboveMaximum`] 等；
/// - 导出密码错误或文件被改动：[`CryptoError::DecryptionFailed`]。
pub fn open_export(password: &str, data: &[u8]) -> Result<SecretBytes> {
    let rest = data
        .strip_prefix(EXPORT_MAGIC)
        .ok_or(CryptoError::Malformed)?;
    let (&version, rest) = rest.split_first().ok_or(CryptoError::Malformed)?;
    if version != VERSION {
        return Err(CryptoError::UnsupportedVersion);
    }
    let (params, rest) = rest
        .split_first_chunk::<{ KdfParams::ENCODED_LEN }>()
        .ok_or(CryptoError::Malformed)?;
    let params = KdfParams::decode(params)?;
    if !params.within_auto_budget() {
        return Err(CryptoError::KdfAboveMaximum);
    }
    let (nonce, body) = rest
        .split_first_chunk::<NONCE_LEN>()
        .ok_or(CryptoError::Malformed)?;
    if body.len() < TAG_LEN || body.len() > MAX_EXPORT_LEN.saturating_add(TAG_LEN) {
        return Err(CryptoError::Malformed);
    }
    let header = data.get(..HEADER_LEN).ok_or(CryptoError::Malformed)?;
    let mut buf = Zeroizing::new(body.to_vec());
    cipher(password, &params)?
        .decrypt_in_place(&XNonce::from(*nonce), header, &mut *buf)
        .map_err(|_| CryptoError::DecryptionFailed)?;
    Ok(buf)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn params() -> KdfParams {
        KdfParams::new(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1, [3; 16]).unwrap()
    }

    #[test]
    fn round_trip_and_tampering() {
        let sealed = seal_export("export password", &params(), b"{\"items\":[]}").unwrap();
        assert!(is_export(&sealed));
        assert_eq!(sealed.len(), HEADER_LEN + 12 + TAG_LEN);
        assert_eq!(
            open_export("export password", &sealed).unwrap().as_slice(),
            b"{\"items\":[]}"
        );
        // NFKD：全角与半角相同
        assert!(open_export("ｅｘｐｏｒｔ password", &sealed).is_ok());
        assert_eq!(
            open_export("export passworD", &sealed).err(),
            Some(CryptoError::DecryptionFailed)
        );
        for i in [0, 8, 9, HEADER_LEN - 1, HEADER_LEN, sealed.len() - 1] {
            let mut bad = sealed.clone();
            bad[i] ^= 1;
            assert!(open_export("export password", &bad).is_err(), "byte {i}");
        }
        assert_eq!(
            open_export("x", &sealed[..HEADER_LEN + 3]).err(),
            Some(CryptoError::Malformed)
        );
        assert_eq!(
            open_export("x", b"not an export").err(),
            Some(CryptoError::Malformed)
        );
    }

    #[test]
    fn rejects_expensive_parameters() {
        let expensive = KdfParams::new(KdfParams::MAX_M_KIB, KdfParams::MIN_T, 1, [3; 16]).unwrap();
        let mut forged = Vec::new();
        forged.extend_from_slice(EXPORT_MAGIC);
        forged.push(VERSION);
        forged.extend_from_slice(&expensive.encode());
        forged.extend_from_slice(&[0; NONCE_LEN + TAG_LEN]);
        assert_eq!(
            open_export("pw", &forged).err(),
            Some(CryptoError::KdfAboveMaximum)
        );
    }
}
