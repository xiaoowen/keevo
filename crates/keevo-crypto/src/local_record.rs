//! 本机记录（`spec/crypto.md` §8.8，本机格式 v1）：浏览器配对记录与站点授权的加密。

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::SecretBytes;
use crate::envelope::TAG_LEN;
use crate::error::{CryptoError, Result};
use crate::hkdf::hkdf_sha256;
use crate::id::Id128;
use crate::key::SymmetricKey;
use crate::random;

const VERSION: u8 = 0x01;
const LABEL: &[u8] = b"keevo/v1/local-record";
const NONCE_LEN: usize = 24;
/// 明文的长度上限。
pub const MAX_LOCAL_RECORD_LEN: usize = 64 * 1024;
const MAX_KIND_LEN: usize = 32;
const MAX_ID_LEN: usize = 64;

fn check(kind: &str, id: &[u8]) -> Result<()> {
    let kind_ok = (1..=MAX_KIND_LEN).contains(&kind.len())
        && kind.bytes().all(|b| b.is_ascii_lowercase() || b == b'_');
    if !kind_ok || !(1..=MAX_ID_LEN).contains(&id.len()) {
        return Err(CryptoError::InvalidContext);
    }
    Ok(())
}

fn cipher(ask: &SymmetricKey, account_id: &Id128, kind: &str) -> Result<XChaCha20Poly1305> {
    let mut info = Vec::with_capacity(LABEL.len().saturating_add(kind.len()));
    info.extend_from_slice(LABEL);
    info.extend_from_slice(kind.as_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf_sha256(ask.expose(), account_id.as_bytes(), &info, key.as_mut())?;
    XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| CryptoError::Malformed)
}

fn aad(kind: &str, account_id: &Id128, id: &[u8]) -> Result<Vec<u8>> {
    let kind_len = u8::try_from(kind.len()).map_err(|_| CryptoError::InvalidContext)?;
    let mut out = Vec::with_capacity(LABEL.len().saturating_add(64));
    out.extend_from_slice(LABEL);
    out.push(VERSION);
    out.push(kind_len);
    out.extend_from_slice(kind.as_bytes());
    out.extend_from_slice(account_id.as_bytes());
    out.extend_from_slice(id);
    Ok(out)
}

/// 加密一条本机记录。`ask` 是账户对称密钥（[`crate::AccountKeyset::account_key`]）。
///
/// # Errors
/// `kind` 或 `id` 不合法时返回 [`CryptoError::InvalidContext`]；明文超过 64 KiB 时返回 [`CryptoError::TooLarge`]。
pub fn seal_local_record(
    ask: &SymmetricKey,
    account_id: &Id128,
    kind: &str,
    id: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    check(kind, id)?;
    if plaintext.len() > MAX_LOCAL_RECORD_LEN {
        return Err(CryptoError::TooLarge);
    }
    let nonce: [u8; NONCE_LEN] = random::array()?;
    let mut buf = Zeroizing::new(plaintext.to_vec());
    cipher(ask, account_id, kind)?
        .encrypt_in_place(&XNonce::from(nonce), &aad(kind, account_id, id)?, &mut *buf)
        .map_err(|_| CryptoError::TooLarge)?;
    let mut out = Vec::with_capacity(1usize.saturating_add(NONCE_LEN).saturating_add(buf.len()));
    out.push(VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&buf);
    Ok(out)
}

/// 解密一条本机记录。
///
/// # Errors
/// 格式错误返回 [`CryptoError::Malformed`]；版本不符返回 [`CryptoError::UnsupportedVersion`]；
/// 认证失败（篡改、换到另一条记录或另一个账户）返回 [`CryptoError::DecryptionFailed`]。
pub fn open_local_record(
    ask: &SymmetricKey,
    account_id: &Id128,
    kind: &str,
    id: &[u8],
    ct: &[u8],
) -> Result<SecretBytes> {
    check(kind, id)?;
    let max = MAX_LOCAL_RECORD_LEN
        .saturating_add(1)
        .saturating_add(NONCE_LEN)
        .saturating_add(TAG_LEN);
    if ct.len() > max {
        return Err(CryptoError::Malformed);
    }
    let (&version, rest) = ct.split_first().ok_or(CryptoError::Malformed)?;
    if version != VERSION {
        return Err(CryptoError::UnsupportedVersion);
    }
    let (nonce, body) = rest
        .split_first_chunk::<NONCE_LEN>()
        .ok_or(CryptoError::Malformed)?;
    if body.len() < TAG_LEN {
        return Err(CryptoError::Malformed);
    }
    let mut buf = Zeroizing::new(body.to_vec());
    cipher(ask, account_id, kind)?
        .decrypt_in_place(
            &XNonce::from(*nonce),
            &aad(kind, account_id, id)?,
            &mut *buf,
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: Id128 = Id128::from_bytes([1; 16]);

    #[test]
    fn round_trip_and_bindings() {
        let ask = SymmetricKey::from_raw([0; 16], [7; 32]);
        let ct = seal_local_record(&ask, &ACCOUNT, "pairing", b"pk-1", br#"{"x":1}"#).unwrap();
        assert_eq!(
            open_local_record(&ask, &ACCOUNT, "pairing", b"pk-1", &ct)
                .unwrap()
                .as_slice(),
            br#"{"x":1}"#
        );
        assert_ne!(
            ct,
            seal_local_record(&ask, &ACCOUNT, "pairing", b"pk-1", br#"{"x":1}"#).unwrap(),
            "每次新 nonce"
        );

        let other_key = SymmetricKey::from_raw([0; 16], [8; 32]);
        let other_account = Id128::from_bytes([2; 16]);
        for (key, account, kind, id) in [
            (&other_key, ACCOUNT, "pairing", &b"pk-1"[..]),
            (&ask, other_account, "pairing", &b"pk-1"[..]),
            (&ask, ACCOUNT, "authorization", &b"pk-1"[..]),
            (&ask, ACCOUNT, "pairing", &b"pk-2"[..]),
        ] {
            assert_eq!(
                open_local_record(key, &account, kind, id, &ct).err(),
                Some(CryptoError::DecryptionFailed)
            );
        }
        for i in 0..ct.len() {
            let mut t = ct.clone();
            t[i] ^= 1;
            assert!(
                open_local_record(&ask, &ACCOUNT, "pairing", b"pk-1", &t).is_err(),
                "第 {i} 字节"
            );
        }
    }

    #[test]
    fn rejects_bad_inputs() {
        let ask = SymmetricKey::from_raw([0; 16], [7; 32]);
        for (kind, id) in [
            ("", &b"x"[..]),
            ("Pairing", b"x"),
            ("a-b", b"x"),
            ("pairing", b""),
            ("pairing", &[0u8; 65][..]),
        ] {
            assert_eq!(
                seal_local_record(&ask, &ACCOUNT, kind, id, b"{}").err(),
                Some(CryptoError::InvalidContext),
                "{kind:?}"
            );
        }
        assert_eq!(
            seal_local_record(
                &ask,
                &ACCOUNT,
                "pairing",
                b"x",
                &vec![0; MAX_LOCAL_RECORD_LEN + 1]
            )
            .err(),
            Some(CryptoError::TooLarge)
        );
        assert_eq!(
            open_local_record(&ask, &ACCOUNT, "pairing", b"x", &[]).err(),
            Some(CryptoError::Malformed)
        );
        assert_eq!(
            open_local_record(&ask, &ACCOUNT, "pairing", b"x", &[2; 60]).err(),
            Some(CryptoError::UnsupportedVersion)
        );
        assert_eq!(
            open_local_record(&ask, &ACCOUNT, "pairing", b"x", &[1; 30]).err(),
            Some(CryptoError::Malformed)
        );
    }
}
