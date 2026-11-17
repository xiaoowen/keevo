use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::hkdf::hkdf_sha256;
use crate::id::{Id128, KeyId};
use crate::kdf::KdfParams;
use crate::key::SymmetricKey;
use crate::secret_key::AccountSecretKey;

/// 主密码经 NFKD 规范化后的最大字节数（`spec/crypto.md` §6）。
pub const MAX_PASSWORD_LEN: usize = 4096;

const INFO_SECRET_KEY: &[u8] = b"keevo/v1/secret-key";
const INFO_AUK: &[u8] = b"keevo/v1/auk";
const INFO_AUK_KID: &[u8] = b"keevo/v1/auk-kid";

/// 双因子密钥派生（2SKD），得到账户解锁密钥 AUK（`spec/crypto.md` §6）。
///
/// 耗时主要来自 Argon2id，按默认参数约 0.5–1.5 秒，调用方应在后台线程执行。
///
/// # Errors
/// 主密码为空或过长时返回对应错误；随机数或 KDF 内部错误时返回对应错误。
pub fn derive_account_unlock_key(
    password: &str,
    secret_key: &AccountSecretKey,
    account_id: &Id128,
    params: &KdfParams,
) -> Result<SymmetricKey> {
    let normalized = normalize_password(password)?;
    let k_p = params.argon2id(normalized.as_bytes())?;
    let k_s = derive_k_s(secret_key, account_id)?;
    let auk = combine(&k_p, &k_s, account_id)?;
    let kid = auk_kid(&auk, account_id)?;
    Ok(SymmetricKey::from_parts(kid, auk))
}

/// NFKD 规范化。先计算长度再一次性分配，避免扩容时在已释放内存中留下口令副本。
pub(crate) fn normalize_password(password: &str) -> Result<Zeroizing<String>> {
    let len: usize = password
        .nfkd()
        .map(char::len_utf8)
        .fold(0, usize::saturating_add);
    if len == 0 {
        return Err(CryptoError::EmptyPassword);
    }
    if len > MAX_PASSWORD_LEN {
        return Err(CryptoError::PasswordTooLong);
    }
    let mut out = Zeroizing::new(String::with_capacity(len));
    out.extend(password.nfkd());
    Ok(out)
}

pub(crate) fn derive_k_s(
    secret_key: &AccountSecretKey,
    account_id: &Id128,
) -> Result<Zeroizing<[u8; 32]>> {
    let mut k_s = Zeroizing::new([0u8; 32]);
    hkdf_sha256(
        secret_key.expose(),
        account_id.as_bytes(),
        INFO_SECRET_KEY,
        k_s.as_mut(),
    )?;
    Ok(k_s)
}

pub(crate) fn combine(
    k_p: &[u8; 32],
    k_s: &[u8; 32],
    account_id: &Id128,
) -> Result<Zeroizing<[u8; 32]>> {
    let mut ikm = Zeroizing::new([0u8; 64]);
    let (a, b) = ikm.split_at_mut(32);
    a.copy_from_slice(k_p);
    b.copy_from_slice(k_s);
    let mut auk = Zeroizing::new([0u8; 32]);
    hkdf_sha256(ikm.as_ref(), account_id.as_bytes(), INFO_AUK, auk.as_mut())?;
    Ok(auk)
}

pub(crate) fn auk_kid(auk: &[u8; 32], account_id: &Id128) -> Result<KeyId> {
    let mut kid = [0u8; 16];
    hkdf_sha256(auk, account_id.as_bytes(), INFO_AUK_KID, &mut kid)?;
    Ok(KeyId::from_bytes(kid))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> KdfParams {
        KdfParams::new(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1, [9u8; 16]).unwrap()
    }

    #[test]
    fn empty_and_oversized_passwords_are_rejected() {
        let sk = AccountSecretKey::from_bytes([1; 16]);
        let id = Id128::from_bytes([2; 16]);
        assert_eq!(
            derive_account_unlock_key("", &sk, &id, &params()).err(),
            Some(CryptoError::EmptyPassword)
        );
        let long = "a".repeat(MAX_PASSWORD_LEN + 1);
        assert_eq!(
            derive_account_unlock_key(&long, &sk, &id, &params()).err(),
            Some(CryptoError::PasswordTooLong)
        );
    }

    #[test]
    fn every_input_changes_the_key() {
        let p = params();
        let sk = AccountSecretKey::from_bytes([1; 16]);
        let id = Id128::from_bytes([2; 16]);
        let base = derive_account_unlock_key("hunter2!", &sk, &id, &p).unwrap();

        let other_pw = derive_account_unlock_key("hunter2?", &sk, &id, &p).unwrap();
        let other_sk =
            derive_account_unlock_key("hunter2!", &AccountSecretKey::from_bytes([3; 16]), &id, &p)
                .unwrap();
        let other_id =
            derive_account_unlock_key("hunter2!", &sk, &Id128::from_bytes([4; 16]), &p).unwrap();
        let other_salt = derive_account_unlock_key(
            "hunter2!",
            &sk,
            &id,
            &KdfParams::new(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1, [8u8; 16]).unwrap(),
        )
        .unwrap();

        for other in [&other_pw, &other_sk, &other_id, &other_salt] {
            assert_ne!(other.expose(), base.expose());
            assert_ne!(other.id(), base.id());
        }
    }
}
