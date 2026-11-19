//! OpenSSH 私钥的口令保护（OpenSSH `PROTOCOL.key`）：bcrypt_pbkdf 派生密钥与 IV，AES-CTR 解密私钥段。
//!
//! 只用于导入（`spec/ssh-agent.md` §3）：解密后的私钥由保险库重新加密保存，Keevo 从不写出加密的 OpenSSH 私钥。
//! 支持 OpenSSH 的 `aes128-ctr`、`aes192-ctr`、`aes256-ctr`（`ssh-keygen` 的默认是 `aes256-ctr`）；
//! 带认证的 `aes256-gcm@openssh.com` 与 `chacha20-poly1305@openssh.com` 不支持，由调用方说明转换方法。
//!
//! CTR 不提供完整性：口令是否正确由调用方核对私钥段开头的两个校验数（OpenSSH 同样如此），
//! 解密后的内容还要经过结构与公私钥一致性的检查。

use aes::cipher::{KeyIvInit, StreamCipher};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

/// 支持的加密方式（OpenSSH 的名称）。
pub const OPENSSH_CIPHERS: [&str; 3] = ["aes128-ctr", "aes192-ctr", "aes256-ctr"];
/// 加密后私钥段的块大小（AES）。
pub const OPENSSH_CIPHER_BLOCK: usize = 16;
/// bcrypt 轮数的上限。`ssh-keygen -a` 的默认值是 16；上限远大于常见值，防止恶意文件让导入耗尽 CPU。
pub const OPENSSH_MAX_ROUNDS: u32 = 1024;
/// 盐的长度上限（OpenSSH 写 16 字节）。
const MAX_SALT: usize = 64;
const IV_LEN: usize = 16;

/// 用口令原地解密 OpenSSH 私钥段。`cipher` 是 [`OPENSSH_CIPHERS`] 之一，`salt` 与 `rounds` 取自私钥文件的
/// `kdfoptions`。CTR 模式下加密与解密是同一个运算。
///
/// # Errors
/// - 加密方式不支持：[`CryptoError::UnsupportedAlgorithm`]；
/// - 口令为空：[`CryptoError::EmptyPassword`]；
/// - 盐、轮数或数据长度不合规定：[`CryptoError::Malformed`]；
/// - 密钥派生失败：[`CryptoError::Kdf`]。
pub fn openssh_decrypt(
    cipher: &str,
    passphrase: &[u8],
    salt: &[u8],
    rounds: u32,
    data: &mut [u8],
) -> Result<()> {
    let key_len: usize = match cipher {
        "aes128-ctr" => 16,
        "aes192-ctr" => 24,
        "aes256-ctr" => 32,
        _ => return Err(CryptoError::UnsupportedAlgorithm),
    };
    if passphrase.is_empty() {
        return Err(CryptoError::EmptyPassword);
    }
    if salt.is_empty()
        || salt.len() > MAX_SALT
        || rounds == 0
        || rounds > OPENSSH_MAX_ROUNDS
        || !data.len().is_multiple_of(OPENSSH_CIPHER_BLOCK)
    {
        return Err(CryptoError::Malformed);
    }
    let mut derived = Zeroizing::new([0u8; 32 + IV_LEN]);
    let out = derived
        .get_mut(..key_len.saturating_add(IV_LEN))
        .ok_or(CryptoError::Malformed)?;
    bcrypt_pbkdf::bcrypt_pbkdf(passphrase, salt, rounds, out).map_err(|_| CryptoError::Kdf)?;
    let (key, iv) = out.split_at(key_len);
    match key_len {
        16 => apply::<ctr::Ctr128BE<aes::Aes128>>(key, iv, data),
        24 => apply::<ctr::Ctr128BE<aes::Aes192>>(key, iv, data),
        _ => apply::<ctr::Ctr128BE<aes::Aes256>>(key, iv, data),
    }
}

fn apply<C: KeyIvInit + StreamCipher>(key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<()> {
    let mut c = C::new_from_slices(key, iv).map_err(|_| CryptoError::Malformed)?;
    c.apply_keystream(data);
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn ctr_is_its_own_inverse_and_depends_on_every_input() {
        let plain = [7u8; 32];
        let mut buf = plain;
        openssh_decrypt("aes256-ctr", b"pw", b"saltsaltsaltsalt", 2, &mut buf).unwrap();
        assert_ne!(buf, plain);
        let encrypted = buf;
        openssh_decrypt("aes256-ctr", b"pw", b"saltsaltsaltsalt", 2, &mut buf).unwrap();
        assert_eq!(buf, plain);
        for (cipher, pw, salt, rounds) in [
            ("aes128-ctr", &b"pw"[..], &b"saltsaltsaltsalt"[..], 2),
            ("aes256-ctr", b"pW", b"saltsaltsaltsalt", 2),
            ("aes256-ctr", b"pw", b"saltsaltsaltsalT", 2),
            ("aes256-ctr", b"pw", b"saltsaltsaltsalt", 3),
        ] {
            let mut other = plain;
            openssh_decrypt(cipher, pw, salt, rounds, &mut other).unwrap();
            assert_ne!(other, encrypted, "{cipher} {rounds}");
        }
    }

    #[test]
    fn rejects_bad_parameters() {
        let mut buf = [0u8; 16];
        let salt = b"saltsaltsaltsalt";
        assert_eq!(
            openssh_decrypt("aes256-gcm@openssh.com", b"pw", salt, 16, &mut buf),
            Err(CryptoError::UnsupportedAlgorithm)
        );
        assert_eq!(
            openssh_decrypt("aes256-ctr", b"", salt, 16, &mut buf),
            Err(CryptoError::EmptyPassword)
        );
        assert_eq!(
            openssh_decrypt("aes256-ctr", b"pw", salt, 0, &mut buf),
            Err(CryptoError::Malformed)
        );
        assert_eq!(
            openssh_decrypt("aes256-ctr", b"pw", salt, OPENSSH_MAX_ROUNDS + 1, &mut buf),
            Err(CryptoError::Malformed)
        );
        assert_eq!(
            openssh_decrypt("aes256-ctr", b"pw", b"", 16, &mut buf),
            Err(CryptoError::Malformed)
        );
        assert_eq!(
            openssh_decrypt("aes256-ctr", b"pw", salt, 16, &mut [0u8; 15]),
            Err(CryptoError::Malformed)
        );
    }
}
