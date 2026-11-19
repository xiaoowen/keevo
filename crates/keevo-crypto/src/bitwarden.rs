//! Bitwarden 有密码保护的导出文件（`docs/product.md` §5.7 导入）。只用于导入，Keevo 从不写出这种格式。
//!
//! Bitwarden 的做法：用导出密码与文件中的 salt 派生 32 字节密钥（PBKDF2-SHA256，或 Argon2id 且 salt 先取
//! SHA-256），再用 HKDF-Expand（SHA-256，info 为 `enc` 与 `mac`）拉伸为加密密钥与 MAC 密钥。文件中的
//! 加密字符串为类型 2：AES-256-CBC（PKCS#7 填充），HMAC-SHA256 覆盖 `iv || 密文`（先验证 MAC 再解密）。

use aes::cipher::{BlockCipherDecrypt, KeyInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

/// PBKDF2 迭代次数的上限。Bitwarden 的默认值是 600000；上限防止恶意文件让导入耗尽 CPU。
pub const BITWARDEN_MAX_PBKDF2_ITERATIONS: u32 = 2_000_000;
/// Argon2id 的上限：内存（MiB）、迭代次数、并行度。Bitwarden 允许 15–1024 MiB、2–10 次、1–16。
pub const BITWARDEN_MAX_ARGON2: (u32, u32, u32) = (1024, 10, 16);
const IV_LEN: usize = 16;
const MAC_LEN: usize = 32;
const BLOCK: usize = 16;

/// 导出文件中的密钥派生方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitwardenKdf {
    /// `kdfType` 0。
    Pbkdf2 {
        /// 迭代次数。
        iterations: u32,
    },
    /// `kdfType` 1。
    Argon2id {
        /// 内存（MiB）。
        memory_mib: u32,
        /// 迭代次数。
        iterations: u32,
        /// 并行度。
        parallelism: u32,
    },
}

/// 拉伸后的密钥：加密密钥与 MAC 密钥。
pub struct BitwardenKey {
    enc: Zeroizing<[u8; 32]>,
    mac: Zeroizing<[u8; 32]>,
}

impl BitwardenKey {
    /// 由导出密码派生。耗时与参数有关（默认参数约一秒），应在后台线程调用。
    ///
    /// # Errors
    /// 参数超出上限或为 0：[`CryptoError::KdfAboveMaximum`]、[`CryptoError::KdfBelowMinimum`]；口令为空：
    /// [`CryptoError::EmptyPassword`]；派生失败：[`CryptoError::Kdf`]。
    pub fn derive(password: &str, salt: &str, kdf: BitwardenKdf) -> Result<Self> {
        if password.is_empty() {
            return Err(CryptoError::EmptyPassword);
        }
        let mut master = Zeroizing::new([0u8; 32]);
        match kdf {
            BitwardenKdf::Pbkdf2 { iterations } => {
                if iterations == 0 {
                    return Err(CryptoError::KdfBelowMinimum);
                }
                if iterations > BITWARDEN_MAX_PBKDF2_ITERATIONS {
                    return Err(CryptoError::KdfAboveMaximum);
                }
                pbkdf2::pbkdf2_hmac::<Sha256>(
                    password.as_bytes(),
                    salt.as_bytes(),
                    iterations,
                    master.as_mut(),
                );
            }
            BitwardenKdf::Argon2id {
                memory_mib,
                iterations,
                parallelism,
            } => {
                let (max_m, max_t, max_p) = BITWARDEN_MAX_ARGON2;
                if memory_mib == 0 || iterations == 0 || parallelism == 0 {
                    return Err(CryptoError::KdfBelowMinimum);
                }
                if memory_mib > max_m || iterations > max_t || parallelism > max_p {
                    return Err(CryptoError::KdfAboveMaximum);
                }
                let salt = crate::hkdf::sha256(&[salt.as_bytes()]);
                let params = argon2::Params::new(
                    memory_mib.saturating_mul(1024),
                    iterations,
                    parallelism,
                    Some(32),
                )
                .map_err(|_| CryptoError::Kdf)?;
                argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
                    .hash_password_into(password.as_bytes(), &salt, master.as_mut())
                    .map_err(|_| CryptoError::Kdf)?;
            }
        }
        let hk = Hkdf::<Sha256>::from_prk(master.as_ref()).map_err(|_| CryptoError::Kdf)?;
        let mut enc = Zeroizing::new([0u8; 32]);
        let mut mac = Zeroizing::new([0u8; 32]);
        hk.expand(b"enc", enc.as_mut())
            .map_err(|_| CryptoError::Kdf)?;
        hk.expand(b"mac", mac.as_mut())
            .map_err(|_| CryptoError::Kdf)?;
        Ok(Self { enc, mac })
    }

    /// 解密一个类型 2 的加密字符串（各部分已由调用方从 Base64 解码）。
    ///
    /// # Errors
    /// MAC 不符（口令错误或文件被改动）：[`CryptoError::DecryptionFailed`]；长度或填充不合规定：
    /// [`CryptoError::Malformed`]。
    pub fn decrypt(&self, iv: &[u8], ciphertext: &[u8], mac: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if iv.len() != IV_LEN || mac.len() != MAC_LEN {
            return Err(CryptoError::Malformed);
        }
        let mut m = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(self.mac.as_ref())
            .map_err(|_| CryptoError::Malformed)?;
        m.update(iv);
        m.update(ciphertext);
        m.verify_slice(mac)
            .map_err(|_| CryptoError::DecryptionFailed)?;
        if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(BLOCK) {
            return Err(CryptoError::Malformed);
        }
        let cipher = aes::Aes256Dec::new_from_slice(self.enc.as_ref())
            .map_err(|_| CryptoError::Malformed)?;
        let mut out = Zeroizing::new(ciphertext.to_vec());
        let mut prev = [0u8; BLOCK];
        prev.copy_from_slice(iv);
        for chunk in out.chunks_exact_mut(BLOCK) {
            let mut saved = [0u8; BLOCK];
            saved.copy_from_slice(chunk);
            let mut block = aes::Block::default();
            block.copy_from_slice(chunk);
            cipher.decrypt_block(&mut block);
            for ((o, d), p) in chunk.iter_mut().zip(block.iter()).zip(prev.iter()) {
                *o = d ^ p;
            }
            prev = saved;
        }
        // PKCS#7（MAC 已经通过，不存在填充预言的问题）
        let pad = usize::from(*out.last().ok_or(CryptoError::Malformed)?);
        if pad == 0 || pad > BLOCK || pad > out.len() {
            return Err(CryptoError::Malformed);
        }
        let body = out.len().saturating_sub(pad);
        if out
            .get(body..)
            .is_none_or(|tail| tail.iter().any(|b| usize::from(*b) != pad))
        {
            return Err(CryptoError::Malformed);
        }
        out.truncate(body);
        Ok(out)
    }

    /// 测试用：加密为类型 2 的各部分 (iv, 密文, mac)。
    #[cfg(test)]
    pub(crate) fn encrypt_for_tests(
        &self,
        iv: [u8; 16],
        plain: &[u8],
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use aes::cipher::BlockCipherEncrypt;
        let cipher =
            aes::Aes256Enc::new_from_slice(self.enc.as_ref()).unwrap_or_else(|_| unreachable!());
        let pad = BLOCK.saturating_sub(plain.len() % BLOCK);
        let mut data = plain.to_vec();
        data.extend(std::iter::repeat_n(u8::try_from(pad).unwrap_or(16), pad));
        let mut prev = iv;
        for chunk in data.chunks_exact_mut(BLOCK) {
            let mut block = aes::Block::default();
            for ((b, c), p) in block.iter_mut().zip(chunk.iter()).zip(prev.iter()) {
                *b = c ^ p;
            }
            cipher.encrypt_block(&mut block);
            chunk.copy_from_slice(&block);
            prev.copy_from_slice(chunk);
        }
        let mut m = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(self.mac.as_ref())
            .unwrap_or_else(|_| unreachable!());
        m.update(&iv);
        m.update(&data);
        (iv.to_vec(), data, m.finalize().into_bytes().to_vec())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_rejections() {
        for kdf in [
            BitwardenKdf::Pbkdf2 { iterations: 1000 },
            BitwardenKdf::Argon2id {
                memory_mib: 16,
                iterations: 2,
                parallelism: 1,
            },
        ] {
            let key = BitwardenKey::derive("correct horse", "salt-from-file", kdf).unwrap();
            for plain in [
                &b""[..],
                b"x",
                b"exactly sixteen!",
                br#"{"items":[{"name":"GitHub"}]}"#,
            ] {
                let (iv, ct, mac) = key.encrypt_for_tests([9; 16], plain);
                assert_eq!(key.decrypt(&iv, &ct, &mac).unwrap().as_slice(), plain);
                let mut bad = ct.clone();
                bad[0] ^= 1;
                assert_eq!(
                    key.decrypt(&iv, &bad, &mac).err(),
                    Some(CryptoError::DecryptionFailed)
                );
            }
            let wrong = BitwardenKey::derive("correct horsE", "salt-from-file", kdf).unwrap();
            let (iv, ct, mac) = key.encrypt_for_tests([1; 16], b"secret");
            assert_eq!(
                wrong.decrypt(&iv, &ct, &mac).err(),
                Some(CryptoError::DecryptionFailed)
            );
        }
    }

    #[test]
    fn derivation_matches_known_pbkdf2_vector() {
        // PBKDF2-HMAC-SHA256("password", "salt", 1) 的前 32 字节（RFC 7914 §11 同源的公开测试值）
        let mut out = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(b"password", b"salt", 1, &mut out);
        assert_eq!(
            hex::encode(out),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
    }

    #[test]
    fn limits() {
        assert_eq!(
            BitwardenKey::derive(
                "pw",
                "s",
                BitwardenKdf::Pbkdf2 {
                    iterations: 2_000_001
                }
            )
            .err(),
            Some(CryptoError::KdfAboveMaximum)
        );
        assert_eq!(
            BitwardenKey::derive(
                "pw",
                "s",
                BitwardenKdf::Argon2id {
                    memory_mib: 2048,
                    iterations: 3,
                    parallelism: 4
                }
            )
            .err(),
            Some(CryptoError::KdfAboveMaximum)
        );
        assert_eq!(
            BitwardenKey::derive("", "s", BitwardenKdf::Pbkdf2 { iterations: 1 }).err(),
            Some(CryptoError::EmptyPassword)
        );
    }
}
