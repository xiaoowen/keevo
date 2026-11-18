//! 一次性密码：HOTP（RFC 4226）与 TOTP（RFC 6238），支持 HMAC-SHA-1、SHA-256、SHA-512。
//!
//! 只做计算。`otpauth://` 的解析在 `keevo-core`（不涉及密码学原语）。

use hmac::{Hmac, KeyInit, Mac};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

/// HMAC 使用的哈希。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OtpAlgorithm {
    /// HMAC-SHA-1（默认，绝大多数网站使用）。
    Sha1,
    /// HMAC-SHA-256。
    Sha256,
    /// HMAC-SHA-512。
    Sha512,
}

/// 验证码位数的范围。RFC 4226 要求至少 6 位；超过 8 位时 31 位的截断值已不足以均匀覆盖。
pub const OTP_DIGITS: core::ops::RangeInclusive<u32> = 6..=8;
/// 密钥长度上限（字节）。
pub const MAX_OTP_SECRET_LEN: usize = 256;

/// 一次性密码的密钥与参数。释放时清零密钥。
pub struct OtpKey {
    secret: Zeroizing<Vec<u8>>,
    algorithm: OtpAlgorithm,
    digits: u32,
}

impl OtpKey {
    /// 构造。
    ///
    /// # Errors
    /// 密钥为空或超过 [`MAX_OTP_SECRET_LEN`]、位数不在 [`OTP_DIGITS`] 内时返回 [`CryptoError::Malformed`]。
    pub fn new(secret: Zeroizing<Vec<u8>>, algorithm: OtpAlgorithm, digits: u32) -> Result<Self> {
        if secret.is_empty() || secret.len() > MAX_OTP_SECRET_LEN || !OTP_DIGITS.contains(&digits) {
            return Err(CryptoError::Malformed);
        }
        Ok(Self {
            secret,
            algorithm,
            digits,
        })
    }

    /// HOTP：计数器 `counter` 对应的验证码（RFC 4226 §5.3），定长、左侧补零。
    ///
    /// # Errors
    /// 不会失败；保留 `Result` 是为了与其他构造一致。
    pub fn hotp(&self, counter: u64) -> Result<Zeroizing<String>> {
        let msg = counter.to_be_bytes();
        let mac: Zeroizing<Vec<u8>> = match self.algorithm {
            OtpAlgorithm::Sha1 => {
                let mut m = Hmac::<sha1::Sha1>::new_from_slice(&self.secret)
                    .map_err(|_| CryptoError::Malformed)?;
                m.update(&msg);
                Zeroizing::new(m.finalize().into_bytes().to_vec())
            }
            OtpAlgorithm::Sha256 => {
                let mut m = Hmac::<sha2::Sha256>::new_from_slice(&self.secret)
                    .map_err(|_| CryptoError::Malformed)?;
                m.update(&msg);
                Zeroizing::new(m.finalize().into_bytes().to_vec())
            }
            OtpAlgorithm::Sha512 => {
                let mut m = Hmac::<sha2::Sha512>::new_from_slice(&self.secret)
                    .map_err(|_| CryptoError::Malformed)?;
                m.update(&msg);
                Zeroizing::new(m.finalize().into_bytes().to_vec())
            }
        };
        // 动态截断：取最后一个字节的低 4 位作为偏移，读出 31 位
        let last = mac.last().copied().ok_or(CryptoError::Malformed)?;
        let offset = usize::from(last & 0x0f);
        let window: [u8; 4] = mac
            .get(offset..offset.saturating_add(4))
            .and_then(|s| s.try_into().ok())
            .ok_or(CryptoError::Malformed)?;
        let binary = u32::from_be_bytes(window) & 0x7fff_ffff;
        let code = 10u32
            .checked_pow(self.digits)
            .and_then(|modulus| binary.checked_rem(modulus))
            .ok_or(CryptoError::Malformed)?;
        let width = usize::try_from(self.digits).map_err(|_| CryptoError::Malformed)?;
        Ok(Zeroizing::new(format!("{code:0width$}")))
    }

    /// TOTP：Unix 时间 `unix_seconds` 所在时间步的验证码（RFC 6238 §4，T0 = 0）。
    ///
    /// # Errors
    /// `period` 为 0 时返回 [`CryptoError::Malformed`]。
    pub fn totp(&self, unix_seconds: u64, period: u32) -> Result<Zeroizing<String>> {
        let step = unix_seconds
            .checked_div(u64::from(period))
            .ok_or(CryptoError::Malformed)?;
        self.hotp(step)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: &[u8], algorithm: OtpAlgorithm, digits: u32) -> OtpKey {
        OtpKey::new(Zeroizing::new(seed.to_vec()), algorithm, digits).unwrap()
    }

    /// RFC 4226 附录 D：HMAC-SHA-1，6 位，计数器 0–9。
    #[test]
    fn rfc4226_appendix_d() {
        let k = key(b"12345678901234567890", OtpAlgorithm::Sha1, 6);
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, code) in (0u64..).zip(expected) {
            assert_eq!(k.hotp(counter).unwrap().as_str(), code, "计数器 {counter}");
        }
    }

    /// RFC 6238 附录 B：8 位，周期 30 秒，三种哈希各用对应长度的种子。
    #[test]
    fn rfc6238_appendix_b() {
        let sha1 = key(b"12345678901234567890", OtpAlgorithm::Sha1, 8);
        let sha256 = key(b"12345678901234567890123456789012", OtpAlgorithm::Sha256, 8);
        let sha512 = key(
            b"1234567890123456789012345678901234567890123456789012345678901234",
            OtpAlgorithm::Sha512,
            8,
        );
        let cases: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];
        for (t, c1, c256, c512) in cases {
            assert_eq!(sha1.totp(t, 30).unwrap().as_str(), c1, "SHA-1 t={t}");
            assert_eq!(sha256.totp(t, 30).unwrap().as_str(), c256, "SHA-256 t={t}");
            assert_eq!(sha512.totp(t, 30).unwrap().as_str(), c512, "SHA-512 t={t}");
        }
    }

    #[test]
    fn parameters_are_checked() {
        let seed = || Zeroizing::new(b"12345678901234567890".to_vec());
        assert!(OtpKey::new(Zeroizing::new(Vec::new()), OtpAlgorithm::Sha1, 6).is_err());
        assert!(
            OtpKey::new(
                Zeroizing::new(vec![1; MAX_OTP_SECRET_LEN + 1]),
                OtpAlgorithm::Sha1,
                6
            )
            .is_err()
        );
        assert!(OtpKey::new(seed(), OtpAlgorithm::Sha1, 5).is_err());
        assert!(OtpKey::new(seed(), OtpAlgorithm::Sha1, 9).is_err());
        let k = OtpKey::new(seed(), OtpAlgorithm::Sha1, 7).unwrap();
        assert_eq!(k.hotp(0).unwrap().len(), 7, "定长、左侧补零");
        assert!(k.totp(59, 0).is_err());
        assert_eq!(k.totp(59, 60).unwrap(), k.hotp(0).unwrap());
    }
}
