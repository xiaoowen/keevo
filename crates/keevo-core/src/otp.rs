//! 一次性密码字段（`totp`）的解析与计算（`docs/product.md` §5.4）。
//!
//! 字段的文本是 `otpauth://totp/…` URI（Key Uri Format），也可以只是一个 Base32 密钥，此时使用默认参数：
//! HMAC-SHA-1、6 位、30 秒。HOTP 与 Steam 等变体不在 M1 中。

use keevo_crypto::{OTP_DIGITS, OtpAlgorithm, OtpKey};
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

/// 周期的范围（秒）。
pub const OTP_PERIOD: core::ops::RangeInclusive<u32> = 1..=3600;
const DEFAULT_PERIOD: u32 = 30;
const DEFAULT_DIGITS: u32 = 6;
/// 输入文本的长度上限。
const MAX_INPUT_LEN: usize = 4096;

/// 解析后的一次性密码配置。
pub struct OtpConfig {
    /// 发行方（如 `GitHub`）。
    pub issuer: Option<String>,
    /// 账户名（如 `octocat@example.com`）。
    pub account: Option<String>,
    /// HMAC 使用的哈希。
    pub algorithm: OtpAlgorithm,
    /// 位数。
    pub digits: u32,
    /// 周期（秒）。
    pub period: u32,
    key: OtpKey,
}

/// 某一时刻的验证码。
pub struct OtpCode {
    /// 验证码（定长数字）。
    pub code: Zeroizing<String>,
    /// 周期（秒）。
    pub period: u32,
    /// 距这个验证码失效还有多少毫秒。
    pub remaining_ms: u64,
}

impl OtpConfig {
    /// 解析 `otpauth://totp/…` URI 或 Base32 密钥。
    ///
    /// # Errors
    /// 格式不对、不是 TOTP、密钥不是合法的 Base32、参数超出范围时返回 [`CoreError::InvalidOtp`]。
    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim();
        if text.is_empty() || text.len() > MAX_INPUT_LEN {
            return Err(CoreError::InvalidOtp);
        }
        if !text
            .get(..10)
            .is_some_and(|p| p.eq_ignore_ascii_case("otpauth://"))
        {
            return Self::build(
                None,
                None,
                &base32_decode(text)?,
                OtpAlgorithm::Sha1,
                DEFAULT_DIGITS,
                DEFAULT_PERIOD,
            );
        }
        let url = url::Url::parse(text).map_err(|_| CoreError::InvalidOtp)?;
        if !url
            .host_str()
            .is_some_and(|h| h.eq_ignore_ascii_case("totp"))
        {
            return Err(CoreError::InvalidOtp);
        }
        let label = percent_decode(url.path().trim_start_matches('/'))?;
        let (mut issuer, account) = match label.split_once(':') {
            Some((i, a)) => (non_empty(i), non_empty(a)),
            None => (None, non_empty(&label)),
        };
        let mut secret = None;
        let mut algorithm = OtpAlgorithm::Sha1;
        let mut digits = DEFAULT_DIGITS;
        let mut period = DEFAULT_PERIOD;
        for (k, v) in url.query_pairs() {
            match k.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(base32_decode(&v)?),
                "issuer" => issuer = non_empty(&v).or(issuer),
                "algorithm" => {
                    algorithm = match v.to_ascii_uppercase().as_str() {
                        "SHA1" => OtpAlgorithm::Sha1,
                        "SHA256" => OtpAlgorithm::Sha256,
                        "SHA512" => OtpAlgorithm::Sha512,
                        _ => return Err(CoreError::InvalidOtp),
                    };
                }
                "digits" => digits = v.parse().map_err(|_| CoreError::InvalidOtp)?,
                "period" => period = v.parse().map_err(|_| CoreError::InvalidOtp)?,
                // 其他参数（image、counter 等）不影响 TOTP，忽略
                _ => {}
            }
        }
        let secret = secret.ok_or(CoreError::InvalidOtp)?;
        Self::build(issuer, account, &secret, algorithm, digits, period)
    }

    fn build(
        issuer: Option<String>,
        account: Option<String>,
        secret: &Zeroizing<Vec<u8>>,
        algorithm: OtpAlgorithm,
        digits: u32,
        period: u32,
    ) -> Result<Self> {
        if !OTP_DIGITS.contains(&digits) || !OTP_PERIOD.contains(&period) {
            return Err(CoreError::InvalidOtp);
        }
        let key =
            OtpKey::new(secret.clone(), algorithm, digits).map_err(|_| CoreError::InvalidOtp)?;
        Ok(Self {
            issuer,
            account,
            algorithm,
            digits,
            period,
            key,
        })
    }

    /// Unix 毫秒 `unix_ms` 时的验证码。
    ///
    /// # Errors
    /// 不会失败；保留 `Result` 是为了与密码学层一致。
    pub fn code_at(&self, unix_ms: u64) -> Result<OtpCode> {
        let seconds = unix_ms / 1000;
        let code = self.key.totp(seconds, self.period)?;
        let period_ms = u64::from(self.period).saturating_mul(1000);
        let elapsed = unix_ms.checked_rem(period_ms).unwrap_or(0);
        Ok(OtpCode {
            code,
            period: self.period,
            remaining_ms: period_ms.saturating_sub(elapsed),
        })
    }
}

fn non_empty(s: &str) -> Option<String> {
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_owned())
}

fn percent_decode(s: &str) -> Result<String> {
    let mut out = Vec::with_capacity(s.len());
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hi = bytes.next().and_then(|c| char::from(c).to_digit(16));
            let lo = bytes.next().and_then(|c| char::from(c).to_digit(16));
            let (Some(hi), Some(lo)) = (hi, lo) else {
                return Err(CoreError::InvalidOtp);
            };
            out.push(u8::try_from((hi << 4) | lo).map_err(|_| CoreError::InvalidOtp)?);
        } else {
            out.push(b);
        }
    }
    String::from_utf8(out).map_err(|_| CoreError::InvalidOtp)
}

/// RFC 4648 Base32：不区分大小写，忽略空格与连字符，末尾的 `=` 可有可无。
fn base32_decode(s: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(s.len()));
    // 缓冲区只保留尚未输出的不足 8 位，因此不会溢出
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    let mut padding = false;
    for c in s.bytes() {
        let value = match c {
            b' ' | b'-' | b'\t' => continue,
            b'=' => {
                padding = true;
                continue;
            }
            _ if padding => return Err(CoreError::InvalidOtp),
            b'A'..=b'Z' => c.wrapping_sub(b'A'),
            b'a'..=b'z' => c.wrapping_sub(b'a'),
            b'2'..=b'7' => c.wrapping_sub(b'2').wrapping_add(26),
            _ => return Err(CoreError::InvalidOtp),
        };
        buffer = (buffer << 5) | u32::from(value);
        bits = bits.wrapping_add(5);
        if bits >= 8 {
            bits = bits.wrapping_sub(8);
            out.push(u8::try_from((buffer >> bits) & 0xff).map_err(|_| CoreError::InvalidOtp)?);
            buffer &= (1u32 << bits).wrapping_sub(1);
        }
    }
    // 剩下不足 8 位的部分必须是 0，否则不是规范的 Base32
    if buffer != 0 || out.is_empty() {
        return Err(CoreError::InvalidOtp);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_SEED_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // "12345678901234567890"

    #[test]
    fn base32() {
        assert_eq!(
            base32_decode(RFC_SEED_B32).unwrap().as_slice(),
            b"12345678901234567890"
        );
        assert_eq!(
            base32_decode("gezd gnbv-gy3t qojq gezd gnbv gy3t qojq")
                .unwrap()
                .as_slice(),
            b"12345678901234567890"
        );
        assert_eq!(base32_decode("MZXW6===").unwrap().as_slice(), b"foo");
        assert_eq!(base32_decode("MZXW6").unwrap().as_slice(), b"foo");
        for bad in ["", "====", "MZXW1", "MZXW6=A", "MZXW7", "中文"] {
            assert!(base32_decode(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn uri_and_bare_secret() {
        let uri = format!(
            "otpauth://totp/ACME%20Co:alice%40example.com?secret={RFC_SEED_B32}&issuer=ACME%20Co&digits=8&period=30&algorithm=sha1&image=x"
        );
        let c = OtpConfig::parse(&uri).unwrap();
        assert_eq!(c.issuer.as_deref(), Some("ACME Co"));
        assert_eq!(c.account.as_deref(), Some("alice@example.com"));
        assert_eq!(
            (c.digits, c.period, c.algorithm),
            (8, 30, OtpAlgorithm::Sha1)
        );
        assert_eq!(
            c.code_at(59_000).unwrap().code.as_str(),
            "94287082",
            "RFC 6238 附录 B"
        );

        let bare = OtpConfig::parse(&format!("  {RFC_SEED_B32}\n")).unwrap();
        assert_eq!((bare.digits, bare.period), (6, 30));
        assert!(bare.issuer.is_none() && bare.account.is_none());
        assert_eq!(
            bare.code_at(59_000).unwrap().code.as_str(),
            "287082",
            "8 位结果的后 6 位"
        );

        let label_only = OtpConfig::parse(&format!(
            "OTPAUTH://TOTP/GitHub:octocat?secret={RFC_SEED_B32}"
        ))
        .unwrap();
        assert_eq!(
            label_only.issuer.as_deref(),
            Some("GitHub"),
            "标签中的发行方"
        );
        let sha256 = OtpConfig::parse(&format!(
            "otpauth://totp/x?secret={RFC_SEED_B32}&algorithm=SHA256"
        ))
        .unwrap();
        assert_eq!(sha256.algorithm, OtpAlgorithm::Sha256);
    }

    #[test]
    fn remaining_time() {
        let c = OtpConfig::parse(RFC_SEED_B32).unwrap();
        let at = c.code_at(59_000).unwrap();
        assert_eq!((at.period, at.remaining_ms), (30, 1_000));
        assert_eq!(c.code_at(60_000).unwrap().remaining_ms, 30_000);
        assert_ne!(
            c.code_at(59_999).unwrap().code,
            c.code_at(60_000).unwrap().code,
            "跨过周期边界换码"
        );
    }

    #[test]
    fn rejects_bad_input() {
        let s = RFC_SEED_B32;
        for bad in [
            String::new(),
            "otpauth://hotp/x?secret=GEZDGNBV&counter=1".to_owned(),
            "otpauth://totp/x".to_owned(),
            format!("otpauth://totp/x?secret={s}&digits=5"),
            format!("otpauth://totp/x?secret={s}&digits=9"),
            format!("otpauth://totp/x?secret={s}&period=0"),
            format!("otpauth://totp/x?secret={s}&period=3601"),
            format!("otpauth://totp/x?secret={s}&algorithm=MD5"),
            "otpauth://totp/x?secret=not-base32!".to_owned(),
            format!("otpauth://totp/%ZZ?secret={s}"),
            "https://example.com".to_owned(),
            "x".repeat(MAX_INPUT_LEN + 1),
        ] {
            assert_eq!(
                OtpConfig::parse(&bad).err(),
                Some(CoreError::InvalidOtp),
                "{bad:?}"
            );
        }
    }
}
