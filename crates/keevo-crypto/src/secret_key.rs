use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::error::{Result, SecretKeyError};
use crate::random;

/// Crockford Base32 字母表（不含 I、L、O、U）。
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const BODY_CHARS: usize = 26;
const CHECK_CHARS: usize = 2;
const TOTAL_CHARS: usize = BODY_CHARS + CHECK_CHARS;

/// 账户密钥（Secret Key），128 位随机数（`spec/crypto.md` §4）。
///
/// 与主密码共同派生 AUK。释放时清零；不实现 `Debug`、`Clone` 与序列化。
pub struct AccountSecretKey(Zeroizing<[u8; 16]>);

impl AccountSecretKey {
    /// 生成新的账户密钥。
    ///
    /// # Errors
    /// 操作系统随机数生成器不可用时返回 [`crate::CryptoError::Random`]。
    pub fn generate() -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; 16]);
        random::fill(bytes.as_mut())?;
        Ok(Self(bytes))
    }

    /// 测试专用：由已知字节构造。
    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub(crate) fn expose(&self) -> &[u8; 16] {
        &self.0
    }

    /// 显示形式：`K1-XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX`。返回值同样是秘密，用后清零。
    #[must_use]
    pub fn to_display_string(&self) -> Zeroizing<String> {
        let values = codeword(&self.0);
        let mut out = Zeroizing::new(String::with_capacity(34));
        out.push_str("K1");
        for group in values.chunks(7) {
            out.push('-');
            for &v in group {
                out.push(char::from(symbol(v)));
            }
        }
        out
    }

    /// 按 §4.3 解析用户输入。容忍大小写、分隔符、空白、全角字符，以及 O/I/L 与 0/1 的混淆。
    ///
    /// # Errors
    /// 返回 [`crate::CryptoError::SecretKey`]，内含具体原因。
    pub fn parse(input: &str) -> Result<Self> {
        Ok(Self(parse_inner(input)?))
    }
}

fn parse_inner(input: &str) -> core::result::Result<Zeroizing<[u8; 16]>, SecretKeyError> {
    // 1–3：NFKC、转大写、去掉分隔符与空白
    let mut cleaned: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(32));
    for c in input.nfkc() {
        if matches!(c, '-' | ' ' | '\t' | '\r' | '\n') {
            continue;
        }
        if cleaned.len() >= 30 {
            return Err(SecretKeyError::WrongLength);
        }
        // 非 ASCII 字符在第 6 步统一报告为 invalid_character；这里先用占位符保留长度
        cleaned.push(if c.is_ascii() {
            u8::try_from(c.to_ascii_uppercase()).unwrap_or(b'?')
        } else {
            b'?'
        });
    }

    // 4：前缀与长度
    let chars: &[u8] = match cleaned.len() {
        30 => cleaned
            .strip_prefix(b"K1")
            .ok_or(SecretKeyError::WrongPrefix)?,
        TOTAL_CHARS => &cleaned,
        _ => return Err(SecretKeyError::WrongLength),
    };

    // 5–6：容错替换并映射为 5 位值
    let mut values = Zeroizing::new([0u8; TOTAL_CHARS]);
    for (slot, &c) in values.iter_mut().zip(chars) {
        let c = match c {
            b'O' => b'0',
            b'I' | b'L' => b'1',
            other => other,
        };
        *slot = alphabet_index(c).ok_or(SecretKeyError::InvalidCharacter)?;
    }

    // 7：首字符的高 2 位必须为 0
    let (body, check) = values.split_at(BODY_CHARS);
    if body.first().is_none_or(|&v| v > 7) {
        return Err(SecretKeyError::NonCanonical);
    }

    // 8：校验位
    if rs_check(body) != check {
        return Err(SecretKeyError::ChecksumMismatch);
    }
    let mut acc: u128 = 0;
    for &v in body {
        acc = (acc << 5) | u128::from(v);
    }
    Ok(Zeroizing::new(acc.to_be_bytes()))
}

fn alphabet_index(c: u8) -> Option<u8> {
    ALPHABET
        .iter()
        .position(|&a| a == c)
        .and_then(|i| u8::try_from(i).ok())
}

fn symbol(v: u8) -> u8 {
    ALPHABET.get(usize::from(v & 0x1f)).copied().unwrap_or(b'0')
}

/// 完整码字：26 个数据符号（`0b00 ‖ SK` 的 130 位，每 5 位一个）‖ 2 个校验符号。
fn codeword(bytes: &[u8; 16]) -> Zeroizing<[u8; TOTAL_CHARS]> {
    let value = u128::from_be_bytes(*bytes);
    let mut out = Zeroizing::new([0u8; TOTAL_CHARS]);
    let (body, check) = out.split_at_mut(BODY_CHARS);
    for (i, slot) in body.iter_mut().enumerate() {
        // 第 i 个符号是 130 位整数中从高位数第 i 个 5 位组；首组只含 3 个有效位
        let shift = 125usize.saturating_sub(i.saturating_mul(5));
        *slot = u8::try_from((value >> shift) & 0x1f).unwrap_or(0);
    }
    check.copy_from_slice(&rs_check(body));
    out
}

/// GF(32) 乘法，本原多项式 p(x) = x⁵ + x² + 1。
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut r = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            r ^= a;
        }
        b >>= 1;
        a <<= 1;
        if a & 0x20 != 0 {
            a ^= 0x25;
        }
    }
    r
}

/// GF(32) 上的 Reed–Solomon 校验（`spec/crypto.md` §4.2）。
///
/// 生成多项式 g(x) = (x + α)(x + α²) = x² + 6x + 8，α = 2。返回 m(x)·x² mod g(x) 的两个系数
/// （高次在前）。码长 28 ≤ 31，最小距离为 3，因此能检出任意 1–2 个符号的错误。
fn rs_check(data: &[u8]) -> [u8; CHECK_CHARS] {
    let (mut r1, mut r0) = (0u8, 0u8);
    for &m in data {
        let feedback = m ^ r1;
        r1 = r0 ^ gf_mul(feedback, 6);
        r0 = gf_mul(feedback, 8);
    }
    [r1, r0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_display_parse_roundtrip() {
        for _ in 0..200 {
            let sk = AccountSecretKey::generate().unwrap();
            let shown = sk.to_display_string();
            assert_eq!(shown.len(), 34);
            let parsed = AccountSecretKey::parse(&shown).unwrap();
            assert_eq!(parsed.expose(), sk.expose());
        }
    }

    #[test]
    fn generator_roots_are_alpha_and_alpha_squared() {
        // g(x) = x² + 6x + 8 在 α=2 与 α²=4 处为零
        for root in [2u8, 4] {
            let value = gf_mul(root, root) ^ gf_mul(6, root) ^ 8;
            assert_eq!(value, 0);
        }
    }

    /// 码字是否通过校验：校验符号等于由数据符号重新计算的值。
    fn valid(word: &[u8; TOTAL_CHARS]) -> bool {
        let (body, check) = word.split_at(BODY_CHARS);
        rs_check(body) == check
    }

    #[test]
    fn all_single_and_double_symbol_errors_are_detected() {
        let word = codeword(&[0x5a; 16]);
        assert!(valid(&word));
        for i in 0..TOTAL_CHARS {
            for ei in 1..32u8 {
                let mut w = *word;
                w[i] ^= ei;
                assert!(!valid(&w), "单符号错误未检出：位置 {i}");
                for j in (i + 1)..TOTAL_CHARS {
                    for ej in 1..32u8 {
                        let mut w2 = w;
                        w2[j] ^= ej;
                        assert!(!valid(&w2), "双符号错误未检出：位置 {i}, {j}");
                    }
                }
            }
        }
    }

    #[test]
    fn adjacent_transpositions_are_detected_through_parse() {
        let sk = AccountSecretKey::from_bytes([0x3c; 16]);
        let compact: Vec<u8> = sk.to_display_string().replace('-', "").into_bytes();
        for i in 2..compact.len() - 1 {
            if compact[i] == compact[i + 1] {
                continue;
            }
            let mut t = compact.clone();
            t.swap(i, i + 1);
            let t = String::from_utf8(t).unwrap();
            assert!(parse_inner(&t).is_err(), "相邻互换未检出：{t}");
        }
    }
}
