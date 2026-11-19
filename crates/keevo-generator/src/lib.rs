//! 密码生成器：随机字符、口令短语、PIN。
//!
//! 随机数只来自 `keevo-crypto` 的无偏均匀抽样（[`keevo_crypto::random_below`]）。熵按实际的取值空间计算：
//! 要求"每个选中的字符类别至少出现一次"时，用容斥原理计算满足条件的密码个数，而不是 `长度 × log₂(字符数)`。
//!
//! 口令短语使用 EFF 大词表（7776 个单词，Electronic Frontier Foundation，CC BY 3.0 US，
//! <https://www.eff.org/dice>），见 `wordlist/eff_large.txt` 与 `wordlist/README.md`。
//!
//! 单独成为一个 crate，是为了让 Keevo.app（经 `keevo-core`）与浏览器扩展（经 `keevo-wasm`）用同一份实现：
//! 它只依赖 `keevo-crypto` 的随机数，不依赖存储。

use std::sync::OnceLock;

use keevo_crypto::{CryptoError, random_below};
use zeroize::Zeroizing;

/// 生成失败的原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneratorError {
    /// 参数超出范围，或没有选中任何字符类别。
    OutOfRange,
    /// 随机数不可用。
    Crypto(CryptoError),
}

impl core::fmt::Display for GeneratorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OutOfRange => f.write_str("value out of range"),
            Self::Crypto(e) => write!(f, "crypto: {e}"),
        }
    }
}

impl std::error::Error for GeneratorError {}

impl From<CryptoError> for GeneratorError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

type Result<T> = core::result::Result<T, GeneratorError>;

/// 随机字符密码的长度范围。
pub const PASSWORD_LENGTH: core::ops::RangeInclusive<u32> = 8..=128;
/// 口令短语的单词数范围。
pub const PASSPHRASE_WORDS: core::ops::RangeInclusive<u32> = 3..=20;
/// PIN 的位数范围。
pub const PIN_LENGTH: core::ops::RangeInclusive<u32> = 4..=32;
/// 口令短语分隔符的最大字符数。
const MAX_SEPARATOR_CHARS: usize = 3;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
/// 绝大多数网站都接受的符号。不含引号、反斜杠、空格与括号，避免在命令行或配置文件里出问题。
const SYMBOLS: &str = "!#$%&*+-.:;=?@^_~";
/// 容易看错的字符（手动输入时）。
const AMBIGUOUS: &str = "0Oo1lI";

const WORDLIST: &str = include_str!("wordlist/eff_large.txt");
/// EFF 大词表的单词数。
pub const WORDLIST_LEN: usize = 7776;

/// 生成方式。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipe {
    /// 随机字符。每个选中的类别至少出现一次。
    Password {
        /// 长度。
        length: u32,
        /// 小写字母。
        lowercase: bool,
        /// 大写字母。
        uppercase: bool,
        /// 数字。
        digits: bool,
        /// 符号。
        symbols: bool,
        /// 排除容易看错的字符（`0 O o 1 l I`）。
        avoid_ambiguous: bool,
    },
    /// 口令短语：从词表中独立均匀地选出若干单词。
    Passphrase {
        /// 单词数。
        words: u32,
        /// 分隔符（最多 3 个字符）。
        separator: String,
        /// 每个单词首字母大写。不增加熵。
        capitalize: bool,
        /// 在随机一个单词后面加一位随机数字。
        include_number: bool,
    },
    /// 纯数字。
    Pin {
        /// 位数。
        length: u32,
    },
}

/// 生成结果。
pub struct Generated {
    /// 生成的值。
    pub value: Zeroizing<String>,
    /// 熵（比特），按实际的取值空间计算。
    pub entropy_bits: f64,
}

/// 按 `recipe` 生成。
///
/// # Errors
/// 参数超出范围或没有选中任何字符类别时返回 [`GeneratorError::OutOfRange`]；随机数不可用时返回对应错误。
pub fn generate(recipe: &Recipe) -> Result<Generated> {
    match recipe {
        Recipe::Password {
            length,
            lowercase,
            uppercase,
            digits,
            symbols,
            avoid_ambiguous,
        } => {
            if !PASSWORD_LENGTH.contains(length) {
                return Err(GeneratorError::OutOfRange);
            }
            let classes: Vec<Vec<char>> = [
                (*lowercase, LOWER),
                (*uppercase, UPPER),
                (*digits, DIGITS),
                (*symbols, SYMBOLS),
            ]
            .into_iter()
            .filter(|(on, _)| *on)
            .map(|(_, set)| {
                set.chars()
                    .filter(|c| !*avoid_ambiguous || !AMBIGUOUS.contains(*c))
                    .collect()
            })
            .collect();
            if classes.is_empty() {
                return Err(GeneratorError::OutOfRange);
            }
            password(&classes, *length)
        }
        Recipe::Passphrase {
            words,
            separator,
            capitalize,
            include_number,
        } => {
            if !PASSPHRASE_WORDS.contains(words) || separator.chars().count() > MAX_SEPARATOR_CHARS
            {
                return Err(GeneratorError::OutOfRange);
            }
            passphrase(*words, separator, *capitalize, *include_number)
        }
        Recipe::Pin { length } => {
            if !PIN_LENGTH.contains(length) {
                return Err(GeneratorError::OutOfRange);
            }
            let digits: Vec<char> = DIGITS.chars().collect();
            let mut out = Zeroizing::new(String::new());
            for _ in 0..*length {
                out.push(pick(&digits)?);
            }
            Ok(Generated {
                value: out,
                entropy_bits: f64::from(*length) * 10f64.log2(),
            })
        }
    }
}

fn pick(set: &[char]) -> Result<char> {
    let n = u32::try_from(set.len()).map_err(|_| GeneratorError::OutOfRange)?;
    let i = usize::try_from(random_below(n)?).map_err(|_| GeneratorError::OutOfRange)?;
    set.get(i).copied().ok_or(GeneratorError::OutOfRange)
}

/// 在全部选中字符上均匀抽样；缺少某个类别时整体重抽。这样结果在"满足条件的密码"上仍然均匀分布。
fn password(classes: &[Vec<char>], length: u32) -> Result<Generated> {
    let alphabet: Vec<char> = classes.iter().flatten().copied().collect();
    loop {
        let mut out = Zeroizing::new(String::with_capacity(
            usize::try_from(length).unwrap_or(0).saturating_mul(4),
        ));
        for _ in 0..length {
            out.push(pick(&alphabet)?);
        }
        if classes
            .iter()
            .all(|set| out.chars().any(|c| set.contains(&c)))
        {
            let sizes: Vec<usize> = classes.iter().map(Vec::len).collect();
            return Ok(Generated {
                value: out,
                entropy_bits: password_entropy(&sizes, length),
            });
        }
    }
}

/// 长度为 `length`、每个类别至少出现一次的字符串个数的 log₂（容斥原理）：
/// `N^L · Σ_S (−1)^|S| · ((N − Σ_{c∈S} |c|) / N)^L`，其中 S 取遍类别的子集。
#[allow(clippy::as_conversions, clippy::cast_precision_loss)]
fn password_entropy(sizes: &[usize], length: u32) -> f64 {
    let total: usize = sizes.iter().sum();
    let n = total as f64;
    let l = i32::try_from(length).unwrap_or(i32::MAX);
    let mut ratio = 0.0f64;
    for mask in 0u32..(1u32 << sizes.len()) {
        let excluded: usize = sizes
            .iter()
            .enumerate()
            .filter(|(i, _)| mask & (1 << i) != 0)
            .map(|(_, s)| *s)
            .sum();
        let term = ((n - excluded as f64) / n).powi(l);
        if mask.count_ones() % 2 == 0 {
            ratio += term;
        } else {
            ratio -= term;
        }
    }
    f64::from(length) * n.log2() + ratio.log2()
}

fn wordlist() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| WORDLIST.lines().collect())
}

fn passphrase(
    words: u32,
    separator: &str,
    capitalize: bool,
    include_number: bool,
) -> Result<Generated> {
    let list = wordlist();
    let n = u32::try_from(list.len()).map_err(|_| GeneratorError::OutOfRange)?;
    let number_at = if include_number {
        Some(random_below(words)?)
    } else {
        None
    };
    let mut out = Zeroizing::new(String::new());
    for i in 0..words {
        if i > 0 {
            out.push_str(separator);
        }
        let index = usize::try_from(random_below(n)?).map_err(|_| GeneratorError::OutOfRange)?;
        let word = list.get(index).ok_or(GeneratorError::OutOfRange)?;
        if capitalize {
            let mut chars = word.chars();
            if let Some(first) = chars.next() {
                out.extend(first.to_uppercase());
                out.push_str(chars.as_str());
            }
        } else {
            out.push_str(word);
        }
        if number_at == Some(i) {
            out.push(char::from_digit(random_below(10)?, 10).ok_or(GeneratorError::OutOfRange)?);
        }
    }
    let mut entropy = f64::from(words) * f64::from(n).log2();
    if include_number {
        // 数字的位置与数值都随机
        entropy += (f64::from(words) * 10.0).log2();
    }
    Ok(Generated {
        value: out,
        entropy_bits: entropy,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pw(
        length: u32,
        lower: bool,
        upper: bool,
        digits: bool,
        symbols: bool,
        avoid: bool,
    ) -> Recipe {
        Recipe::Password {
            length,
            lowercase: lower,
            uppercase: upper,
            digits,
            symbols,
            avoid_ambiguous: avoid,
        }
    }

    #[test]
    fn wordlist_is_the_eff_large_list() {
        let list = wordlist();
        assert_eq!(list.len(), WORDLIST_LEN);
        assert_eq!(list.first(), Some(&"abacus"));
        assert_eq!(list.last(), Some(&"zoom"));
        let unique: std::collections::BTreeSet<_> = list.iter().collect();
        assert_eq!(unique.len(), WORDLIST_LEN, "没有重复");
    }

    #[test]
    fn passwords_follow_the_recipe() {
        for _ in 0..200 {
            let g = generate(&pw(12, true, true, true, true, false)).unwrap();
            let v = g.value.as_str();
            assert_eq!(v.chars().count(), 12);
            assert!(v.chars().any(|c| c.is_ascii_lowercase()));
            assert!(v.chars().any(|c| c.is_ascii_uppercase()));
            assert!(v.chars().any(|c| c.is_ascii_digit()));
            assert!(
                v.chars().any(|c| SYMBOLS.contains(c)),
                "每个类别至少一次：{v}"
            );
        }
        for _ in 0..200 {
            let g = generate(&pw(64, true, true, true, false, true)).unwrap();
            assert!(
                !g.value.chars().any(|c| AMBIGUOUS.contains(c)),
                "排除易混字符"
            );
            assert!(!g.value.chars().any(|c| SYMBOLS.contains(c)));
        }
        let only_digits = generate(&pw(8, false, false, true, false, false)).unwrap();
        assert!(only_digits.value.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn entropy_matches_the_space() {
        let close = |a: f64, b: f64| (a - b).abs() < 1e-9;
        // 只有一个类别时就是 L·log₂(N)
        let g = generate(&pw(8, true, false, false, false, false)).unwrap();
        assert!(close(g.entropy_bits, 8.0 * 26f64.log2()));
        // 两个类别、长度 2：满足条件的个数为 2·a·b
        assert!(close(
            password_entropy(&[26, 10], 2),
            (2.0 * 26.0 * 10.0f64).log2()
        ));
        // 四个类别时略小于 L·log₂(N)
        let all = password_entropy(&[26, 26, 10, 17], 20);
        assert!(all < 20.0 * 79f64.log2() && all > 20.0 * 79f64.log2() - 1.0);
        let pin = generate(&Recipe::Pin { length: 6 }).unwrap();
        assert!(close(pin.entropy_bits, 6.0 * 10f64.log2()));
        assert!(pin.value.chars().all(|c| c.is_ascii_digit()) && pin.value.len() == 6);
    }

    #[test]
    fn passphrases() {
        let g = generate(&Recipe::Passphrase {
            words: 5,
            separator: "-".into(),
            capitalize: false,
            include_number: false,
        })
        .unwrap();
        assert!((g.entropy_bits - 5.0 * 7776f64.log2()).abs() < 1e-9);
        let g = generate(&Recipe::Passphrase {
            words: 4,
            separator: " ".into(),
            capitalize: true,
            include_number: true,
        })
        .unwrap();
        let parts: Vec<&str> = g.value.split(' ').collect();
        assert_eq!(parts.len(), 4);
        assert!(
            parts
                .iter()
                .all(|w| w.chars().next().is_some_and(char::is_uppercase))
        );
        assert_eq!(
            g.value.chars().filter(char::is_ascii_digit).count(),
            1,
            "恰好一位数字"
        );
        assert!((g.entropy_bits - (4.0 * 7776f64.log2() + 40f64.log2())).abs() < 1e-9);
    }

    #[test]
    fn rejects_out_of_range() {
        for r in [
            pw(7, true, true, true, true, false),
            pw(129, true, true, true, true, false),
            pw(16, false, false, false, false, false),
            Recipe::Pin { length: 3 },
            Recipe::Pin { length: 33 },
            Recipe::Passphrase {
                words: 2,
                separator: "-".into(),
                capitalize: false,
                include_number: false,
            },
            Recipe::Passphrase {
                words: 21,
                separator: "-".into(),
                capitalize: false,
                include_number: false,
            },
            Recipe::Passphrase {
                words: 5,
                separator: "----".into(),
                capitalize: false,
                include_number: false,
            },
        ] {
            assert_eq!(
                generate(&r).err(),
                Some(GeneratorError::OutOfRange),
                "{r:?}"
            );
        }
    }
}
