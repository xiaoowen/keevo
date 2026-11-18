//! 排序键的生成（`spec/vault-format.md` §2.4：字母表 `[0-9A-Za-z]`，1–64 个字符，按字节序比较；
//! 生成算法不属于格式）。
//!
//! [`order_between`] 在两个已有的键之间生成一个新键，因此移动一个字段只需改写这一个字段，
//! 并发的移动也能确定性地合并。它适用于任意合法的键，包括 M0 的定宽十进制键（如 `"0000000000"`）：
//! 按字节序，较短的前缀更小，所以 `"0"` < `"00"`，常见的分数索引算法假设键不以最小字符结尾，这里不作此假设。

/// 排序键的字母表，按 ASCII（也就是字节序）排列。
const ALPHABET: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
/// 排序键的最大长度。
pub const MAX_ORDER_LEN: usize = 64;

fn digit(c: u8) -> Option<i32> {
    ALPHABET
        .iter()
        .position(|&x| x == c)
        .and_then(|i| i32::try_from(i).ok())
}

fn char_of(d: i32) -> Option<char> {
    usize::try_from(d)
        .ok()
        .and_then(|i| ALPHABET.get(i))
        .map(|&b| char::from(b))
}

/// 生成一个严格介于 `lower` 与 `upper` 之间的键。`None` 表示没有这一侧的界限。
///
/// 返回 `None` 的情形：两个键不合法、`lower >= upper`，或者两者之间放不下新键
/// （例如 `upper` 是 `"0"`，或者结果会超过 64 个字符）。此时调用方应重新编号整个列表（[`order_sequence`]）。
#[must_use]
pub fn order_between(lower: Option<&str>, upper: Option<&str>) -> Option<String> {
    let a: Vec<i32> = lower
        .unwrap_or("")
        .bytes()
        .map(digit)
        .collect::<Option<_>>()?;
    let b: Option<Vec<i32>> = match upper {
        Some(u) => Some(u.bytes().map(digit).collect::<Option<_>>()?),
        None => None,
    };
    if let (Some(l), Some(u)) = (lower, upper)
        && l >= u
    {
        return None;
    }
    if b.as_ref().is_some_and(Vec::is_empty) {
        return None;
    }
    // 逐位决定。lower_tight：到目前为止生成的前缀等于 lower 的前缀；upper_tight 同理。
    // 生成的键尽量不以最小字符 `0` 结尾：以它结尾的键 X 与 X 加更多 `0` 之间放不下任何键。
    // 没有别的选择时才退而使用这样的键（fallback）
    let mut out = String::new();
    let mut lower_tight = true;
    let mut upper_tight = b.is_some();
    let mut fallback = None;
    for i in 0..MAX_ORDER_LEN {
        // lo：取大于它的字符就严格大于 lower；hi：取小于它的字符就严格小于 upper。-1 表示"已到末尾"
        let lo = if lower_tight {
            a.get(i).copied().unwrap_or(-1)
        } else {
            -1
        };
        let hi = match &b {
            Some(b) if upper_tight => b.get(i).copied().unwrap_or(-1),
            _ => 62,
        };
        // 停在当前前缀：必须严格大于 lower（已不贴着它），并且严格小于 upper（不贴着，或是它的真前缀）
        let below_upper = !upper_tight || b.as_ref().is_some_and(|b| b.len() > i);
        if !out.is_empty() && !lower_tight && below_upper {
            if !out.ends_with('0') {
                return Some(out);
            }
            fallback.get_or_insert_with(|| out.clone());
        }
        if hi.saturating_sub(lo) > 1 {
            let mid = lo.saturating_add(hi).div_euclid(2);
            out.push(char_of(mid)?);
            if mid != 0 {
                return Some(out);
            }
            // 只有 lo = -1、hi = 1 时 mid 才是 0：两侧都已严格分开，再加一位避免以 0 结尾
            lower_tight = false;
            upper_tight = false;
            continue;
        }
        if lo == hi && lo >= 0 {
            out.push(char_of(lo)?);
            continue;
        }
        if hi.saturating_sub(lo) == 1 {
            if lo >= 0 {
                // 取 lower 的字符：仍贴着 lower，已严格小于 upper
                out.push(char_of(lo)?);
                upper_tight = false;
            } else {
                // lower 已到末尾而 upper 这一位是最小字符：只能取它，已严格大于 lower
                out.push(char_of(hi)?);
                lower_tight = false;
            }
            continue;
        }
        break;
    }
    fallback
}

/// 为 `n` 个元素生成均匀分布的新键（重新编号整个列表时使用）。
#[must_use]
pub fn order_sequence(n: usize) -> Vec<String> {
    // 两位已足够 3843 个元素；更多时用三位
    let width: u32 = if n < 62 * 62 - 1 { 2 } else { 3 };
    let space = 62usize.saturating_pow(width);
    let slots = n.saturating_add(1);
    (1..=n)
        .map(|i| {
            let mut v = i.saturating_mul(space).checked_div(slots).unwrap_or(0);
            let mut s = Vec::with_capacity(3);
            for _ in 0..width {
                s.push(
                    ALPHABET
                        .get(v.checked_rem(62).unwrap_or(0))
                        .copied()
                        .unwrap_or(b'0'),
                );
                v = v.checked_div(62).unwrap_or(0);
            }
            s.reverse();
            // 去掉末尾的最小字符，给之后在它前面插入留出空间
            while s.len() > 1 && s.last() == Some(&b'0') {
                s.pop();
            }
            String::from_utf8(s).unwrap_or_default()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid(k: &str) -> bool {
        (1..=MAX_ORDER_LEN).contains(&k.len()) && k.bytes().all(|c| c.is_ascii_alphanumeric())
    }

    fn between(a: Option<&str>, b: Option<&str>) -> String {
        let k = order_between(a, b).unwrap_or_else(|| panic!("{a:?} 与 {b:?} 之间应能插入"));
        assert!(valid(&k), "{k}");
        if let Some(a) = a {
            assert!(a < k.as_str(), "{a} < {k}");
        }
        if let Some(b) = b {
            assert!(k.as_str() < b, "{k} < {b}");
        }
        k
    }

    #[test]
    fn basic_cases() {
        assert_eq!(between(None, None), "U");
        between(Some("az"), None);
        between(Some("z"), None);
        between(None, Some("1"));
        between(Some("a"), Some("b"));
        between(Some("aU"), Some("aV"));
        between(Some("0000000000"), Some("0000001024"));
        between(Some("0000000000"), Some("0000000001"));
        between(None, Some("0000000000"));
        between(Some("0000000000"), None);
        between(Some("zzzz"), None);
        assert_eq!(between(Some("0000000000"), Some("0000001024")), "0000000V");
        assert!(!between(None, Some("1")).ends_with('0'), "尽量不以 0 结尾");
    }

    #[test]
    fn impossible_or_invalid() {
        assert_eq!(
            order_between(None, Some("0")),
            None,
            "没有比 \"0\" 更小的键"
        );
        assert_eq!(
            order_between(Some("0"), Some("00")),
            None,
            "按字节序，两者之间放不下任何键"
        );
        assert_eq!(order_between(Some("a"), Some("a0")), None);
        assert_eq!(order_between(Some("b"), Some("a")), None);
        assert_eq!(order_between(Some("a"), Some("a")), None);
        assert_eq!(order_between(Some("a-b"), None), None, "不合法的键");
        assert_eq!(order_between(None, Some("")), None);
        assert_eq!(
            order_between(Some(&"z".repeat(64)), None),
            None,
            "超过 64 个字符"
        );
    }

    /// 随机地在列表中插入：每次插入后整个列表仍严格递增、键都合法。
    #[test]
    fn random_insertions_keep_order() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = move |n: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            usize::try_from(state % u64::try_from(n).unwrap()).unwrap()
        };
        let mut list: Vec<String> = vec![
            "0000000000".into(),
            "0000001024".into(),
            "0000002048".into(),
        ];
        for _ in 0..2000 {
            let pos = next(list.len() + 1);
            let lower = pos.checked_sub(1).map(|i| list[i].as_str());
            let upper = list.get(pos).map(String::as_str);
            match order_between(lower, upper) {
                Some(k) => list.insert(pos, k),
                None => {
                    // 只有 upper 等于 lower 后面再加若干个 0 时才放不下（M0 的全零键会造成这种情况）
                    let u = upper.unwrap();
                    let rest = lower.map_or(u, |l| u.strip_prefix(l).unwrap());
                    assert!(rest.bytes().all(|c| c == b'0'), "{lower:?} {upper:?}");
                    continue;
                }
            }
            assert!(list.windows(2).all(|w| w[0] < w[1]));
        }
        assert!(list.iter().all(|k| valid(k)));
        assert!(
            list.iter().map(String::len).max().unwrap() < 40,
            "随机插入下长度增长很慢"
        );
    }

    /// 总在同一个位置插入（最坏情况）：朝上界方向大约每 6 次、朝下界方向大约每 4–5 次增加一个字符。
    #[test]
    fn repeated_insertions_at_the_same_place() {
        let mut lower = "a".to_owned();
        let upper = "b".to_owned();
        for _ in 0..200 {
            lower = between(Some(&lower), Some(&upper));
        }
        assert!(lower.len() <= 45, "{}", lower.len());
        // 朝下界方向（例如总在最前面插入）增长更快，大约每 4–5 次加一个字符；
        // 超过 64 个字符时返回 None，调用方重新编号整个列表
        let mut upper2 = "b".to_owned();
        for _ in 0..200 {
            upper2 = between(Some("a"), Some(&upper2));
        }
        assert!(upper2.len() <= 55, "{}", upper2.len());
    }

    #[test]
    fn sequence_is_increasing_and_leaves_room() {
        for n in [0usize, 1, 2, 10, 61, 62, 500, 4000] {
            let s = order_sequence(n);
            assert_eq!(s.len(), n);
            assert!(s.windows(2).all(|w| w[0] < w[1]), "n = {n}");
            assert!(s.iter().all(|k| valid(k) && !k.ends_with('0')), "n = {n}");
            if let Some(first) = s.first() {
                between(None, Some(first));
            }
        }
    }
}
