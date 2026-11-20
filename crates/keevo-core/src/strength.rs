//! 密码强度评估（`docs/product.md` §5.6）：与 zxcvbn（Dropbox，MIT）等价的算法。
//!
//! 先找出密码中所有可能的模式（常见密码与单词、键盘路径、重复、序列、年份、日期），每种模式估计猜中所需的次数；
//! 再用动态规划找出"最容易猜"的不重叠组合，未被模式覆盖的部分按暴力枚举计。结果是估计的猜测次数与 0–4 分：
//! 少于 10³ 次为 0，10⁶ 为 1，10⁸ 为 2，10¹⁰ 为 3，以上为 4。
//!
//! 与 zxcvbn 的差别：按 Unicode 标量值（而不是 UTF-16 码元）处理；"近年"包括 1900–2099；只分析前 [`MAX_ANALYZED`]
//! 个字符，更长的部分按暴力枚举计入（如此之长的密码本来就足够强）。词频表见 `strength/README.md`。
//!
//! 只在本机计算，不涉及网络与存储。

#![allow(
    clippy::arithmetic_side_effects,
    reason = "下标与长度不超过 MAX_ANALYZED（64），猜测次数用 f64 计算，不会溢出或 panic"
)]

use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;

/// 每段分析这么多个字符（[`estimate`]）。
pub const MAX_ANALYZED: usize = 64;
/// 最多分析这么多段（1024 个字符）；之后的部分不计入，只会低估。
const MAX_WINDOWS: usize = 16;

const BRUTEFORCE_CARDINALITY: f64 = 10.0;
const MIN_GUESSES_BEFORE_GROWING_SEQUENCE: f64 = 10_000.0;
const MIN_SUBMATCH_GUESSES_SINGLE_CHAR: f64 = 10.0;
const MIN_SUBMATCH_GUESSES_MULTI_CHAR: f64 = 50.0;
const MIN_YEAR_SPACE: i32 = 20;
const DATE_MIN_YEAR: i64 = 1000;
const DATE_MAX_YEAR: i64 = 2050;
const MAX_DELTA: i64 = 5;

/// 评估结果。
#[derive(Debug, Clone, PartialEq)]
pub struct Strength {
    /// 估计的猜测次数。
    pub guesses: f64,
    /// 0（很弱）到 4（很强）。
    pub score: u8,
    /// 最主要的问题（只在 0–2 分时给出）。
    pub warning: Option<Warning>,
}

impl Strength {
    /// 以 2 为底的对数，即"约多少比特熵"。
    #[must_use]
    pub fn bits(&self) -> f64 {
        self.guesses.max(1.0).log2()
    }
}

/// 弱密码的主要原因。显示文字由界面层本地化。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Warning {
    /// 最常见的 10 个密码之一。
    Top10,
    /// 最常见的 100 个密码之一。
    Top100,
    /// 非常常见的密码。
    VeryCommon,
    /// 常见密码的变体（大小写、替换字符、倒写等），附原词。
    SimilarToCommon(String),
    /// 只是一个单词。
    SingleWord,
    /// 只是一个人名或姓氏。
    NameByItself,
    /// 包含常见的人名或姓氏。
    CommonName,
    /// 键盘上的一整行（如 `qwerty`）。
    KeyboardRow,
    /// 较短的键盘路径。
    KeyboardPattern,
    /// 重复的字符（如 `aaa`）。
    RepeatedCharacter,
    /// 重复的片段（如 `abcabc`）。
    RepeatedPattern,
    /// 序列（如 `abc`、`6543`）。
    Sequence,
    /// 近年的年份。
    RecentYear,
    /// 日期。
    Date,
}

/// 评估密码强度。空密码为 0 分。
#[must_use]
pub fn estimate(password: &str) -> Strength {
    // 超过 MAX_WINDOWS 段（1024 个字符）的部分不计入：只会低估
    let chars: Vec<char> = password
        .chars()
        .take(MAX_ANALYZED.saturating_mul(MAX_WINDOWS))
        .collect();
    let (guesses, first) = estimate_chars(&chars);
    let score = guesses_to_score(guesses);
    let warning = match (&first, period(&chars)) {
        // 整段是重复：提示与 zxcvbn 的重复模式相同
        (_, Some(p)) if score <= 2 => Some(if p == 1 {
            Warning::RepeatedCharacter
        } else {
            Warning::RepeatedPattern
        }),
        (Some(result), _) if score <= 2 && !result.sequence.is_empty() => {
            let longest = result
                .sequence
                .iter()
                .max_by_key(|m| (m.len(), core::cmp::Reverse(m.i)))
                .cloned();
            longest.and_then(|m| match_warning(&m, result.sequence.len() == 1))
        }
        _ => None,
    };
    Strength {
        guesses,
        score,
        warning,
    }
}

/// 估计一段字符（第五轮评审 L1，确认评审 M1、N1），取以下几种中最小的（更保守）：
/// - 不超过 [`MAX_ANALYZED`] 个字符时，zxcvbn 整段分析（它自己识别一段之内的重复）；
/// - LZ77 分解（[`lz_estimate`]）：对前面内容的复制只计入少量猜测，插入与替换不会凭空增加猜测次数；
/// - 近似周期（[`near_period_estimate`]）：同一片段重复、其中最多 [`MAX_EDITS`] 处改动。
///
/// 返回猜测次数，以及用于给出提示的分析。
fn estimate_chars(chars: &[char]) -> (f64, Option<Analysis>) {
    let mut best = lz_estimate(chars);
    if chars.len() <= MAX_ANALYZED {
        let whole = most_guessable(chars, omnimatch(chars), false);
        if whole.guesses <= best.0 {
            best = (whole.guesses, Some(whole));
        }
    }
    if let Some(near) = near_period_estimate(chars)
        && near.0 < best.0
    {
        best = near;
    }
    best
}

/// 近似周期最多允许的改动处数（替换、插入或删除）。
const MAX_EDITS: usize = 3;
/// 每处改动的猜测次数中，字符的选择数（可打印 ASCII）。
const EDIT_CHARS: f64 = 95.0;
/// 近似周期最多检查的候选周期数（每个候选要做几次带状动态规划）。
const MAX_PERIOD_CANDIDATES: usize = 32;

/// 近似周期（确认评审 N1、P1）：原文是同一片段的重复，其中最多 [`MAX_EDITS`] 处改动（替换、插入或删除，
/// 改动可以在任何一份重复中，包括第一份）。估计为：基础片段的猜测次数 × 重复次数 × 每处改动（位置数 × [`EDIT_CHARS`]）。
///
/// 候选的周期 `p`（至少重复两次）：长度为 `p`、出现次数最多的片段，它的重复要覆盖原文的绝大部分。对每个候选，
/// 在没有改动时的对齐位置前后 [`MAX_EDITS`] 个相位上，求原文与"基础片段无限重复"的带状编辑距离。
/// 在全部候选中取改动最少的，同样多时取最短的周期；只对选中的那个递归估计基础片段，它的长度至少减半。
fn near_period_estimate(chars: &[char]) -> Option<(f64, Option<Analysis>)> {
    let n = chars.len();
    // 最好的匹配：(改动处数, 周期, 基础片段的起点, 相位)。改动最少优先，同样多时取最短的周期
    let mut best: Option<(usize, usize, usize, usize)> = None;
    let mut candidates = 0usize;
    for p in 1..=n / 2 {
        let (start, count) = most_frequent(chars, p)?;
        if count < 2 {
            // 没有长度为 p 的片段重复出现，更长的也不会有
            break;
        }
        // 片段的重复要覆盖原文的绝大部分：允许每处改动破坏一份，再加上不完整的第一份与最后一份
        if count
            .saturating_add(MAX_EDITS)
            .saturating_add(2)
            .saturating_mul(p)
            < n
        {
            continue;
        }
        let Some(base) = chars.get(start..start.saturating_add(p)) else {
            continue;
        };
        // 没有改动时，原文的开头对应基础片段中的位置
        let anchor = (p - start % p) % p;
        for shift in 0..=2 * MAX_EDITS {
            let phase = (anchor + p * (MAX_EDITS + 1) + shift - MAX_EDITS) % p;
            if let Some(edits) = periodic_edit_distance(chars, base, phase)
                && best.is_none_or(|b| edits < b.0)
            {
                best = Some((edits, p, start, phase));
            }
        }
        if best.is_some_and(|b| b.0 == 0) {
            break;
        }
        candidates = candidates.saturating_add(1);
        if candidates >= MAX_PERIOD_CANDIDATES {
            break;
        }
    }
    let (edits, p, start, phase) = best?;
    let base = chars.get(start..start.saturating_add(p))?;
    let rotated: Vec<char> = (0..p)
        .filter_map(|k| base.get((phase + k) % p).copied())
        .collect();
    let (g, analysis) = estimate_chars(&rotated);
    let per_edit = to_f64(n) * EDIT_CHARS;
    let edit_cost = per_edit.powi(i32::try_from(edits).unwrap_or(i32::MAX));
    Some((
        (g * to_f64(n.div_ceil(p)) * edit_cost).min(f64::MAX),
        analysis,
    ))
}

/// 长度为 `p` 的片段中出现次数最多的一个：(第一次出现的位置, 次数)。滚动哈希，重叠的出现也计入；等次数时取最早的。
fn most_frequent(chars: &[char], p: usize) -> Option<(usize, usize)> {
    const B: u64 = 1_000_003;
    if p == 0 || p > chars.len() {
        return None;
    }
    let pow = (1..p).fold(1u64, |acc, _| acc.wrapping_mul(B));
    let mut seen: HashMap<u64, (usize, usize)> = HashMap::new();
    let mut h = 0u64;
    for (i, c) in chars.iter().enumerate() {
        if i >= p {
            let old = u64::from(*chars.get(i - p)?);
            h = h.wrapping_sub(old.wrapping_mul(pow));
        }
        h = h.wrapping_mul(B).wrapping_add(u64::from(*c));
        if i + 1 >= p {
            let entry = seen.entry(h).or_insert((i + 1 - p, 0));
            entry.1 = entry.1.saturating_add(1);
        }
    }
    seen.into_values()
        .max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0)))
}

/// 原文与"`base` 从 `phase` 开始无限重复"之间的编辑距离（替换、插入、删除各算一处；重复的长度可以与原文不同，
/// 最后一份可以不完整）。只算到 [`MAX_EDITS`]，超过时返回 `None`。带状动态规划，O(n × MAX_EDITS)。
fn periodic_edit_distance(text: &[char], base: &[char], phase: usize) -> Option<usize> {
    let p = base.len();
    if p == 0 {
        return None;
    }
    let k = MAX_EDITS;
    let width = 2 * k + 1;
    let inf = usize::MAX / 4;
    let pattern = |j: usize| base.get((phase + j) % p);
    // row[c] 是 d[i][j]，其中 j = i + c − k
    let mut row: Vec<usize> = (0..width)
        .map(|c| if c >= k { c - k } else { inf })
        .collect();
    for i in 1..=text.len() {
        let t = text.get(i - 1)?;
        let mut next = vec![inf; width];
        for c in 0..width {
            let Some(j) = (i + c).checked_sub(k) else {
                continue;
            };
            let value = if j == 0 {
                i
            } else {
                let diagonal = row
                    .get(c)?
                    .saturating_add(usize::from(pattern(j - 1) != Some(t)));
                let up = row.get(c + 1).map_or(inf, |v| v.saturating_add(1));
                let left = c
                    .checked_sub(1)
                    .and_then(|l| next.get(l))
                    .map_or(inf, |v| v.saturating_add(1));
                diagonal.min(up).min(left)
            };
            *next.get_mut(c)? = value;
        }
        if next.iter().all(|v| *v > k) {
            return None;
        }
        row = next;
    }
    let best = row.into_iter().min()?;
    (best <= k).then_some(best)
}

/// LZ77 分解中，用 zxcvbn 分析的新内容最多这么多个字符。
const MAX_LITERAL: usize = 2 * MAX_ANALYZED;

/// 复制的最短长度：更短的重复片段按新内容计。
const MIN_COPY: usize = 4;

/// LZ77 分解的估计。从头往后，每个位置找与前面某处（可以与自身重叠）相同的最长片段：
/// - 不短于 [`MIN_COPY`] 时记为一次**复制**，猜测次数按 zxcvbn 重复模式的方式计：重复次数（长度 ÷ 距离，向上取整）
///   × 复制来源的选择数（前面已有的片段数）；
/// - 否则这个字符是**新内容**。连续的新内容拼在一起，每 [`MAX_ANALYZED`] 个字符一段，用 zxcvbn 估计，各段相乘；
///   新内容最多分析 [`MAX_LITERAL`] 个字符。
///
/// 因此在常见口令上重复、插入或替换少量字符、两段交替，猜测次数都只比基础片段多一个小的因子。这是保守的低估：
/// 真正随机的长口令几乎没有长的重复，几乎全是新内容，不受影响。
fn lz_estimate(chars: &[char]) -> (f64, Option<Analysis>) {
    let n = chars.len();
    let mut guesses = 1.0_f64;
    let mut first: Option<Analysis> = None;
    let mut literal: Vec<char> = Vec::new();
    let mut tokens = 0usize;
    // 新内容最多分析 MAX_LITERAL 个字符，之后的不计入（只会低估）：几段真正的新内容已足够判断强弱，
    // 而 zxcvbn 对某些输入（大量 l33t 字符）每段都很慢（确认评审 P2）
    let mut budget = MAX_LITERAL;
    let mut flush = |literal: &mut Vec<char>, guesses: &mut f64, first: &mut Option<Analysis>| {
        let take = literal.len().min(budget);
        budget -= take;
        for w in literal.get(..take).unwrap_or_default().chunks(MAX_ANALYZED) {
            let result = most_guessable(w, omnimatch(w), false);
            *guesses = (*guesses * result.guesses).min(f64::MAX);
            if first.is_none() {
                *first = Some(result);
            }
        }
        literal.clear();
    };
    let mut i = 0usize;
    while i < n {
        let (len, distance) = longest_match(chars, i);
        if len >= MIN_COPY {
            if !literal.is_empty() {
                flush(&mut literal, &mut guesses, &mut first);
                tokens = tokens.saturating_add(1);
            }
            let repeats = to_f64(len.div_ceil(distance.max(1)));
            let sources = to_f64(tokens.max(1));
            guesses = (guesses * repeats * sources).min(f64::MAX);
            tokens = tokens.saturating_add(1);
            i = i.saturating_add(len);
        } else {
            if let Some(c) = chars.get(i) {
                literal.push(*c);
            }
            i = i.saturating_add(1);
        }
    }
    if tokens == 0 && chars.is_empty() {
        let result = most_guessable(chars, Vec::new(), false);
        return (result.guesses, Some(result));
    }
    flush(&mut literal, &mut guesses, &mut first);
    (guesses, first)
}

/// 从 `i` 开始、与前面某处相同的最长片段：(长度, 距离)。来源可以与自身重叠（周期性的模式）。等长时取最近的。
fn longest_match(chars: &[char], i: usize) -> (usize, usize) {
    let rest = chars.get(i..).unwrap_or_default();
    let mut best = (0usize, 0usize);
    for start in (0..i).rev() {
        let len = rest
            .iter()
            .zip(chars.get(start..).unwrap_or_default())
            .take_while(|(a, b)| a == b)
            .count();
        if len > best.0 {
            best = (len, i - start);
            if len == rest.len() {
                break;
            }
        }
    }
    best
}

/// 最短的周期 `p`：对所有 `i`，`chars[i] == chars[i + p]`；只在至少重复两次（`2p ≤ n`）时返回（KMP 前缀函数）。
fn period(chars: &[char]) -> Option<usize> {
    let n = chars.len();
    if n < 2 {
        return None;
    }
    // pi[i]：chars[..=i] 最长的、同时是前缀的真后缀的长度
    let mut pi = vec![0usize; n];
    for i in 1..n {
        let c = chars.get(i)?;
        let mut k = *pi.get(i - 1)?;
        while k > 0 && chars.get(k)? != c {
            k = *pi.get(k - 1)?;
        }
        if chars.get(k)? == c {
            k += 1;
        }
        *pi.get_mut(i)? = k;
    }
    let p = n - *pi.last()?;
    (p < n && 2 * p <= n).then_some(p)
}

#[allow(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    reason = "长度与排名远小于 2^52，转换没有精度损失"
)]
fn to_f64(n: usize) -> f64 {
    n as f64
}

fn guesses_to_score(guesses: f64) -> u8 {
    const DELTA: f64 = 5.0;
    if guesses < 1e3 + DELTA {
        0
    } else if guesses < 1e6 + DELTA {
        1
    } else if guesses < 1e8 + DELTA {
        2
    } else if guesses < 1e10 + DELTA {
        3
    } else {
        4
    }
}

// ---- 词典

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dict {
    Passwords,
    English,
    FemaleNames,
    Surnames,
    TvAndFilm,
    MaleNames,
}

const DICTS: [(Dict, &str); 6] = [
    (Dict::Passwords, include_str!("strength/passwords.txt")),
    (
        Dict::English,
        include_str!("strength/english_wikipedia.txt"),
    ),
    (Dict::FemaleNames, include_str!("strength/female_names.txt")),
    (Dict::Surnames, include_str!("strength/surnames.txt")),
    (Dict::TvAndFilm, include_str!("strength/us_tv_and_film.txt")),
    (Dict::MaleNames, include_str!("strength/male_names.txt")),
];

fn ranked() -> &'static [(Dict, HashMap<&'static str, usize>)] {
    static RANKED: OnceLock<Vec<(Dict, HashMap<&'static str, usize>)>> = OnceLock::new();
    RANKED.get_or_init(|| {
        DICTS
            .iter()
            .map(|(d, text)| {
                let mut map = HashMap::new();
                for (rank, word) in text.lines().enumerate() {
                    map.entry(word).or_insert(rank.saturating_add(1));
                }
                (*d, map)
            })
            .collect()
    })
}

// ---- 匹配

#[derive(Debug, Clone)]
struct Match {
    i: usize,
    j: usize,
    token: Vec<char>,
    kind: Kind,
}

impl Match {
    fn len(&self) -> usize {
        self.token.len()
    }
}

#[derive(Debug, Clone)]
enum Kind {
    Dictionary {
        word: String,
        rank: usize,
        dict: Dict,
        reversed: bool,
        /// l33t 替换（替换字符 → 原字母），只含这个片段中用到的。
        sub: Vec<(char, char)>,
    },
    Spatial {
        keypad: bool,
        turns: usize,
        shifted: usize,
    },
    Repeat {
        base_len: usize,
        base_guesses: f64,
        count: usize,
    },
    Sequence {
        ascending: bool,
    },
    RecentYear {
        year: i32,
    },
    Date {
        year: i64,
        separator: bool,
    },
    Bruteforce,
}

fn omnimatch(pw: &[char]) -> Vec<Match> {
    let mut out = Vec::new();
    out.extend(dictionary_match(pw));
    out.extend(reverse_dictionary_match(pw));
    out.extend(l33t_match(pw));
    out.extend(spatial_match(pw));
    out.extend(repeat_match(pw));
    out.extend(sequence_match(pw));
    out.extend(year_match(pw));
    out.extend(date_match(pw));
    out.sort_by_key(|m| (m.i, m.j));
    out
}

fn lower(c: char) -> char {
    c.to_lowercase().next().unwrap_or(c)
}

fn dictionary_match(pw: &[char]) -> Vec<Match> {
    let lowered: Vec<char> = pw.iter().map(|c| lower(*c)).collect();
    let mut out = Vec::new();
    let mut word = String::new();
    for (dict, map) in ranked() {
        for i in 0..pw.len() {
            word.clear();
            for j in i..pw.len() {
                if let Some(c) = lowered.get(j) {
                    word.push(*c);
                }
                if let Some(&rank) = map.get(word.as_str()) {
                    out.push(Match {
                        i,
                        j,
                        token: pw.get(i..=j).map(<[char]>::to_vec).unwrap_or_default(),
                        kind: Kind::Dictionary {
                            word: word.clone(),
                            rank,
                            dict: *dict,
                            reversed: false,
                            sub: Vec::new(),
                        },
                    });
                }
            }
        }
    }
    out
}

fn reverse_dictionary_match(pw: &[char]) -> Vec<Match> {
    let reversed: Vec<char> = pw.iter().rev().copied().collect();
    let n = pw.len();
    dictionary_match(&reversed)
        .into_iter()
        .map(|mut m| {
            m.token.reverse();
            let (i, j) = (
                n.saturating_sub(1).saturating_sub(m.j),
                n.saturating_sub(1).saturating_sub(m.i),
            );
            m.i = i;
            m.j = j;
            if let Kind::Dictionary { reversed, .. } = &mut m.kind {
                *reversed = true;
            }
            m
        })
        .collect()
}

const L33T_TABLE: [(char, &[char]); 12] = [
    ('a', &['4', '@']),
    ('b', &['8']),
    ('c', &['(', '{', '[', '<']),
    ('e', &['3']),
    ('g', &['6', '9']),
    ('i', &['1', '!', '|']),
    ('l', &['1', '|', '7']),
    ('o', &['0']),
    ('s', &['$', '5']),
    ('t', &['+', '7']),
    ('x', &['%']),
    ('z', &['2']),
];

/// 密码中可能用到的 l33t 替换的全部组合（每个替换字符只对应一个字母），与 zxcvbn 的 `enumerate_l33t_subs` 相同。
fn enumerate_l33t_subs(pw: &[char]) -> Vec<Vec<(char, char)>> {
    let table: Vec<(char, Vec<char>)> = L33T_TABLE
        .iter()
        .filter_map(|(letter, subs)| {
            let relevant: Vec<char> = subs.iter().copied().filter(|s| pw.contains(s)).collect();
            (!relevant.is_empty()).then_some((*letter, relevant))
        })
        .collect();
    let mut subs: Vec<Vec<(char, char)>> = vec![Vec::new()];
    for (letter, l33t_chars) in &table {
        let mut next: Vec<Vec<(char, char)>> = Vec::new();
        for l33t in l33t_chars {
            for sub in &subs {
                match sub.iter().position(|(c, _)| c == l33t) {
                    None => {
                        let mut ext = sub.clone();
                        ext.push((*l33t, *letter));
                        next.push(ext);
                    }
                    Some(dup) => {
                        let mut alt = sub.clone();
                        alt.remove(dup);
                        alt.push((*l33t, *letter));
                        next.push(sub.clone());
                        next.push(alt);
                    }
                }
            }
        }
        // 去重：按排序后的映射
        let mut seen = std::collections::HashSet::new();
        subs = next
            .into_iter()
            .filter(|s| {
                let mut key = s.clone();
                key.sort_unstable();
                seen.insert(key)
            })
            .collect();
        // 组合数随替换字符种类指数增长：设上限，超过时只取前面的组合（与漏判相比，误判为较强的影响有限）
        subs.truncate(256);
    }
    subs.retain(|s| !s.is_empty());
    subs
}

fn l33t_match(pw: &[char]) -> Vec<Match> {
    let mut out = Vec::new();
    for sub in enumerate_l33t_subs(pw) {
        let map: HashMap<char, char> = sub.iter().copied().collect();
        let subbed: Vec<char> = pw.iter().map(|c| *map.get(c).unwrap_or(c)).collect();
        for mut m in dictionary_match(&subbed) {
            let Some(token) = pw.get(m.i..=m.j) else {
                continue;
            };
            let Kind::Dictionary {
                word, sub: msub, ..
            } = &mut m.kind
            else {
                continue;
            };
            let token_lower: String = token.iter().map(|c| lower(*c)).collect();
            if token_lower == *word {
                continue; // 没有真正用到替换
            }
            // 单个字符的 l33t 匹配噪声太大（如 1 → i）
            if token.len() <= 1 {
                continue;
            }
            *msub = sub
                .iter()
                .copied()
                .filter(|(c, _)| token.contains(c))
                .collect();
            m.token = token.to_vec();
            out.push(m);
        }
    }
    out
}

// ---- 键盘路径

struct Graph {
    keypad: bool,
    /// 字符 → 各方向上相邻的键（每个键有未按 Shift 与按 Shift 两个字符）。
    adjacency: HashMap<char, Vec<Option<Vec<char>>>>,
}

const QWERTY: &str = r#"
`~ 1! 2@ 3# 4$ 5% 6^ 7& 8* 9( 0) -_ =+
    qQ wW eE rR tT yY uU iI oO pP [{ ]} \|
     aA sS dD fF gG hH jJ kK lL ;: '"
      zZ xX cC vV bB nN mM ,< .> /?
"#;
const DVORAK: &str = r#"
`~ 1! 2@ 3# 4$ 5% 6^ 7& 8* 9( 0) [{ ]}
    '" ,< .> pP yY fF gG cC rR lL /? =+ \|
     aA oO eE uU iI dD hH tT nN sS -_
      ;: qQ jJ kK xX bB mM wW vV zZ
"#;
const KEYPAD: &str = "
  / * -
7 8 9 +
4 5 6
1 2 3
  0 .
";
const MAC_KEYPAD: &str = "
  = / *
7 8 9 -
4 5 6 +
1 2 3
  0 .
";

/// 由键盘布局建立相邻关系，与 zxcvbn 的 `build_keyboard_adjacency_graphs.py` 相同：
/// 键盘每行比上一行右移半个键（6 个方向），小键盘上下对齐（8 个方向）。
fn build_graph(layout: &str, slanted: bool) -> Graph {
    let token_size = layout
        .split_whitespace()
        .next()
        .map_or(1, |t| t.chars().count());
    let x_unit = token_size.saturating_add(1);
    let mut positions: HashMap<(i64, i64), Vec<char>> = HashMap::new();
    for (y, line) in layout.split('\n').enumerate() {
        let y = i64::try_from(y).unwrap_or(0);
        let slant = if slanted { y.saturating_sub(1) } else { 0 };
        let mut col = 0usize;
        let chars: Vec<char> = line.chars().collect();
        while col < chars.len() {
            if chars.get(col).is_some_and(|c| c.is_whitespace()) {
                col = col.saturating_add(1);
                continue;
            }
            let token: Vec<char> = chars
                .get(col..col.saturating_add(token_size))
                .map(<[char]>::to_vec)
                .unwrap_or_default();
            let offset = i64::try_from(col).unwrap_or(0).saturating_sub(slant);
            let x = offset / i64::try_from(x_unit).unwrap_or(1);
            positions.insert((x, y), token);
            col = col.saturating_add(token_size);
        }
    }
    let dirs: &[(i64, i64)] = if slanted {
        &[(-1, 0), (0, -1), (1, -1), (1, 0), (0, 1), (-1, 1)]
    } else {
        &[
            (-1, 0),
            (-1, -1),
            (0, -1),
            (1, -1),
            (1, 0),
            (1, 1),
            (0, 1),
            (-1, 1),
        ]
    };
    let mut adjacency = HashMap::new();
    for ((x, y), token) in &positions {
        let neighbors: Vec<Option<Vec<char>>> = dirs
            .iter()
            .map(|(dx, dy)| {
                positions
                    .get(&(x.saturating_add(*dx), y.saturating_add(*dy)))
                    .cloned()
            })
            .collect();
        for c in token {
            adjacency.insert(*c, neighbors.clone());
        }
    }
    Graph {
        keypad: !slanted,
        adjacency,
    }
}

fn graphs() -> &'static [Graph] {
    static GRAPHS: OnceLock<Vec<Graph>> = OnceLock::new();
    GRAPHS.get_or_init(|| {
        vec![
            build_graph(QWERTY, true),
            build_graph(DVORAK, true),
            build_graph(KEYPAD, false),
            build_graph(MAC_KEYPAD, false),
        ]
    })
}

/// (起点数, 平均相邻键数)：键盘取 QWERTY，小键盘取标准小键盘。
fn graph_stats(keypad: bool) -> (f64, f64) {
    static STATS: OnceLock<[(f64, f64); 2]> = OnceLock::new();
    let stats = STATS.get_or_init(|| {
        let calc = |g: &Graph| {
            let n = g.adjacency.len();
            let total: usize = g
                .adjacency
                .values()
                .map(|adj| adj.iter().filter(|a| a.is_some()).count())
                .sum();
            (to_f64(n), to_f64(total) / to_f64(n.max(1)))
        };
        let gs = graphs();
        [
            gs.first().map_or((1.0, 1.0), calc),
            gs.get(2).map_or((1.0, 1.0), calc),
        ]
    });
    if keypad { stats[1] } else { stats[0] }
}

const SHIFTED: &str = "~!@#$%^&*()_+QWERTYUIOP{}|ASDFGHJKL:\"ZXCVBNM<>?";

fn spatial_match(pw: &[char]) -> Vec<Match> {
    let mut out = Vec::new();
    for graph in graphs() {
        let mut i = 0usize;
        while i.saturating_add(1) < pw.len() {
            let mut j = i.saturating_add(1);
            let mut last_dir: Option<usize> = None;
            let mut turns = 0usize;
            let mut shifted =
                usize::from(!graph.keypad && pw.get(i).is_some_and(|c| SHIFTED.contains(*c)));
            loop {
                let prev = pw.get(j.saturating_sub(1)).copied();
                let mut found = false;
                if let (Some(prev), Some(cur)) = (prev, pw.get(j))
                    && let Some(adjacent) = graph.adjacency.get(&prev)
                {
                    {
                        for (dir, adj) in adjacent.iter().enumerate() {
                            if let Some(keys) = adj
                                && let Some(pos) = keys.iter().position(|k| k == cur)
                            {
                                found = true;
                                if pos == 1 {
                                    shifted = shifted.saturating_add(1);
                                }
                                if last_dir != Some(dir) {
                                    turns = turns.saturating_add(1);
                                    last_dir = Some(dir);
                                }
                                break;
                            }
                        }
                    }
                }
                if found {
                    j = j.saturating_add(1);
                } else {
                    if j.saturating_sub(i) > 2 {
                        out.push(Match {
                            i,
                            j: j.saturating_sub(1),
                            token: pw.get(i..j).map(<[char]>::to_vec).unwrap_or_default(),
                            kind: Kind::Spatial {
                                keypad: graph.keypad,
                                turns,
                                shifted,
                            },
                        });
                    }
                    i = j;
                    break;
                }
            }
        }
    }
    out
}

// ---- 重复与序列

/// 从 `start` 起，`pw` 中是否存在重复：返回 (片段起点, 片段长度, 重复次数)。`shortest` 选最短的周期（懒惰），
/// 否则选最长的周期（贪婪）。与正则 `(.+?)\1+` / `(.+)\1+` 在最左位置的匹配相同。
fn find_repeat(pw: &[char], start: usize, shortest: bool) -> Option<(usize, usize, usize)> {
    for i in start..pw.len() {
        let max_len = pw.len().saturating_sub(i) / 2;
        let lens: Box<dyn Iterator<Item = usize>> = if shortest {
            Box::new(1..=max_len)
        } else {
            Box::new((1..=max_len).rev())
        };
        for l in lens {
            let base = pw.get(i..i.saturating_add(l));
            if base.is_some() && base == pw.get(i.saturating_add(l)..i.saturating_add(2 * l)) {
                let mut count = 2usize;
                while base == pw.get(i.saturating_add(count * l)..i.saturating_add((count + 1) * l))
                {
                    count = count.saturating_add(1);
                }
                return Some((i, l, count));
            }
        }
    }
    None
}

fn repeat_match(pw: &[char]) -> Vec<Match> {
    let mut out = Vec::new();
    let mut last = 0usize;
    while last < pw.len() {
        let (Some(greedy), Some(lazy)) =
            (find_repeat(pw, last, false), find_repeat(pw, last, true))
        else {
            break;
        };
        let (i, total, base_len) = if greedy.1 * greedy.2 > lazy.1 * lazy.2 {
            // 贪婪的片段本身可能是更短片段的重复（如 aabaab 中的 aab）：取最短周期
            let total = greedy.1 * greedy.2;
            let token = pw.get(greedy.0..greedy.0 + total).unwrap_or_default();
            let period = (1..=total)
                .find(|p| total % p == 0 && token.chunks(*p).all(|c| Some(c) == token.get(..*p)))
                .unwrap_or(total);
            (greedy.0, total, period)
        } else {
            (lazy.0, lazy.1 * lazy.2, lazy.1)
        };
        let base: Vec<char> = pw
            .get(i..i + base_len)
            .map(<[char]>::to_vec)
            .unwrap_or_default();
        let base_matches = omnimatch(&base);
        let base_guesses = most_guessable(&base, base_matches, false).guesses;
        out.push(Match {
            i,
            j: i + total - 1,
            token: pw
                .get(i..i + total)
                .map(<[char]>::to_vec)
                .unwrap_or_default(),
            kind: Kind::Repeat {
                base_len,
                base_guesses,
                count: total / base_len.max(1),
            },
        });
        last = i + total;
    }
    out
}

fn sequence_match(pw: &[char]) -> Vec<Match> {
    if pw.len() < 2 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut push = |i: usize, j: usize, delta: i64| {
        if (j - i > 1 || delta.abs() == 1) && delta != 0 && delta.abs() <= MAX_DELTA {
            out.push(Match {
                i,
                j,
                token: pw.get(i..=j).map(<[char]>::to_vec).unwrap_or_default(),
                kind: Kind::Sequence {
                    ascending: delta > 0,
                },
            });
        }
    };
    let code = |k: usize| pw.get(k).map_or(0, |c| i64::from(u32::from(*c)));
    let mut i = 0usize;
    let mut last_delta: Option<i64> = None;
    for k in 1..pw.len() {
        let delta = code(k) - code(k - 1);
        let ld = *last_delta.get_or_insert(delta);
        if delta == ld {
            continue;
        }
        let j = k - 1;
        push(i, j, ld);
        i = j;
        last_delta = Some(delta);
    }
    push(i, pw.len() - 1, last_delta.unwrap_or(0));
    out
}

// ---- 年份与日期

fn digits_value(s: &[char]) -> Option<i64> {
    if s.is_empty() || !s.iter().all(char::is_ascii_digit) {
        return None;
    }
    s.iter().collect::<String>().parse().ok()
}

fn year_match(pw: &[char]) -> Vec<Match> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 4 <= pw.len() {
        let token = pw.get(i..i + 4).unwrap_or_default();
        let year = digits_value(token).filter(|_| matches!(token.first(), Some('1' | '2')));
        match year {
            Some(y) if (1900..=2099).contains(&y) => {
                out.push(Match {
                    i,
                    j: i + 3,
                    token: token.to_vec(),
                    kind: Kind::RecentYear {
                        year: i32::try_from(y).unwrap_or(2000),
                    },
                });
                i += 4;
            }
            _ => i += 1,
        }
    }
    out
}

fn map_ints_to_dm(a: i64, b: i64) -> Option<(i64, i64)> {
    for (d, m) in [(a, b), (b, a)] {
        if (1..=31).contains(&d) && (1..=12).contains(&m) {
            return Some((d, m));
        }
    }
    None
}

fn two_to_four_digit_year(y: i64) -> i64 {
    if y > 99 {
        y
    } else if y > 50 {
        y + 1900
    } else {
        y + 2000
    }
}

/// 三个整数能否解释为日、月、年（年在首或尾），与 zxcvbn 的 `map_ints_to_dmy` 相同。返回年份。
fn map_ints_to_dmy(ints: [i64; 3]) -> Option<i64> {
    if ints[1] > 31 || ints[1] <= 0 {
        return None;
    }
    let (mut over_12, mut over_31, mut under_1) = (0, 0, 0);
    for v in ints {
        if (99 < v && v < DATE_MIN_YEAR) || v > DATE_MAX_YEAR {
            return None;
        }
        over_31 += i32::from(v > 31);
        over_12 += i32::from(v > 12);
        under_1 += i32::from(v <= 0);
    }
    if over_31 >= 2 || over_12 == 3 || under_1 >= 2 {
        return None;
    }
    let splits = [(ints[2], (ints[0], ints[1])), (ints[0], (ints[1], ints[2]))];
    for (y, (a, b)) in splits {
        if (DATE_MIN_YEAR..=DATE_MAX_YEAR).contains(&y) {
            return map_ints_to_dm(a, b).map(|_| y);
        }
    }
    for (y, (a, b)) in splits {
        if map_ints_to_dm(a, b).is_some() {
            return Some(two_to_four_digit_year(y));
        }
    }
    None
}

fn reference_year() -> i64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    1970 + i64::try_from(secs / 31_556_952).unwrap_or(0)
}

fn date_match(pw: &[char]) -> Vec<Match> {
    let mut found: Vec<Match> = Vec::new();
    let reference = reference_year();
    let splits: [&[(usize, usize)]; 9] = [
        &[],
        &[],
        &[],
        &[],
        &[(1, 2), (2, 3)],
        &[(1, 3), (2, 3)],
        &[(1, 2), (2, 4), (4, 5)],
        &[(1, 3), (2, 3), (4, 5), (4, 6)],
        &[(2, 4), (4, 6)],
    ];
    // 没有分隔符：4–8 位数字
    for i in 0..pw.len() {
        for len in 4..=8usize {
            let Some(token) = pw.get(i..i + len) else {
                break;
            };
            if !token.iter().all(char::is_ascii_digit) {
                continue;
            }
            let mut best: Option<i64> = None;
            for (k, l) in splits.get(len).copied().unwrap_or_default() {
                let parts = (
                    digits_value(token.get(..*k).unwrap_or_default()),
                    digits_value(token.get(*k..*l).unwrap_or_default()),
                    digits_value(token.get(*l..).unwrap_or_default()),
                );
                if let (Some(a), Some(b), Some(c)) = parts
                    && let Some(y) = map_ints_to_dmy([a, b, c])
                    && best.is_none_or(|bst| (y - reference).abs() < (bst - reference).abs())
                {
                    best = Some(y);
                }
            }
            if let Some(year) = best {
                found.push(Match {
                    i,
                    j: i + len - 1,
                    token: token.to_vec(),
                    kind: Kind::Date {
                        year,
                        separator: false,
                    },
                });
            }
        }
    }
    // 有分隔符：1–4 位、分隔符、1–2 位、同一个分隔符、1–4 位
    for i in 0..pw.len() {
        for len in 6..=10usize {
            let Some(token) = pw.get(i..i + len) else {
                break;
            };
            if let Some(year) = date_with_separator(token) {
                found.push(Match {
                    i,
                    j: i + len - 1,
                    token: token.to_vec(),
                    kind: Kind::Date {
                        year,
                        separator: true,
                    },
                });
            }
        }
    }
    // 去掉被其他日期完全包含的
    let spans: Vec<(usize, usize)> = found.iter().map(|m| (m.i, m.j)).collect();
    found
        .into_iter()
        .enumerate()
        .filter(|(idx, m)| {
            !spans
                .iter()
                .enumerate()
                .any(|(o, (i, j))| o != *idx && *i <= m.i && *j >= m.j && (*i, *j) != (m.i, m.j))
        })
        .map(|(_, m)| m)
        .collect()
}

fn date_with_separator(token: &[char]) -> Option<i64> {
    let is_sep = |c: &char| c.is_whitespace() || matches!(c, '/' | '\\' | '_' | '.' | '-');
    let first_sep = token.iter().position(is_sep)?;
    let sep = *token.get(first_sep)?;
    let rest = token.get(first_sep + 1..)?;
    let second = rest.iter().position(|c| *c == sep)?;
    let (a, b, c) = (
        token.get(..first_sep)?,
        rest.get(..second)?,
        rest.get(second + 1..)?,
    );
    if !(1..=4).contains(&a.len()) || !(1..=2).contains(&b.len()) || !(1..=4).contains(&c.len()) {
        return None;
    }
    map_ints_to_dmy([digits_value(a)?, digits_value(b)?, digits_value(c)?])
}

// ---- 评分

struct Analysis {
    guesses: f64,
    sequence: Vec<Match>,
}

fn factorial(n: usize) -> f64 {
    (2..=n).map(to_f64).product::<f64>().max(1.0)
}
fn n_ck(n: usize, k: usize) -> f64 {
    if k > n {
        return 0.0;
    }
    let mut r = 1.0;
    let mut n = to_f64(n);
    for d in 1..=k {
        r *= n;
        r /= to_f64(d);
        n -= 1.0;
    }
    r
}
fn estimate_guesses(m: &Match, password_len: usize) -> f64 {
    let min_guesses = if m.len() < password_len {
        if m.len() == 1 {
            MIN_SUBMATCH_GUESSES_SINGLE_CHAR
        } else {
            MIN_SUBMATCH_GUESSES_MULTI_CHAR
        }
    } else {
        1.0
    };
    let guesses = match &m.kind {
        Kind::Bruteforce => {
            let g = BRUTEFORCE_CARDINALITY.powi(i32::try_from(m.len()).unwrap_or(i32::MAX));
            let g = if g.is_finite() { g } else { f64::MAX };
            let floor = if m.len() == 1 {
                MIN_SUBMATCH_GUESSES_SINGLE_CHAR + 1.0
            } else {
                MIN_SUBMATCH_GUESSES_MULTI_CHAR + 1.0
            };
            g.max(floor)
        }
        Kind::Dictionary {
            rank,
            reversed,
            sub,
            ..
        } => {
            to_f64(*rank)
                * uppercase_variations(&m.token)
                * l33t_variations(&m.token, sub)
                * if *reversed { 2.0 } else { 1.0 }
        }
        Kind::Spatial {
            keypad,
            turns,
            shifted,
        } => spatial_guesses(m.len(), *keypad, *turns, *shifted),
        Kind::Repeat {
            base_guesses,
            count,
            ..
        } => base_guesses * to_f64(*count),
        Kind::Sequence { ascending } => {
            let first = m.token.first().copied().unwrap_or('a');
            let mut base = if matches!(first, 'a' | 'A' | 'z' | 'Z' | '0' | '1' | '9') {
                4.0
            } else if first.is_ascii_digit() {
                10.0
            } else {
                26.0
            };
            if !ascending {
                base *= 2.0;
            }
            base * to_f64(m.len())
        }
        Kind::RecentYear { year } => {
            let reference = i32::try_from(reference_year()).unwrap_or(2026);
            f64::from((year - reference).abs().max(MIN_YEAR_SPACE))
        }
        Kind::Date { year, separator } => {
            let space = (year - reference_year())
                .abs()
                .max(i64::from(MIN_YEAR_SPACE));
            let g = f64::from(i32::try_from(space).unwrap_or(i32::MAX)) * 365.0;
            if *separator { g * 4.0 } else { g }
        }
    };
    guesses.max(min_guesses)
}
fn spatial_guesses(len: usize, keypad: bool, turns: usize, shifted: usize) -> f64 {
    let (s, d) = graph_stats(keypad);
    let mut guesses = 0.0;
    for i in 2..=len {
        let possible_turns = turns.min(i - 1);
        for j in 1..=possible_turns {
            guesses += n_ck(i - 1, j - 1) * s * d.powi(i32::try_from(j).unwrap_or(i32::MAX));
        }
    }
    if shifted > 0 {
        let unshifted = len.saturating_sub(shifted);
        if unshifted == 0 {
            guesses *= 2.0;
        } else {
            let variations: f64 = (1..=shifted.min(unshifted))
                .map(|i| n_ck(shifted + unshifted, i))
                .sum();
            guesses *= variations;
        }
    }
    guesses
}

fn uppercase_variations(token: &[char]) -> f64 {
    let upper = token.iter().filter(|c| c.is_ascii_uppercase()).count();
    let lower_count = token.iter().filter(|c| c.is_ascii_lowercase()).count();
    if upper == 0 {
        return 1.0;
    }
    let first_upper_only = token.first().is_some_and(char::is_ascii_uppercase)
        && token.len() > 1
        && token.iter().skip(1).all(|c| !c.is_ascii_uppercase());
    let last_upper_only = token.last().is_some_and(char::is_ascii_uppercase)
        && token.len() > 1
        && token
            .iter()
            .take(token.len() - 1)
            .all(|c| !c.is_ascii_uppercase());
    let all_upper = lower_count == 0;
    if first_upper_only || last_upper_only || all_upper {
        return 2.0;
    }
    (1..=upper.min(lower_count))
        .map(|i| n_ck(upper + lower_count, i))
        .sum()
}

fn l33t_variations(token: &[char], sub: &[(char, char)]) -> f64 {
    let mut variations = 1.0;
    let lowered: Vec<char> = token.iter().map(|c| lower(*c)).collect();
    for (subbed, unsubbed) in sub {
        let s = lowered.iter().filter(|c| *c == subbed).count();
        let u = lowered.iter().filter(|c| *c == unsubbed).count();
        if s == 0 || u == 0 {
            variations *= 2.0;
        } else {
            variations *= (1..=s.min(u)).map(|i| n_ck(u + s, i)).sum::<f64>();
        }
    }
    variations
}

/// 找出猜测次数最少的不重叠模式序列（zxcvbn 的 `most_guessable_match_sequence`）：
/// 最小化 `l! · Π 猜测次数 + D^(l-1)`，`l` 为序列长度。
fn most_guessable(pw: &[char], matches: Vec<Match>, exclude_additive: bool) -> Analysis {
    let n = pw.len();
    if n == 0 {
        return Analysis {
            guesses: 1.0,
            sequence: Vec::new(),
        };
    }
    // 每个位置 k 上，长度为 l 的最优序列的最后一个模式、乘积项与目标值
    let mut opt_m: Vec<BTreeMap<usize, Match>> = vec![BTreeMap::new(); n];
    let mut opt_pi: Vec<BTreeMap<usize, f64>> = vec![BTreeMap::new(); n];
    let mut opt_g: Vec<BTreeMap<usize, f64>> = vec![BTreeMap::new(); n];

    let mut by_j: Vec<Vec<Match>> = vec![Vec::new(); n];
    for m in matches {
        if let Some(slot) = by_j.get_mut(m.j) {
            slot.push(m);
        }
    }
    for list in &mut by_j {
        list.sort_by_key(|m| m.i);
    }

    let update = |m: &Match,
                  l: usize,
                  opt_m: &mut Vec<BTreeMap<usize, Match>>,
                  opt_pi: &mut Vec<BTreeMap<usize, f64>>,
                  opt_g: &mut Vec<BTreeMap<usize, f64>>| {
        let k = m.j;
        let mut pi = estimate_guesses(m, n);
        if l > 1 {
            let prev =
                m.i.checked_sub(1)
                    .and_then(|p| opt_pi.get(p))
                    .and_then(|p| p.get(&(l - 1)));
            match prev {
                Some(p) => pi *= p,
                None => return,
            }
        }
        let mut g = factorial(l) * pi;
        if !exclude_additive {
            g += MIN_GUESSES_BEFORE_GROWING_SEQUENCE.powi(i32::try_from(l - 1).unwrap_or(i32::MAX));
        }
        if let Some(competing) = opt_g.get(k)
            && competing.iter().any(|(cl, cg)| *cl <= l && *cg <= g)
        {
            return;
        }
        if let (Some(gm), Some(gm_m), Some(gm_pi)) =
            (opt_g.get_mut(k), opt_m.get_mut(k), opt_pi.get_mut(k))
        {
            gm.insert(l, g);
            gm_m.insert(l, m.clone());
            gm_pi.insert(l, pi);
        }
    };
    let bruteforce = |i: usize, j: usize| Match {
        i,
        j,
        token: pw.get(i..=j).map(<[char]>::to_vec).unwrap_or_default(),
        kind: Kind::Bruteforce,
    };

    for k in 0..n {
        let list = by_j.get(k).cloned().unwrap_or_default();
        for m in &list {
            if m.i > 0 {
                let ls: Vec<usize> = opt_m
                    .get(m.i - 1)
                    .map(|x| x.keys().copied().collect())
                    .unwrap_or_default();
                for l in ls {
                    update(m, l + 1, &mut opt_m, &mut opt_pi, &mut opt_g);
                }
            } else {
                update(m, 1, &mut opt_m, &mut opt_pi, &mut opt_g);
            }
        }
        // 暴力枚举：单个覆盖 [0, k] 的，以及接在已有序列之后的 [i, k]
        update(&bruteforce(0, k), 1, &mut opt_m, &mut opt_pi, &mut opt_g);
        for i in 1..=k {
            let m = bruteforce(i, k);
            let prev: Vec<(usize, bool)> = opt_m
                .get(i - 1)
                .map(|x| {
                    x.iter()
                        .map(|(l, lm)| (*l, matches!(lm.kind, Kind::Bruteforce)))
                        .collect()
                })
                .unwrap_or_default();
            for (l, last_is_bruteforce) in prev {
                // 两个相邻的暴力枚举不如一个更长的
                if !last_is_bruteforce {
                    update(&m, l + 1, &mut opt_m, &mut opt_pi, &mut opt_g);
                }
            }
        }
    }

    // 回溯
    let last = n - 1;
    let Some((&best_l, &best_g)) = opt_g.get(last).and_then(|g| {
        g.iter()
            .min_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(core::cmp::Ordering::Equal))
    }) else {
        return Analysis {
            guesses: BRUTEFORCE_CARDINALITY.powi(i32::try_from(n).unwrap_or(i32::MAX)),
            sequence: Vec::new(),
        };
    };
    let mut sequence = Vec::new();
    let mut k = Some(last);
    let mut l = best_l;
    while let Some(kk) = k {
        let Some(m) = opt_m.get(kk).and_then(|x| x.get(&l)) else {
            break;
        };
        sequence.push(m.clone());
        k = m.i.checked_sub(1);
        l = l.saturating_sub(1);
    }
    sequence.reverse();
    Analysis {
        guesses: best_g,
        sequence,
    }
}

// ---- 提示

fn match_warning(m: &Match, sole: bool) -> Option<Warning> {
    match &m.kind {
        Kind::Dictionary {
            word,
            rank,
            dict,
            reversed,
            sub,
        } => match dict {
            Dict::Passwords => {
                let l33t = !sub.is_empty();
                if sole && !l33t && !reversed && uppercase_variations(&m.token) <= 1.0 {
                    Some(if *rank <= 10 {
                        Warning::Top10
                    } else if *rank <= 100 {
                        Warning::Top100
                    } else {
                        Warning::VeryCommon
                    })
                } else if estimate_guesses(m, usize::MAX).log10() <= 4.0 {
                    Some(Warning::SimilarToCommon(word.clone()))
                } else {
                    None
                }
            }
            Dict::English => sole.then_some(Warning::SingleWord),
            Dict::Surnames | Dict::MaleNames | Dict::FemaleNames => Some(if sole {
                Warning::NameByItself
            } else {
                Warning::CommonName
            }),
            Dict::TvAndFilm => None,
        },
        Kind::Spatial { turns, .. } => Some(if *turns == 1 {
            Warning::KeyboardRow
        } else {
            Warning::KeyboardPattern
        }),
        Kind::Repeat { base_len, .. } => Some(if *base_len == 1 {
            Warning::RepeatedCharacter
        } else {
            Warning::RepeatedPattern
        }),
        Kind::Sequence { .. } => Some(Warning::Sequence),
        Kind::RecentYear { .. } => Some(Warning::RecentYear),
        Kind::Date { .. } => Some(Warning::Date),
        Kind::Bruteforce => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::float_cmp)]
mod tests {
    use super::*;

    #[test]
    fn common_passwords_are_very_weak() {
        // "password" 在常见密码表中排第 2：猜测次数 = 1! × 2 + 10000⁰ = 3（与 zxcvbn 相同）
        let s = estimate("password");
        assert_eq!(s.guesses, 3.0);
        assert_eq!(s.score, 0);
        assert_eq!(s.warning, Some(Warning::Top10));
        assert_eq!(estimate("qwerty").guesses, 5.0);
        for weak in ["123456", "iloveyou", "letmein", "1qaz2wsx", "monkey123"] {
            assert!(estimate(weak).score <= 1, "{weak}");
        }
        assert_eq!(estimate("").score, 0);
    }

    #[test]
    fn variations_of_common_passwords_are_still_weak() {
        let s = estimate("P@ssw0rd");
        assert!(s.score <= 1, "{s:?}");
        assert_eq!(s.warning, Some(Warning::SimilarToCommon("password".into())));
        assert!(estimate("drowssap").score <= 1, "倒写");
        assert!(estimate("Password1").score <= 1);
    }

    #[test]
    fn patterns_are_recognized() {
        assert_eq!(estimate("4rfvbgt5").warning, Some(Warning::KeyboardPattern));
        assert_eq!(estimate("rtyuiop[]").warning, Some(Warning::KeyboardRow));
        assert_eq!(
            estimate("aaaaaaaaaaaa").warning,
            Some(Warning::RepeatedCharacter)
        );
        assert_eq!(
            estimate("abcabcabcabc").warning,
            Some(Warning::RepeatedPattern)
        );
        assert_eq!(estimate("mnopqrstuv").warning, Some(Warning::Sequence));
        assert_eq!(estimate("1987").warning, Some(Warning::RecentYear));
        assert_eq!(estimate("1987-03-14").warning, Some(Warning::Date));
        for weak in [
            "4rfvbgt5",
            "rtyuiop[]",
            "aaaaaaaaaaaa",
            "abcdefghij",
            "19870314",
        ] {
            assert!(estimate(weak).score <= 2, "{weak}");
        }
    }

    #[test]
    fn strong_passwords_score_high() {
        for strong in [
            "V.uwt*^H:tGdt~5bJWXO",
            "correcthorsebatterystaple",
            "violin-maple-orbit-cactus-ember",
            "Wq7#kd.Rz2!mTx9e:Hp4",
        ] {
            let s = estimate(strong);
            assert_eq!(s.score, 4, "{strong}: {s:?}");
            assert_eq!(s.warning, None);
            assert!(s.bits() > 40.0);
        }
    }

    #[test]
    fn handles_unicode_and_long_input() {
        assert!(estimate("密码").score <= 2);
        // 长的重复模式不因为长就算强（第五轮评审 L1）
        let long: String = "x7".repeat(200);
        let s = estimate(&long);
        assert!(s.guesses.is_finite() && s.score <= 2, "{s:?}");
        for repeated in ["a".repeat(80), "abc".repeat(100), "password".repeat(10)] {
            assert!(estimate(&repeated).score <= 2, "{repeated}");
        }
        // 常见口令重复几次，无论长短，都达不到最高档（确认评审 M1）
        for base in ["password123", "letmein123!", "qwerty123456", "abc123!"] {
            for n in [2, 3, 5, 20, 93] {
                let repeated = base.repeat(n);
                assert!(estimate(&repeated).score <= 3, "{base} × {n}");
            }
        }
        // 近似重复的各种变体（确认评审 N1）：在常见口令的重复上追加、插入、替换一个字符，或与另一个常见片段交替。
        // 1. 对非常常见的基础口令，这些变体都达不到最高档；
        // 2. 对任意基础片段，估计不超过模型上限：基础 × 重复次数 × 一处改动的代价（位置 × 95），重复本身不再虚增
        let variants_of = |base: &str, n: usize| -> Vec<String> {
            let plain = base.repeat(n);
            let len = plain.chars().count();
            let mut out = vec![
                format!("{plain}!"),
                format!("!{plain}"),
                format!("{}#{}", base.repeat(n / 2), base.repeat(n - n / 2)),
                format!("{}{}", base.repeat(2), "qwerty".repeat(2)).repeat(n),
            ];
            for pos in [0, len / 3, len / 2, len - 1] {
                let mut chars: Vec<char> = plain.chars().collect();
                chars[pos] = '%';
                out.push(chars.into_iter().collect());
            }
            // 第一份之内的插入与删除（确认评审 P1），以及中间的删除
            for pos in [1, 2, base.len() / 2, len / 2] {
                let mut inserted: Vec<char> = plain.chars().collect();
                inserted.insert(pos, '!');
                out.push(inserted.into_iter().collect());
                let mut removed: Vec<char> = plain.chars().collect();
                removed.remove(pos);
                out.push(removed.into_iter().collect());
            }
            out
        };
        for base in ["password", "password123", "qwerty123456", "abc123"] {
            for n in [3, 5, 10, 20] {
                for v in variants_of(base, n) {
                    let s = estimate(&v);
                    assert!(s.score <= 3, "{v} → {s:?}");
                }
            }
        }
        for base in ["letmein123!", "iloveyou2026", "Tr0ub4dor&3"] {
            let g = estimate(base).guesses;
            for n in [3, 5, 10, 20] {
                for v in variants_of(base, n)
                    .into_iter()
                    .take(3)
                    .chain(variants_of(base, n).into_iter().skip(4))
                {
                    let len = to_f64(v.chars().count());
                    let bound = g * to_f64(n + 1) * len * 95.0 * 2.0;
                    let s = estimate(&v);
                    assert!(s.guesses <= bound, "{v} → {s:?}，上限 {bound}");
                }
            }
        }
        // 两个不同的常见口令拼在一起，重复只多一个小的因子，估计与拼接本身相同（是否达到 4 分由 zxcvbn 对拼接的估计决定）
        let pair = estimate("letmein123!dragon99");
        let pair_repeated = estimate(&"letmein123!dragon99".repeat(3));
        assert!(
            pair_repeated.guesses <= pair.guesses * 4.0,
            "{pair:?} {pair_repeated:?}"
        );
        // 真正随机的长口令仍然很强（几乎没有长的重复，全是新内容）
        let random_long = "q7Lm2Xv9Rk4Tz8Wc1Hn6Jp3Bd5Fg0YstR8vN2kQ9wL4mZ7xP1cH6jB3dF5gY0sAe9Ku3Wn7Qz1Rx5Tm8Vb2Hc4Pf6Lj0Ds";
        assert!(random_long.len() > MAX_ANALYZED);
        assert_eq!(estimate(random_long).score, 4);
        let words =
            "maple orbit cactus velvet lantern quarry ember thimble walrus gazebo prism falcon";
        assert!(words.len() > MAX_ANALYZED);
        assert_eq!(estimate(words).score, 4, "{:?}", estimate(words));
        // 很长或刻意构造的输入也很快算完
        let tricky: String = (0..5000)
            .map(|i| if i % 37 == 0 { 'b' } else { 'a' })
            .collect();
        let started = std::time::Instant::now();
        let _ = estimate(&tricky);
        assert!(started.elapsed().as_secs() < 5);
        // 真正随机的长口令仍然很强；很长的输入也很快算完
        let random = "q7Lm2Xv9Rk4Tz8Wc1Hn6Jp3Bd5Fg0YstR8vN2kQ9wL4mZ7xP1cH6jB3dF5gY0sA";
        assert_eq!(estimate(random).score, 4);
        let huge: String = (0..100_000u32)
            .map(|i| char::from_u32(0x4e00 + (i * 7919) % 20_000).unwrap_or('x'))
            .collect();
        let started = std::time::Instant::now();
        let _ = estimate(&huge);
        assert!(started.elapsed().as_secs() < 5);
        // 很多种 l33t 字符也能很快算完
        let noisy = "4@8({[<3691!|7|0$5+%2".repeat(3);
        let _ = estimate(&noisy);
    }

    #[test]
    fn keyboard_graphs_match_zxcvbn() {
        let g = &graphs()[0];
        let adj = g.adjacency.get(&'g').unwrap();
        let names: Vec<Option<String>> = adj
            .iter()
            .map(|a| a.as_ref().map(|k| k.iter().collect()))
            .collect();
        assert_eq!(
            names,
            ["fF", "tT", "yY", "hH", "bB", "vV"].map(|s| Some(s.to_owned()))
        );
        let (starts, degree) = graph_stats(false);
        assert_eq!(starts, 94.0);
        assert!((degree - 4.595_744).abs() < 1e-3, "{degree}");
    }
}
