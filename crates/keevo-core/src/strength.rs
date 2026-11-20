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
    if let Some(near) = near_period_estimate(chars, best.0)
        && near.0 < best.0
    {
        best = near;
    }
    best
}

/// 最高档（4 分）的门槛：猜测次数达到它之后，更精确的估计不改变分数。
const TOP_SCORE_GUESSES: f64 = 1e10;

/// 近似周期最多允许的改动处数（替换、插入或删除）。
const MAX_EDITS: usize = 3;
/// 每处改动的猜测次数中，字符的选择数（可打印 ASCII）。
const EDIT_CHARS: f64 = 95.0;
/// 近似周期中，按出现次数找候选时最多检查的周期数。
const MAX_PERIOD_CANDIDATES: usize = 32;
/// 近似周期中，最多比较总代价的匹配数。
const MAX_COST_EVALS: usize = 16;
/// 第二阶段（同一位置都被改动）最多比较总代价的匹配数。
const MAX_WILD_EVALS: usize = 256;
/// 两份在同一位置都被改动时，基础片段在这个位置的字符两份都没有，按这些字符逐个尝试：常见口令中出现的字符。
/// 不尝试大写字母。只把这一个字母改成小写，估计不一定更低（确认评审 T4，已知局限）；全是大写的常见词由
/// 第四种候选（常见词，按小写核对）覆盖。
const COMMON_CHARS: &str = "abcdefghijklmnopqrstuvwxyz0123456789@$!#*._-";
/// 两份之间最多允许的差异处数：两份的改动之和，再加上固定长度的切片在末尾多出的差异。
const MAX_PAIR_DIFF: usize = MAX_EDITS + 2;
/// 一对候选最多还原出的基础片段数。
const MAX_BETWEEN: usize = 4096;

/// 夹在两份 `a`、`b` 之间的基础片段（确认评审 R1）：先求两份的对齐（编辑距离不超过 [`MAX_PAIR_DIFF`]）；
/// 每处差异取 `a` 的一侧或 `b` 的一侧，枚举全部组合。`wild` 时改为两份在同一位置都被改动的情形：基础片段在这个
/// 位置的字符两份都没有，对每处替换逐个尝试 [`COMMON_CHARS`] 中的字符（每个片段最多一处）。
fn between(a: &[char], b: &[char], wild: bool) -> Vec<Vec<char>> {
    // 两份同一个基础片段只在少数几处不同；任意两段随机字符几乎处处不同。差异超过一半的不是两份（否则很短的
    // 片段总能"配上"，每个强口令都要做一遍还原）。先用带状距离快速排除，对绝大多数输入这里就结束了
    let limit = MAX_PAIR_DIFF.min(a.len() / 2);
    if limit == 0 || periodic_edit_distance_within(a, b, 0, limit).is_none() {
        return Vec::new();
    }
    let Some(columns) = align(a, b) else {
        return Vec::new();
    };
    let diffs: Vec<usize> = columns
        .iter()
        .enumerate()
        .filter(|(_, (x, y))| x != y)
        .map(|(i, _)| i)
        .collect();
    if diffs.is_empty() || diffs.len() > limit {
        return Vec::new();
    }
    let mut out = Vec::new();
    for mask in 0u32..(1 << diffs.len()) {
        let take_b = |col: usize| {
            diffs
                .iter()
                .position(|d| *d == col)
                .is_some_and(|bit| mask & (1 << bit) != 0)
        };
        let build = |wild: Option<(usize, char)>| -> Vec<char> {
            columns
                .iter()
                .enumerate()
                .filter_map(|(col, (x, y))| match wild {
                    Some((w, c)) if w == col => Some(c),
                    _ => {
                        if take_b(col) {
                            *y
                        } else {
                            *x
                        }
                    }
                })
                .collect()
        };
        if !wild {
            out.push(build(None));
            continue;
        }
        for &col in &diffs {
            if let Some((Some(_), Some(_))) = columns.get(col) {
                for c in COMMON_CHARS.chars() {
                    out.push(build(Some((col, c))));
                }
            }
        }
        if out.len() >= MAX_BETWEEN {
            break;
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// 两段字符的最短编辑路径（完整动态规划与回溯）：每一列是 (a 的字符, b 的字符)，`None` 表示这一侧没有字符。
/// 只用于不超过约 [`MAX_ANALYZED`] 个字符的片段。
fn align(a: &[char], b: &[char]) -> Option<Vec<(Option<char>, Option<char>)>> {
    let (n, m) = (a.len(), b.len());
    let w = m + 1;
    let mut d = vec![0usize; (n + 1) * w];
    for i in 0..=n {
        *d.get_mut(i * w)? = i;
    }
    for j in 0..=m {
        *d.get_mut(j)? = j;
    }
    for i in 1..=n {
        for j in 1..=m {
            let sub = d.get((i - 1) * w + j - 1)? + usize::from(a.get(i - 1) != b.get(j - 1));
            let del = d.get((i - 1) * w + j)? + 1;
            let ins = d.get(i * w + j - 1)? + 1;
            *d.get_mut(i * w + j)? = sub.min(del).min(ins);
        }
    }
    let mut columns = Vec::new();
    let (mut i, mut j) = (n, m);
    while i > 0 || j > 0 {
        let here = *d.get(i * w + j)?;
        if i > 0
            && j > 0
            && here == d.get((i - 1) * w + j - 1)? + usize::from(a.get(i - 1) != b.get(j - 1))
        {
            columns.push((a.get(i - 1).copied(), b.get(j - 1).copied()));
            i -= 1;
            j -= 1;
        } else if i > 0 && here == d.get((i - 1) * w + j)? + 1 {
            columns.push((a.get(i - 1).copied(), None));
            i -= 1;
        } else {
            columns.push((None, b.get(j - 1).copied()));
            j -= 1;
        }
    }
    columns.reverse();
    Some(columns)
}
/// 重复份数不超过这么多时，另外把每一份的位置都当作基础片段的候选（这时完全相同的两份可能不存在）。
const FEW_COPIES: usize = 4;

/// 近似周期（确认评审 N1、P1、Q1、Q2）：原文是同一片段的重复（至少两份），其中最多 [`MAX_EDITS`] 处改动（替换、
/// 插入或删除，改动可以在任何一份中）。估计为：基础片段的猜测次数 × 重复次数 × 每处改动（位置数 × [`EDIT_CHARS`]）。
///
/// 基础片段的候选有四个来源：
/// 1. 长度为 `p`、出现次数最多的片段，它的重复要覆盖原文的绝大部分（份数多时，总有完好的两份）；
/// 2. 份数不超过 [`FEW_COPIES`] 时，每一份所在的位置，前后各错开最多 [`MAX_EDITS`] 个字符（份数少、又有改动时，
///    完全相同的两份可能不存在）。只用于不超过 [`MAX_ANALYZED`] 个字符的基础片段；
/// 3. 两三份、每一份都有改动时，从第一份与另一份的差异中还原（[`between`]，确认评审 R1）。
///
/// 4. 基础片段是词典中排名靠前的词时，直接核对（[`common_word_candidates`]，确认评审 T1–T3）：两份改成相同的
///    字符、在不同位置删除、三份在同一位置都被改动时，基础片段不在原文中，也不在两份之间。
///
/// 这些来源是启发式的，**不保证完备**：份数多时出现最多的片段可能是被改动的那个（确认评审 T5c），两份的差异
/// 不超过一半、跳过已找到周期的倍数都是为性能所做的剪枝（T5a、T5b）。见 export §3。
///
/// 对每个候选，在没有改动时的对齐位置前后 [`MAX_EDITS`] 个相位上（周期很短时是全部相位）求带状编辑距离。
/// 匹配成功的按（改动处数, 周期）排序，取前 [`MAX_COST_EVALS`] 个按**总代价**比较，取最小的：改动最少的解释不一定
/// 最便宜，基础片段是常见口令的解释可能多一处改动、代价却低得多。基础片段的估计不再递归找近似周期。
///
/// 只有比 `limit`（其他估计中最小的）更小、并且低于最高档门槛时，近似周期才影响结果：代价的下限（重复次数 ×
/// 改动的代价，基础片段至少 1 次猜测）已经达到 `min(limit, 门槛)` 的候选不再估计基础片段（确认评审 P2）。
fn near_period_estimate(chars: &[char], limit: f64) -> Option<(f64, Option<Analysis>)> {
    let n = chars.len();
    // 匹配成功的：(改动处数, 周期, 从原文开头对齐的基础片段)
    let mut found: Vec<(usize, usize, Vec<char>)> = Vec::new();
    let try_base = |p: usize, start: usize, found: &mut Vec<(usize, usize, Vec<char>)>| {
        let Some(base) = chars.get(start..start.saturating_add(p)) else {
            return;
        };
        let phases: Vec<usize> = if p <= 2 * MAX_EDITS + 1 {
            (0..p).collect()
        } else {
            // 没有改动时，原文的开头对应基础片段中的位置
            let anchor = (p - start % p) % p;
            (0..=2 * MAX_EDITS)
                .map(|shift| (anchor + p * (MAX_EDITS + 1) + shift - MAX_EDITS) % p)
                .collect()
        };
        for phase in phases {
            if let Some(edits) = periodic_edit_distance(chars, base, phase) {
                let rotated: Vec<char> = (0..p)
                    .filter_map(|k| base.get((phase + k) % p).copied())
                    .collect();
                found.push((edits, p, rotated));
            }
        }
    };
    // 1. 按出现次数
    // 至少两份；删除可以让原文比两份完整的基础片段更短
    let longest = n.saturating_add(MAX_EDITS) / 2;
    let mut candidates = 0usize;
    for p in 1..=longest.min(n) {
        let Some((start, count)) = most_frequent(chars, p) else {
            break;
        };
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
        try_base(p, start, &mut found);
        if found.iter().any(|f| f.0 == 0) {
            // 完全的周期：最短的就是最好的
            break;
        }
        candidates = candidates.saturating_add(1);
        if candidates >= MAX_PERIOD_CANDIDATES {
            break;
        }
    }
    // 2. 份数少：每一份的位置。基础片段更长时它自己就有足够的新内容，或者里面的重复由第 1 种候选找到
    if !found.iter().any(|f| f.0 == 0) {
        let low = (n.saturating_sub(MAX_EDITS) / FEW_COPIES).max(1);
        for p in low..=longest.min(n).min(MAX_ANALYZED) {
            for copy in 0..FEW_COPIES {
                // 前面的插入或删除会让这一份前后错开最多 MAX_EDITS 个字符
                let slot = copy.saturating_mul(p);
                for start in slot.saturating_sub(MAX_EDITS)..=slot.saturating_add(MAX_EDITS) {
                    if start.saturating_add(p) <= n {
                        try_base(p, start, &mut found);
                    }
                }
            }
        }
    }
    // 已经找到的周期：它们的倍数作为第三种来源是多余的（同一个解释，基础片段更长、代价更高）
    let periods: Vec<usize> = found.iter().map(|f| f.1).collect();
    let mut best = cheapest(chars, found, limit, None, MAX_COST_EVALS);
    // 3. 两三份、每一份都有改动：基础片段从第一份与另一份的差异中还原。这样的解释每一份都有改动，至少两处，
    //    代价至少 2 × (n × 95)² > 10⁶，不会让密码落到弱密码（0–1 分）或主密码的下限以下，只影响能否导出（4 分）。
    //    因此只在估计仍在最高档时进行（debug 构建下逐个还原很慢）
    if best.as_ref().map_or(limit, |b| b.0).min(limit) < TOP_SCORE_GUESSES {
        return best;
    }
    let mut found = Vec::new();
    let mut pairs: Vec<(Vec<char>, Vec<char>)> = Vec::new();
    {
        let low = (n.saturating_sub(MAX_EDITS) / 3).max(1);
        for p in low..=longest.min(n).min(MAX_ANALYZED) {
            if periods.iter().any(|q| *q < p && p % q == 0) {
                continue;
            }
            let Some(first) = chars.get(..p) else {
                continue;
            };
            for copy in 1usize..3 {
                let slot = copy.saturating_mul(p);
                for start in slot.saturating_sub(MAX_EDITS)..=slot.saturating_add(MAX_EDITS) {
                    let Some(other) = chars.get(start..start.saturating_add(p)) else {
                        continue;
                    };
                    let bases = between(first, other, false);
                    // 两份在同一位置都被改动，只可能是正好两份：三份时第三份在那个位置是完好的
                    if !bases.is_empty() && p.saturating_mul(2).saturating_add(MAX_EDITS) >= n {
                        pairs.push((first.to_vec(), other.to_vec()));
                    }
                    verify_bases(chars, bases, &mut found);
                }
            }
        }
    }
    // 4. 常见词（确认评审 T1–T3）
    let words = common_word_candidates(chars, longest);
    let limit = best.as_ref().map_or(limit, |b| b.0);
    if let Some(found) = cheapest(chars, words, limit, None, MAX_COST_EVALS)
        && best.as_ref().is_none_or(|b| found.0 < b.0)
    {
        best = Some(found);
    }
    // 第一阶段：不含未知字符的候选
    let limit = best.as_ref().map_or(limit, |b| b.0);
    if let Some(found) = cheapest(chars, found, limit, None, MAX_COST_EVALS)
        && best.as_ref().is_none_or(|b| found.0 < b.0)
    {
        best = Some(found);
    }
    // 第二阶段：两份在同一位置都被改动时，逐个尝试那个位置的字符。只在还没有低于最高档门槛时进行，
    // 一旦低于门槛就停下：能否导出已经确定
    if best.as_ref().is_none_or(|b| b.0 >= TOP_SCORE_GUESSES) && !pairs.is_empty() {
        let mut wild = Vec::new();
        for (first, other) in &pairs {
            verify_bases(chars, between(first, other, true), &mut wild);
        }
        let limit = best.as_ref().map_or(limit, |b| b.0);
        if let Some(found) = cheapest(chars, wild, limit, Some(TOP_SCORE_GUESSES), MAX_WILD_EVALS)
            && best.as_ref().is_none_or(|b| found.0 < b.0)
        {
            best = Some(found);
        }
    }
    best
}

/// 常见词的候选只看各词典中排名不超过它的词。没有完好的一份时，每一份都有改动，至少两处，按词典排名的代价至少
/// 排名 × 2 × (95n)²；可导出的口令至少 10 个字符，这时是 排名 × 1.805 × 10⁶，排名超过约 5540 的词不可能低于
/// 最高档门槛。更长的口令上限更低，按 n 另算（[`common_word_candidates`]）。
const MAX_COMMON_RANK: usize = 6000;

/// 长度 → 这个长度的常见词与排名。
type WordsByLen = HashMap<usize, Vec<(Vec<char>, usize)>>;

/// 各词典中排名不超过 [`MAX_COMMON_RANK`] 的词，按长度分组（同一个词取最低的排名），组内按排名排序。
fn common_words_by_len() -> &'static WordsByLen {
    static WORDS: OnceLock<WordsByLen> = OnceLock::new();
    WORDS.get_or_init(|| {
        let mut best: HashMap<&'static str, usize> = HashMap::new();
        for (_, text) in &DICTS {
            for (rank, word) in text.lines().enumerate().take(MAX_COMMON_RANK) {
                let rank = rank.saturating_add(1);
                best.entry(word)
                    .and_modify(|r| *r = (*r).min(rank))
                    .or_insert(rank);
            }
        }
        let mut by_len: WordsByLen = HashMap::new();
        for (word, rank) in best {
            let chars: Vec<char> = word.chars().collect();
            by_len.entry(chars.len()).or_default().push((chars, rank));
        }
        for list in by_len.values_mut() {
            list.sort_by(|a, b| (a.1, &a.0).cmp(&(b.1, &b.0)));
        }
        by_len
    })
}

/// 第四种候选（确认评审 T1–T3）：基础片段就是词典中排名靠前的一个词，每一份都可能有改动——包括两份改成相同的
/// 字符、在不同位置删除、三份在同一位置都被改动。这些情形下基础片段不在原文中，也不在两份之间，但它是一个常见词，
/// 可以直接核对。
///
/// 先看原文在结构上是否像重复：错开一个周期的前后两段，差异不超过 [`MAX_EDITS`] + 1，也不超过这两段长度的一半
/// （两三份、每份最多两处改动时成立；随机字符几乎处处不同，所以强口令在这里就结束了）。再取长度相近、排名足够低的词核对编辑距离。按小写比较：
/// 词典中的词是小写的，大小写不同不算改动，估计只会更低（更保守）。
fn common_word_candidates(chars: &[char], longest: usize) -> Vec<(usize, usize, Vec<char>)> {
    let n = chars.len();
    let rank_limit = TOP_SCORE_GUESSES / (2.0 * (to_f64(n) * EDIT_CHARS).powi(2));
    if rank_limit < 1.0 {
        return Vec::new();
    }
    let lower: Vec<char> = chars
        .iter()
        .map(|c| c.to_lowercase().next().unwrap_or(*c))
        .collect();
    let words = common_words_by_len();
    let low = (n.saturating_sub(MAX_EDITS) / 3).max(1);
    let mut lengths: Vec<usize> = Vec::new();
    for p in low..=longest.min(n.saturating_sub(1)) {
        let (Some(a), Some(b)) = (lower.get(..n - p), lower.get(p..)) else {
            continue;
        };
        // 比较的两段很短时，"差异不多"对任何输入都成立，所以也要求差异不超过一半；差异还必须小于周期本身，
        // 否则带状对齐可以漂回错开 0 的位置，拿原文和它自己比
        let limit = (MAX_EDITS + 1).min(a.len().div_ceil(2)).min(p - 1);
        if limit == 0 || periodic_edit_distance_within(a, b, 0, limit).is_none() {
            continue;
        }
        for len in p.saturating_sub(MAX_EDITS).max(1)..=p.saturating_add(MAX_EDITS) {
            if !lengths.contains(&len) {
                lengths.push(len);
            }
        }
    }
    let per_edit = to_f64(n) * EDIT_CHARS;
    let mut keyed: Vec<(f64, usize, usize, &[char])> = Vec::new();
    for len in lengths {
        for (word, rank) in words.get(&len).map(Vec::as_slice).unwrap_or_default() {
            if to_f64(*rank) > rank_limit {
                break;
            }
            let phases: Vec<usize> = if len <= 2 * MAX_EDITS + 1 {
                (0..len).collect()
            } else {
                (0..=2 * MAX_EDITS)
                    .map(|shift| (len * (MAX_EDITS + 1) + shift - MAX_EDITS) % len)
                    .collect()
            };
            let Some(edits) = phases
                .into_iter()
                .filter_map(|phase| periodic_edit_distance(&lower, word, phase))
                .min()
            else {
                continue;
            };
            let key = to_f64(*rank)
                * to_f64(n.div_ceil(len))
                * per_edit.powi(i32::try_from(edits).unwrap_or(i32::MAX));
            keyed.push((key, edits, len, word.as_slice()));
        }
    }
    // 交给 [`cheapest`] 的是词本身（不按相位旋转：模型按词本身计，旋转的选择数不计入，只会更低），按排名估计的
    // 总代价取最便宜的几个；`cheapest` 按改动处数排序后只比较前 [`MAX_COST_EVALS`] 个，不能让排名靠后的词挤掉
    // 排名靠前的
    keyed.sort_by(|a, b| a.0.total_cmp(&b.0).then_with(|| a.3.cmp(b.3)));
    keyed
        .into_iter()
        .take(MAX_COST_EVALS)
        .map(|(_, edits, len, word)| (edits, len, word.to_vec()))
        .collect()
}

/// 对还原出的基础片段（与原文的开头对齐）核对编辑距离，成功的记下：(改动处数, 周期, 基础片段)。
fn verify_bases(chars: &[char], bases: Vec<Vec<char>>, found: &mut Vec<(usize, usize, Vec<char>)>) {
    for base in bases {
        let len = base.len();
        if len == 0 {
            continue;
        }
        for shift in 0..=2 * MAX_EDITS {
            let phase = (len * (MAX_EDITS + 1) + shift - MAX_EDITS) % len;
            if let Some(edits) = periodic_edit_distance(chars, &base, phase) {
                let rotated: Vec<char> = (0..len)
                    .filter_map(|k| base.get((phase + k) % len).copied())
                    .collect();
                found.push((edits, len, rotated));
            }
        }
    }
}

/// 在匹配成功的解释中按总代价取最小：按（改动处数, 周期）排序，最多估计 `evals` 个基础片段。代价下限（重复次数
/// × 改动的代价）已经达到 `min(limit, 门槛)` 的不再估计。`stop_below` 不为空时，一旦低于它就停下。
fn cheapest(
    chars: &[char],
    mut found: Vec<(usize, usize, Vec<char>)>,
    limit: f64,
    stop_below: Option<f64>,
    evals: usize,
) -> Option<(f64, Option<Analysis>)> {
    let n = chars.len();
    found.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)).then_with(|| a.2.cmp(&b.2)));
    found.dedup();
    let per_edit = to_f64(n) * EDIT_CHARS;
    let mut best: Option<(f64, Option<Analysis>)> = None;
    for (edits, p, rotated) in found.into_iter().take(evals) {
        let edit_cost = per_edit.powi(i32::try_from(edits).unwrap_or(i32::MAX));
        let floor = to_f64(n.div_ceil(p)) * edit_cost;
        let target = best.as_ref().map_or(limit, |b| b.0).min(TOP_SCORE_GUESSES);
        if floor >= target {
            continue;
        }
        let (g, analysis) = base_estimate(&rotated);
        let guesses = (g * floor).min(f64::MAX);
        if best.as_ref().is_none_or(|b| guesses < b.0) {
            best = Some((guesses, analysis));
        }
        if stop_below.is_some_and(|stop| best.as_ref().is_some_and(|b| b.0 < stop)) {
            break;
        }
    }
    best
}

/// 近似周期中基础片段的估计：zxcvbn（不超过 [`MAX_ANALYZED`] 个字符时）与 LZ77 分解中较小的，不再递归。
fn base_estimate(chars: &[char]) -> (f64, Option<Analysis>) {
    let lz = lz_estimate(chars);
    if chars.len() <= MAX_ANALYZED {
        let whole = most_guessable(chars, omnimatch(chars), false);
        if whole.guesses <= lz.0 {
            return (whole.guesses, Some(whole));
        }
    }
    lz
}

/// 长度为 `p` 的片段中出现次数最多的一个：(第一次出现的位置, 次数)。滚动哈希找候选，同一个哈希值下再比较真实的
/// 字符，碰撞不会被当作相同的片段（确认评审 Q3）。重叠的出现也计入；等次数时取最早的。
fn most_frequent(chars: &[char], p: usize) -> Option<(usize, usize)> {
    const B: u64 = 1_000_003;
    if p == 0 || p > chars.len() {
        return None;
    }
    let pow = (1..p).fold(1u64, |acc, _| acc.wrapping_mul(B));
    // 哈希值 → 这个值下不同的片段：(第一次出现的位置, 次数)
    let mut seen: HashMap<u64, Vec<(usize, usize)>> = HashMap::new();
    let mut h = 0u64;
    for (i, c) in chars.iter().enumerate() {
        if i >= p {
            let old = u64::from(*chars.get(i - p)?);
            h = h.wrapping_sub(old.wrapping_mul(pow));
        }
        h = h.wrapping_mul(B).wrapping_add(u64::from(*c));
        if i + 1 >= p {
            let start = i + 1 - p;
            let slice = chars.get(start..=i)?;
            let bucket = seen.entry(h).or_default();
            match bucket
                .iter_mut()
                .find(|(first, _)| chars.get(*first..first + p) == Some(slice))
            {
                Some(entry) => entry.1 = entry.1.saturating_add(1),
                None => bucket.push((start, 1)),
            }
        }
    }
    seen.into_values()
        .flatten()
        .max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0)))
}

/// 原文与"`base` 从 `phase` 开始无限重复"之间的编辑距离（替换、插入、删除各算一处；重复的长度可以与原文不同，
/// 最后一份可以不完整）。只算到 [`MAX_EDITS`]，超过时返回 `None`。带状动态规划，O(n × MAX_EDITS)。
fn periodic_edit_distance(text: &[char], base: &[char], phase: usize) -> Option<usize> {
    periodic_edit_distance_within(text, base, phase, MAX_EDITS)
}

/// 与 [`periodic_edit_distance`] 相同，只算到 `k`。
fn periodic_edit_distance_within(
    text: &[char],
    base: &[char],
    phase: usize,
    k: usize,
) -> Option<usize> {
    let p = base.len();
    if p == 0 {
        return None;
    }
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
#[allow(clippy::unwrap_used, clippy::float_cmp, clippy::print_stderr)]
mod tests {
    /// 常见词变体的模型代价：基础片段的估计 × 份数 × 每处改动（位置数 × 95），改动处数按大小写敏感的编辑距离。
    fn review5i_model(chars: &[char], base: &[char]) -> Option<f64> {
        let edits = super::periodic_edit_distance(chars, base, 0)?;
        Some(
            super::base_estimate(base).0
                * super::to_f64(chars.len().div_ceil(base.len()))
                * (super::to_f64(chars.len()) * 95.0).powi(i32::try_from(edits).unwrap()),
        )
    }

    /// 一个常见词在"重复两三份、每一份都有改动"下的各种变体：相同替换、相同插入、三份同位置替换或删除、
    /// 不同位置删除、替换加删除、两份删除加一份完好。
    fn review5i_variants(word: &[char]) -> Vec<Vec<char>> {
        let p = word.len();
        let sub = |i: usize, x: char| {
            let mut v = word.to_vec();
            v[i] = x;
            v
        };
        let del = |i: usize| {
            let mut v = word.to_vec();
            v.remove(i);
            v
        };
        let ins = |i: usize, x: char| {
            let mut v = word.to_vec();
            v.insert(i, x);
            v
        };
        let mut out = Vec::new();
        for i in 0..p {
            for x in ['%', '1', 'q'] {
                out.push([sub(i, x), sub(i, x)].concat());
                out.push([sub(i, x), sub(i, x), sub(i, x)].concat());
                out.push([ins(i, x), ins(i, x)].concat());
            }
            out.push([sub(i, '%'), sub(i, '#'), sub(i, '&')].concat());
            out.push([del(i), del(i), del(i)].concat());
            for j in (0..p).filter(|j| *j != i) {
                out.push([del(i), del(j)].concat());
                out.push([sub(i, '%'), del(j)].concat());
                out.push([del(i), del(j), word.to_vec()].concat());
            }
        }
        out
    }

    #[test]
    fn review5i_common_word_variants_are_rejected() {
        // 每一类一个代表（debug 构建下逐个估计很慢）；整族的核对见下面的 release 测试
        for (word, password) in [
            ("password", "pa%swordpa%sword"),
            ("development", "develo%pmentdevelo%pment"),
            ("DEVELOPMENT", "DEVEOPMENTDEVELPMENT"),
            ("mary", "mar%mar#mar&"),
            ("development", "deveopmentdevelpmentdevelopment"),
        ] {
            let base: Vec<char> = word.chars().collect();
            let chars: Vec<char> = password.chars().collect();
            let model = review5i_model(&chars, &base).unwrap();
            assert!(model < 1e10 && chars.len() >= 10, "{password}: {model}");
            assert!(
                !crate::export::export_password_ok(password),
                "{password}: model {model}"
            );
        }
    }

    #[test]
    #[ignore = "release 构建下约 1 分钟：常见词变体的整族核对"]
    fn review5i_common_word_variant_family_is_rejected() {
        let words = super::common_words_by_len();
        let mut checked = 0usize;
        let mut accepted = Vec::new();
        for len in 4..=12 {
            let list = words.get(&len).unwrap();
            // 每个长度取排名最靠前的 4 个，再按排名均匀取 9 个（直到排名上限）
            let step = (list.len() / 10).max(1);
            for (word, _) in list.iter().take(4).chain(list.iter().step_by(step).skip(1)) {
                for upper in [false, true] {
                    let base: Vec<char> = if upper {
                        word.iter().map(char::to_ascii_uppercase).collect()
                    } else {
                        word.clone()
                    };
                    for chars in review5i_variants(&base) {
                        let Some(model) = review5i_model(&chars, &base) else {
                            continue;
                        };
                        if chars.len() < 10 || model >= 1e10 {
                            continue;
                        }
                        checked += 1;
                        let password: String = chars.iter().collect();
                        if crate::export::export_password_ok(&password) {
                            accepted.push((password, model));
                        }
                    }
                }
            }
        }
        eprintln!("checked {checked}, accepted {}", accepted.len());
        assert!(checked > 20_000);
        assert!(
            accepted.is_empty(),
            "{:?}",
            accepted.get(..accepted.len().min(10))
        );
    }

    fn review5h_assert_rejected(word: &str, password: &str, edits: usize, g: f64, bound: f64) {
        let base: Vec<char> = word.chars().collect();
        let chars: Vec<char> = password.chars().collect();
        assert_eq!(super::base_estimate(&base).0, g);
        assert_eq!(super::periodic_edit_distance(&chars, &base, 0), Some(edits));
        let model = g
            * super::to_f64(chars.len().div_ceil(base.len()))
            * (super::to_f64(chars.len()) * 95.0).powi(i32::try_from(edits).unwrap());
        assert_eq!(model, bound);
        assert!(model < 1e10);
        assert!(chars.len() >= 10);
        let actual = crate::export::export_password_strength(password);
        eprintln!("{password}: g={g}, model={model}, actual={actual:?}");
        assert!(
            !crate::export::export_password_ok(password),
            "low-cost repeated common base must reject export"
        );
    }

    #[test]
    fn review5h_t1_identical_substitutions_are_rejected() {
        let copy: Vec<char> = "deve%opment".chars().collect();
        // Equal damaged columns never enter the unknown-character enumeration.
        assert!(super::between(&copy, &copy, true).is_empty());
        review5h_assert_rejected(
            "development",
            "deve%opmentdeve%opment",
            2,
            225.0,
            1_965_645_000.0,
        );
    }

    #[test]
    fn review5h_t2_different_deletions_are_rejected() {
        let a: Vec<char> = "deveopment".chars().collect();
        let b: Vec<char> = "develpment".chars().collect();
        let base: Vec<char> = "development".chars().collect();
        // One substitution is shorter than the path through the original base
        // (one insertion and one deletion). Its candidates all lack a character.
        let columns = super::align(&a, &b).unwrap();
        assert_eq!(columns.iter().filter(|(x, y)| x != y).count(), 1);
        assert!(!super::between(&a, &b, false).contains(&base));
        review5h_assert_rejected(
            "development",
            "deveopmentdevelpment",
            2,
            225.0,
            1_624_500_000.0,
        );
    }

    #[test]
    #[ignore = "已知局限（确认评审 T5a，不阻塞）：两份差异不超过一半是性能上的剪枝，不能由最多三处改动推出"]
    fn review5h_t5a_half_difference_limit_preserves_the_original_base() {
        let base: Vec<char> = "mary".chars().collect();
        let a: Vec<char> = "%#ry".chars().collect();
        let b: Vec<char> = "ma&y".chars().collect();
        let text: Vec<char> = a.iter().chain(&b).copied().collect();
        assert_eq!(super::periodic_edit_distance(&text, &base, 0), Some(3));
        let model = super::base_estimate(&base).0 * 2.0 * (8.0_f64 * 95.0).powi(3);
        assert_eq!(model, 1_755_904_000.0);
        // This is a proof counterexample only: length 8 already forbids export.
        assert!(!crate::export::export_password_ok("%#ryma&y"));
        assert!(
            super::between(&a, &b, false).contains(&base),
            "three disjoint changes need not be at most half of p"
        );
    }

    #[test]
    #[ignore = "已知局限（确认评审 T5b，不阻塞）：跳过已找到周期的倍数是剪枝，不是代价上的支配"]
    fn review5h_t5b_shorter_period_is_not_a_cost_dominance_proof() {
        let chars: Vec<char> = "123121123921".chars().collect();
        let short: Vec<char> = "123".chars().collect();
        let long: Vec<char> = "123321".chars().collect();
        assert_eq!(super::periodic_edit_distance(&chars, &short, 0), Some(3));
        assert_eq!(super::periodic_edit_distance(&chars, &long, 0), Some(2));
        let short_cost = super::base_estimate(&short).0 * 4.0 * (12.0_f64 * 95.0).powi(3);
        let long_cost = super::base_estimate(&long).0 * 2.0 * (12.0_f64 * 95.0).powi(2);
        eprintln!("short={short_cost}, long={long_cost}");
        assert!(long_cost < 1e10);
        // Other estimators reject this sample; the pruning rationale still fails.
        assert!(!crate::export::export_password_ok("123121123921"));
        assert!(
            short_cost <= long_cost,
            "divisibility alone must not discard a cheaper explanation"
        );
    }

    #[test]
    #[ignore = "已知局限（确认评审 T5c，不阻塞）：出现次数最多的片段不一定是最便宜的基础片段"]
    fn review5h_t5c_most_frequent_does_not_imply_cheapest_base() {
        let chars: Vec<char> = "m%rym%rym%rymarymary".chars().collect();
        let base: Vec<char> = "mary".chars().collect();
        let (start, count) = super::most_frequent(&chars, 4).unwrap();
        assert_eq!((start, count), (0, 3));
        let selected = &chars[start..start + 4];
        assert_eq!(super::periodic_edit_distance(&chars, &base, 0), Some(3));
        assert_eq!(super::periodic_edit_distance(&chars, selected, 0), Some(2));
        let original = super::base_estimate(&base).0 * 5.0 * (20.0_f64 * 95.0).powi(3);
        let chosen = super::base_estimate(selected).0 * 5.0 * (20.0_f64 * 95.0).powi(2);
        eprintln!("intact base={original}, most frequent={chosen}");
        assert!(original >= 1e10); // Outside the freeze-blocking cost range.
        assert!(
            chosen <= original,
            "two intact copies do not ensure that the most frequent candidate covers them cheaply"
        );
    }

    #[test]
    #[ignore = "release measurement; no timing assertion"]
    fn review5h_c1_release_performance_samples() {
        let _ = super::estimate("warm dictionaries");
        for (label, password) in [
            ("R1", "pa!sword123#assword123".to_owned()),
            (
                "two wild substitutions",
                "pa!sword123pa#sword123".to_owned(),
            ),
            ("T1", "deve%opmentdeve%opment".to_owned()),
            ("T2", "deveopmentdevelpment".to_owned()),
            ("T3", "m%rym#rym&ry".to_owned()),
            ("uppercase", "DEVE%OPMENTDEVE#OPMENT".to_owned()),
            (
                "above threshold, two copies",
                "le%mein123!le#mein123!".to_owned(),
            ),
            (
                "above threshold, three copies",
                "le%mein123!le#mein123!le&mein123!".to_owned(),
            ),
        ] {
            let mut times = Vec::new();
            for _ in 0..7 {
                let started = std::time::Instant::now();
                let actual = std::hint::black_box(crate::export::export_password_strength(
                    std::hint::black_box(&password),
                ));
                times.push(started.elapsed());
                assert!(actual.guesses.is_finite());
            }
            times.sort_unstable();
            eprintln!("{label}: median={:?}, max={:?}", times[3], times[6]);
        }
    }

    #[test]
    #[ignore = "已知局限（确认评审 T4，不阻塞）：只把未知字母改成小写不一定让估计更低"]
    fn review5h_t4_lowercasing_only_the_unknown_letter_is_not_conservative() {
        let base: Vec<char> = "DEVELOPMENT".chars().collect();
        let lower_one: Vec<char> = "DEVElOPMENT".chars().collect();
        let password = "DEVE%OPMENTDEVE#OPMENT";
        let chars: Vec<char> = password.chars().collect();
        let g = super::base_estimate(&base).0;
        let changed_g = super::base_estimate(&lower_one).0;
        assert_eq!(super::periodic_edit_distance(&chars, &base, 0), Some(2));
        let model = g * 2.0 * (22.0_f64 * 95.0).powi(2);
        let actual = crate::export::export_password_strength(password);
        eprintln!("{password}: g={g}, lower_one={changed_g}, model={model}, actual={actual:?}");
        assert!(model < 1e10);
        assert!(!crate::export::export_password_ok(password));
        assert!(
            changed_g <= g,
            "the documented one-letter lowercase monotonicity does not hold"
        );
    }

    #[test]
    fn review5h_t3_three_copies_can_all_lose_the_same_character() {
        review5h_assert_rejected("mary", "m%rym#rym&ry", 3, 2.0, 8_889_264_000.0);
    }

    #[test]
    fn review5g_r1_damaged_copies_below_model_threshold_are_rejected() {
        let base: Vec<char> = "password123".chars().collect();
        let mut password = "password123".repeat(2);
        password.replace_range(2..3, "!");
        password.replace_range(11..12, "#");
        assert_eq!(password, "pa!sword123#assword123");
        let chars: Vec<char> = password.chars().collect();
        // 每个候选长度的原文窗口都带有改动，连旋转后的完好基础片段也取不到。
        assert!(
            chars
                .windows(base.len())
                .all(|w| w.contains(&'!') || w.contains(&'#'))
        );
        assert_eq!(super::periodic_edit_distance(&chars, &base, 0), Some(2));
        let g = super::base_estimate(&base).0;
        let bound = g * 2.0 * (super::to_f64(chars.len()) * 95.0).powi(2);
        assert_eq!(g, 596.0);
        assert_eq!(bound, 5_206_775_200.0);
        assert!(bound < 1e10);
        let near = super::near_period_estimate(&chars, f64::MAX).map(|v| v.0);
        let actual = crate::export::export_password_strength(&password);
        let allowed = crate::export::export_password_ok(&password);
        eprintln!("{password}: model={bound}, near={near:?}, actual={actual:?}, allowed={allowed}");
        assert!(
            !allowed,
            "two low-cost substitutions must not permit export"
        );
    }

    #[test]
    fn review5g_c1_intact_common_base_variants_respect_model_threshold() {
        let mut checked = 0usize;
        for base in ["password123", "password", "letmein", "qwerty", "123456"] {
            let g = super::estimate(base).guesses;
            let p = base.len();
            for copies in [2, 3, 4] {
                for kind in 0..4 {
                    for i in 0..p {
                        for j in 0..p - 1 {
                            let mut chars: Vec<char> = base.repeat(copies).chars().collect();
                            match kind {
                                0 => {
                                    chars.remove(i);
                                    chars[j] = '!';
                                }
                                1 => {
                                    chars.remove(i);
                                    chars.remove(j);
                                }
                                2 => {
                                    chars.insert(i, '!');
                                    chars[j] = '#';
                                }
                                _ => {
                                    chars[i] = '!';
                                    chars[j] = '#';
                                }
                            }
                            let bound = g
                                * super::to_f64(chars.len().div_ceil(p))
                                * (super::to_f64(chars.len()) * 95.0).powi(2);
                            if bound >= 1e10 {
                                continue;
                            }
                            let password: String = chars.into_iter().collect();
                            let actual = crate::export::export_password_strength(&password);
                            checked += 1;
                            assert!(
                                actual.score < 4,
                                "base={base}, copies={copies}, kind={kind}, i={i}, j={j}, password={password}, model={bound}, actual={actual:?}"
                            );
                        }
                    }
                }
            }
        }
        eprintln!("intact-base low-cost variants checked={checked}");
        assert!(checked > 100);
    }

    #[test]
    fn review5f_q1_two_copies_with_one_substitution_are_rejected() {
        let base: Vec<char> = "password123".chars().collect();
        let mut failures = Vec::new();
        for pos in [2, 5] {
            let mut password = "password123".repeat(2);
            password.replace_range(pos..pos + 1, "!");
            let chars: Vec<char> = password.chars().collect();
            assert_eq!(super::periodic_edit_distance(&chars, &base, 0), Some(1));
            let bound =
                super::estimate("password123").guesses * 2.0 * super::to_f64(chars.len()) * 95.0;
            assert!(bound < 1e10);
            let near = super::near_period_estimate(&chars, f64::MAX).map(|v| v.0);
            let actual = crate::export::export_password_strength(&password);
            let allowed = crate::export::export_password_ok(&password);
            eprintln!(
                "{password}: model={bound}, near={near:?}, actual={actual:?}, allowed={allowed}"
            );
            if allowed {
                failures.push(password);
            }
        }
        assert!(
            failures.is_empty(),
            "low-cost substitutions must not permit export: {failures:?}"
        );
    }

    #[test]
    fn review5f_q2_cheaper_common_password_phase_must_not_be_discarded() {
        let base: Vec<char> = "letmein".chars().collect();
        let password = "etm!inletmeinletmein"; // letmein × 3，删除开头 l，再替换一个 e
        let chars: Vec<char> = password.chars().collect();
        assert_eq!(super::periodic_edit_distance(&chars, &base, 0), Some(2));
        assert_eq!(super::periodic_edit_distance(&chars, &base, 1), Some(1));
        let bound =
            super::estimate("letmein").guesses * 3.0 * (super::to_f64(chars.len()) * 95.0).powi(2);
        assert!(bound < 1e10);
        let near = super::near_period_estimate(&chars, f64::MAX).map(|v| v.0);
        let strength = crate::export::export_password_strength(password);
        eprintln!(
            "canonical_base={}, rotated_base={}, model={bound}, near={near:?}, actual={strength:?}",
            super::estimate("letmein").guesses,
            super::estimate("etmeinl").guesses
        );
        assert!(
            !crate::export::export_password_ok(password),
            "model={bound}, actual={strength:?}"
        );
    }

    #[test]
    fn review5f_q3_hash_collision_is_not_a_repeated_substring() {
        // 0 * B + B == 1 * B + 0，但 [0, B] 与 [1, 0] 不同。
        let chars = ['\0', '\u{f4243}', '\u{1}', '\0'];
        assert_ne!(&chars[..2], &chars[2..]);
        assert_eq!(super::most_frequent(&chars, 2), Some((0, 1)));
    }

    #[test]
    fn review5f_c1_banded_distance_matches_full_matrix() {
        fn word(bits: usize, len: usize) -> Vec<char> {
            (0..len)
                .map(|i| if bits & (1 << i) == 0 { 'a' } else { 'b' })
                .collect()
        }
        let mut checked = 0;
        for n in 0..=7 {
            for bits in 0..1 << n {
                let text = word(bits, n);
                for p in 1..=4 {
                    for pattern in 0..1 << p {
                        let base = word(pattern, p);
                        for phase in 0..p {
                            let m = n + super::MAX_EDITS;
                            let mut row: Vec<usize> = (0..=m).collect();
                            for i in 1..=n {
                                let mut next = vec![i; m + 1];
                                for j in 1..=m {
                                    next[j] = (row[j] + 1).min(next[j - 1] + 1).min(
                                        row[j - 1]
                                            + usize::from(text[i - 1] != base[(phase + j - 1) % p]),
                                    );
                                }
                                row = next;
                            }
                            let expected = row.into_iter().min().filter(|d| *d <= super::MAX_EDITS);
                            assert_eq!(
                                super::periodic_edit_distance(&text, &base, phase),
                                expected,
                                "text={text:?}, base={base:?}, phase={phase}"
                            );
                            checked += 1;
                        }
                    }
                }
            }
        }
        eprintln!("full-matrix comparisons={checked}");
    }

    #[test]
    fn review5f_c2_additional_performance_cases() {
        let symbols = b"4@8({[<3691!|70$5+%2";
        let mut dense = String::new();
        for i in 100_u32..132 {
            for b in keevo_crypto::sha256(&i.to_le_bytes()) {
                dense.push(char::from(symbols[usize::from(b) % symbols.len()]));
            }
        }
        let mut repeated = dense[..64].repeat(16);
        for pos in [2, 400, 900] {
            repeated.insert(pos, 'Z');
        }
        let digits: String = (0_u32..32)
            .flat_map(|i| keevo_crypto::sha256(&i.to_le_bytes()))
            .map(|b| char::from(b'0' + b % 10))
            .collect();
        let _ = super::estimate("warm dictionaries");
        for (label, password) in [
            ("dense64", dense[..64].to_owned()),
            ("dense128", dense[..128].to_owned()),
            ("dense1024", dense),
            ("l33t_period64_plus_three_insertions", repeated),
            ("digits1024", digits),
            (
                "copy_interleaved",
                (0..32)
                    .map(|i| format!("4@8({{[<3691!|70$5+%2{i:02}"))
                    .collect(),
            ),
        ] {
            let start = std::time::Instant::now();
            let strength = super::estimate(&password);
            let elapsed = start.elapsed();
            eprintln!("{label}: {elapsed:?}, score={}", strength.score);
            assert!(
                elapsed < std::time::Duration::from_secs(5),
                "{label}: {elapsed:?}"
            );
            assert!(strength.guesses.is_finite());
        }
    }

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
        // (变体, 改动处数)；与另一个常见片段交替的变体没有改动处数（它是精确的周期，基础片段由两个常见口令组成）
        let variants_of = |base: &str, n: usize| -> Vec<(String, Option<i32>)> {
            let plain = base.repeat(n);
            let len = plain.chars().count();
            let mut out = vec![
                (format!("{plain}!"), Some(1)),
                (format!("!{plain}"), Some(1)),
                (
                    format!("{}#{}", base.repeat(n / 2), base.repeat(n - n / 2)),
                    Some(1),
                ),
                (
                    format!("{}{}", base.repeat(2), "qwerty".repeat(2)).repeat(n),
                    None,
                ),
            ];
            for pos in [0, len / 3, len / 2, len - 1] {
                let mut chars: Vec<char> = plain.chars().collect();
                chars[pos] = '%';
                out.push((chars.into_iter().collect(), Some(1)));
            }
            // 每一份都有改动：前两份在不同位置各替换一个字符（确认评审 R1），以及在同一位置替换成不同的字符
            if n >= 2 {
                let p = base.chars().count();
                let mut damaged: Vec<char> = plain.chars().collect();
                damaged[1] = '%';
                damaged[p + p / 2] = '#';
                out.push((damaged.into_iter().collect(), Some(2)));
                let mut same: Vec<char> = plain.chars().collect();
                same[2] = '%';
                same[p + 2] = '#';
                out.push((same.into_iter().collect(), Some(2)));
            }
            // 删掉开头一个字符、再替换一个字符：从常见口令的相位看是两处改动（确认评审 Q2）
            let mut shifted: Vec<char> = plain.chars().skip(1).collect();
            shifted[2] = '!';
            out.push((shifted.into_iter().collect(), Some(2)));
            // 第一份之内的插入与删除（确认评审 P1），以及中间的删除
            for pos in [1, 2, base.len() / 2, len / 2] {
                let mut inserted: Vec<char> = plain.chars().collect();
                inserted.insert(pos, '!');
                out.push((inserted.into_iter().collect(), Some(1)));
                let mut removed: Vec<char> = plain.chars().collect();
                removed.remove(pos);
                out.push((removed.into_iter().collect(), Some(1)));
            }
            out
        };
        // 按规范的枚举模型（基础 × 重复次数 × 每处改动的位置数 × 95）代价低于 10¹⁰ 的，一律达不到最高档；
        // 只有两份时，完全相同的两份可能不存在（确认评审 Q1）
        let mut below = 0usize;
        // debug 构建下 zxcvbn 较慢，这里取有代表性的组合；评审测试（review5e_、review5f_）另外覆盖了更多重复次数
        for base in ["password", "password123", "letmein"] {
            let g = estimate(base).guesses;
            for n in [2, 3, 10] {
                for (v, edits) in variants_of(base, n) {
                    let s = estimate(&v);
                    let len = v.chars().count();
                    let bound = edits.map_or(0.0, |e| {
                        g * to_f64(len.div_ceil(base.len())) * (to_f64(len) * 95.0).powi(e)
                    });
                    if bound < 1e10 {
                        below += 1;
                        assert!(s.score <= 3, "{v} → {s:?}，模型代价 {bound}");
                    }
                }
            }
        }
        assert!(below > 100, "{below}");
        // 对其他基础片段，估计不超过模型上限：重复本身不再虚增
        // 这些变体按模型本来就在门槛之上，估计要把各种还原都做完，debug 构建下慢；这里只取一个代表（release 构建下
        // 每个不超过 30 ms）
        for base in ["letmein123!"] {
            let g = estimate(base).guesses;
            for n in [3] {
                for (v, edits) in variants_of(base, n) {
                    let Some(1) = edits else { continue };
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
