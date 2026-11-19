//! 安全中心的检查（`docs/product.md` §5.6，设计稿"macOS · 安全中心"）。
//!
//! 全部在本机完成：弱密码（[`crate::strength`]）、重复使用、已泄露（只在用户开启后，由界面层查询 Have I Been
//! Pwned 的 k-匿名接口，这里只做本机比对）、未开启两步验证（对照内置的 2fa.directory 数据）、即将过期、
//! 不安全的网址、过时的 SSH 密钥、恢复码不足。回收站与归档中的条目不检查；属性 `security_alerts` 为 `off`
//! 的条目不出现在结果中（"忽略这个条目的提醒"，`spec/vault-format.md` §2.1）。
//!
//! 秘密值只在这里比较与评估，不出现在结果中：结果只有条目 ID 与说明问题所需的非秘密信息。

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::OnceLock;

use keevo_crypto::{Id128, sha1_for_breach_check, sha256};
use keevo_format::{FieldData, FieldKind, ItemDoc, ItemType, Purpose, RecordKey, RecordValue};
use zeroize::Zeroizing;

use crate::error::Result;
use crate::strength::{self, Strength};
use crate::vault::Vault;

/// "忽略这个条目的提醒"的属性名。值为 `off` 时不报告这个条目。
pub const ATTRIBUTE: &str = "security_alerts";
/// 多少天内到期算"即将过期"（已过期的也算）。
pub const EXPIRY_WINDOW_DAYS: i64 = 30;
/// 剩余少于这么多个未使用的恢复码时提醒。
pub const MIN_RECOVERY_CODES: usize = 3;
/// RSA 公钥少于这么多位时算过时。
pub const MIN_RSA_BITS: usize = 3072;
/// 0–1 分算弱密码。
pub const WEAK_SCORE: u8 = 1;

const TOTP_SITES: &str = include_str!("security/totp_sites.txt");

/// 一项检查。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Check {
    /// 弱密码。
    Weak,
    /// 重复使用。
    Reused,
    /// 已泄露（需要用户开启泄露检查）。
    Breached,
    /// 网站支持一次性密码，条目中却没有。
    MissingTotp,
    /// 即将过期或已过期。
    Expiring,
    /// 保存的网址是 `http://`。
    InsecureUrl,
    /// RSA 少于 3072 位、DSA。
    OutdatedSshKey,
    /// 恢复码不足。
    FewRecoveryCodes,
}

impl Check {
    /// 全部检查，按界面上的顺序。
    pub const ALL: [Self; 8] = [
        Self::Weak,
        Self::Reused,
        Self::Breached,
        Self::MissingTotp,
        Self::Expiring,
        Self::InsecureUrl,
        Self::OutdatedSshKey,
        Self::FewRecoveryCodes,
    ];

    /// 稳定的名称（供界面与 FFI）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Weak => "weak",
            Self::Reused => "reused",
            Self::Breached => "breached",
            Self::MissingTotp => "missing_totp",
            Self::Expiring => "expiring",
            Self::InsecureUrl => "insecure_url",
            Self::OutdatedSshKey => "outdated_ssh_key",
            Self::FewRecoveryCodes => "few_recovery_codes",
        }
    }
}

/// 一个问题的说明（不含秘密）。
#[derive(Debug, Clone, PartialEq)]
pub enum Detail {
    /// 弱密码。
    Weak(Strength),
    /// 与其他条目使用同一个密码。`group` 标识使用同一密码的一组条目。
    Reused {
        /// 组号（同一组的条目使用同一个密码）。
        group: usize,
        /// 同组的其他条目。
        others: Vec<Id128>,
    },
    /// 在已知泄露中出现的次数。
    Breached {
        /// 次数。
        count: u64,
    },
    /// 支持一次性密码的网站。
    MissingTotp {
        /// 匹配到的域名。
        domain: String,
    },
    /// 即将过期或已过期。
    Expiring {
        /// 字段名。
        label: String,
        /// 字段中的日期（原文）。
        date: String,
        /// 距今天数，负数表示已过期。
        days: i64,
    },
    /// `http://` 网址。
    InsecureUrl {
        /// 网址。
        url: String,
    },
    /// 过时的 SSH 密钥。
    OutdatedSshKey {
        /// 算法名（如 `ssh-rsa`）。
        algorithm: String,
        /// RSA 的位数。
        bits: Option<usize>,
    },
    /// 恢复码不足。
    FewRecoveryCodes {
        /// 剩余的未使用恢复码。
        remaining: usize,
    },
}

impl Detail {
    /// 所属的检查。
    #[must_use]
    pub const fn check(&self) -> Check {
        match self {
            Self::Weak(_) => Check::Weak,
            Self::Reused { .. } => Check::Reused,
            Self::Breached { .. } => Check::Breached,
            Self::MissingTotp { .. } => Check::MissingTotp,
            Self::Expiring { .. } => Check::Expiring,
            Self::InsecureUrl { .. } => Check::InsecureUrl,
            Self::OutdatedSshKey { .. } => Check::OutdatedSshKey,
            Self::FewRecoveryCodes { .. } => Check::FewRecoveryCodes,
        }
    }
}

/// 一个问题。
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    /// 条目。
    pub item_id: Id128,
    /// 说明。
    pub detail: Detail,
}

/// 一个条目的安全概况（条目详情的"安全"区）。
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ItemReport {
    /// 密码强度（条目有密码时）。
    pub strength: Option<Strength>,
    /// 这个条目的问题（即使被忽略也列出，界面据此说明）。
    pub findings: Vec<Detail>,
    /// 用户忽略了这个条目的提醒。
    pub ignored: bool,
}

/// 检查结果。
#[derive(Debug, Clone, Default)]
pub struct Report {
    /// 全部问题（被忽略的条目除外），按检查与条目排序。
    pub findings: Vec<Finding>,
    /// 每个条目的概况（包括被忽略的条目）。
    pub items: HashMap<Id128, ItemReport>,
    /// 泄露检查是否已对全部密码完成。
    pub breach_checked: bool,
}

impl Report {
    /// 有问题的条目数（侧边栏的数字）。
    #[must_use]
    pub fn affected_items(&self) -> usize {
        self.findings
            .iter()
            .map(|f| f.item_id)
            .collect::<HashSet<_>>()
            .len()
    }

    /// 弱密码的条目（搜索 `is:weak`）。
    #[must_use]
    pub fn weak_items(&self) -> HashSet<Id128> {
        self.findings
            .iter()
            .filter(|f| f.detail.check() == Check::Weak)
            .map(|f| f.item_id)
            .collect()
    }
}

/// 泄露检查的结果：用户开启后，界面层按前缀查询 Have I Been Pwned，这里在本机比对。
/// 完整的哈希不离开这里；结果只在内存中，锁定时随整个对象丢弃。
#[derive(Default)]
pub struct Breaches {
    /// 需要查询的密码的 SHA-1。
    wanted: HashSet<[u8; 20]>,
    /// 已查询的前缀。
    done: HashSet<String>,
    /// 出现过的密码 → 次数。
    counts: HashMap<[u8; 20], u64>,
}

impl Drop for Breaches {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for mut h in self.wanted.drain() {
            h.zeroize();
        }
        for (mut h, _) in self.counts.drain() {
            h.zeroize();
        }
    }
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

impl Breaches {
    /// 准备一次检查：记下全部密码的 SHA-1，返回要查询的前缀（5 个十六进制字符，去重排序）。
    ///
    /// # Errors
    /// 保险库已锁定或读取失败。
    pub fn prepare(&mut self, vault: &Vault) -> Result<Vec<String>> {
        let mut wanted = HashSet::new();
        for (_, doc) in live_items(vault)? {
            for password in passwords(&doc) {
                wanted.insert(*sha1_for_breach_check(password.as_bytes()));
            }
        }
        let mut prefixes: Vec<String> = wanted
            .iter()
            .map(|h| hex_upper(h.get(..3).unwrap_or_default()))
            .map(|p| p.chars().take(5).collect())
            .collect();
        prefixes.sort_unstable();
        prefixes.dedup();
        self.wanted = wanted;
        self.done.clear();
        self.counts.clear();
        Ok(prefixes)
    }

    /// 记下一个前缀的查询结果（Have I Been Pwned `range` 接口的响应正文：每行 `后缀:次数`，
    /// 开启填充时包含次数为 0 的假条目）。返回 `false` 表示格式不对。
    pub fn record(&mut self, prefix: &str, body: &str) -> bool {
        let prefix = prefix.to_ascii_uppercase();
        if prefix.len() != 5 || !prefix.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Some((suffix, count)) = line.split_once(':') else {
                return false;
            };
            let Ok(count) = count.trim().parse::<u64>() else {
                return false;
            };
            if suffix.len() != 35 || count == 0 {
                continue;
            }
            let full = format!("{prefix}{}", suffix.to_ascii_uppercase());
            let Some(hash) = unhex20(&full) else {
                continue;
            };
            if self.wanted.contains(&hash) {
                self.counts.insert(hash, count);
            }
        }
        self.done.insert(prefix);
        true
    }

    /// 是否已查询完全部前缀。
    #[must_use]
    pub fn complete(&self) -> bool {
        !self.wanted.is_empty()
            && self.wanted.iter().all(|h| {
                self.done.contains(
                    &hex_upper(h.get(..3).unwrap_or_default())
                        .chars()
                        .take(5)
                        .collect::<String>(),
                )
            })
    }

    fn count(&self, password: &str) -> Option<u64> {
        self.counts
            .get(&*sha1_for_breach_check(password.as_bytes()))
            .copied()
    }
}

fn unhex20(s: &str) -> Option<[u8; 20]> {
    let mut out = [0u8; 20];
    for (slot, pair) in out.iter_mut().zip(s.as_bytes().chunks_exact(2)) {
        *slot = u8::from_str_radix(core::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    (s.len() == 40).then_some(out)
}

/// 不在回收站、没有归档的条目，及其详情。
fn live_items(vault: &Vault) -> Result<Vec<(Id128, ItemDoc)>> {
    let mut out = Vec::new();
    for summary in vault.items()? {
        let o = &summary.overview;
        if o.trashed_at.is_some() || o.archived {
            continue;
        }
        let view = vault.item(summary.id)?;
        out.push((summary.id, view.doc));
    }
    Ok(out)
}

fn fields(doc: &ItemDoc) -> impl Iterator<Item = &keevo_format::FieldValue> {
    doc.records.iter().filter_map(|(k, v)| match (k, &v.value) {
        (RecordKey::Field(_), Some(RecordValue::Field(f))) => Some(f),
        _ => None,
    })
}

/// 条目中用途为"密码"的非空文本。
fn passwords(doc: &ItemDoc) -> Vec<Zeroizing<String>> {
    fields(doc)
        .filter(|f| f.purpose == Some(Purpose::Password))
        .filter_map(|f| {
            f.text()
                .filter(|t| !t.is_empty())
                .map(|t| Zeroizing::new(t.to_owned()))
        })
        .collect()
}

fn ignored(doc: &ItemDoc) -> bool {
    matches!(doc.get(&RecordKey::attr(ATTRIBUTE)), Some(RecordValue::Text(t)) if t.expose() == "off")
}

/// 检查全部条目。`breaches` 为用户开启泄露检查后的查询结果。
///
/// # Errors
/// 保险库已锁定或读取失败。
pub fn analyze(vault: &Vault, breaches: Option<&Breaches>) -> Result<Report> {
    analyze_at(vault, breaches, today())
}

fn analyze_at(vault: &Vault, breaches: Option<&Breaches>, today: i64) -> Result<Report> {
    let items = live_items(vault)?;
    let mut report = Report {
        breach_checked: breaches.is_some_and(Breaches::complete),
        ..Report::default()
    };
    // 重复使用：按密码的哈希分组，不保留明文
    let mut by_password: BTreeMap<[u8; 32], Vec<Id128>> = BTreeMap::new();
    for (id, doc) in &items {
        for p in passwords(doc) {
            let ids = by_password.entry(sha256(p.as_bytes())).or_default();
            if !ids.contains(id) {
                ids.push(*id);
            }
        }
    }
    let mut reused: HashMap<Id128, Detail> = HashMap::new();
    for (group, ids) in by_password.values().filter(|ids| ids.len() > 1).enumerate() {
        for id in ids {
            reused.entry(*id).or_insert_with(|| Detail::Reused {
                group,
                others: ids.iter().copied().filter(|o| o != id).collect(),
            });
        }
    }
    drop(by_password);

    for (id, doc) in &items {
        let mut entry = ItemReport {
            ignored: ignored(doc),
            ..ItemReport::default()
        };
        let pws = passwords(doc);
        // 强度取最弱的那个密码
        let weakest = pws.iter().map(|p| strength::estimate(p)).min_by(|a, b| {
            a.guesses
                .partial_cmp(&b.guesses)
                .unwrap_or(core::cmp::Ordering::Equal)
        });
        if let Some(s) = &weakest
            && s.score <= WEAK_SCORE
        {
            entry.findings.push(Detail::Weak(s.clone()));
        }
        entry.strength = weakest;
        if let Some(d) = reused.remove(id) {
            entry.findings.push(d);
        }
        if let Some(b) = breaches
            && let Some(count) = pws.iter().filter_map(|p| b.count(p)).max()
        {
            entry.findings.push(Detail::Breached { count });
        }
        entry.findings.extend(item_checks(doc, today));
        if !entry.ignored {
            for d in &entry.findings {
                report.findings.push(Finding {
                    item_id: *id,
                    detail: d.clone(),
                });
            }
        }
        report.items.insert(*id, entry);
    }
    report
        .findings
        .sort_by_key(|f| (f.detail.check(), f.item_id));
    Ok(report)
}

/// 不涉及其他条目的检查：两步验证、过期、网址、SSH 密钥、恢复码。
fn item_checks(doc: &ItemDoc, today: i64) -> Vec<Detail> {
    let mut out = Vec::new();
    let urls: Vec<String> = fields(doc)
        .filter(|f| f.kind == FieldKind::Url)
        .filter_map(|f| f.text().map(str::to_owned))
        .collect();
    if doc.item_type == ItemType::Login {
        let has_totp = fields(doc)
            .any(|f| f.kind == FieldKind::Totp && f.text().is_some_and(|t| !t.trim().is_empty()));
        if !has_totp && let Some(domain) = urls.iter().find_map(|u| totp_domain(u)) {
            out.push(Detail::MissingTotp { domain });
        }
    }
    if let Some(url) = urls.iter().find(|u| insecure(u)) {
        out.push(Detail::InsecureUrl { url: url.clone() });
    }
    for f in fields(doc) {
        match (&f.kind, &f.data) {
            (FieldKind::Date, FieldData::Text(t)) if is_expiry_label(&f.label) => {
                if let Some(day) = parse_date(t.expose()) {
                    let days = day.saturating_sub(today);
                    if days <= EXPIRY_WINDOW_DAYS {
                        out.push(Detail::Expiring {
                            label: f.label.clone(),
                            date: t.expose().trim().to_owned(),
                            days,
                        });
                    }
                }
            }
            (FieldKind::RecoveryCodes, FieldData::Codes(codes)) if !codes.is_empty() => {
                let remaining = codes.iter().filter(|c| !c.used).count();
                if remaining < MIN_RECOVERY_CODES {
                    out.push(Detail::FewRecoveryCodes { remaining });
                }
            }
            _ => {}
        }
    }
    if doc.item_type == ItemType::SshKey
        && let Some(d) = fields(doc).find_map(|f| f.text().and_then(outdated_ssh_key))
    {
        out.push(d);
    }
    out
}

fn is_expiry_label(label: &str) -> bool {
    let l = label.to_lowercase();
    ["过期", "到期", "有效期", "expir", "valid until"]
        .iter()
        .any(|k| l.contains(k))
}

/// 网址的主机名（小写）与协议。
pub(crate) fn host_of(url: &str) -> Option<(String, String)> {
    let url = url.trim();
    let (scheme, rest) = url.split_once("://").unwrap_or(("https", url));
    let authority = rest.split(['/', '?', '#']).next()?;
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(stripped) = host_port.strip_prefix('[') {
        stripped.split(']').next()?.to_owned()
    } else {
        host_port.split(':').next()?.to_owned()
    };
    (!host.is_empty()).then(|| (scheme.to_ascii_lowercase(), host.to_ascii_lowercase()))
}

fn totp_sites() -> &'static HashSet<&'static str> {
    static SITES: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SITES.get_or_init(|| TOTP_SITES.lines().filter(|l| !l.is_empty()).collect())
}

/// 网址的主机（或它的某个上级域名）是否在支持一次性密码的网站列表中。
fn totp_domain(url: &str) -> Option<String> {
    let (_, host) = host_of(url)?;
    let sites = totp_sites();
    let mut candidate = host.as_str();
    loop {
        if sites.contains(candidate) {
            return Some(candidate.to_owned());
        }
        candidate = candidate.split_once('.')?.1;
        if !candidate.contains('.') {
            return None;
        }
    }
}

/// `http://` 网址，本机与内网地址除外（本地开发很常见，也不经过公网）。
fn insecure(url: &str) -> bool {
    let Some((scheme, host)) = host_of(url) else {
        return false;
    };
    if scheme != "http" {
        return false;
    }
    let local_name = host == "localhost"
        || [".localhost", ".local", ".lan", ".internal", ".home.arpa"]
            .iter()
            .any(|s| host.ends_with(s));
    let private_ip = match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        Ok(std::net::IpAddr::V6(v6)) => {
            v6.is_loopback() || (v6.segments().first().is_some_and(|s| s & 0xfe00 == 0xfc00))
        }
        Err(_) => false,
    };
    !(local_name || private_ip)
}

/// 日期字段的文本：`2026-11-19`、`2026/11/19`、`2026.11.19`、`2026年11月19日`。返回自 1970-01-01 起的天数。
fn parse_date(text: &str) -> Option<i64> {
    let digits: Vec<&str> = text
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .collect();
    let [y, m, d] = digits.as_slice() else {
        return None;
    };
    let (y, m, d): (i64, i64, i64) = (y.parse().ok()?, m.parse().ok()?, d.parse().ok()?);
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some(days_from_civil(y, m, d))
}

/// 公历日期 → 自 1970-01-01 起的天数（Howard Hinnant 的算法）。
#[allow(
    clippy::arithmetic_side_effects,
    reason = "年份已限制在 1970–9999，不会溢出"
)]
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn today() -> i64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    i64::try_from(secs / 86_400).unwrap_or(0)
}

/// 公钥行（`ssh-rsa AAAA… 注释`）是否为过时的 SSH 密钥：DSA，或少于 3072 位的 RSA。
fn outdated_ssh_key(line: &str) -> Option<Detail> {
    use base64::Engine as _;
    let mut parts = line.split_whitespace();
    let alg = parts.next()?;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(parts.next()?)
        .ok()?;
    match alg {
        "ssh-dss" => Some(Detail::OutdatedSshKey {
            algorithm: alg.to_owned(),
            bits: None,
        }),
        "ssh-rsa" => {
            // blob：string "ssh-rsa"、mpint e、mpint n
            let mut rest = blob.as_slice();
            let mut take = || -> Option<&[u8]> {
                let len =
                    usize::try_from(u32::from_be_bytes(rest.get(..4)?.try_into().ok()?)).ok()?;
                let (head, tail) = rest.get(4..)?.split_at_checked(len)?;
                rest = tail;
                Some(head)
            };
            if take()? != b"ssh-rsa" {
                return None;
            }
            let _e = take()?;
            let n = take()?;
            let n = n
                .iter()
                .skip_while(|b| **b == 0)
                .copied()
                .collect::<Vec<u8>>();
            let first = *n.first()?;
            let bits = n.len().saturating_sub(1).saturating_mul(8).saturating_add(
                8usize.saturating_sub(usize::try_from(first.leading_zeros()).unwrap_or(0)),
            );
            (bits < MIN_RSA_BITS).then(|| Detail::OutdatedSshKey {
                algorithm: alg.to_owned(),
                bits: Some(bits),
            })
        }
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn dates_and_expiry_labels() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2026, 11, 19), 20_776);
        assert_eq!(parse_date("2026-11-19"), Some(20_776));
        assert_eq!(parse_date("2026年11月19日"), Some(20_776));
        assert_eq!(parse_date("2026/1/2"), Some(days_from_civil(2026, 1, 2)));
        assert_eq!(parse_date("明天"), None);
        assert_eq!(parse_date("2026-13-01"), None);
        assert!(
            is_expiry_label("过期时间")
                && is_expiry_label("Expires")
                && !is_expiry_label("签发时间")
        );
    }

    #[test]
    fn urls() {
        assert!(insecure("http://forum.example.com/login"));
        assert!(!insecure("https://forum.example.com/"));
        for local in [
            "http://localhost:3000",
            "http://127.0.0.1:8080",
            "http://192.168.1.1",
            "http://nas.local",
            "http://[::1]:8000",
        ] {
            assert!(!insecure(local), "{local}");
        }
        assert_eq!(
            totp_domain("https://github.com/login").as_deref(),
            Some("github.com")
        );
        assert_eq!(
            totp_domain("https://gist.github.com/").as_deref(),
            Some("github.com")
        );
        assert_eq!(totp_domain("https://no-2fa.example/"), None);
    }

    #[test]
    fn rsa_key_size() {
        // ssh-keygen -t rsa -b 2048 生成的公钥（测试数据，见 keevo-ssh 的 testdata）
        let short = include_str!("../../keevo-ssh/src/testdata/rsa-aes256-ctr.pub");
        assert_eq!(
            outdated_ssh_key(short),
            Some(Detail::OutdatedSshKey {
                algorithm: "ssh-rsa".into(),
                bits: Some(2048)
            })
        );
        assert_eq!(
            outdated_ssh_key(
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO9fhNi5eNgkx390VfLRbowBEnQAcpHN6we/lRG6ehH6"
            ),
            None
        );
    }

    /// 一个保险库中的各种问题：每项检查都能发现，忽略的条目不出现在结果中，概况仍然给出。
    #[test]
    fn analyzes_a_vault() {
        use crate::vault::{Edit, NewField};
        use keevo_crypto::KdfParams;
        use keevo_format::CodeEntry;
        let params = KdfParams::new(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1, [5; 16]).unwrap();
        let (mut v, _) =
            Vault::create_with_store(keevo_store::Store::open_in_memory().unwrap(), "pw", params)
                .unwrap();
        let vault_id = v.vaults().unwrap()[0].id;
        let text = |kind, label: &str, purpose, value: &str| NewField {
            kind,
            label: label.into(),
            purpose,
            data: FieldData::Text(value.into()),
        };
        let login = |v: &mut Vault, title: &str, url: &str, pw: &str| {
            v.create_item(
                vault_id,
                ItemType::Login,
                title,
                vec![
                    text(FieldKind::Text, "用户名", Some(Purpose::Username), "me"),
                    text(FieldKind::Concealed, "密码", Some(Purpose::Password), pw),
                    text(FieldKind::Url, "网站", None, url),
                ],
            )
            .unwrap()
        };
        let strong = "V.uwt*^H:tGdt~5bJWXO";
        let weak = login(&mut v, "论坛", "http://forum.example.com", "password1");
        let reused_a = login(&mut v, "阿里云", "https://account.aliyun.com", strong);
        let reused_b = login(&mut v, "Figma", "https://figma.example", strong);
        let ok = login(
            &mut v,
            "银行",
            "https://bank.example",
            "Wq7#kd.Rz2!mTx9e:Hp4",
        );
        let ignored_id = login(&mut v, "旧账户", "http://old.example", "123456");
        v.update_item(ignored_id, vec![Edit::SetSecurityAlerts(false)])
            .unwrap();
        let token = v
            .create_item(
                vault_id,
                ItemType::ApiCredential,
                "旧令牌",
                vec![text(FieldKind::Date, "过期时间", None, "2026-11-25")],
            )
            .unwrap();
        let codes = v
            .create_item(
                vault_id,
                ItemType::TwoFactor,
                "恢复码",
                vec![NewField {
                    kind: FieldKind::RecoveryCodes,
                    label: "恢复码".into(),
                    purpose: None,
                    data: FieldData::Codes(vec![
                        CodeEntry {
                            code: "a".into(),
                            used: true,
                        },
                        CodeEntry {
                            code: "b".into(),
                            used: false,
                        },
                    ]),
                }],
            )
            .unwrap();
        let ssh = v
            .create_item(
                vault_id,
                ItemType::SshKey,
                "旧 SSH 密钥",
                vec![text(
                    FieldKind::Multiline,
                    "公钥",
                    None,
                    include_str!("../../keevo-ssh/src/testdata/rsa-aes256-ctr.pub"),
                )],
            )
            .unwrap();

        let report = analyze_at(&v, None, days_from_civil(2026, 11, 19)).unwrap();
        let of = |id: Id128| -> Vec<Check> {
            let mut c: Vec<Check> = report
                .findings
                .iter()
                .filter(|f| f.item_id == id)
                .map(|f| f.detail.check())
                .collect();
            c.sort();
            c
        };
        assert_eq!(of(weak), [Check::Weak, Check::InsecureUrl]);
        assert_eq!(
            of(reused_a),
            [Check::Reused, Check::MissingTotp],
            "阿里云支持一次性密码"
        );
        assert_eq!(of(reused_b), [Check::Reused]);
        assert_eq!(of(ok), []);
        assert_eq!(of(token), [Check::Expiring]);
        assert_eq!(of(codes), [Check::FewRecoveryCodes]);
        assert_eq!(of(ssh), [Check::OutdatedSshKey]);
        assert_eq!(of(ignored_id), [], "忽略的条目不报告");
        let ig = &report.items[&ignored_id];
        assert!(ig.ignored && !ig.findings.is_empty(), "概况中仍然列出");
        assert_eq!(report.affected_items(), 6);
        assert_eq!(report.weak_items(), HashSet::from([weak]));
        assert_eq!(report.items[&ok].strength.as_ref().unwrap().score, 4);
        let Some(Detail::Reused { others, .. }) = report.items[&reused_a]
            .findings
            .iter()
            .find(|d| d.check() == Check::Reused)
        else {
            panic!()
        };
        assert_eq!(others, &[reused_b]);
        let Some(Detail::Expiring { days, .. }) = report.items[&token].findings.first() else {
            panic!()
        };
        assert_eq!(*days, 6);
        assert!(!report.breach_checked);

        // 泄露检查：准备前缀，记录响应后，弱密码被标为已泄露
        let mut b = Breaches::default();
        let prefixes = b.prepare(&v).unwrap();
        assert_eq!(prefixes.len(), 4, "4 个不同的密码");
        let hash = hex_upper(&*sha1_for_breach_check(b"password1"));
        for p in &prefixes {
            let body = if hash.starts_with(p.as_str()) {
                format!("{}:2427", &hash[5..])
            } else {
                String::new()
            };
            assert!(b.record(p, &body));
        }
        let report = analyze_at(&v, Some(&b), days_from_civil(2026, 11, 19)).unwrap();
        assert!(report.breach_checked);
        assert!(
            report.items[&weak]
                .findings
                .contains(&Detail::Breached { count: 2427 })
        );
    }

    #[test]
    fn breach_ranges_are_matched_locally() {
        let mut b = Breaches::default();
        let hash = *sha1_for_breach_check(b"password");
        b.wanted.insert(hash);
        let hex = hex_upper(&hash);
        assert_eq!(&hex[..5], "5BAA6");
        let body = format!(
            "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n{}:9545824\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0\r\n",
            &hex[5..]
        );
        assert!(b.record("5baa6", &body));
        assert!(b.complete());
        assert_eq!(b.count("password"), Some(9_545_824));
        assert_eq!(b.count("other"), None);
        assert!(!b.record("XYZ", ""));
        assert!(!b.record("5BAA6", "garbage"));
    }
}
