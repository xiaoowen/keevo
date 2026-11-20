//! 安全中心（`docs/product.md` §5.6，设计稿"macOS · 安全中心"）：检查结果、条目的安全概况、泄露检查。
//!
//! 检查在调用方的后台线程中进行（[`KeevoVault::run_security_check`]），结果缓存在内存中，锁定时丢弃。
//! 泄露检查只在用户开启后进行：这里给出要查询的 SHA-1 前缀，网络请求由 Swift 发起，响应交回这里在本机比对，
//! 完整的哈希与密码都不离开 Rust。

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use keevo_core::security::{self, Breaches, Check, Detail, Report};
use keevo_core::strength::{self, Strength, Warning};

use crate::{KeevoError, KeevoVault, parse_id};

/// 安全中心的内存状态。
#[derive(Default)]
pub(crate) struct SecurityState {
    report: Option<(Report, u64)>,
    breaches: Option<Breaches>,
}

impl SecurityState {
    pub(crate) fn weak_items(&self) -> HashSet<keevo_core::Id128> {
        self.report
            .as_ref()
            .map(|(r, _)| r.weak_items())
            .unwrap_or_default()
    }
}

/// 密码强度（`keevo-core::strength`，与 zxcvbn 等价）。
#[derive(uniffi::Record, Debug, Clone, PartialEq)]
pub struct PasswordStrengthInfo {
    /// 0（很弱）到 4（很强）。
    pub score: u8,
    /// 约多少比特熵（log₂ 猜测次数）。
    pub bits: f64,
    /// 主要问题：`top10`、`top100`、`very_common`、`similar_to_common`、`single_word`、`name`、`common_name`、
    /// `keyboard_row`、`keyboard_pattern`、`repeated_character`、`repeated_pattern`、`sequence`、`recent_year`、`date`。
    pub warning: Option<String>,
    /// `similar_to_common` 时为原词。
    pub warning_detail: Option<String>,
}

pub(crate) fn strength_info(s: &Strength) -> PasswordStrengthInfo {
    let (warning, detail) = match &s.warning {
        None => (None, None),
        Some(w) => {
            let (code, detail) = match w {
                Warning::Top10 => ("top10", None),
                Warning::Top100 => ("top100", None),
                Warning::VeryCommon => ("very_common", None),
                Warning::SimilarToCommon(word) => ("similar_to_common", Some(word.clone())),
                Warning::SingleWord => ("single_word", None),
                Warning::NameByItself => ("name", None),
                Warning::CommonName => ("common_name", None),
                Warning::KeyboardRow => ("keyboard_row", None),
                Warning::KeyboardPattern => ("keyboard_pattern", None),
                Warning::RepeatedCharacter => ("repeated_character", None),
                Warning::RepeatedPattern => ("repeated_pattern", None),
                Warning::Sequence => ("sequence", None),
                Warning::RecentYear => ("recent_year", None),
                Warning::Date => ("date", None),
            };
            (Some(code.to_owned()), detail)
        }
    };
    PasswordStrengthInfo {
        score: s.score,
        bits: s.bits(),
        warning,
        warning_detail: detail,
    }
}

/// 评估一个密码的强度（主密码、生成器、编辑器中的实时反馈）。不需要解锁，不涉及存储。
#[uniffi::export]
#[must_use]
pub fn password_strength(password: String) -> PasswordStrengthInfo {
    let password = zeroize::Zeroizing::new(password);
    strength_info(&strength::estimate(&password))
}

/// 一个问题。
#[derive(uniffi::Record, Debug, Clone, PartialEq)]
pub struct SecurityFinding {
    /// 条目 ID。
    pub item_id: String,
    /// 条目标题。
    pub title: String,
    /// 条目副标题（通常是用户名）。
    pub subtitle: String,
    /// 检查：`weak`、`reused`、`breached`、`missing_totp`、`expiring`、`insecure_url`、`outdated_ssh_key`、
    /// `few_recovery_codes`。
    pub check: String,
    /// 重复使用：组号（同一组使用同一个密码）。
    pub group: u32,
    /// 数值：弱密码为分数，已泄露为次数，即将过期为剩余天数（负数为已过期），过时的 SSH 密钥为位数（DSA 为 0），
    /// 恢复码不足为剩余个数，重复使用为同组的条目数。
    pub number: i64,
    /// 文字：弱密码为问题代码，未开启两步验证为域名，即将过期为"字段名 日期"，不安全的网址为网址，
    /// 过时的 SSH 密钥为算法名。
    pub text: String,
    /// 补充：弱密码为 `similar_to_common` 时的原词。
    pub extra: String,
}

/// 检查结果。
#[derive(uniffi::Record, Debug, Clone, PartialEq)]
pub struct SecurityReport {
    /// 全部问题（被忽略的条目除外）。
    pub findings: Vec<SecurityFinding>,
    /// 有问题的条目数。
    pub affected_items: u32,
    /// 泄露检查是否已完成。
    pub breach_checked: bool,
    /// 检查时间（Unix 毫秒）。
    pub checked_at_ms: u64,
}

/// 条目详情的"安全"区。
#[derive(uniffi::Record, Debug, Clone, PartialEq)]
pub struct ItemSecurity {
    /// 密码强度（条目有密码时）。
    pub strength: Option<PasswordStrengthInfo>,
    /// 与哪些条目使用同一个密码（标题）。
    pub reused_with: Vec<String>,
    /// 在已知泄露中出现的次数；没有检查时为 `None`，检查过且没有出现时为 0。
    pub breach_count: Option<u64>,
    /// 支持一次性密码、而条目中没有时，为匹配到的域名。
    pub totp_domain: Option<String>,
    /// 其他问题（即将过期、不安全的网址、过时的 SSH 密钥、恢复码不足）。
    pub others: Vec<SecurityFinding>,
    /// 用户忽略了这个条目的提醒。
    pub ignored: bool,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn finding(
    item_id: keevo_core::Id128,
    detail: &Detail,
    titles: &HashMap<keevo_core::Id128, (String, String)>,
) -> SecurityFinding {
    let (title, subtitle) = titles.get(&item_id).cloned().unwrap_or_default();
    let mut extra = String::new();
    let (group, number, text) = match detail {
        Detail::Weak(s) => {
            let info = strength_info(s);
            extra = info.warning_detail.unwrap_or_default();
            (0, i64::from(s.score), info.warning.unwrap_or_default())
        }
        Detail::Reused { group, others } => (
            u32::try_from(*group).unwrap_or(u32::MAX),
            i64::try_from(others.len().saturating_add(1)).unwrap_or(i64::MAX),
            String::new(),
        ),
        Detail::Breached { count } => (0, i64::try_from(*count).unwrap_or(i64::MAX), String::new()),
        Detail::MissingTotp { domain } => (0, 0, domain.clone()),
        Detail::Expiring { label, date, days } => (0, *days, format!("{label} {date}")),
        Detail::InsecureUrl { url } => (0, 0, url.clone()),
        Detail::OutdatedSshKey { algorithm, bits } => (
            0,
            bits.map_or(0, |b| i64::try_from(b).unwrap_or(i64::MAX)),
            algorithm.clone(),
        ),
        Detail::FewRecoveryCodes { remaining } => (
            0,
            i64::try_from(*remaining).unwrap_or(i64::MAX),
            String::new(),
        ),
    };
    SecurityFinding {
        item_id: item_id.to_hex(),
        title,
        subtitle,
        check: detail.check().as_str().to_owned(),
        group,
        number,
        text,
        extra,
    }
}

impl KeevoVault {
    fn titles(&self) -> Result<HashMap<keevo_core::Id128, (String, String)>, KeevoError> {
        Ok(self
            .vault()
            .items()?
            .into_iter()
            .map(|i| (i.id, (i.overview.title, i.overview.subtitle)))
            .collect())
    }

    fn report_info(
        &self,
        report: &Report,
        checked_at_ms: u64,
    ) -> Result<SecurityReport, KeevoError> {
        let titles = self.titles()?;
        Ok(SecurityReport {
            findings: report
                .findings
                .iter()
                .map(|f| finding(f.item_id, &f.detail, &titles))
                .collect(),
            affected_items: u32::try_from(report.affected_items()).unwrap_or(u32::MAX),
            breach_checked: report.breach_checked,
            checked_at_ms,
        })
    }
}

#[uniffi::export]
impl KeevoVault {
    /// 检查全部条目（在后台线程中调用；一万个条目约需一秒）。结果缓存到锁定为止，并用于搜索 `is:weak`。
    ///
    /// # Errors
    /// 已锁定时返回 [`KeevoError::Locked`]。
    pub fn run_security_check(&self) -> Result<SecurityReport, KeevoError> {
        let report = {
            let vault = self.vault();
            let state = self.security_state();
            security::analyze(&vault, state.breaches.as_ref())?
        };
        let checked_at = now_ms();
        let info = self.report_info(&report, checked_at)?;
        let weak = report.weak_items();
        self.security_state().report = Some((report, checked_at));
        if let Some(ix) = self.index().as_mut() {
            ix.set_weak(&weak);
        }
        Ok(info)
    }

    /// 最近一次检查的结果；还没有检查时为 `None`。
    ///
    /// # Errors
    /// 已锁定时返回 [`KeevoError::Locked`]。
    pub fn security_report(&self) -> Result<Option<SecurityReport>, KeevoError> {
        let cached = self
            .security_state()
            .report
            .as_ref()
            .map(|(r, t)| (r.clone(), *t));
        cached.map(|(r, t)| self.report_info(&r, t)).transpose()
    }

    /// 条目详情的"安全"区，取自最近一次检查；还没有检查、或条目是之后新建的，为 `None`。
    ///
    /// # Errors
    /// 条目 ID 无效或已锁定。
    pub fn item_security(&self, item_id: String) -> Result<Option<ItemSecurity>, KeevoError> {
        let id = parse_id(&item_id)?;
        let titles = self.titles()?;
        let state = self.security_state();
        let Some((report, _)) = state.report.as_ref() else {
            return Ok(None);
        };
        let Some(item) = report.items.get(&id) else {
            return Ok(None);
        };
        let mut info = ItemSecurity {
            strength: item.strength.as_ref().map(strength_info),
            reused_with: Vec::new(),
            // 只有这个条目现在的密码都查过，才能说"没有出现在泄露中"（第五轮评审 L7）
            breach_count: item.breach_checked.then_some(0),
            totp_domain: None,
            others: Vec::new(),
            ignored: item.ignored,
        };
        for d in &item.findings {
            match d {
                Detail::Weak(_) => {}
                Detail::Reused { others, .. } => {
                    info.reused_with = others
                        .iter()
                        .filter_map(|o| titles.get(o).map(|(t, _)| t.clone()))
                        .collect();
                }
                Detail::Breached { count } => info.breach_count = Some(*count),
                Detail::MissingTotp { domain } => info.totp_domain = Some(domain.clone()),
                other => info.others.push(finding(id, other, &titles)),
            }
        }
        Ok(Some(info))
    }

    /// 安全中心是否报告这个条目（"忽略这个条目的提醒"）。之后需要重新检查。
    ///
    /// # Errors
    /// 条目不存在或已锁定。
    pub fn set_security_alerts(&self, item_id: String, enabled: bool) -> Result<(), KeevoError> {
        let id = parse_id(&item_id)?;
        self.vault()
            .update_item(id, vec![keevo_core::Edit::SetSecurityAlerts(enabled)])?;
        Ok(())
    }

    /// 开始一次泄露检查（用户已开启）：返回要向 Have I Been Pwned 查询的 SHA-1 前缀（每个 5 个十六进制字符）。
    ///
    /// # Errors
    /// 已锁定时返回 [`KeevoError::Locked`]。
    pub fn prepare_breach_check(&self) -> Result<Vec<String>, KeevoError> {
        let mut breaches = Breaches::default();
        let prefixes = breaches.prepare(&self.vault())?;
        self.security_state().breaches = Some(breaches);
        Ok(prefixes)
    }

    /// 记下一个前缀的查询结果（`range` 接口的响应正文）。返回 `false` 表示格式不对，或还没有开始检查。
    pub fn record_breach_range(&self, prefix: String, body: String) -> bool {
        self.security_state()
            .breaches
            .as_mut()
            .is_some_and(|b| b.record(&prefix, &body))
    }

    /// 关闭泄露检查：丢弃全部结果。
    pub fn clear_breach_results(&self) {
        self.security_state().breaches = None;
    }
}

/// 检查的名称（供界面列出全部 8 项）。
#[uniffi::export]
#[must_use]
pub fn security_checks() -> Vec<String> {
    Check::ALL.iter().map(|c| c.as_str().to_owned()).collect()
}
