//! 导入（`docs/product.md` §5.7，设计稿"macOS · 导入与导出"）：1Password（1PUX）、Bitwarden（JSON，
//! 可以有密码保护）、Chrome / Safari / Firefox / LastPass（CSV）与 Keevo 自己的导出文件。
//!
//! 流程：[`parse`] 把文件解析为 [`Imported`] 列表（不写入任何东西）→ [`duplicates`] 标出与保险库中已有
//! 登录完全相同的条目 → [`crate::Vault::import_items`] 在一个事务中写入（失败时什么都不写）。
//! 文件来自外部，一律当作不可信输入：有大小上限，解析失败返回 [`ImportError`]，绝不 panic。
//!
//! 不能直接对应的类别（银行卡、身份等）作为安全笔记导入，字段逐个保留，并记下原来的类别
//! （[`Imported::original`]）。文件夹变成标签，收藏与一次性密码保留。附件暂不导入，在备注中说明。

mod bitwarden;
mod browsers;
pub(crate) mod csv;
pub(crate) mod keevo;
mod onepux;
pub mod zip;

use std::collections::HashSet;

use keevo_format::{FieldData, FieldKind, ItemType, Purpose, SecretString};
use zeroize::Zeroizing;

use crate::error::Result;
use crate::vault::{NewField, Vault};

/// 导入文件的大小上限：512 MiB（1PUX 中可能有附件）。
pub const MAX_FILE_LEN: usize = 512 * 1024 * 1024;
/// 条目数上限。
pub const MAX_ITEMS: usize = 50_000;
/// 一个条目的字段数上限（`spec/revisions.md` §7.1 的记录键上限为 4096）。
const MAX_FIELDS: usize = 1000;
/// 文本值的长度上限（`keevo_format` 的单个值上限）。
const MAX_TEXT: usize = 256 * 1024;
const MAX_LABEL: usize = 200;
const MAX_TAG: usize = 256;

/// 导入来源。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Keevo 的导出文件（加密或明文 JSON）。
    Keevo,
    /// 1Password 的 1PUX。
    OnePassword,
    /// Bitwarden 的 JSON。
    Bitwarden,
    /// Chrome 的 CSV。
    Chrome,
    /// Safari 的 CSV。
    Safari,
    /// Firefox 的 CSV。
    Firefox,
    /// LastPass 的 CSV。
    LastPass,
}

impl Source {
    /// 全部来源。
    pub const ALL: [Self; 7] = [
        Self::Keevo,
        Self::OnePassword,
        Self::Bitwarden,
        Self::Chrome,
        Self::Safari,
        Self::Firefox,
        Self::LastPass,
    ];

    /// 标识。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Keevo => "keevo",
            Self::OnePassword => "1password",
            Self::Bitwarden => "bitwarden",
            Self::Chrome => "chrome",
            Self::Safari => "safari",
            Self::Firefox => "firefox",
            Self::LastPass => "lastpass",
        }
    }

    /// 由标识解析。
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|x| x.as_str() == s)
    }

    /// 显示名（产品名，不翻译）。
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Keevo => "Keevo",
            Self::OnePassword => "1Password",
            Self::Bitwarden => "Bitwarden",
            Self::Chrome => "Chrome",
            Self::Safari => "Safari",
            Self::Firefox => "Firefox",
            Self::LastPass => "LastPass",
        }
    }
}

/// 导入失败的原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportError {
    /// 不是所选来源的导出文件。
    NotRecognized,
    /// 文件有密码保护，需要导出时设置的密码。
    PasswordRequired,
    /// 密码不正确。
    WrongPassword,
    /// Bitwarden 的"账户限制"加密导出：只能由原来的 Bitwarden 账户解密。
    AccountRestricted,
    /// 文件或内容过大。
    TooLarge,
    /// 文件损坏或不完整。
    Malformed,
    /// 文件中没有可以导入的条目。
    Empty,
}

impl ImportError {
    /// 原因代码。
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotRecognized => "not_recognized",
            Self::PasswordRequired => "password_required",
            Self::WrongPassword => "wrong_password",
            Self::AccountRestricted => "account_restricted",
            Self::TooLarge => "too_large",
            Self::Malformed => "malformed",
            Self::Empty => "empty",
        }
    }
}

/// 解析出的一个条目（尚未写入）。
#[derive(Debug, Clone)]
pub struct Imported {
    /// Keevo 中的类型。
    pub item_type: ItemType,
    /// 原来的类别，作为安全笔记导入时记下（如 `credit_card`、`identity`）。
    pub original: Option<&'static str>,
    /// 标题。
    pub title: String,
    /// 分区名称。
    pub sections: Vec<String>,
    /// 字段与所在分区（下标指向 `sections`）。
    pub fields: Vec<(Option<usize>, NewField)>,
    /// 标签（文件夹、原来的标签）。
    pub tags: Vec<String>,
    /// 收藏。
    pub favorite: bool,
    /// 原文件中附件的个数（暂不导入）。
    pub attachments: usize,
}

impl Imported {
    fn text_of(&self, purpose: Purpose) -> Option<&str> {
        self.fields.iter().find_map(|(_, f)| match &f.data {
            FieldData::Text(t) if f.purpose == Some(purpose) && !t.expose().is_empty() => {
                Some(t.expose())
            }
            _ => None,
        })
    }

    fn first_url(&self) -> Option<&str> {
        self.fields.iter().find_map(|(_, f)| match &f.data {
            FieldData::Text(t) if f.kind == FieldKind::Url && !t.expose().is_empty() => {
                Some(t.expose())
            }
            _ => None,
        })
    }
}

/// 解析结果。
#[derive(Debug, Default)]
pub struct Parsed {
    /// 条目，按文件中的顺序。
    pub items: Vec<Imported>,
}

/// 解析导入文件。`password` 为有密码保护的文件（Bitwarden、Keevo 加密导出）的密码。
///
/// # Errors
/// 见 [`ImportError`]。
pub fn parse(
    source: Source,
    data: &[u8],
    password: Option<&str>,
) -> core::result::Result<Parsed, ImportError> {
    if data.len() > MAX_FILE_LEN {
        return Err(ImportError::TooLarge);
    }
    let parsed = match source {
        Source::Keevo => keevo::parse(data, password)?,
        Source::OnePassword => onepux::parse(data)?,
        Source::Bitwarden => bitwarden::parse(data, password)?,
        Source::Chrome | Source::Safari | Source::Firefox | Source::LastPass => {
            browsers::parse(source, data)?
        }
    };
    if parsed.items.is_empty() {
        return Err(ImportError::Empty);
    }
    if parsed.items.len() > MAX_ITEMS {
        return Err(ImportError::TooLarge);
    }
    Ok(parsed)
}

/// 登录的指纹：网址的主机、用户名、密码。三者相同即视为"完全相同"。只在内存中短暂存在。
fn fingerprint(host: &str, username: &str, password: &str) -> [u8; 32] {
    let mut buf = Zeroizing::new(Vec::with_capacity(
        host.len()
            .saturating_add(username.len())
            .saturating_add(password.len())
            .saturating_add(2),
    ));
    buf.extend_from_slice(host.as_bytes());
    buf.push(0);
    buf.extend_from_slice(username.as_bytes());
    buf.push(0);
    buf.extend_from_slice(password.as_bytes());
    keevo_crypto::sha256(&buf)
}

fn login_fingerprint(
    url: Option<&str>,
    username: Option<&str>,
    password: Option<&str>,
) -> Option<[u8; 32]> {
    let password = password.filter(|p| !p.is_empty())?;
    let host = url
        .and_then(crate::security::host_of)
        .map(|(_, h)| h.trim_start_matches("www.").to_owned())
        .unwrap_or_default();
    Some(fingerprint(&host, username.unwrap_or_default(), password))
}

/// 每个条目是否与保险库中已有的登录（不含最近删除）完全相同：网址主机、用户名与密码都相同。
///
/// # Errors
/// 已锁定或读取失败。
pub fn duplicates(vault: &Vault, items: &[Imported]) -> Result<Vec<bool>> {
    let mut existing = HashSet::new();
    for summary in vault.items()? {
        if summary.overview.item_type != ItemType::Login || summary.overview.trashed_at.is_some() {
            continue;
        }
        let view = vault.item(summary.id)?;
        let fields: Vec<&keevo_format::FieldValue> = view
            .doc
            .records
            .values()
            .filter_map(|v| match &v.value {
                Some(keevo_format::RecordValue::Field(f)) => Some(f),
                _ => None,
            })
            .collect();
        let text = |pred: &dyn Fn(&keevo_format::FieldValue) -> bool| {
            fields
                .iter()
                .filter(|f| pred(f))
                .find_map(|f| f.text().filter(|t| !t.is_empty()))
        };
        let username = text(&|f| f.purpose == Some(Purpose::Username));
        let password = text(&|f| f.purpose == Some(Purpose::Password));
        let urls: Vec<&str> = fields
            .iter()
            .filter(|f| f.kind == FieldKind::Url)
            .filter_map(|f| f.text())
            .collect();
        if urls.is_empty() {
            existing.extend(login_fingerprint(None, username, password));
        }
        for url in urls {
            existing.extend(login_fingerprint(Some(url), username, password));
        }
    }
    Ok(items
        .iter()
        .map(|i| {
            i.item_type == ItemType::Login
                && login_fingerprint(
                    i.first_url(),
                    i.text_of(Purpose::Username),
                    i.text_of(Purpose::Password),
                )
                .is_some_and(|f| existing.contains(&f))
        })
        .collect())
}

/// 截断到 `max` 字节（字符边界）。
fn clip(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_owned();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    s.get(..end).unwrap_or_default().to_owned()
}

/// 逐步构造一个 [`Imported`]。空值不生成字段。
pub(crate) struct Builder {
    item: Imported,
    notes: Vec<String>,
}

impl Builder {
    pub(crate) fn new(item_type: ItemType, title: &str) -> Self {
        Self {
            item: Imported {
                item_type,
                original: None,
                title: clip(title.trim(), MAX_LABEL),
                sections: Vec::new(),
                fields: Vec::new(),
                tags: Vec::new(),
                favorite: false,
                attachments: 0,
            },
            notes: Vec::new(),
        }
    }

    /// 作为安全笔记导入的原类别。
    pub(crate) const fn original(mut self, code: &'static str) -> Self {
        self.item.original = Some(code);
        self
    }

    /// 分区；同名的分区合并，空名称为默认分区。
    pub(crate) fn section(&mut self, label: &str) -> Option<usize> {
        let label = clip(label.trim(), MAX_LABEL);
        if label.is_empty() {
            return None;
        }
        if let Some(i) = self.item.sections.iter().position(|s| *s == label) {
            return Some(i);
        }
        self.item.sections.push(label);
        Some(self.item.sections.len().saturating_sub(1))
    }

    pub(crate) fn add(
        &mut self,
        section: Option<usize>,
        kind: FieldKind,
        label: &str,
        purpose: Option<Purpose>,
        value: &str,
    ) {
        if value.trim().is_empty() || self.item.fields.len() >= MAX_FIELDS {
            return;
        }
        let label = clip(label.trim(), MAX_LABEL);
        let label = if label.is_empty() {
            default_label(kind).to_owned()
        } else {
            label
        };
        // 同一个用途只保留第一个（例如 1Password 的登录有两个"密码"字段时）
        let purpose = purpose.filter(|p| {
            !self
                .item
                .fields
                .iter()
                .any(|(_, f)| f.purpose == Some(*p) && *p != Purpose::Notes)
        });
        let value = if kind == FieldKind::Multiline || kind == FieldKind::SshPrivateKey {
            value.to_owned()
        } else {
            value.trim().to_owned()
        };
        self.item.fields.push((
            section,
            NewField {
                kind,
                label,
                purpose,
                data: FieldData::Text(SecretString::new(clip(&value, MAX_TEXT))),
            },
        ));
    }

    /// 原样加入一个字段（结构化字段：环境变量、恢复码）。
    pub(crate) fn push(&mut self, section: Option<usize>, mut field: NewField) {
        if self.item.fields.len() >= MAX_FIELDS {
            return;
        }
        field.label = clip(field.label.trim(), MAX_LABEL);
        self.item.fields.push((section, field));
    }

    /// 一次性密码：能识别时为一次性密码字段，否则保留为秘密文本（例如 Steam 令牌）。
    pub(crate) fn add_totp(&mut self, section: Option<usize>, label: &str, value: &str) {
        let value = value.trim();
        if crate::otp::OtpConfig::parse(value).is_ok() {
            let has_otp = self
                .item
                .fields
                .iter()
                .any(|(_, f)| f.kind == FieldKind::Totp);
            let label = if label.trim().is_empty() || !has_otp {
                "一次性密码"
            } else {
                label
            };
            self.add(section, FieldKind::Totp, label, Some(Purpose::Otp), value);
        } else {
            self.add(
                section,
                FieldKind::Concealed,
                "一次性密码（无法识别）",
                None,
                value,
            );
        }
    }

    pub(crate) fn note(&mut self, text: &str) {
        if !text.trim().is_empty() {
            self.notes.push(text.trim_end().to_owned());
        }
    }

    pub(crate) fn tag(&mut self, tag: &str) {
        let tag = clip(tag.trim(), MAX_TAG);
        if !tag.is_empty() && !self.item.tags.contains(&tag) {
            self.item.tags.push(tag);
        }
    }

    pub(crate) const fn favorite(&mut self, on: bool) {
        self.item.favorite = on;
    }

    pub(crate) const fn attachments(&mut self, n: usize) {
        self.item.attachments = self.item.attachments.saturating_add(n);
    }

    pub(crate) fn finish(mut self) -> Imported {
        if self.item.attachments > 0 {
            self.notes.push(format!(
                "原文件中的 {} 个附件没有导入：Keevo 暂不支持从这个来源导入附件。",
                self.item.attachments
            ));
        }
        let notes = self.notes.join("\n\n");
        let label = if self.item.item_type == ItemType::SecureNote {
            "正文"
        } else {
            "备注"
        };
        self.add(
            None,
            FieldKind::Multiline,
            label,
            Some(Purpose::Notes),
            &notes,
        );
        if self.item.title.is_empty() {
            self.item.title = self
                .item
                .first_url()
                .and_then(crate::security::host_of)
                .map_or_else(|| "导入的条目".to_owned(), |(_, h)| h);
        }
        // 默认分区的字段在前：写入时按这里的顺序编号
        self.item.fields.sort_by_key(|(s, _)| s.is_some());
        self.item
    }
}

/// 自 1970-01-01 起的天数 → `YYYY-MM-DD`（公历）。
#[allow(
    clippy::arithmetic_side_effects,
    reason = "调用方保证在 0001–9999 年之间"
)]
pub(crate) fn date_from_days(days: i64) -> String {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

const fn default_label(kind: FieldKind) -> &'static str {
    match kind {
        FieldKind::Concealed => "密码",
        FieldKind::Email => "电子邮件",
        FieldKind::Url => "网站",
        FieldKind::Phone => "电话",
        FieldKind::Date => "日期",
        FieldKind::Totp => "一次性密码",
        FieldKind::SshPrivateKey => "私钥",
        FieldKind::Multiline => "备注",
        _ => "字段",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests;
