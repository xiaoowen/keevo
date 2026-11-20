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

use std::collections::{HashMap, HashSet};

use keevo_format::{FieldData, FieldKind, ItemType, Purpose, SecretString};
use zeroize::Zeroizing;

use crate::error::Result;
use crate::vault::{NewField, Vault};

/// 导入文件的大小上限：512 MiB（1PUX 中可能有附件）。
pub const MAX_FILE_LEN: usize = 512 * 1024 * 1024;
/// 条目数上限。
pub const MAX_ITEMS: usize = 50_000;
/// 解析 JSON 之前允许的节点数（约每个值一个）。解析树的大小因此有上限，压缩文件不能把几十 KB 放大成数 GB
/// （第五轮预审 K10）。这是**有界**而不是低内存：输入文件、解压后的数据、解析树与输出的条目可能同时在内存中。
pub const MAX_JSON_NODES: usize = 4_000_000;
/// 一个条目的字段数上限（`spec/revisions.md` §7.1 的记录键上限为 4096）。
const MAX_FIELDS: usize = 1000;
/// 一个条目的分区数上限。
const MAX_SECTIONS: usize = 200;
/// 一个条目的标签数上限。
const MAX_TAGS: usize = 100;
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

impl Parsed {
    /// 加入一个条目；超过 [`MAX_ITEMS`] 时立即停止解析，而不是全部解析完再检查（第五轮预审 K10）。
    pub(crate) fn push(&mut self, item: Imported) -> core::result::Result<(), ImportError> {
        if self.items.len() >= MAX_ITEMS {
            return Err(ImportError::TooLarge);
        }
        self.items.push(item);
        Ok(())
    }
}

/// 解析 JSON 之前先数节点：字符串之外的 `{`、`[`、`,`、`:`。超过 [`MAX_JSON_NODES`] 时返回
/// [`ImportError::TooLarge`]，不建立解析树。只做计数，JSON 是否合法仍由解析器判断。
pub(crate) fn check_json_nodes(bytes: &[u8]) -> core::result::Result<(), ImportError> {
    let mut nodes = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for &b in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' | b',' | b':' => {
                nodes = nodes.saturating_add(1);
                if nodes > MAX_JSON_NODES {
                    return Err(ImportError::TooLarge);
                }
            }
            _ => {}
        }
    }
    Ok(())
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

/// 每个条目是否与保险库中已有的登录（不含最近删除）重复：网址主机、用户名与密码都相同，并且导入条目的每个字段值
/// 都已在那个登录中。导入条目带有已有登录没有的内容（一次性密码、备注、其他字段）时不算重复，否则跳过它会丢掉
/// 这些内容（第五轮预审 K8）。
///
/// # Errors
/// 已锁定或读取失败。
pub fn duplicates(vault: &Vault, items: &[Imported]) -> Result<Vec<bool>> {
    // 指纹 → 有这个指纹的每个登录的字段值集合（值的 SHA-256，只在内存中短暂存在）
    let mut existing: HashMap<[u8; 32], Vec<HashSet<[u8; 32]>>> = HashMap::new();
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
        let values: HashSet<[u8; 32]> = fields
            .iter()
            .filter_map(|f| f.text().map(|t| value_hash(f.kind, t)))
            .collect();
        let urls: Vec<&str> = fields
            .iter()
            .filter(|f| f.kind == FieldKind::Url)
            .filter_map(|f| f.text())
            .collect();
        let prints: Vec<[u8; 32]> = if urls.is_empty() {
            login_fingerprint(None, username, password)
                .into_iter()
                .collect()
        } else {
            urls.iter()
                .filter_map(|url| login_fingerprint(Some(url), username, password))
                .collect()
        };
        for print in prints {
            existing.entry(print).or_default().push(values.clone());
        }
    }
    Ok(items
        .iter()
        .map(|i| {
            if i.item_type != ItemType::Login {
                return false;
            }
            let Some(print) = login_fingerprint(
                i.first_url(),
                i.text_of(Purpose::Username),
                i.text_of(Purpose::Password),
            ) else {
                return false;
            };
            // 结构化字段（环境变量、恢复码）无法逐值比较：有这样的字段就不算重复
            let values: Option<Vec<[u8; 32]>> = i
                .fields
                .iter()
                .map(|(_, f)| match &f.data {
                    FieldData::Text(t) => Some(value_hash(f.kind, t.expose())),
                    _ => None,
                })
                .collect();
            values.is_some_and(|values| {
                existing.get(&print).is_some_and(|logins| {
                    logins
                        .iter()
                        .any(|have| values.iter().all(|v| have.contains(v)))
                })
            })
        })
        .collect())
}

/// 重复判定中一个字段值的摘要。网址只比较主机（去掉 `www.`），与登录指纹相同。
fn value_hash(kind: FieldKind, text: &str) -> [u8; 32] {
    if kind == FieldKind::Url
        && let Some((_, host)) = crate::security::host_of(text)
    {
        let host = host.trim_start_matches("www.");
        return keevo_crypto::sha256(format!("url\0{host}").as_bytes());
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(text.len().saturating_add(5)));
    buf.extend_from_slice(b"text\0");
    buf.extend_from_slice(text.as_bytes());
    keevo_crypto::sha256(&buf)
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

/// 逐步构造一个 [`Imported`]。
///
/// 两种模式：
/// - **规整**（[`Builder::new`]，其他来源）：去掉名称与普通值的首尾空白，名称超长时截断并在备注中说明，空值不生成
///   字段，同名分区合并，字段、分区、标签有个数上限；
/// - **原样**（[`Builder::exact`]，Keevo 自己的导出文件）：名称、值、空值与分区的位置都原样保留，同名的分区不合并
///   （`spec/export.md` §2；第五轮评审 L6）。上限只有格式本身的上限，由写入时检查。
///
/// 两种模式都不改变秘密值与多行文本（包括备注）。
pub(crate) struct Builder {
    item: Imported,
    exact: bool,
    /// 规整模式下被截断的名称数，在备注中说明。
    clipped: usize,
    notes: Vec<String>,
    /// 分区名 → 序号（去重用；第五轮预审 K9：线性查找使去重成为平方复杂度）。
    section_index: HashMap<String, usize>,
    tag_set: HashSet<String>,
    /// 因超过上限而没有导入的字段、分区与标签数，在备注中说明（第五轮预审 K8：不静默丢弃）。
    dropped_fields: usize,
    dropped_sections: usize,
    dropped_tags: usize,
    /// 数据与字段类型不符、因而没有导入的字段数。
    malformed_fields: usize,
}

impl Builder {
    pub(crate) fn new(item_type: ItemType, title: &str) -> Self {
        let mut b = Self::exact(item_type, "");
        b.exact = false;
        b.item.title = b.name(title, MAX_LABEL);
        b
    }

    /// 原样模式（Keevo 自己的导出文件）。
    pub(crate) fn exact(item_type: ItemType, title: &str) -> Self {
        Self {
            exact: true,
            clipped: 0,
            item: Imported {
                item_type,
                original: None,
                title: title.to_owned(),
                sections: Vec::new(),
                fields: Vec::new(),
                tags: Vec::new(),
                favorite: false,
                attachments: 0,
            },
            notes: Vec::new(),
            section_index: HashMap::new(),
            tag_set: HashSet::new(),
            dropped_fields: 0,
            dropped_sections: 0,
            dropped_tags: 0,
            malformed_fields: 0,
        }
    }

    /// 作为安全笔记导入的原类别。
    pub(crate) const fn original(mut self, code: &'static str) -> Self {
        self.item.original = Some(code);
        self
    }

    /// 名称（标题、字段名、分区名、标签）：规整模式去掉首尾空白，超过 `max` 字节时截断并计数；原样模式不变。
    fn name(&mut self, s: &str, max: usize) -> String {
        if self.exact {
            return s.to_owned();
        }
        let trimmed = s.trim();
        let out = clip(trimmed, max);
        if out.len() < trimmed.len() {
            self.clipped = self.clipped.saturating_add(1);
        }
        out
    }

    /// 分区。规整模式：同名的分区合并，空名称为默认分区，超过 [`MAX_SECTIONS`] 个时其余分区的字段放进默认分区。
    /// 原样模式：每次调用都是一个新的分区（分区以位置为身份）。
    pub(crate) fn section(&mut self, label: &str) -> Option<usize> {
        if self.exact {
            self.item.sections.push(label.to_owned());
            return Some(self.item.sections.len().saturating_sub(1));
        }
        let label = self.name(label, MAX_LABEL);
        if label.is_empty() {
            return None;
        }
        if let Some(i) = self.section_index.get(&label) {
            return Some(*i);
        }
        if self.item.sections.len() >= MAX_SECTIONS {
            self.dropped_sections = self.dropped_sections.saturating_add(1);
            return None;
        }
        let i = self.item.sections.len();
        self.section_index.insert(label.clone(), i);
        self.item.sections.push(label);
        Some(i)
    }

    pub(crate) fn add(
        &mut self,
        section: Option<usize>,
        kind: FieldKind,
        label: &str,
        purpose: Option<Purpose>,
        value: &str,
    ) {
        if self.exact {
            self.item.fields.push((
                section,
                NewField {
                    kind,
                    label: label.to_owned(),
                    purpose,
                    data: FieldData::Text(SecretString::new(value.to_owned())),
                },
            ));
            return;
        }
        // 秘密值与多行文本原样保留，首尾的空格也是值的一部分（第五轮预审 K8）；其余的值去掉首尾空白
        let raw = matches!(
            kind,
            FieldKind::Concealed | FieldKind::Multiline | FieldKind::SshPrivateKey
        );
        if value.is_empty() || (!raw && value.trim().is_empty()) {
            return;
        }
        if self.item.fields.len() >= MAX_FIELDS {
            self.dropped_fields = self.dropped_fields.saturating_add(1);
            return;
        }
        let label = self.name(label, MAX_LABEL);
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
        let value = if raw {
            value.to_owned()
        } else {
            value.trim().to_owned()
        };
        if value.len() > MAX_TEXT {
            self.clipped = self.clipped.saturating_add(1);
        }
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
        if !self.exact && self.item.fields.len() >= MAX_FIELDS {
            self.dropped_fields = self.dropped_fields.saturating_add(1);
            return;
        }
        field.label = self.name(&field.label, MAX_LABEL);
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

    /// 备注：原样保留，包括首尾的空白（第五轮评审 L6）。
    pub(crate) fn note(&mut self, text: &str) {
        if !text.trim().is_empty() {
            self.notes.push(text.to_owned());
        }
    }

    pub(crate) fn tag(&mut self, tag: &str) {
        let tag = self.name(tag, MAX_TAG);
        if tag.is_empty() || self.tag_set.contains(&tag) {
            return;
        }
        if !self.exact && self.item.tags.len() >= MAX_TAGS {
            self.dropped_tags = self.dropped_tags.saturating_add(1);
            return;
        }
        self.tag_set.insert(tag.clone());
        self.item.tags.push(tag);
    }

    /// 一个格式不对的字段（数据与字段类型不符）：不导入，在备注中说明。
    pub(crate) const fn skip_field(&mut self) {
        self.malformed_fields = self.malformed_fields.saturating_add(1);
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
        if self.clipped > 0 {
            self.notes.push(format!(
                "原文件中有 {} 个名称或值超过长度上限，导入时截断了。",
                self.clipped
            ));
        }
        // 备注本身也是一个字段：字段已满时让出最后一个，用来说明没有导入的内容
        if !self.exact
            && !self.notes.is_empty()
            && self.item.fields.len() >= MAX_FIELDS
            && self.item.fields.pop().is_some()
        {
            self.dropped_fields = self.dropped_fields.saturating_add(1);
        }
        if self.dropped_fields > 0 {
            self.notes.push(format!(
                "原文件中还有 {} 个字段没有导入：一个条目最多 {MAX_FIELDS} 个字段。",
                self.dropped_fields
            ));
        }
        if self.dropped_sections > 0 {
            self.notes.push(format!(
                "原文件中还有 {} 个分区：一个条目最多 {MAX_SECTIONS} 个分区，这些分区中的字段放在了默认分区。",
                self.dropped_sections
            ));
        }
        if self.malformed_fields > 0 {
            self.notes.push(format!(
                "原文件中有 {} 个字段的格式不对（数据与字段类型不符），没有导入。",
                self.malformed_fields
            ));
        }
        if self.dropped_tags > 0 {
            self.notes.push(format!(
                "原文件中还有 {} 个标签没有导入：一个条目最多 {MAX_TAGS} 个标签。",
                self.dropped_tags
            ));
        }
        let notes = self.notes.join("\n\n");
        let label = if self.item.item_type == ItemType::SecureNote {
            "正文"
        } else {
            "备注"
        };
        if !notes.is_empty() {
            self.add(
                None,
                FieldKind::Multiline,
                label,
                Some(Purpose::Notes),
                &notes,
            );
        }
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
