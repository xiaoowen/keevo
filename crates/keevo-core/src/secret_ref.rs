//! `keevo://` 密钥引用（`spec/secret-refs.md`）：解析、按名称解析到值、为字段生成引用。
//!
//! 原则：名称有歧义时报错，从不猜测。

use std::fmt;

use keevo_crypto::Id128;
use keevo_format::{FieldData, FieldKind, FieldValue, ItemType, RecordKey, RecordValue};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::error::CoreError;
use crate::vault::Vault;

/// 引用的最大长度（字节）。
pub const MAX_REF_LEN: usize = 2048;
/// 解码后每段的最大长度（字节）。
pub const MAX_SEGMENT_LEN: usize = 256;

const SCHEME: &str = "keevo://";
/// 数据库条目的虚拟字段名（§3 第 5 步）。
const CONNECTION_STRING: [&str; 2] = ["connection_string", "连接串"];

/// 取值方式（`attribute` 参数）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attribute {
    /// 字段的值。
    Value,
    /// 一次性密码字段的当前验证码。
    Otp,
}

/// 一个解析后的引用。各段已百分号解码并做 NFC 规范化。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRef {
    /// 保险库名称或 ID。
    pub vault: String,
    /// 条目标题或 ID。
    pub item: String,
    /// 分区名称或 ID（第 4 段或 `profile` 参数）。
    pub section: Option<String>,
    /// 字段名称、ID 或键值对的键。
    pub field: String,
    /// 取值方式。
    pub attribute: Attribute,
}

/// 引用中的一段（用于错误说明）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Segment {
    /// 保险库。
    Vault,
    /// 条目。
    Item,
    /// 分区。
    Section,
    /// 字段。
    Field,
}

impl Segment {
    fn name(self) -> &'static str {
        match self {
            Self::Vault => "保险库",
            Self::Item => "条目",
            Self::Section => "分区",
            Self::Field => "字段",
        }
    }
}

/// 解析或取值失败（`spec/secret-refs.md` §6）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefError {
    /// 语法错误。附原因。
    BadRef(&'static str),
    /// 某一段没有匹配。
    NotFound {
        /// 哪一段。
        segment: Segment,
        /// 引用中写的名称。
        name: String,
    },
    /// 某一段匹配多于 1 个。
    Ambiguous {
        /// 哪一段。
        segment: Segment,
        /// 引用中写的名称。
        name: String,
        /// 候选（ID 或说明）。
        candidates: Vec<String>,
    },
    /// 字段类型不支持所请求的取值。
    UnsupportedField,
    /// 一次性密码配置不合法。
    InvalidOtp,
    /// 已锁定。
    Locked,
    /// 其他内部错误。
    Failed,
}

impl RefError {
    /// 稳定的错误码。
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadRef(_) => "bad_ref",
            Self::NotFound { .. } => "not_found",
            Self::Ambiguous { .. } => "ambiguous",
            Self::UnsupportedField => "unsupported_field",
            Self::InvalidOtp => "invalid_otp",
            Self::Locked => "locked",
            Self::Failed => "failed",
        }
    }
}

impl fmt::Display for RefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadRef(why) => write!(f, "引用的格式不正确：{why}"),
            Self::NotFound { segment, name } => write!(f, "找不到{}「{name}」", segment.name()),
            Self::Ambiguous {
                segment,
                name,
                candidates,
            } => write!(
                f,
                "{}「{name}」有 {} 个匹配，请改用 ID：{}",
                segment.name(),
                candidates.len(),
                candidates.join("、")
            ),
            Self::UnsupportedField => f.write_str("这个字段不支持所请求的取值"),
            Self::InvalidOtp => f.write_str("一次性密码的配置不正确"),
            Self::Locked => f.write_str("Keevo 已锁定"),
            Self::Failed => f.write_str("读取失败"),
        }
    }
}

impl std::error::Error for RefError {}

impl From<CoreError> for RefError {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::Locked => Self::Locked,
            CoreError::InvalidOtp => Self::InvalidOtp,
            CoreError::NotFound => Self::NotFound {
                segment: Segment::Item,
                name: String::new(),
            },
            _ => Self::Failed,
        }
    }
}

// ---- 解析

fn nfc(s: &str) -> String {
    s.nfc().collect()
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => b.checked_sub(b'0'),
        b'a'..=b'f' => b.checked_sub(b'a').and_then(|v| v.checked_add(10)),
        b'A'..=b'F' => b.checked_sub(b'A').and_then(|v| v.checked_add(10)),
        _ => None,
    }
}

/// 百分号解码一段，检查长度与控制字符，并做 NFC 规范化。
fn decode_segment(raw: &str) -> Result<String, RefError> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while let Some(&b) = bytes.get(i) {
        if b == b'%' {
            let hi = bytes.get(i.saturating_add(1)).copied().and_then(hex_value);
            let lo = bytes.get(i.saturating_add(2)).copied().and_then(hex_value);
            let (Some(hi), Some(lo)) = (hi, lo) else {
                return Err(RefError::BadRef("百分号编码不完整"));
            };
            out.push(hi.wrapping_mul(16).wrapping_add(lo));
            i = i.saturating_add(3);
        } else {
            out.push(b);
            i = i.saturating_add(1);
        }
    }
    let s = String::from_utf8(out).map_err(|_| RefError::BadRef("不是合法的 UTF-8"))?;
    if s.is_empty() {
        return Err(RefError::BadRef("有一段为空"));
    }
    if s.len() > MAX_SEGMENT_LEN {
        return Err(RefError::BadRef("有一段太长"));
    }
    if s.chars().any(char::is_control) {
        return Err(RefError::BadRef("含有控制字符"));
    }
    Ok(nfc(&s))
}

impl SecretRef {
    /// 解析引用文本。
    ///
    /// # Errors
    /// 语法错误返回 [`RefError::BadRef`]。
    pub fn parse(text: &str) -> Result<Self, RefError> {
        if text.len() > MAX_REF_LEN {
            return Err(RefError::BadRef("引用太长"));
        }
        let rest = text
            .strip_prefix(SCHEME)
            .ok_or(RefError::BadRef("必须以 keevo:// 开头"))?;
        if rest.contains('#') {
            return Err(RefError::BadRef("不允许 # 片段"));
        }
        let (path, query) = match rest.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (rest, None),
        };
        let segments = path
            .split('/')
            .map(decode_segment)
            .collect::<Result<Vec<_>, _>>()?;
        let (vault, item, section, field) = match segments.as_slice() {
            [v, i, f] => (v.clone(), i.clone(), None, f.clone()),
            [v, i, s, f] => (v.clone(), i.clone(), Some(s.clone()), f.clone()),
            _ => {
                return Err(RefError::BadRef(
                    "应为 保险库/条目/字段 或 保险库/条目/分区/字段",
                ));
            }
        };
        let mut attribute = None;
        let mut profile = None;
        if let Some(query) = query {
            for param in query.split('&') {
                let (k, v) = param
                    .split_once('=')
                    .ok_or(RefError::BadRef("参数应为 名称=值"))?;
                match k {
                    "attribute" => {
                        if attribute.is_some() {
                            return Err(RefError::BadRef("attribute 出现了两次"));
                        }
                        attribute = Some(match v {
                            "value" => Attribute::Value,
                            "otp" => Attribute::Otp,
                            _ => return Err(RefError::BadRef("attribute 只能是 value 或 otp")),
                        });
                    }
                    "profile" => {
                        if profile.is_some() {
                            return Err(RefError::BadRef("profile 出现了两次"));
                        }
                        profile = Some(decode_segment(v)?);
                    }
                    _ => return Err(RefError::BadRef("不认识的参数")),
                }
            }
        }
        if profile.is_some() && section.is_some() {
            return Err(RefError::BadRef("分区段与 profile 不能同时给出"));
        }
        Ok(Self {
            vault,
            item,
            section: section.or(profile),
            field,
            attribute: attribute.unwrap_or(Attribute::Value),
        })
    }
}

// ---- 名称匹配（§2）

fn is_id_like(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// 在 (ID, 显示名) 候选中按 §2 查找。
fn pick<T: Copy>(
    segment: Segment,
    name: &str,
    candidates: &[(Id128, String, T)],
) -> Result<T, RefError> {
    if is_id_like(name)
        && let Some((_, _, t)) = candidates.iter().find(|(id, _, _)| id.to_hex() == name)
    {
        return Ok(*t);
    }
    let exact: Vec<_> = candidates
        .iter()
        .filter(|(_, label, _)| nfc(label) == name)
        .collect();
    let matches = if exact.is_empty() {
        let lower = name.to_lowercase();
        candidates
            .iter()
            .filter(|(_, label, _)| nfc(label).to_lowercase() == lower)
            .collect()
    } else {
        exact
    };
    match matches.as_slice() {
        [(_, _, t)] => Ok(*t),
        [] => Err(RefError::NotFound {
            segment,
            name: name.to_owned(),
        }),
        many => Err(RefError::Ambiguous {
            segment,
            name: name.to_owned(),
            candidates: many.iter().map(|(id, _, _)| id.to_hex()).collect(),
        }),
    }
}

/// 按名称或 ID 找保险库（§2 的匹配规则）。
///
/// # Errors
/// 没有或多于一个匹配、已锁定时返回错误。
pub fn find_vault(vault: &Vault, name: &str) -> Result<Id128, RefError> {
    let vaults: Vec<_> = vault
        .vaults()?
        .into_iter()
        .map(|v| (v.id, v.name, v.id))
        .collect();
    pick(Segment::Vault, &nfc(name), &vaults)
}

/// 按 `保险库/条目`（两段都可以百分号编码）或条目 ID 找条目，不含回收站中的条目。
///
/// # Errors
/// 格式错误、没有或多于一个匹配、已锁定时返回错误。
pub fn find_item(vault: &Vault, spec: &str) -> Result<Id128, RefError> {
    let items = vault.items()?;
    if is_id_like(spec) {
        return items
            .iter()
            .find(|i| i.id.to_hex() == spec && i.overview.trashed_at.is_none())
            .map(|i| i.id)
            .ok_or(RefError::NotFound {
                segment: Segment::Item,
                name: spec.to_owned(),
            });
    }
    let (v, i) = spec
        .split_once('/')
        .ok_or(RefError::BadRef("条目应写成 保险库/条目，或条目 ID"))?;
    let vault_id = find_vault(vault, &decode_segment(v)?)?;
    let candidates: Vec<_> = items
        .into_iter()
        .filter(|x| x.vault_id == vault_id && x.overview.trashed_at.is_none())
        .map(|x| (x.id, x.overview.title, x.id))
        .collect();
    pick(Segment::Item, &decode_segment(i)?, &candidates)
}

// ---- 取值（§3）

/// 字段匹配的目标。
enum Target<'a> {
    Field(&'a FieldValue),
    Kv(&'a FieldValue, usize),
    ConnectionString,
}

fn sections(doc: &keevo_format::ItemDoc) -> Vec<(Id128, String, Id128)> {
    doc.records
        .iter()
        .filter_map(|(k, v)| match (k, &v.value) {
            (RecordKey::Section(id), Some(RecordValue::Section(s))) => {
                Some((*id, s.label.clone(), *id))
            }
            _ => None,
        })
        .collect()
}

fn fields(doc: &keevo_format::ItemDoc) -> Vec<(Id128, &FieldValue)> {
    doc.records
        .iter()
        .filter_map(|(k, v)| match (k, &v.value) {
            (RecordKey::Field(id), Some(RecordValue::Field(f))) => Some((*id, f)),
            _ => None,
        })
        .collect()
}

fn section_label(doc: &keevo_format::ItemDoc, section: Option<Id128>) -> String {
    section
        .and_then(|s| match doc.get(&RecordKey::Section(s)) {
            Some(RecordValue::Section(v)) => Some(v.label.clone()),
            _ => None,
        })
        .unwrap_or_else(|| "默认分区".into())
}

fn find_field<'a>(
    doc: &'a keevo_format::ItemDoc,
    section: Option<Id128>,
    name: &str,
) -> Result<Target<'a>, RefError> {
    let all = fields(doc);
    let scoped: Vec<_> = all
        .iter()
        .filter(|(_, f)| section.is_none_or(|s| f.section == Some(s)))
        .collect();
    if is_id_like(name)
        && let Some((_, f)) = scoped.iter().find(|(id, _)| id.to_hex() == name)
    {
        return Ok(Target::Field(f));
    }
    // 字段名（完全相同，否则忽略大小写）与键值对的键（只比较完全相同）合在一起计数
    let mut found: Vec<(Target<'a>, String)> = Vec::new();
    let exact_labels: Vec<_> = scoped
        .iter()
        .filter(|(_, f)| nfc(&f.label) == name)
        .collect();
    let labels = if exact_labels.is_empty() {
        let lower = name.to_lowercase();
        scoped
            .iter()
            .filter(|(_, f)| nfc(&f.label).to_lowercase() == lower)
            .collect()
    } else {
        exact_labels
    };
    for (id, f) in labels {
        found.push((Target::Field(f), id.to_hex()));
    }
    for (id, f) in &scoped {
        if let FieldData::Kv(entries) = &f.data {
            for (i, e) in entries.iter().enumerate() {
                if nfc(&e.key) == name {
                    found.push((
                        Target::Kv(f, i),
                        format!(
                            "{}（{} 中的 {}）",
                            id.to_hex(),
                            section_label(doc, f.section),
                            e.key
                        ),
                    ));
                }
            }
        }
    }
    match found.len() {
        1 => found.pop().map(|(t, _)| t).ok_or(RefError::Failed),
        0 => {
            if doc.item_type == ItemType::Database
                && CONNECTION_STRING
                    .iter()
                    .any(|n| n.eq_ignore_ascii_case(name))
            {
                Ok(Target::ConnectionString)
            } else {
                Err(RefError::NotFound {
                    segment: Segment::Field,
                    name: name.to_owned(),
                })
            }
        }
        _ => Err(RefError::Ambiguous {
            segment: Segment::Field,
            name: name.to_owned(),
            candidates: found.into_iter().map(|(_, d)| d).collect(),
        }),
    }
}

impl SecretRef {
    /// 在保险库中解析到值（`spec/secret-refs.md` §3）。`now_ms` 用于一次性密码。
    ///
    /// # Errors
    /// 见 [`RefError`]。
    pub fn resolve(&self, vault: &Vault, now_ms: u64) -> Result<Zeroizing<String>, RefError> {
        let vaults: Vec<_> = vault
            .vaults()?
            .into_iter()
            .map(|v| (v.id, v.name, v.id))
            .collect();
        let vault_id = pick(Segment::Vault, &self.vault, &vaults)?;
        let items: Vec<_> = vault
            .items()?
            .into_iter()
            .filter(|i| i.vault_id == vault_id && i.overview.trashed_at.is_none())
            .map(|i| (i.id, i.overview.title, i.id))
            .collect();
        let item_id = pick(Segment::Item, &self.item, &items)?;
        let view = vault.item(item_id)?;
        let doc = &view.doc;
        let section = match &self.section {
            Some(s) => Some(pick(Segment::Section, s, &sections(doc))?),
            None => None,
        };
        let target = find_field(doc, section, &self.field)?;
        match (target, self.attribute) {
            (Target::Field(f), Attribute::Value) => match &f.data {
                FieldData::Text(t) => Ok(Zeroizing::new(t.expose().to_owned())),
                _ => Err(RefError::UnsupportedField),
            },
            (Target::Field(f), Attribute::Otp) => match (&f.kind, &f.data) {
                (FieldKind::Totp, FieldData::Text(t)) => {
                    let code = crate::otp::OtpConfig::parse(t.expose())
                        .and_then(|c| c.code_at(now_ms))
                        .map_err(|_| RefError::InvalidOtp)?;
                    Ok(Zeroizing::new(code.code.to_string()))
                }
                _ => Err(RefError::UnsupportedField),
            },
            (Target::Kv(f, i), Attribute::Value) => match &f.data {
                FieldData::Kv(entries) => entries
                    .get(i)
                    .map(|e| Zeroizing::new(e.value.expose().to_owned()))
                    .ok_or(RefError::Failed),
                _ => Err(RefError::Failed),
            },
            (Target::ConnectionString, Attribute::Value) => connection_uri(doc),
            (Target::Kv(..) | Target::ConnectionString, Attribute::Otp) => {
                Err(RefError::UnsupportedField)
            }
        }
    }
}

// ---- 连接串（§4）

/// 按名称取文本字段：先找默认分区，再找其他分区。
fn text_field(doc: &keevo_format::ItemDoc, labels: &[&str]) -> String {
    let all = fields(doc);
    let pick = |default_only: bool| {
        all.iter().find_map(|(_, f)| {
            if default_only && f.section.is_some() {
                return None;
            }
            if !labels.iter().any(|l| f.label == *l) {
                return None;
            }
            match &f.data {
                FieldData::Text(t) => Some(t.expose().trim().to_owned()),
                _ => None,
            }
        })
    };
    pick(true).or_else(|| pick(false)).unwrap_or_default()
}

/// RFC 3986 百分号编码：只保留 unreserved 字符。
fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// 由数据库条目的字段生成连接 URI。
fn connection_uri(doc: &keevo_format::ItemDoc) -> Result<Zeroizing<String>, RefError> {
    let engine = text_field(doc, &["引擎", "Engine"]).to_lowercase();
    let host = text_field(doc, &["主机", "Host"]);
    if host.is_empty() {
        return Err(RefError::UnsupportedField);
    }
    let port = text_field(doc, &["端口", "Port"]);
    let database = text_field(doc, &["数据库", "Database"]);
    let user = text_field(doc, &["用户名", "Username"]);
    let password = Zeroizing::new(text_field(doc, &["密码", "Password"]));
    let ssl = text_field(doc, &["SSL 模式", "SSL Mode"]);
    let params = text_field(doc, &["连接参数", "Parameters"]);
    let (scheme, ssl_param) = match engine.as_str() {
        "postgresql" | "postgres" => ("postgresql", Some("sslmode")),
        "mysql" | "mariadb" => ("mysql", Some("ssl-mode")),
        "mongodb" => ("mongodb", None),
        "redis" => {
            if ssl.is_empty() || ssl.eq_ignore_ascii_case("disable") {
                ("redis", None)
            } else {
                ("rediss", None)
            }
        }
        _ => return Err(RefError::UnsupportedField),
    };
    let mut uri = Zeroizing::new(format!("{scheme}://"));
    if !user.is_empty() {
        uri.push_str(&pct(&user));
        if !password.is_empty() {
            uri.push(':');
            uri.push_str(&Zeroizing::new(pct(&password)));
        }
        uri.push('@');
    }
    if host.contains(':') && !host.starts_with('[') {
        uri.push('[');
        uri.push_str(&host);
        uri.push(']');
    } else {
        uri.push_str(&host);
    }
    if !port.is_empty() {
        uri.push(':');
        uri.push_str(&port);
    }
    if !database.is_empty() {
        uri.push('/');
        uri.push_str(&pct(&database));
    }
    let mut query: Vec<String> = Vec::new();
    if let (Some(name), false) = (ssl_param, ssl.is_empty()) {
        query.push(format!("{name}={}", pct(&ssl)));
    }
    if !params.is_empty() {
        query.push(params.trim_start_matches(['?', '&']).to_owned());
    }
    if !query.is_empty() {
        uri.push('?');
        uri.push_str(&query.join("&"));
    }
    Ok(uri)
}

// ---- 生成引用（§5）

/// 编码一段：ASCII 只保留 unreserved 字符，非 ASCII 字符原样保留（便于阅读）。
fn encode_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if !c.is_ascii() || c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~') {
            out.push(c);
        } else {
            let mut buf = [0u8; 4];
            for b in c.encode_utf8(&mut buf).bytes() {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    out
}

/// 名称能否唯一确定：在候选中按 §2 第 2 步恰好命中一个，且名称本身不像 ID。
fn unique_name(name: &str, labels: &[String]) -> bool {
    !is_id_like(name) && labels.iter().filter(|l| nfc(l) == nfc(name)).count() == 1
}

/// 为条目中的一个字段（或键值对中的一项）生成引用（`spec/secret-refs.md` §5）。
///
/// # Errors
/// 已锁定、条目或字段不存在时返回错误。
pub fn reference_for(
    vault: &Vault,
    item_id: Id128,
    field_id: Id128,
    kv_key: Option<&str>,
) -> Result<String, RefError> {
    let item = vault
        .items()?
        .into_iter()
        .find(|i| i.id == item_id)
        .ok_or(RefError::NotFound {
            segment: Segment::Item,
            name: item_id.to_hex(),
        })?;
    let vaults = vault.vaults()?;
    let vault_info = vaults
        .iter()
        .find(|v| v.id == item.vault_id)
        .ok_or(RefError::Failed)?;
    let vault_names: Vec<String> = vaults.iter().map(|v| v.name.clone()).collect();
    let vault_seg = if unique_name(&vault_info.name, &vault_names) {
        encode_segment(&vault_info.name)
    } else {
        vault_info.id.to_hex()
    };
    let titles: Vec<String> = vault
        .items()?
        .into_iter()
        .filter(|i| i.vault_id == item.vault_id && i.overview.trashed_at.is_none())
        .map(|i| i.overview.title)
        .collect();
    let item_seg = if unique_name(&item.overview.title, &titles) {
        encode_segment(&item.overview.title)
    } else {
        item_id.to_hex()
    };
    let view = vault.item(item_id)?;
    let doc = &view.doc;
    let field = match doc.get(&RecordKey::Field(field_id)) {
        Some(RecordValue::Field(f)) => f,
        _ => {
            return Err(RefError::NotFound {
                segment: Segment::Field,
                name: field_id.to_hex(),
            });
        }
    };
    let section_labels: Vec<String> = sections(doc).into_iter().map(|(_, l, _)| l).collect();
    let section_seg = field.section.map(|s| {
        let label = section_label(doc, Some(s));
        if unique_name(&label, &section_labels) {
            encode_segment(&label)
        } else {
            s.to_hex()
        }
    });
    let all = fields(doc);
    // 一个名称在给定范围（全部，或某个分区）中作为字段名或键出现的次数
    let occurrences = |name: &str, section: Option<Option<Id128>>| {
        all.iter()
            .filter(|(_, f)| section.is_none_or(|s| f.section == s))
            .map(|(_, f)| {
                let label = usize::from(nfc(&f.label) == nfc(name));
                let keys = match &f.data {
                    FieldData::Kv(entries) => {
                        entries.iter().filter(|e| nfc(&e.key) == nfc(name)).count()
                    }
                    _ => 0,
                };
                label.saturating_add(keys)
            })
            .sum::<usize>()
    };
    let (name, in_section) = match kv_key {
        Some(key) => (key.to_owned(), true),
        None => (field.label.clone(), false),
    };
    let unique_everywhere = !is_id_like(&name) && occurrences(&name, None) == 1;
    let unique_in_section = !is_id_like(&name) && occurrences(&name, Some(field.section)) == 1;
    let path = match (&section_seg, kv_key) {
        // 键值对：总是带上分区段（默认分区中的键只能在全条目唯一时引用）
        (Some(sec), Some(_)) if unique_in_section => format!("{sec}/{}", encode_segment(&name)),
        (None, Some(_)) if unique_everywhere => encode_segment(&name),
        (_, Some(_)) => {
            return Err(RefError::Ambiguous {
                segment: Segment::Field,
                name,
                candidates: vec![field_id.to_hex()],
            });
        }
        (_, None) if unique_everywhere && !in_section => encode_segment(&name),
        (Some(sec), None) if unique_in_section => format!("{sec}/{}", encode_segment(&name)),
        (_, None) => field_id.to_hex(),
    };
    Ok(format!("{SCHEME}{vault_seg}/{item_seg}/{path}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests;
