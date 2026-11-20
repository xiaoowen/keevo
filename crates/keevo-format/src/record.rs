//! 记录映射（`spec/revisions.md` §4）。

use core::fmt;
use std::collections::BTreeMap;

use keevo_crypto::Id128;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{FormatError, Result};
use crate::hlc::Hlc;
use crate::id_hex;
use crate::item::{FieldKind, Purpose};
use crate::secret::SecretString;

const MAX_ATTR_NAME: usize = 64;
const MAX_TAG_LEN: usize = 256;

/// 记录键。
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum RecordKey {
    /// 单值属性，如 `title`、`favorite`。名称只能包含小写字母、数字和下划线。
    Attr(String),
    /// 标签。
    Tag(String),
    /// 分区。
    Section(Id128),
    /// 字段。
    Field(Id128),
}

impl RecordKey {
    /// 是否为保留键 `attr:purged`：只由合并（墓碑头）与确定恢复产生，客户端不得直接写入。
    #[must_use]
    pub fn is_reserved(&self) -> bool {
        matches!(self, Self::Attr(n) if n == "purged")
    }

    /// 是否为删除状态键：`attr:trashed`（回收站）或 `attr:purged`（永久删除，合并时由墓碑头产生）。
    #[must_use]
    pub fn is_deletion_state(&self) -> bool {
        matches!(self, Self::Attr(n) if n == "trashed" || n == "purged")
    }

    /// 属性键。
    #[must_use]
    pub fn attr(name: &str) -> Self {
        Self::Attr(name.to_owned())
    }

    /// 记录值的类型是否与键匹配。
    #[must_use]
    pub fn accepts(&self, value: &RecordValue) -> bool {
        match (self, value) {
            (Self::Attr(_), RecordValue::Text(_) | RecordValue::Bool(_) | RecordValue::Int(_))
            | (Self::Tag(_), RecordValue::Tag)
            | (Self::Section(_), RecordValue::Section(_)) => true,
            (Self::Field(_), RecordValue::Field(f)) => f.is_consistent(),
            _ => false,
        }
    }

    /// 解析并校验名称：写入接口与 [`core::str::FromStr`] 使用。
    fn parse(s: &str) -> Option<Self> {
        Self::parse_syntax(s).filter(Self::is_valid)
    }

    /// 只解析语法：种类前缀与 ID 格式（`spec/vault-format.md` §1.1 错误先后的第 1 步，不符合即 `malformed`）。
    /// 属性名、标签名的规则属于语义（第 3 步，`invalid_key`），由 [`crate::ItemDoc::validate`] 在规范编码检查之后校验。
    fn parse_syntax(s: &str) -> Option<Self> {
        let (kind, rest) = s.split_once(':')?;
        Some(match kind {
            "attr" => Self::Attr(rest.to_owned()),
            "tag" => Self::Tag(rest.to_owned()),
            "section" => Self::Section(id_hex::parse(rest)?),
            "field" => Self::Field(id_hex::parse(rest)?),
            _ => return None,
        })
    }

    /// 名称是否合法（`spec/vault-format.md` §2）：属性名 `[a-z0-9_]`、1–64 字节；标签名 1–256 字节。
    /// 写入与解码使用同一条规则，写进去的键一定读得出来（第四轮评审 J3）。
    #[must_use]
    pub fn is_valid(&self) -> bool {
        match self {
            Self::Attr(n) => {
                !n.is_empty()
                    && n.len() <= MAX_ATTR_NAME
                    && n.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            }
            Self::Tag(t) => !t.is_empty() && t.len() <= MAX_TAG_LEN,
            Self::Section(_) | Self::Field(_) => true,
        }
    }
}

impl core::str::FromStr for RecordKey {
    type Err = FormatError;

    /// 从 `attr:title`、`field:<32 位十六进制>` 等字符串解析，规则与解码相同。
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s).ok_or(FormatError::InvalidKey)
    }
}

impl fmt::Display for RecordKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Attr(n) => write!(f, "attr:{n}"),
            Self::Tag(t) => write!(f, "tag:{t}"),
            Self::Section(id) => write!(f, "section:{}", id.to_hex()),
            Self::Field(id) => write!(f, "field:{}", id.to_hex()),
        }
    }
}

impl Serialize for RecordKey {
    fn serialize<S: Serializer>(&self, s: S) -> core::result::Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for RecordKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> core::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse_syntax(&s).ok_or_else(|| serde::de::Error::custom("invalid record key"))
    }
}

/// 记录值。JSON 中采用外部标签形式，例如 `{"text": "GitHub"}`、`"tag"`。
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordValue {
    /// 文本属性。
    Text(SecretString),
    /// 布尔属性。
    Bool(bool),
    /// 整数属性（如回收站时间，Unix 毫秒）。
    Int(i64),
    /// 标签存在。
    Tag,
    /// 分区。
    Section(SectionValue),
    /// 字段。
    Field(FieldValue),
}

/// 分区的值。
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SectionValue {
    /// 显示名。
    pub label: String,
    /// 排序键（分数索引）。
    pub order: String,
}

/// 字段的值。
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldValue {
    /// 所属分区；`None` 表示默认分区。
    #[serde(
        with = "id_hex::option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub section: Option<Id128>,
    /// 排序键（分数索引）。
    pub order: String,
    /// 字段类型。
    pub kind: FieldKind,
    /// 显示名。
    pub label: String,
    /// 自动填充用途。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<Purpose>,
    /// 字段数据。
    pub data: FieldData,
}

impl FieldValue {
    /// 字段类型与数据形态是否一致。
    #[must_use]
    pub fn is_consistent(&self) -> bool {
        matches!(
            (self.kind, &self.data),
            (FieldKind::KvList, FieldData::Kv(_))
                | (FieldKind::RecoveryCodes, FieldData::Codes(_))
                | (FieldKind::Attachment, FieldData::Attachment(_))
        ) || (!matches!(
            self.kind,
            FieldKind::KvList | FieldKind::RecoveryCodes | FieldKind::Attachment
        ) && matches!(self.data, FieldData::Text(_)))
    }

    /// 文本数据（`kv_list` 与 `recovery_codes` 字段返回 `None`）。
    #[must_use]
    pub fn text(&self) -> Option<&str> {
        match &self.data {
            FieldData::Text(s) => Some(s.expose()),
            _ => None,
        }
    }
}

/// 字段数据。
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldData {
    /// 文本，适用于除下列两种之外的全部字段类型。
    Text(SecretString),
    /// 键值对列表（`kv_list`，环境变量）。
    Kv(Vec<KvEntry>),
    /// 恢复码列表（`recovery_codes`）。
    Codes(Vec<CodeEntry>),
    /// 附件引用（`attachment`，条目详情 v2）。
    Attachment(AttachmentRef),
}

/// 附件引用（`spec/vault-format.md` §2.5）：附件内容另行分块加密保存（`spec/crypto.md` §8.9），
/// 这里只有找到它、显示它所需的信息。附件内容不可变：替换文件即是新的附件。
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentRef {
    /// 附件 ID。
    #[serde(with = "id_hex")]
    pub id: Id128,
    /// 文件名。
    pub name: String,
    /// 大小（字节），0 到 2⁵³−1。
    pub size: i64,
    /// 添加时间（Unix 毫秒），0 到 2⁵³−1。
    pub added: i64,
    /// 内容（明文）的 SHA-256：条目修订对附件内容的承诺，读取时核对（第五轮预审 K13）。可选：缺省表示没有
    /// 承诺（M1.5 草案期间写入的附件）；Keevo 新写入的附件一律带上。
    #[serde(
        with = "id_hex::sha256_option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub sha256: Option<[u8; 32]>,
}

/// 环境变量中的一项。
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KvEntry {
    /// 变量名。
    pub key: String,
    /// 变量值。
    pub value: SecretString,
    /// 是否为秘密值（默认隐藏）。
    pub concealed: bool,
}

/// 一个恢复码。
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeEntry {
    /// 恢复码。
    pub code: SecretString,
    /// 是否已使用。
    pub used: bool,
}

/// 记录的一个版本（`spec/revisions.md` §4.2）。`value` 为 `None` 表示墓碑。
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordVersion {
    /// 写入时的 HLC。
    pub hlc: Hlc,
    /// 写入该版本的修订。
    #[serde(with = "id_hex")]
    pub rev: Id128,
    /// 值；墓碑时省略。
    #[serde(rename = "val", default, skip_serializing_if = "Option::is_none")]
    pub value: Option<RecordValue>,
}

impl RecordVersion {
    /// 是否为墓碑。
    #[must_use]
    pub const fn is_tombstone(&self) -> bool {
        self.value.is_none()
    }
}

/// 记录映射。按键有序，序列化结果确定。
pub type RecordMap = BTreeMap<RecordKey, RecordVersion>;

/// 并发版本映射（`spec/revisions.md` §4.3）。每个列表非空、按 `rev` 严格升序。
pub type ConcurrentMap = BTreeMap<RecordKey, Vec<RecordVersion>>;

/// 校验并发版本：列表非空，值与键匹配，按 `rev` 严格升序，且不与当前版本同 `rev`；
/// 只有删除状态（`attr:trashed`、`attr:purged`）可以只有并发版本而没有当前版本（§4.3）。
pub(crate) fn validate_concurrent(records: &RecordMap, concurrent: &ConcurrentMap) -> Result<()> {
    for (key, versions) in concurrent {
        if !key.is_valid() {
            return Err(FormatError::InvalidKey);
        }
        if !records.contains_key(key) && !key.is_deletion_state() {
            return Err(FormatError::Malformed(
                "concurrent: key without current version".into(),
            ));
        }
        if versions.is_empty() {
            return Err(FormatError::Malformed("concurrent: empty list".into()));
        }
        if versions
            .windows(2)
            .any(|w| matches!(w, [a, b] if a.rev >= b.rev))
        {
            return Err(FormatError::Malformed(
                "concurrent: not sorted by rev".into(),
            ));
        }
        if let Some(current) = records.get(key)
            && versions.iter().any(|v| v.rev == current.rev)
        {
            return Err(FormatError::Malformed(
                "concurrent: duplicates current".into(),
            ));
        }
        for v in versions {
            if let Some(value) = &v.value {
                check_value(key, value)?;
            }
        }
    }
    Ok(())
}

/// 每个条目最多的记录键数（含墓碑与并发版本的键，`spec/revisions.md` §7.1）。
/// 键名长度也有上限，因此"删除全部键"之后的墓碑总能放进一个信封。
pub const MAX_KEYS: usize = 4096;

/// 单个记录值编码后的上限：256 KiB。更大的内容应作为附件（`spec/vault-format.md` §2）。
pub const MAX_VALUE_LEN: usize = 256 * 1024;
/// 整数值的范围：±(2⁵³−1)，保证在 JavaScript 等环境中无损，规范编码也唯一。
pub const MAX_SAFE_INT: i64 = (1 << 53) - 1;

/// 排序键的字母表与长度（`spec/vault-format.md` §2.4）。
const MAX_ORDER_LEN: usize = 64;

fn valid_order(order: &str) -> bool {
    !order.is_empty()
        && order.len() <= MAX_ORDER_LEN
        && order.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// 校验一个值：类型与键匹配，整数在安全范围内，排序键合法，编码后不超过 [`MAX_VALUE_LEN`]。
pub(crate) fn check_value(key: &RecordKey, value: &RecordValue) -> Result<()> {
    if !key.is_valid() {
        return Err(FormatError::InvalidKey);
    }
    if !key.accepts(value) {
        return Err(FormatError::ValueKindMismatch);
    }
    let order_ok = match value {
        RecordValue::Section(s) => valid_order(&s.order),
        RecordValue::Field(f) => valid_order(&f.order),
        _ => true,
    };
    if !order_ok {
        return Err(FormatError::ValueKindMismatch);
    }
    if let RecordValue::Int(i) = value
        && !(-MAX_SAFE_INT..=MAX_SAFE_INT).contains(i)
    {
        return Err(FormatError::ValueTooLarge);
    }
    if let RecordValue::Field(FieldValue {
        data: FieldData::Attachment(a),
        ..
    }) = value
        && !((0..=MAX_SAFE_INT).contains(&a.size) && (0..=MAX_SAFE_INT).contains(&a.added))
    {
        return Err(FormatError::ValueTooLarge);
    }
    if crate::json::to_json(value)?.len() > MAX_VALUE_LEN {
        return Err(FormatError::ValueTooLarge);
    }
    Ok(())
}

pub(crate) fn validate(records: &RecordMap) -> Result<()> {
    for (key, version) in records {
        if !key.is_valid() {
            return Err(FormatError::InvalidKey);
        }
        if let Some(value) = &version.value {
            check_value(key, value)?;
        }
    }
    Ok(())
}

/// 反序列化记录映射与并发版本映射时拒绝重复键：JSON 对象中同一记录键出现两次时，
/// 不同实现可能保留第一个或最后一个，因此一律视为格式错误（`spec/vault-format.md` §1）。
pub(crate) fn unique_map<'de, D, V>(d: D) -> core::result::Result<BTreeMap<RecordKey, V>, D::Error>
where
    D: serde::Deserializer<'de>,
    V: serde::Deserialize<'de>,
{
    struct Visitor<V>(core::marker::PhantomData<V>);
    impl<'de, V: serde::Deserialize<'de>> serde::de::Visitor<'de> for Visitor<V> {
        type Value = BTreeMap<RecordKey, V>;
        fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("a map with unique record keys")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> core::result::Result<Self::Value, A::Error> {
            let mut out = BTreeMap::new();
            while let Some((k, v)) = map.next_entry::<RecordKey, V>()? {
                if out.insert(k, v).is_some() {
                    return Err(serde::de::Error::custom("duplicate record key"));
                }
            }
            Ok(out)
        }
    }
    d.deserialize_map(Visitor(core::marker::PhantomData))
}

/// 校验保留键 `attr:purged` 的形态（`spec/vault-format.md` §2.1）：当前版本只能是墓碑（已确定的恢复）；
/// 并发版本只能是墓碑，或墓碑头产生的删除版本（`hlc = 0`，值为 `true`）。
pub(crate) fn validate_reserved(records: &RecordMap, concurrent: &ConcurrentMap) -> Result<()> {
    let key = RecordKey::attr("purged");
    if records.get(&key).is_some_and(|v| !v.is_tombstone()) {
        return Err(FormatError::ReservedKey);
    }
    let purge_ok = |v: &RecordVersion| {
        v.is_tombstone()
            || (v.hlc == crate::hlc::Hlc(0) && v.value == Some(RecordValue::Bool(true)))
    };
    if concurrent
        .get(&key)
        .is_some_and(|vs| !vs.iter().all(purge_ok))
    {
        return Err(FormatError::ReservedKey);
    }
    Ok(())
}
