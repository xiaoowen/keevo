//! 条目与保险库的明文结构（`spec/vault-format.md`）。

use keevo_crypto::Id128;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::FORMAT_VERSION;

/// 含附件字段的条目详情的版本（`spec/vault-format.md` §2.5）。
pub const ITEM_DETAILS_V2: u32 = 2;
use crate::error::{FormatError, Result};
use crate::hlc::Hlc;
use crate::json::{from_canonical_json, from_json, to_json};
use crate::record::{
    self, ConcurrentMap, MAX_KEYS, MAX_SAFE_INT, RecordKey, RecordMap, RecordValue, RecordVersion,
};

/// 条目类型。创建后不可更改。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemType {
    /// 网站登录。
    Login,
    /// 电子邮件账户。
    EmailAccount,
    /// 安全笔记。
    SecureNote,
    /// SSH 密钥。
    SshKey,
    /// API 凭证（API 密钥、访问令牌等）。
    ApiCredential,
    /// 数据库凭证。
    Database,
    /// 环境变量。
    Environment,
    /// 双因素验证。
    TwoFactor,
}

/// 字段类型（`docs/product.md` §5.2）。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    /// 单行文本。
    Text,
    /// 多行文本。
    Multiline,
    /// 秘密值。
    Concealed,
    /// 电子邮件地址。
    Email,
    /// 网址。
    Url,
    /// 电话。
    Phone,
    /// 日期。
    Date,
    /// 年月。
    MonthYear,
    /// 枚举值。
    Select,
    /// 一次性密码（`otpauth://` URI）。
    Totp,
    /// SSH 私钥。
    SshPrivateKey,
    /// 引用另一个条目。
    Reference,
    /// 恢复码列表。
    RecoveryCodes,
    /// 键值对列表。
    KvList,
    /// 附件（条目详情 v2，`spec/vault-format.md` §2.5）。
    Attachment,
}

impl FieldKind {
    /// 是否默认隐藏。
    #[must_use]
    pub const fn is_concealed(self) -> bool {
        matches!(
            self,
            Self::Concealed | Self::SshPrivateKey | Self::RecoveryCodes
        )
    }
}

/// 字段的自动填充用途。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    /// 用户名。
    Username,
    /// 密码。
    Password,
    /// 一次性密码。
    Otp,
    /// 备注。
    Notes,
}

/// 一个条目修订的完整明文（详情）。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ItemDoc {
    /// 条目类型。
    pub item_type: ItemType,
    /// 记录映射：每个键的当前版本。
    pub records: RecordMap,
    /// 并发版本（`spec/revisions.md` §4.3）：合并后仍互不覆盖、但不是当前值的版本，按 `rev` 升序。
    /// 它们继续参与之后的合并，直到该键被重新写入或用户处理冲突，从而保证分组合并的结果一致。
    pub concurrent: ConcurrentMap,
}

#[derive(Serialize)]
struct ItemDocJsonRef<'a> {
    v: u32,
    #[serde(rename = "type")]
    item_type: ItemType,
    records: &'a RecordMap,
    #[serde(skip_serializing_if = "ConcurrentMap::is_empty")]
    concurrent: &'a ConcurrentMap,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ItemDocJson {
    v: u32,
    #[serde(rename = "type")]
    item_type: ItemType,
    #[serde(deserialize_with = "record::unique_map")]
    records: RecordMap,
    #[serde(default, deserialize_with = "record::unique_map")]
    concurrent: ConcurrentMap,
}

impl ItemDoc {
    /// 空条目。
    #[must_use]
    pub const fn new(item_type: ItemType) -> Self {
        Self {
            item_type,
            records: RecordMap::new(),
            concurrent: ConcurrentMap::new(),
        }
    }

    /// 编码为 JSON。
    ///
    /// # Errors
    /// 序列化失败时返回 [`FormatError::Malformed`]。
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        to_json(&ItemDocJsonRef {
            v: self.version(),
            item_type: self.item_type,
            records: &self.records,
            concurrent: &self.concurrent,
        })
    }

    /// 编码为 JSON，并检查能否放进单个信封（`spec/revisions.md` §7.1）。写入修订前必须用它，
    /// 而不是 [`ItemDoc::encode`]。
    ///
    /// # Errors
    /// 超过 [`keevo_crypto::MAX_PLAINTEXT_LEN`] 时返回 [`FormatError::ItemTooLarge`]：合并后的状态可能
    /// 超过上限，此时读取照常，但需要先精简才能保存，绝不静默丢弃版本。
    pub fn encode_for_write(&self) -> Result<Zeroizing<Vec<u8>>> {
        // 写入边界保证不变量：公开字段可以被直接构造，这里重新校验一遍（第三轮评审 H7）
        self.validate()?;
        let bytes = self.encode()?;
        if bytes.len() > keevo_crypto::MAX_PLAINTEXT_LEN {
            return Err(FormatError::ItemTooLarge);
        }
        Ok(bytes)
    }

    /// 从 JSON 解码并校验。
    ///
    /// # Errors
    /// 结构错误、版本不支持或记录值与键不匹配时返回对应错误。
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        crate::json::check_version_in(bytes, &[FORMAT_VERSION, ITEM_DETAILS_V2])?;
        let doc: ItemDocJson = from_json(bytes)?;
        if doc.v != FORMAT_VERSION && doc.v != ITEM_DETAILS_V2 {
            return Err(FormatError::UnsupportedVersion(doc.v));
        }
        let doc = Self {
            item_type: doc.item_type,
            records: doc.records,
            concurrent: doc.concurrent,
        };
        // 只接受规范编码（第四轮评审 J7）。先比较字节，再做语义校验，错误的先后与规范一致
        if doc.encode()?.as_slice() != bytes {
            return Err(FormatError::Malformed("not canonical".into()));
        }
        doc.validate()?;
        Ok(doc)
    }

    /// 文档的版本（`spec/vault-format.md` §2.5）：任何记录版本（含并发版本）的字段类型是 `attachment`、
    /// 或数据是附件引用时为 2，否则为 1。没有附件的条目仍按 v1 编码，旧版本的 Keevo 照常读取。
    ///
    /// 两个条件都看：`"v":1` 而字段类型与数据只有一方是附件的文档不是规范编码，返回 `malformed`，与 v1 读取方
    /// 对同一文档的结果相同（第五轮预审 K11）。
    #[must_use]
    pub fn version(&self) -> u32 {
        let is_attachment = |v: &crate::RecordVersion| {
            matches!(&v.value, Some(crate::RecordValue::Field(f))
                if f.kind == FieldKind::Attachment || matches!(f.data, crate::FieldData::Attachment(_)))
        };
        let any = self.records.values().any(is_attachment)
            || self.concurrent.values().flatten().any(is_attachment);
        if any { ITEM_DETAILS_V2 } else { FORMAT_VERSION }
    }

    /// 记录键的总数（当前版本与并发版本的键取并集）。
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.records.len().saturating_add(
            self.concurrent
                .keys()
                .filter(|k| !self.records.contains_key(*k))
                .count(),
        )
    }

    /// 校验全部不变量：值的类型、大小与整数范围，并发版本的结构，保留键的形态，键数上限。
    ///
    /// # Errors
    /// 返回第一个不满足的不变量对应的错误。
    pub fn validate(&self) -> Result<()> {
        record::validate(&self.records)?;
        record::validate_concurrent(&self.records, &self.concurrent)?;
        record::validate_reserved(&self.records, &self.concurrent)?;
        if self.key_count() > MAX_KEYS {
            return Err(FormatError::TooManyKeys);
        }
        Ok(())
    }

    /// 读取未删除记录的值。
    #[must_use]
    pub fn get(&self, key: &RecordKey) -> Option<&RecordValue> {
        self.records.get(key).and_then(|v| v.value.as_ref())
    }

    /// 写入记录。
    ///
    /// # Errors
    /// 值的类型与键不匹配时返回 [`FormatError::ValueKindMismatch`]。
    pub fn set(&mut self, key: RecordKey, value: RecordValue, hlc: Hlc, rev: Id128) -> Result<()> {
        if key.is_reserved() {
            return Err(FormatError::ReservedKey);
        }
        record::check_value(&key, &value)?;
        // 新版本写于全部头之后，因果覆盖该键的所有并发版本（§4.2）
        self.concurrent.remove(&key);
        self.records.insert(
            key,
            RecordVersion {
                hlc,
                rev,
                value: Some(value),
            },
        );
        Ok(())
    }

    /// 删除记录：写入墓碑，而不是移除（`spec/revisions.md` §4.2）。
    ///
    /// # Errors
    /// 保留键返回 [`FormatError::ReservedKey`]：确定恢复只能经由 [`ItemDoc::settle_for_write`]。
    pub fn delete(&mut self, key: RecordKey, hlc: Hlc, rev: Id128) -> Result<()> {
        if key.is_reserved() {
            return Err(FormatError::ReservedKey);
        }
        if !key.is_valid() {
            return Err(FormatError::InvalidKey);
        }
        self.write_tombstone(key, hlc, rev);
        Ok(())
    }

    fn write_tombstone(&mut self, key: RecordKey, hlc: Hlc, rev: Id128) {
        self.concurrent.remove(&key);
        self.records.insert(
            key,
            RecordVersion {
                hlc,
                rev,
                value: None,
            },
        );
    }

    /// 某个键上的全部版本：当前版本（若有）在前，其后是并发版本。
    #[must_use]
    pub fn versions(&self, key: &RecordKey) -> Vec<&RecordVersion> {
        self.records
            .get(key)
            .into_iter()
            .chain(self.concurrent.get(key).into_iter().flatten())
            .collect()
    }

    /// 处理冲突（`spec/revisions.md` §5.4）：把用户选中的版本 `keep` 的值作为新版本写入，
    /// 覆盖该键的全部并发版本。
    ///
    /// # Errors
    /// 该键上没有写于 `keep` 的版本时返回 [`FormatError::NoSuchVersion`]。
    pub fn resolve(&mut self, key: &RecordKey, keep: Id128, hlc: Hlc, rev: Id128) -> Result<()> {
        let value = self
            .versions(key)
            .into_iter()
            .find(|v| v.rev == keep)
            .ok_or(FormatError::NoSuchVersion)?
            .value
            .clone();
        match value {
            Some(v) => self.set(key.clone(), v, hlc, rev),
            None => self.delete(key.clone(), hlc, rev),
        }
    }

    /// 写时收敛前的准备（`spec/revisions.md` §5.4）：只有并发版本、没有当前值的键（只会因撤销删除产生）
    /// 写入墓碑，把"已撤销删除"确定下来。否则并发的修改日后被覆盖时，旧的删除会重新生效。
    ///
    /// 同时收拢删除状态键上全为墓碑的并发版本：它们都表示"未删除"，改写成一个新墓碑不改变语义，
    /// 却能让这类版本不再无限累积（第四轮评审 J2）。
    pub fn settle_for_write(&mut self, hlc: Hlc, rev: Id128) {
        let suppressed: Vec<RecordKey> = self
            .concurrent
            .iter()
            .filter(|(k, versions)| {
                !self.records.contains_key(*k)
                    || (k.is_deletion_state()
                        && self
                            .records
                            .get(*k)
                            .is_some_and(RecordVersion::is_tombstone)
                        && versions.iter().all(RecordVersion::is_tombstone))
            })
            .map(|(k, _)| k.clone())
            .collect();
        for key in suppressed {
            self.write_tombstone(key, hlc, rev);
        }
    }

    fn attr_text(&self, name: &str) -> Option<&str> {
        match self.get(&RecordKey::attr(name)) {
            Some(RecordValue::Text(s)) => Some(s.expose()),
            _ => None,
        }
    }

    fn attr_bool(&self, name: &str) -> bool {
        matches!(
            self.get(&RecordKey::attr(name)),
            Some(RecordValue::Bool(true))
        )
    }

    /// 回收站时间（Unix 毫秒）；不在回收站时为 `None`。
    #[must_use]
    pub fn trashed_at(&self) -> Option<i64> {
        match self.get(&RecordKey::attr("trashed")) {
            Some(RecordValue::Int(t)) => Some(*t),
            _ => None,
        }
    }

    /// 由记录映射计算概要（`spec/revisions.md` §4.1）。
    #[must_use]
    pub fn overview(&self) -> ItemOverview {
        let mut fields: Vec<(&String, &Id128, &record::FieldValue)> = self
            .records
            .iter()
            .filter_map(|(k, v)| match (k, &v.value) {
                (RecordKey::Field(id), Some(RecordValue::Field(f))) => Some((&f.order, id, f)),
                _ => None,
            })
            .collect();
        fields.sort_by(|a, b| a.0.cmp(b.0).then(a.1.cmp(b.1)));

        let subtitle = fields
            .iter()
            .find(|(_, _, f)| f.purpose == Some(Purpose::Username))
            .or_else(|| fields.iter().find(|(_, _, f)| f.kind == FieldKind::Email))
            .and_then(|(_, _, f)| f.text())
            .unwrap_or_default()
            .to_owned();
        let urls = fields
            .iter()
            .filter(|(_, _, f)| f.kind == FieldKind::Url)
            .filter_map(|(_, _, f)| f.text().map(str::to_owned))
            .collect();
        let tags = self
            .records
            .iter()
            .filter_map(|(k, v)| match (k, &v.value) {
                (RecordKey::Tag(t), Some(RecordValue::Tag)) => Some(t.clone()),
                _ => None,
            })
            .collect();

        ItemOverview {
            v: FORMAT_VERSION,
            item_type: self.item_type,
            title: self.attr_text("title").unwrap_or_default().to_owned(),
            subtitle,
            urls,
            tags,
            favorite: self.attr_bool("favorite"),
            archived: self.attr_bool("archived"),
            trashed_at: self.trashed_at(),
            updated: self
                .records
                .values()
                .map(|v| v.hlc)
                .max()
                .unwrap_or_default(),
            conflicts: self.has_unresolved_conflicts(),
        }
    }

    /// 是否存在待用户处理的冲突：某个键的并发版本中有值与当前值不同的版本（`spec/revisions.md` §5.5）。
    #[must_use]
    pub fn has_unresolved_conflicts(&self) -> bool {
        self.concurrent.iter().any(|(key, versions)| {
            // 没有当前版本的键是被撤销的删除，由合并结果的 `resurrected` 表示，不算字段冲突
            self.records
                .get(key)
                .is_some_and(|current| versions.iter().any(|v| v.value != current.value))
        })
    }
}

/// 条目概要：列表与搜索只解密这一部分。
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemOverview {
    /// 格式版本。
    pub v: u32,
    /// 条目类型。
    #[serde(rename = "type")]
    pub item_type: ItemType,
    /// 标题。
    pub title: String,
    /// 副标题（通常是用户名）。
    pub subtitle: String,
    /// 网址，用于自动填充匹配。
    pub urls: Vec<String>,
    /// 标签。
    pub tags: Vec<String>,
    /// 是否收藏。
    pub favorite: bool,
    /// 是否归档。
    pub archived: bool,
    /// 回收站时间。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trashed_at: Option<i64>,
    /// 最近修改时间（所有记录的最大 HLC）。
    pub updated: Hlc,
    /// 是否存在待处理的冲突。列表据此标记条目，而不必解密详情。
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub conflicts: bool,
}

impl ItemOverview {
    /// 编码为 JSON。
    ///
    /// # Errors
    /// 序列化失败时返回 [`FormatError::Malformed`]。
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        to_json(self)
    }

    /// 从 JSON 解码。
    ///
    /// # Errors
    /// 结构错误或版本不支持时返回对应错误。
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        crate::json::check_version(bytes, FORMAT_VERSION)?;
        let o: Self = from_canonical_json(bytes)?;
        if o.v != FORMAT_VERSION {
            return Err(FormatError::UnsupportedVersion(o.v));
        }
        // 与条目详情使用同一个整数范围（第三轮评审 H7）
        if o.trashed_at
            .is_some_and(|t| !(-MAX_SAFE_INT..=MAX_SAFE_INT).contains(&t))
        {
            return Err(FormatError::ValueTooLarge);
        }
        Ok(o)
    }
}

/// 保险库元数据（v0.1 为单一文档，见 `spec/vault-format.md` §5）。
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultMeta {
    /// 格式版本。
    pub v: u32,
    /// 名称。
    pub name: String,
    /// 修改时间。
    pub updated: Hlc,
}

impl VaultMeta {
    /// 新建。
    #[must_use]
    pub fn new(name: &str, updated: Hlc) -> Self {
        Self {
            v: FORMAT_VERSION,
            name: name.to_owned(),
            updated,
        }
    }

    /// 编码为 JSON。
    ///
    /// # Errors
    /// 序列化失败时返回 [`FormatError::Malformed`]。
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        to_json(self)
    }

    /// 从 JSON 解码。
    ///
    /// # Errors
    /// 结构错误或版本不支持时返回对应错误。
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        crate::json::check_version(bytes, FORMAT_VERSION)?;
        let m: Self = from_canonical_json(bytes)?;
        if m.v != FORMAT_VERSION {
            return Err(FormatError::UnsupportedVersion(m.v));
        }
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{FieldData, FieldValue, KvEntry};

    /// 第四轮评审 J3：写入与解码使用同一条键名规则，非法键名在写入时就被拒绝。
    #[test]
    fn review4_j3_invalid_key_names_are_rejected_on_write() {
        let rev = Id128::from_bytes([7; 16]);
        let mut d = ItemDoc::new(ItemType::Login);
        for key in [
            RecordKey::Tag(String::new()),
            RecordKey::Tag("x".repeat(257)),
            RecordKey::attr("Title"),
            RecordKey::attr(""),
        ] {
            assert_eq!(
                d.set(key.clone(), RecordValue::Tag, Hlc(1), rev).err(),
                Some(FormatError::InvalidKey),
                "{key:?}"
            );
            assert_eq!(
                d.delete(key.clone(), Hlc(1), rev).err(),
                Some(FormatError::InvalidKey),
                "{key:?}"
            );
        }
        // 绕过 set 直接构造，也在写入边界被拒绝
        d.records.insert(
            RecordKey::Tag(String::new()),
            RecordVersion {
                hlc: Hlc(1),
                rev,
                value: Some(RecordValue::Tag),
            },
        );
        assert_eq!(d.encode_for_write().err(), Some(FormatError::InvalidKey));
    }

    /// 第四轮评审 J7：只接受规范编码。数组形式的结构体、`tag` 的对象写法、可选字段写成 null、
    /// 非规范的数字写法都拒绝；可以表示但超出安全范围的整数报 `value_too_large`。
    #[test]
    fn review4_j7_only_canonical_encodings_are_accepted() {
        let good = sample().encode().unwrap();
        assert!(ItemDoc::decode(&good).is_ok());
        let text = String::from_utf8(good.to_vec()).unwrap();
        let rejects = |json: &str| {
            assert!(
                matches!(
                    ItemDoc::decode(json.as_bytes()),
                    Err(FormatError::Malformed(_))
                ),
                "{json}"
            );
        };
        rejects(&text.replacen("{\"v\":1,", "{ \"v\":1,", 1));
        rejects(r#"[1,"login",{}]"#);
        rejects(&text.replacen("\"val\":\"tag\"", "\"val\":{\"tag\":null}", 1));
        let rev = "07".repeat(16);
        let with_null = format!(
            r#"{{"v":1,"type":"login","records":{{"field:{f}":{{"hlc":"0000000000000001","rev":"{rev}","val":{{"field":{{"section":null,"order":"a0","kind":"text","label":"l","purpose":null,"data":{{"text":"x"}}}}}}}}}}}}"#,
            f = "01".repeat(16)
        );
        rejects(&with_null);
        for n in ["-0", "0.0", "0e0", "18446744073709551616"] {
            rejects(&format!(
                r#"{{"v":1,"type":"login","records":{{"attr:n":{{"hlc":"0000000000000001","rev":"{rev}","val":{{"int":{n}}}}}}}}}"#
            ));
        }
        let big = format!(
            r#"{{"v":1,"type":"login","records":{{"attr:n":{{"hlc":"0000000000000001","rev":"{rev}","val":{{"int":9007199254740992}}}}}}}}"#
        );
        assert_eq!(
            ItemDoc::decode(big.as_bytes()),
            Err(FormatError::ValueTooLarge)
        );
        // 附件字段不在 v1 中
        rejects(&text.replacen("\"kind\":\"text\"", "\"kind\":\"file\"", 1));
    }

    /// 第四轮评审 J2：删除状态键上全为墓碑的并发版本在写入前收拢成一个新墓碑，不会无限累积。
    #[test]
    fn review4_j2_settled_restore_tombstones_collapse() {
        let purged = RecordKey::attr("purged");
        let mut d = ItemDoc::new(ItemType::Login);
        d.records.insert(
            purged.clone(),
            RecordVersion {
                hlc: Hlc(5),
                rev: Id128::from_bytes([1; 16]),
                value: None,
            },
        );
        let many: Vec<RecordVersion> = (2..200u8)
            .map(|i| RecordVersion {
                hlc: Hlc(5),
                rev: Id128::from_bytes([i; 16]),
                value: None,
            })
            .collect();
        d.concurrent.insert(purged.clone(), many);
        assert!(d.validate().is_ok());
        d.settle_for_write(Hlc(9), Id128::from_bytes([250; 16]));
        assert!(!d.concurrent.contains_key(&purged));
        assert!(d.records[&purged].is_tombstone());
        assert_eq!(d.records[&purged].rev, Id128::from_bytes([250; 16]));
    }

    /// 第三轮评审 H2：键数在上限之内时，"删除全部字段"之后的墓碑一定放得进一个信封，
    /// 即使每个键名都是最长、且每个字节都需要转义（`spec/revisions.md` §7.1）。
    #[test]
    fn review3_h2_all_tombstones_within_key_limit_fit_one_envelope() {
        let mut d = ItemDoc::new(ItemType::Login);
        let rev = Id128::from_bytes([7; 16]);
        for i in 0..MAX_KEYS {
            let mut name = format!("{i:04}");
            name.push_str(&"\u{1}".repeat(256 - name.len()));
            d.delete(RecordKey::Tag(name), Hlc(u64::MAX), rev).unwrap();
        }
        assert_eq!(d.key_count(), MAX_KEYS);
        let bytes = d.encode_for_write().unwrap();
        assert!(
            bytes.len() < keevo_crypto::MAX_PLAINTEXT_LEN / 2,
            "{}",
            bytes.len()
        );
    }

    /// 第三轮评审 H4：保留键不能直接写入；解码时只接受规范允许的形态。
    #[test]
    fn review3_h4_reserved_purged_key_is_enforced() {
        let purged = RecordKey::attr("purged");
        let rev = Id128::from_bytes([7; 16]);
        let mut d = ItemDoc::new(ItemType::Login);
        assert_eq!(
            d.set(purged.clone(), RecordValue::Bool(true), Hlc(2), rev),
            Err(FormatError::ReservedKey)
        );
        assert_eq!(
            d.delete(purged.clone(), Hlc(2), rev),
            Err(FormatError::ReservedKey)
        );

        let decodes = |doc: &ItemDoc| ItemDoc::decode(&doc.encode().unwrap());
        // 当前版本是活的删除标记：拒绝
        let mut live = ItemDoc::new(ItemType::Login);
        live.records.insert(
            purged.clone(),
            RecordVersion {
                hlc: Hlc(7),
                rev,
                value: Some(RecordValue::Bool(false)),
            },
        );
        assert_eq!(decodes(&live), Err(FormatError::ReservedKey));
        assert_eq!(
            live.encode_for_write().err(),
            Some(FormatError::ReservedKey)
        );
        // 并发版本里出现非删除标记的值：拒绝
        let mut odd = ItemDoc::new(ItemType::Login);
        odd.concurrent.insert(
            purged.clone(),
            vec![RecordVersion {
                hlc: Hlc(0),
                rev,
                value: Some(RecordValue::Bool(false)),
            }],
        );
        assert_eq!(decodes(&odd), Err(FormatError::ReservedKey));
        // 合法形态：被撤销的删除版本（hlc 0、true），以及已确定恢复的墓碑
        let mut ok = ItemDoc::new(ItemType::Login);
        ok.concurrent.insert(
            purged.clone(),
            vec![RecordVersion {
                hlc: Hlc(0),
                rev,
                value: Some(RecordValue::Bool(true)),
            }],
        );
        assert!(decodes(&ok).is_ok());
        ok.settle_for_write(Hlc(9), Id128::from_bytes([8; 16]));
        assert!(decodes(&ok).is_ok());
        assert!(ok.records[&purged].is_tombstone());
    }

    /// 第三轮评审 H7：概要与详情使用同一个整数范围；写入前重新校验直接构造的文档。
    #[test]
    fn review3_h7_overview_ints_and_write_validation() {
        let mut o = sample().overview();
        o.trashed_at = Some(record::MAX_SAFE_INT + 1);
        assert_eq!(
            ItemOverview::decode(&o.encode().unwrap()),
            Err(FormatError::ValueTooLarge)
        );
        let mut d = ItemDoc::new(ItemType::Login);
        d.records.insert(
            RecordKey::Tag("t".into()),
            RecordVersion {
                hlc: Hlc(1),
                rev: Id128::from_bytes([7; 16]),
                value: Some(RecordValue::Bool(true)),
            },
        );
        assert_eq!(
            d.encode_for_write().err(),
            Some(FormatError::ValueKindMismatch)
        );
    }

    /// 第二轮评审 §4：重复的记录键、超过 256 KiB 的值、超出 ±(2⁵³−1) 的整数都拒绝。
    #[test]
    fn duplicate_keys_oversized_values_and_unsafe_ints_are_rejected() {
        let dup = br#"{"v":1,"type":"login","records":{"attr:title":{"hlc":"0000000000000001","rev":"07070707070707070707070707070707","val":{"text":"a"}},"attr:title":{"hlc":"0000000000000002","rev":"07070707070707070707070707070707","val":{"text":"b"}}}}"#;
        assert!(matches!(
            ItemDoc::decode(dup),
            Err(FormatError::Malformed(_))
        ));

        let mut d = ItemDoc::new(ItemType::SecureNote);
        let rev = Id128::from_bytes([7; 16]);
        let big = "x".repeat(record::MAX_VALUE_LEN);
        assert_eq!(
            d.set(
                RecordKey::attr("note"),
                RecordValue::Text(big.as_str().into()),
                Hlc(1),
                rev
            ),
            Err(FormatError::ValueTooLarge)
        );
        assert_eq!(
            d.set(
                RecordKey::attr("n"),
                RecordValue::Int(record::MAX_SAFE_INT + 1),
                Hlc(1),
                rev
            ),
            Err(FormatError::ValueTooLarge)
        );
        assert!(
            d.set(
                RecordKey::attr("n"),
                RecordValue::Int(record::MAX_SAFE_INT),
                Hlc(1),
                rev
            )
            .is_ok()
        );
    }

    #[test]
    fn concurrent_versions_roundtrip_and_are_validated() {
        let mut d = ItemDoc::new(ItemType::Login);
        let title = RecordKey::attr("title");
        d.set(
            title.clone(),
            RecordValue::Text("B".into()),
            Hlc(30),
            Id128::from_bytes([3; 16]),
        )
        .unwrap();
        d.concurrent.insert(
            title.clone(),
            vec![RecordVersion {
                hlc: Hlc(20),
                rev: Id128::from_bytes([2; 16]),
                value: Some(RecordValue::Text("A".into())),
            }],
        );
        let json = d.encode().unwrap();
        assert!(
            std::str::from_utf8(&json)
                .unwrap()
                .contains("\"concurrent\"")
        );
        assert_eq!(ItemDoc::decode(&json).unwrap(), d);
        assert!(d.has_unresolved_conflicts());
        assert!(d.overview().conflicts);
        // 没有并发版本时省略该字段，旧文档照常解析
        let plain = sample().encode().unwrap();
        assert!(!std::str::from_utf8(&plain).unwrap().contains("concurrent"));

        let bad = |mutate: &dyn Fn(&mut ItemDoc)| {
            let mut x = d.clone();
            mutate(&mut x);
            ItemDoc::decode(&x.encode().unwrap()).is_err()
        };
        assert!(
            bad(&|x| x.concurrent.get_mut(&title).unwrap().clear()),
            "空列表"
        );
        assert!(
            bad(&|x| {
                let cur = x.records[&title].clone();
                x.concurrent.get_mut(&title).unwrap().push(cur);
            }),
            "与当前版本重复"
        );
        assert!(
            bad(&|x| {
                let v = x.concurrent[&title][0].clone();
                x.concurrent.get_mut(&title).unwrap().push(v);
            }),
            "未按 rev 严格升序"
        );
        assert!(
            bad(&|x| x.concurrent.get_mut(&title).unwrap()[0].value = Some(RecordValue::Tag)),
            "值与键不匹配"
        );
        assert!(
            bad(&|x| {
                x.records.remove(&title);
            }),
            "普通键只有并发版本、没有当前版本"
        );
        // 删除状态键可以只有并发版本（撤销删除后）
        let mut restored = ItemDoc::new(ItemType::Login);
        restored.concurrent.insert(
            RecordKey::attr("trashed"),
            vec![RecordVersion {
                hlc: Hlc(5),
                rev: Id128::from_bytes([9; 16]),
                value: Some(RecordValue::Int(1)),
            }],
        );
        assert_eq!(
            ItemDoc::decode(&restored.encode().unwrap()).unwrap(),
            restored
        );
        assert!(!restored.has_unresolved_conflicts());
    }

    fn sample() -> ItemDoc {
        let rev = Id128::from_bytes([7; 16]);
        let mut d = ItemDoc::new(ItemType::Login);
        d.set(
            RecordKey::attr("title"),
            RecordValue::Text("GitHub".into()),
            Hlc(1),
            rev,
        )
        .unwrap();
        d.set(RecordKey::Tag("work".into()), RecordValue::Tag, Hlc(1), rev)
            .unwrap();
        let field = |order: &str, kind, label: &str, purpose, value: &str| FieldValue {
            section: None,
            order: order.into(),
            kind,
            label: label.into(),
            purpose,
            data: FieldData::Text(value.into()),
        };
        d.set(
            RecordKey::Field(Id128::from_bytes([1; 16])),
            RecordValue::Field(field(
                "a0",
                FieldKind::Text,
                "用户名",
                Some(Purpose::Username),
                "octocat",
            )),
            Hlc(2),
            rev,
        )
        .unwrap();
        d.set(
            RecordKey::Field(Id128::from_bytes([2; 16])),
            RecordValue::Field(field(
                "a1",
                FieldKind::Concealed,
                "密码",
                Some(Purpose::Password),
                "p@ss\"\\🔐",
            )),
            Hlc(3),
            rev,
        )
        .unwrap();
        d.set(
            RecordKey::Field(Id128::from_bytes([3; 16])),
            RecordValue::Field(field(
                "a2",
                FieldKind::Url,
                "网站",
                None,
                "https://github.com/login",
            )),
            Hlc(4),
            rev,
        )
        .unwrap();
        d.delete(RecordKey::Field(Id128::from_bytes([4; 16])), Hlc(5), rev)
            .unwrap();
        d
    }

    #[test]
    fn encode_decode_roundtrip() {
        let d = sample();
        let json = d.encode().unwrap();
        assert_eq!(json.len(), json.capacity(), "按精确长度分配");
        assert_eq!(ItemDoc::decode(&json).unwrap(), d);
    }

    #[test]
    fn overview_is_derived_from_records() {
        let o = sample().overview();
        assert_eq!(o.title, "GitHub");
        assert_eq!(o.subtitle, "octocat");
        assert_eq!(o.urls, vec!["https://github.com/login".to_owned()]);
        assert_eq!(o.tags, vec!["work".to_owned()]);
        assert_eq!(o.updated, Hlc(5));
        assert_eq!(ItemOverview::decode(&o.encode().unwrap()).unwrap(), o);
    }

    #[test]
    fn rejects_mismatched_values_and_bad_documents() {
        let mut d = ItemDoc::new(ItemType::Login);
        let rev = Id128::ZERO;
        assert_eq!(
            d.set(
                RecordKey::Tag("x".into()),
                RecordValue::Bool(true),
                Hlc(1),
                rev
            ),
            Err(FormatError::ValueKindMismatch)
        );
        let kv_as_text = FieldValue {
            section: None,
            order: "a".into(),
            kind: FieldKind::KvList,
            label: "env".into(),
            purpose: None,
            data: FieldData::Text("X=1".into()),
        };
        assert_eq!(
            d.set(
                RecordKey::Field(Id128::ZERO),
                RecordValue::Field(kv_as_text),
                Hlc(1),
                rev
            ),
            Err(FormatError::ValueKindMismatch)
        );
        let kv = FieldValue {
            section: None,
            order: "a".into(),
            kind: FieldKind::KvList,
            label: "env".into(),
            purpose: None,
            data: FieldData::Kv(vec![KvEntry {
                key: "API_KEY".into(),
                value: "s".into(),
                concealed: true,
            }]),
        };
        assert!(
            d.set(
                RecordKey::Field(Id128::ZERO),
                RecordValue::Field(kv),
                Hlc(1),
                rev
            )
            .is_ok()
        );

        assert!(matches!(
            ItemDoc::decode(b"{"),
            Err(FormatError::Malformed(_))
        ));
        assert_eq!(
            ItemDoc::decode(br#"{"v":3,"type":"login","records":{}}"#),
            Err(FormatError::UnsupportedVersion(3))
        );
        // v2 只用于含附件的文档：没有附件的 v2 不是规范编码
        assert!(matches!(
            ItemDoc::decode(br#"{"v":2,"type":"login","records":{}}"#),
            Err(FormatError::Malformed(_))
        ));
        // 键名不合法是语义错误（spec/vault-format.md §1.1 第 3 步），不是 malformed；未知的种类前缀才是结构错误
        let bad_key = br#"{"v":1,"type":"login","records":{"attr:Title":{"hlc":"0000000000000001","rev":"00000000000000000000000000000000"}}}"#;
        assert_eq!(ItemDoc::decode(bad_key), Err(FormatError::InvalidKey));
        let bad_kind = br#"{"v":1,"type":"login","records":{"label:x":{"hlc":"0000000000000001","rev":"00000000000000000000000000000000"}}}"#;
        assert!(matches!(
            ItemDoc::decode(bad_kind),
            Err(FormatError::Malformed(_))
        ));
        let mismatch = br#"{"v":1,"type":"login","records":{"tag:x":{"hlc":"0000000000000001","rev":"00000000000000000000000000000000","val":{"bool":true}}}}"#;
        assert_eq!(
            ItemDoc::decode(mismatch),
            Err(FormatError::ValueKindMismatch)
        );
    }

    #[test]
    fn decode_errors_do_not_leak_content() {
        let leaky = br#"{"v":1,"type":"login","records":{"attr:title":{"hlc":"0000000000000001","rev":"00000000000000000000000000000000","val":{"text":"TOP-SECRET-VALUE","oops":1}}}}"#;
        let err = ItemDoc::decode(leaky).unwrap_err().to_string();
        assert!(!err.contains("TOP-SECRET"), "{err}");
    }
}
