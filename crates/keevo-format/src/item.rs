//! 条目与保险库的明文结构（`spec/vault-format.md`）。

use keevo_crypto::Id128;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::FORMAT_VERSION;
use crate::error::{FormatError, Result};
use crate::hlc::Hlc;
use crate::json::{from_json, to_json};
use crate::record::{self, ConcurrentMap, RecordKey, RecordMap, RecordValue, RecordVersion};

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
    /// 附件引用。
    File,
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
    records: RecordMap,
    #[serde(default)]
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
            v: FORMAT_VERSION,
            item_type: self.item_type,
            records: &self.records,
            concurrent: &self.concurrent,
        })
    }

    /// 从 JSON 解码并校验。
    ///
    /// # Errors
    /// 结构错误、版本不支持或记录值与键不匹配时返回对应错误。
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let doc: ItemDocJson = from_json(bytes)?;
        if doc.v != FORMAT_VERSION {
            return Err(FormatError::UnsupportedVersion(doc.v));
        }
        record::validate(&doc.records)?;
        record::validate_concurrent(&doc.records, &doc.concurrent)?;
        Ok(Self {
            item_type: doc.item_type,
            records: doc.records,
            concurrent: doc.concurrent,
        })
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
        if !key.accepts(&value) {
            return Err(FormatError::ValueKindMismatch);
        }
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
    pub fn delete(&mut self, key: RecordKey, hlc: Hlc, rev: Id128) {
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
            None => {
                self.delete(key.clone(), hlc, rev);
                Ok(())
            }
        }
    }

    /// 写时收敛前的准备（`spec/revisions.md` §5.4）：只有并发版本、没有当前值的键（只会因撤销删除产生）
    /// 写入墓碑，把"已撤销删除"确定下来。否则并发的修改日后被覆盖时，旧的删除会重新生效。
    pub fn settle_for_write(&mut self, hlc: Hlc, rev: Id128) {
        let suppressed: Vec<RecordKey> = self
            .concurrent
            .keys()
            .filter(|k| !self.records.contains_key(*k))
            .cloned()
            .collect();
        for key in suppressed {
            self.delete(key, hlc, rev);
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
            let current = self.records.get(key).map(|v| &v.value);
            versions.iter().any(|v| Some(&v.value) != current)
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
        let o: Self = from_json(bytes)?;
        if o.v != FORMAT_VERSION {
            return Err(FormatError::UnsupportedVersion(o.v));
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
        let m: Self = from_json(bytes)?;
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
        d.delete(RecordKey::Field(Id128::from_bytes([4; 16])), Hlc(5), rev);
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
            ItemDoc::decode(br#"{"v":2,"type":"login","records":{}}"#),
            Err(FormatError::UnsupportedVersion(2))
        );
        let bad_key = br#"{"v":1,"type":"login","records":{"attr:Title":{"hlc":"0000000000000001","rev":"00000000000000000000000000000000"}}}"#;
        assert!(matches!(
            ItemDoc::decode(bad_key),
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
