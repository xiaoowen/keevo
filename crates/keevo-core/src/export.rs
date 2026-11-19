//! 导出（`spec/export.md`，设计稿"macOS · 导入与导出"）：Keevo 加密文件（推荐）、明文 JSON（全部条目与字段）、
//! 明文 CSV（只有登录）。不导出最近删除中的条目与历史版本。明文导出由界面先重新验证用户、提示风险。

use std::collections::BTreeMap;

use keevo_crypto::KdfParams;
use keevo_format::{FieldData, ItemDoc, ItemType, Purpose, RecordKey, RecordValue};
use zeroize::Zeroizing;

use crate::Id128;
use crate::error::{CoreError, Result};
use crate::import::keevo::{
    ExportCode, ExportField, ExportFile, ExportItem, ExportKv, ExportVault, FORMAT, VERSION,
};
use crate::vault::Vault;

/// 导出格式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Keevo 加密文件（`.keevo-export`）。
    Keevo,
    /// 明文 JSON。
    Json,
    /// 明文 CSV，只有登录。
    Csv,
}

impl Format {
    /// 由标识（`keevo`、`json`、`csv`）解析。
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "keevo" => Self::Keevo,
            "json" => Self::Json,
            "csv" => Self::Csv,
            _ => return None,
        })
    }
}

/// 导出的内容与条目数。
pub struct Exported {
    /// 文件内容。明文格式中有全部秘密，用完即清零。
    pub bytes: Zeroizing<Vec<u8>>,
    /// 条目数。
    pub count: usize,
}

/// 导出全部保险库，或 `only` 指定的一个。`password` 只用于 [`Format::Keevo`]（至少 10 个字符）。
/// 加密导出约需一秒（Argon2id），应在后台线程调用。
///
/// # Errors
/// 已锁定；保险库不存在；导出密码过短（[`CoreError::OutOfRange`]）；序列化或加密失败。
pub fn export(
    vault: &Vault,
    format: Format,
    only: Option<Id128>,
    password: Option<&str>,
) -> Result<Exported> {
    let vaults = collect(vault, only)?;
    let mut count = vaults.iter().map(|(_, items)| items.len()).sum();
    let bytes = match format {
        Format::Csv => {
            count = vaults
                .iter()
                .flat_map(|(_, items)| items)
                .filter(|d| d.item_type == ItemType::Login)
                .count();
            csv(&vaults)
        }
        Format::Json => json(vaults)?,
        Format::Keevo => {
            let password = password.ok_or(CoreError::OutOfRange)?;
            if password.chars().count() < 10 {
                return Err(CoreError::OutOfRange);
            }
            let plain = json(vaults)?;
            let params = KdfParams::generate_default()?;
            Zeroizing::new(keevo_crypto::seal_export(password, &params, &plain)?)
        }
    };
    Ok(Exported { bytes, count })
}

fn collect(vault: &Vault, only: Option<Id128>) -> Result<Vec<(String, Vec<ItemDoc>)>> {
    let mut by_vault: BTreeMap<Id128, Vec<ItemDoc>> = BTreeMap::new();
    let infos = vault.vaults()?;
    if only.is_some_and(|id| !infos.iter().any(|v| v.id == id)) {
        return Err(CoreError::NotFound);
    }
    for summary in vault.items()? {
        if summary.overview.trashed_at.is_some() || only.is_some_and(|id| id != summary.vault_id) {
            continue;
        }
        let view = vault.item(summary.id)?;
        by_vault.entry(summary.vault_id).or_default().push(view.doc);
    }
    Ok(infos
        .into_iter()
        .filter(|v| only.is_none_or(|id| id == v.id))
        .map(|v| {
            let mut items = by_vault.remove(&v.id).unwrap_or_default();
            items.sort_by_key(|d| d.overview().title.to_lowercase());
            (v.name, items)
        })
        .collect())
}

fn json(vaults: Vec<(String, Vec<ItemDoc>)>) -> Result<Zeroizing<Vec<u8>>> {
    let file = ExportFile {
        format: FORMAT.into(),
        version: VERSION,
        exported_at: now_rfc3339(),
        vaults: vaults
            .into_iter()
            .map(|(name, docs)| ExportVault {
                name,
                items: docs.iter().map(item).collect(),
            })
            .collect(),
    };
    let mut out = Zeroizing::new(Vec::new());
    serde_json::to_writer_pretty(&mut *out, &file)
        .map_err(|_| CoreError::Format(keevo_format::FormatError::Malformed("export".into())))?;
    Ok(out)
}

fn item(doc: &ItemDoc) -> ExportItem {
    let overview = doc.overview();
    // 分区与字段按排序键排列
    let mut sections: Vec<(Id128, &keevo_format::SectionValue)> = doc
        .records
        .iter()
        .filter_map(|(k, v)| match (k, &v.value) {
            (RecordKey::Section(id), Some(RecordValue::Section(s))) => Some((*id, s)),
            _ => None,
        })
        .collect();
    sections.sort_by(|a, b| a.1.order.cmp(&b.1.order));
    let mut fields: Vec<&keevo_format::FieldValue> = doc
        .records
        .iter()
        .filter_map(|(k, v)| match (k, &v.value) {
            // 附件不导出（spec/export.md §2）
            (RecordKey::Field(_), Some(RecordValue::Field(f)))
                if !matches!(f.data, FieldData::Attachment(_)) =>
            {
                Some(f)
            }
            _ => None,
        })
        .collect();
    let section_index =
        |id: Option<Id128>| id.and_then(|id| sections.iter().position(|(s, _)| *s == id));
    fields.sort_by(|a, b| {
        (
            section_index(a.section).map_or(0, |i| i.saturating_add(1)),
            &a.order,
        )
            .cmp(&(
                section_index(b.section).map_or(0, |i| i.saturating_add(1)),
                &b.order,
            ))
    });
    ExportItem {
        item_type: doc.item_type,
        title: overview.title,
        favorite: overview.favorite,
        tags: overview.tags,
        sections: sections.iter().map(|(_, s)| s.label.clone()).collect(),
        fields: fields
            .into_iter()
            .map(|f| {
                let (value, entries, codes) = match &f.data {
                    FieldData::Text(t) => (Some(t.clone()), None, None),
                    FieldData::Kv(list) => (
                        None,
                        Some(
                            list.iter()
                                .map(|e| ExportKv {
                                    key: e.key.clone(),
                                    value: e.value.clone(),
                                    concealed: e.concealed,
                                })
                                .collect(),
                        ),
                        None,
                    ),
                    FieldData::Attachment(_) => (None, None, None),
                    FieldData::Codes(list) => (
                        None,
                        None,
                        Some(
                            list.iter()
                                .map(|c| ExportCode {
                                    code: c.code.clone(),
                                    used: c.used,
                                })
                                .collect(),
                        ),
                    ),
                };
                ExportField {
                    section: section_index(f.section),
                    kind: f.kind,
                    label: f.label.clone(),
                    purpose: f.purpose,
                    value,
                    entries,
                    codes,
                }
            })
            .collect(),
    }
}

/// CSV：`name,url,username,password,note,totp`，只有登录（Chrome、Safari、Bitwarden 等都能导入这些列）。
fn csv(vaults: &[(String, Vec<ItemDoc>)]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(String::from("name,url,username,password,note,totp\n"));
    for doc in vaults.iter().flat_map(|(_, items)| items) {
        if doc.item_type != ItemType::Login {
            continue;
        }
        let fields: Vec<&keevo_format::FieldValue> = doc
            .records
            .values()
            .filter_map(|v| match &v.value {
                Some(RecordValue::Field(f)) => Some(f),
                _ => None,
            })
            .collect();
        let text = |pred: &dyn Fn(&keevo_format::FieldValue) -> bool| {
            fields
                .iter()
                .filter(|f| pred(f))
                .find_map(|f| f.text().filter(|t| !t.is_empty()))
                .unwrap_or_default()
        };
        let row = [
            doc.overview().title,
            text(&|f| f.kind == keevo_format::FieldKind::Url).to_owned(),
            text(&|f| f.purpose == Some(Purpose::Username)).to_owned(),
            text(&|f| f.purpose == Some(Purpose::Password)).to_owned(),
            text(&|f| f.purpose == Some(Purpose::Notes)).to_owned(),
            text(&|f| f.kind == keevo_format::FieldKind::Totp).to_owned(),
        ];
        let line: Vec<String> = row.iter().map(|v| csv_field(v)).collect();
        out.push_str(&line.join(","));
        out.push('\n');
    }
    Zeroizing::new(core::mem::take(&mut *out).into_bytes())
}

fn csv_field(v: &str) -> String {
    if v.contains([',', '"', '\n', '\r']) || v.starts_with(' ') || v.ends_with(' ') {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v.to_owned()
    }
}

fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    let date = crate::import::date_from_days(days);
    format!(
        "{date}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    )
}
