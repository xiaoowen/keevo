//! Keevo 的导出格式（`spec/export.md`）：明文 JSON，或用导出密码加密的文件（`keevo_crypto::seal_export`）。
//! 导出（`crate::export`）与导入共用这里的结构。

use keevo_crypto::CryptoError;
use keevo_format::{CodeEntry, FieldData, FieldKind, ItemType, KvEntry, Purpose, SecretString};
use serde::{Deserialize, Serialize};

use super::{Builder, ImportError, Parsed};
use crate::vault::NewField;

/// `format` 的值。
pub(crate) const FORMAT: &str = "keevo-export";
/// 当前版本。
pub(crate) const VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
pub(crate) struct ExportFile {
    pub(crate) format: String,
    pub(crate) version: u32,
    /// 导出时间（UTC，RFC 3339）。
    pub(crate) exported_at: String,
    pub(crate) vaults: Vec<ExportVault>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ExportVault {
    pub(crate) name: String,
    pub(crate) items: Vec<ExportItem>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ExportItem {
    #[serde(rename = "type")]
    pub(crate) item_type: ItemType,
    pub(crate) title: String,
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub(crate) favorite: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) sections: Vec<String>,
    pub(crate) fields: Vec<ExportField>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ExportField {
    /// 分区下标（`sections`）；没有时为默认分区。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) section: Option<usize>,
    pub(crate) kind: FieldKind,
    pub(crate) label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) purpose: Option<Purpose>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) value: Option<SecretString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) entries: Option<Vec<ExportKv>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) codes: Option<Vec<ExportCode>>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ExportKv {
    pub(crate) key: String,
    pub(crate) value: SecretString,
    #[serde(default)]
    pub(crate) concealed: bool,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ExportCode {
    pub(crate) code: SecretString,
    #[serde(default)]
    pub(crate) used: bool,
}

pub(super) fn parse(data: &[u8], password: Option<&str>) -> Result<Parsed, ImportError> {
    let plain;
    let json = if keevo_crypto::is_export(data) {
        let password = password.ok_or(ImportError::PasswordRequired)?;
        plain = keevo_crypto::open_export(password, data).map_err(|e| match e {
            CryptoError::DecryptionFailed | CryptoError::EmptyPassword => {
                ImportError::WrongPassword
            }
            CryptoError::KdfAboveMaximum => ImportError::TooLarge,
            _ => ImportError::Malformed,
        })?;
        plain.as_slice()
    } else {
        data
    };
    super::check_json_nodes(json)?;
    let file: ExportFile = serde_json::from_slice(json).map_err(|_| ImportError::NotRecognized)?;
    if file.format != FORMAT || file.version != VERSION {
        return Err(ImportError::NotRecognized);
    }
    let several = file.vaults.len() > 1;
    let mut out = Parsed::default();
    for vault in file.vaults {
        for item in vault.items {
            // Keevo 自己的格式：原样导入（spec/export.md §2）
            let mut b = Builder::exact(item.item_type, &item.title);
            let sections: Vec<Option<usize>> = item.sections.iter().map(|s| b.section(s)).collect();
            for f in item.fields {
                let section = f.section.and_then(|i| sections.get(i).copied().flatten());
                // 恰好一种数据，且与字段类型一致（spec/export.md §2）；否则跳过这个字段并在备注中说明，
                // 而不是让整次导入失败（第五轮预审 K20）
                let text_kind = !matches!(
                    f.kind,
                    FieldKind::KvList | FieldKind::RecoveryCodes | FieldKind::Attachment
                );
                match (f.value, f.entries, f.codes) {
                    (None, None, None) => {}
                    (Some(v), None, None) if text_kind => {
                        b.add(section, f.kind, &f.label, f.purpose, v.expose());
                    }
                    (None, Some(entries), None) if f.kind == FieldKind::KvList => b.push(
                        section,
                        NewField {
                            kind: FieldKind::KvList,
                            label: f.label,
                            purpose: None,
                            data: FieldData::Kv(
                                entries
                                    .into_iter()
                                    .map(|e| KvEntry {
                                        key: e.key,
                                        value: e.value,
                                        concealed: e.concealed,
                                    })
                                    .collect(),
                            ),
                        },
                    ),
                    (None, None, Some(codes)) if f.kind == FieldKind::RecoveryCodes => b.push(
                        section,
                        NewField {
                            kind: FieldKind::RecoveryCodes,
                            label: f.label,
                            purpose: None,
                            data: FieldData::Codes(
                                codes
                                    .into_iter()
                                    .map(|c| CodeEntry {
                                        code: c.code,
                                        used: c.used,
                                    })
                                    .collect(),
                            ),
                        },
                    ),
                    _ => b.skip_field(),
                }
            }
            for t in &item.tags {
                b.tag(t);
            }
            if several {
                b.tag(&format!("Keevo · {}", vault.name));
            }
            b.favorite(item.favorite);
            out.push(b.finish())?;
        }
    }
    Ok(out)
}
