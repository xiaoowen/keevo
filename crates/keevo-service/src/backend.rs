use std::time::{SystemTime, UNIX_EPOCH};

use keevo_core::{FieldKind, Id128, ItemType, Purpose, RecordKey, RecordValue, Vault, url_match};
use keevo_ipc::message::{Candidate, FillData};
use keevo_ipc::service::VaultBackend;

/// 把 IPC 状态机的后端接口接到保险库上。只有登录条目、且不在回收站中的条目才会参与匹配。
pub struct CoreBackend<'a> {
    vault: &'a Vault,
}

impl<'a> CoreBackend<'a> {
    /// 包装一个保险库。
    #[must_use]
    pub const fn new(vault: &'a Vault) -> Self {
        Self { vault }
    }
}

pub(crate) fn parse_id(hex: &str) -> Option<Id128> {
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (slot, pair) in out.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(Id128::from_bytes(out))
}

impl VaultBackend for CoreBackend<'_> {
    fn is_locked(&self) -> bool {
        !self.vault.is_unlocked()
    }

    fn unlock_epoch(&self) -> Option<u64> {
        self.vault.unlock_epoch()
    }

    fn candidates(&self, url: &str) -> Vec<Candidate> {
        let Ok(items) = self.vault.items() else {
            return Vec::new();
        };
        items
            .into_iter()
            .filter(|i| i.overview.item_type == ItemType::Login && i.overview.trashed_at.is_none())
            .filter(|i| {
                i.overview
                    .urls
                    .iter()
                    .any(|saved| url_match::matches(saved, url))
            })
            .map(|i| Candidate {
                item_id: i.id.to_hex(),
                title: i.overview.title,
                subtitle: i.overview.subtitle,
            })
            .collect()
    }

    fn item_matches(&self, item_id: &str, url: &str) -> Option<bool> {
        let id = parse_id(item_id)?;
        let items = self.vault.items().ok()?;
        let item = items.into_iter().find(|i| i.id == id)?;
        Some(
            item.overview.item_type == ItemType::Login
                && item.overview.trashed_at.is_none()
                && item
                    .overview
                    .urls
                    .iter()
                    .any(|saved| url_match::matches(saved, url)),
        )
    }

    fn describe(&self, item_id: &str) -> Option<(String, String)> {
        let id = parse_id(item_id)?;
        let item = self.vault.items().ok()?.into_iter().find(|i| i.id == id)?;
        Some((item.overview.title, item.overview.subtitle))
    }

    fn fill(&self, item_id: &str) -> Option<FillData> {
        let id = parse_id(item_id)?;
        let view = self.vault.item(id).ok()?;
        let text_with = |purpose: Purpose| {
            view.doc
                .records
                .iter()
                .find_map(|(k, v)| match (k, &v.value) {
                    (RecordKey::Field(_), Some(RecordValue::Field(f)))
                        if f.purpose == Some(purpose) =>
                    {
                        f.text().map(str::to_owned)
                    }
                    _ => None,
                })
        };
        // 第一个一次性密码字段的当前验证码；生成失败（如 otpauth 无效）时不带
        let totp = view
            .doc
            .records
            .iter()
            .find_map(|(k, v)| match (k, &v.value) {
                (RecordKey::Field(field_id), Some(RecordValue::Field(f)))
                    if matches!(f.kind, FieldKind::Totp) =>
                {
                    Some(*field_id)
                }
                _ => None,
            })
            .and_then(|field_id| {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
                let ms = u64::try_from(now.as_millis()).ok()?;
                self.vault.otp_code(id, field_id, ms).ok()
            })
            .map(|c| c.code.as_str().to_owned());
        Some(FillData {
            username: text_with(Purpose::Username).unwrap_or_default(),
            password: text_with(Purpose::Password)?,
            totp,
        })
    }
}
