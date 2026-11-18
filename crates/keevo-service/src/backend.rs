use keevo_core::{Id128, ItemType, Purpose, RecordKey, RecordValue, Vault, url_match};
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

fn parse_id(hex: &str) -> Option<Id128> {
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

    fn fill(&self, item_id: &str) -> Option<FillData> {
        let view = self.vault.item(parse_id(item_id)?).ok()?;
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
        Some(FillData {
            username: text_with(Purpose::Username).unwrap_or_default(),
            password: text_with(Purpose::Password)?,
            // M1.2 实现 TOTP 生成后提供
            totp: None,
        })
    }
}
