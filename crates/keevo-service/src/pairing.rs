//! 配对记录的存储（`spec/ipc.md` §4.2 第 6 步）：存入加密的保险库数据库（本机记录，`spec/crypto.md` §8.8）。
//!
//! - 解锁时读入内存（[`PairingCache::load`]），之后直到进程退出都留在内存中，锁定时也留着，以便已配对的扩展
//!   查询 `status`；进程启动后、首次解锁前不可读，IK 握手返回 `locked`。
//! - 保存与撤销都在已解锁时进行，经由调用方已持有的保险库（[`Bound`]）：服务按"保险库 → 配对"的固定顺序加锁，
//!   存储本身不再去锁保险库，避免死锁，也让"确认时仍是同一次解锁"（第四轮评审 J5）与保存处于同一把锁下。
//! - **待提交的撤销**：撤销立即从内存删除；写入数据库失败时留在内存中，之后每次解锁先应用、再重试写入。

use std::collections::BTreeSet;

use keevo_core::Vault;
use keevo_ipc::service::{PairingRecord, PairingStore};
use serde::{Deserialize, Serialize};

/// 本机记录的种类（`spec/crypto.md` §8.8）。
pub const PAIRING_KIND: &str = "pairing";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordJson {
    v: u32,
    extension_origin: String,
    browser: String,
    name: String,
    paired_at_ms: u64,
}

/// 读入内存的配对记录。
#[derive(Debug, Default)]
pub struct PairingCache {
    records: Vec<PairingRecord>,
    loaded: bool,
    pending_revocations: BTreeSet<[u8; 32]>,
}

/// 读入时的情况。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LoadReport {
    /// 读入的配对数。
    pub records: usize,
    /// 解不开或格式不对而跳过的记录数（被篡改或损坏；跳过等于撤销，是安全的方向）。
    pub skipped: usize,
    /// 仍未写入数据库的撤销数。大于 0 时必须提示用户"撤销可能在重启后失效"（§4.4）。
    pub pending_revocations: usize,
}

impl PairingCache {
    /// 解锁后读入：先应用待提交的撤销并重试写入，再读出记录。
    ///
    /// # Errors
    /// 保险库已锁定或数据库读取失败时返回错误；此时内存中的记录不变。
    pub fn load(&mut self, vault: &mut Vault) -> std::io::Result<LoadReport> {
        let pending: Vec<[u8; 32]> = self.pending_revocations.iter().copied().collect();
        for pk in pending {
            if vault.delete_local_record(PAIRING_KIND, &pk).is_ok() {
                self.pending_revocations.remove(&pk);
            }
        }
        let (rows, mut skipped) = vault
            .local_records(PAIRING_KIND)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let mut records = Vec::with_capacity(rows.len());
        for (id, plain) in rows {
            let Ok(extension_public) = <[u8; 32]>::try_from(id.as_slice()) else {
                skipped = skipped.saturating_add(1);
                continue;
            };
            // 待提交的撤销优先于数据库中的记录
            if self.pending_revocations.contains(&extension_public) {
                continue;
            }
            match serde_json::from_slice::<RecordJson>(&plain) {
                Ok(r) if r.v == 1 => records.push(PairingRecord {
                    extension_public,
                    extension_origin: r.extension_origin,
                    browser: r.browser,
                    name: r.name,
                    paired_at_ms: r.paired_at_ms,
                }),
                _ => skipped = skipped.saturating_add(1),
            }
        }
        self.records = records;
        self.loaded = true;
        Ok(LoadReport {
            records: self.records.len(),
            skipped,
            pending_revocations: self.pending_revocations.len(),
        })
    }

    /// 全部配对记录。
    #[must_use]
    pub fn records(&self) -> &[PairingRecord] {
        &self.records
    }

    /// 仍未写入数据库的撤销数。
    #[must_use]
    pub fn pending_revocations(&self) -> usize {
        self.pending_revocations.len()
    }
}

/// 只读视图：协议状态机处理普通帧时只需要查找。
pub(crate) struct ReadOnly<'a>(pub(crate) &'a PairingCache);

impl PairingStore for ReadOnly<'_> {
    fn is_loaded(&self) -> bool {
        self.0.loaded
    }

    fn find(&self, extension_public: &[u8; 32]) -> Option<PairingRecord> {
        find(self.0, extension_public)
    }

    fn save(&mut self, _: PairingRecord) -> std::io::Result<()> {
        Err(std::io::ErrorKind::Unsupported.into())
    }

    fn revoke(&mut self, _: &[u8; 32]) -> std::io::Result<()> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
}

/// 绑定到调用方已持有的保险库上的可写视图。
pub(crate) struct Bound<'a> {
    /// 配对记录。
    pub(crate) cache: &'a mut PairingCache,
    /// 调用方已持有锁的保险库。
    pub(crate) vault: &'a mut Vault,
}

fn find(cache: &PairingCache, extension_public: &[u8; 32]) -> Option<PairingRecord> {
    cache
        .records
        .iter()
        .find(|r| &r.extension_public == extension_public)
        .cloned()
}

impl PairingStore for Bound<'_> {
    fn is_loaded(&self) -> bool {
        self.cache.loaded
    }

    fn find(&self, extension_public: &[u8; 32]) -> Option<PairingRecord> {
        find(self.cache, extension_public)
    }

    /// 先写数据库，成功后才更新内存：写入失败时配对按拒绝处理（§4.2）。
    fn save(&mut self, record: PairingRecord) -> std::io::Result<()> {
        let json = RecordJson {
            v: 1,
            extension_origin: record.extension_origin.clone(),
            browser: record.browser.clone(),
            name: record.name.clone(),
            paired_at_ms: record.paired_at_ms,
        };
        let bytes = serde_json::to_vec(&json).map_err(std::io::Error::other)?;
        self.vault
            .put_local_record(PAIRING_KIND, &record.extension_public, &bytes)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        self.cache
            .pending_revocations
            .remove(&record.extension_public);
        self.cache
            .records
            .retain(|r| r.extension_public != record.extension_public);
        self.cache.records.push(record);
        Ok(())
    }

    /// 立即从内存删除；写入数据库失败时记为待提交的撤销，并返回错误。
    fn revoke(&mut self, extension_public: &[u8; 32]) -> std::io::Result<()> {
        self.cache
            .records
            .retain(|r| &r.extension_public != extension_public);
        match self
            .vault
            .delete_local_record(PAIRING_KIND, extension_public)
        {
            Ok(()) => {
                self.cache.pending_revocations.remove(extension_public);
                Ok(())
            }
            Err(e) => {
                self.cache.pending_revocations.insert(*extension_public);
                Err(std::io::Error::other(e.to_string()))
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use keevo_core::{KdfParams, Store};

    use super::*;

    fn record(n: u8) -> PairingRecord {
        PairingRecord {
            extension_public: [n; 32],
            extension_origin: "chrome-extension://abc/".into(),
            browser: "com.google.Chrome".into(),
            name: format!("Chrome {n}"),
            paired_at_ms: 1,
        }
    }

    #[test]
    fn persists_in_the_vault_and_supports_pending_revocations() {
        let params = KdfParams::new(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1, [5; 16]).unwrap();
        let (mut vault, sk) =
            Vault::create_with_store(Store::open_in_memory().unwrap(), "pw", params).unwrap();
        let mut cache = PairingCache::default();
        assert!(!ReadOnly(&cache).is_loaded(), "首次解锁前不可读");
        cache.load(&mut vault).unwrap();
        Bound {
            cache: &mut cache,
            vault: &mut vault,
        }
        .save(record(1))
        .unwrap();
        Bound {
            cache: &mut cache,
            vault: &mut vault,
        }
        .save(record(2))
        .unwrap();

        // 重新读入：来自加密数据库
        let mut fresh = PairingCache::default();
        assert_eq!(
            fresh.load(&mut vault).unwrap(),
            LoadReport {
                records: 2,
                skipped: 0,
                pending_revocations: 0
            }
        );
        assert_eq!(ReadOnly(&fresh).find(&[1; 32]).unwrap().name, "Chrome 1");

        // 锁定时撤销：内存立即生效，数据库写入失败，记为待提交
        vault.lock();
        assert!(
            Bound {
                cache: &mut fresh,
                vault: &mut vault
            }
            .revoke(&[1; 32])
            .is_err()
        );
        assert!(ReadOnly(&fresh).find(&[1; 32]).is_none(), "内存中立即生效");
        assert_eq!(fresh.pending_revocations(), 1);
        assert!(
            Bound {
                cache: &mut fresh,
                vault: &mut vault
            }
            .save(record(3))
            .is_err(),
            "锁定时不能保存"
        );
        assert!(
            ReadOnly(&fresh).find(&[3; 32]).is_none(),
            "保存失败时内存不变"
        );

        // 下次解锁：先应用待提交的撤销
        vault.unlock("pw", &sk).unwrap();
        let report = fresh.load(&mut vault).unwrap();
        assert_eq!((report.records, report.pending_revocations), (1, 0));
        let mut again = PairingCache::default();
        assert_eq!(
            again.load(&mut vault).unwrap().records,
            1,
            "撤销已写入数据库"
        );
        assert!(ReadOnly(&again).find(&[1; 32]).is_none());
    }
}
