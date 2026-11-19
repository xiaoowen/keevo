//! 配对记录的存储（`spec/ipc.md` §4.2 第 6 步）：存入加密的保险库数据库（本机记录，`spec/crypto.md` §8.8）。
//!
//! - 解锁时读入内存（[`PairingCache::load`]），之后直到进程退出都留在内存中，锁定时也留着，以便已配对的扩展
//!   查询 `status`；进程启动后、首次解锁前不可读，IK 握手返回 `locked`。
//! - 保存与撤销都在已解锁时进行，经由调用方已持有的保险库（[`Bound`]）：服务按"保险库 → 配对"的固定顺序加锁，
//!   存储本身不再去锁保险库，避免死锁，也让"确认时仍是同一次解锁"（第四轮评审 J5）与保存处于同一把锁下。
//! - **待提交的撤销**：撤销立即从内存删除；写入数据库失败时留在内存中，之后每次解锁先应用、再重试写入。

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use keevo_core::Vault;
use keevo_ipc::service::{FillGate, PairingRecord, PairingStore};
use serde::{Deserialize, Serialize};

/// 本机记录的种类（`spec/crypto.md` §8.8）。
pub const PAIRING_KIND: &str = "pairing";
/// 站点授权的本机记录种类：每个配对一条，id 为扩展静态公钥。
pub const AUTHORIZATION_KIND: &str = "authorization";
/// 频率限制的时间窗（`spec/ipc.md` §5.2 第 3 条）。
pub const FILL_WINDOW: Duration = Duration::from_secs(10 * 60);
/// 时间窗内允许取用的不同条目数；第 6 个不同条目触发暂停。
pub const FILL_DISTINCT_LIMIT: usize = 5;
/// 协议 v2 `save` 的频率限制（`spec/ipc.md` §5.5）：同一配对在任意 10 分钟内最多保存这么多条目。
pub const SAVE_LIMIT: usize = 5;
/// `candidates` 的频率限制（`spec/ipc.md` §5.2）：同一配对在任意 10 分钟内最多查询这么多不同的站点。
pub const QUERY_DISTINCT_LIMIT: usize = 60;

/// 一项站点授权：某个配对可以为某个条目在某个站点取用凭据（`spec/ipc.md` §5.2）。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    /// 条目 ID。
    pub item_id: String,
    /// 规范化后的站点。
    pub site: String,
    /// 授权时间（Unix 毫秒）。
    pub granted_at_ms: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationsJson {
    v: u32,
    items: Vec<Authorization>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordJson {
    v: u32,
    extension_origin: String,
    browser: String,
    name: String,
    paired_at_ms: u64,
}

/// 读入内存的配对记录与站点授权。频率限制的计数只在内存中（一次服务运行内有效）。
#[derive(Debug, Default)]
pub struct PairingCache {
    records: Vec<PairingRecord>,
    loaded: bool,
    pending_revocations: BTreeSet<[u8; 32]>,
    authorizations: BTreeMap<[u8; 32], BTreeSet<Authorization>>,
    usage: HashMap<[u8; 32], VecDeque<(Instant, String)>>,
    paused: HashSet<[u8; 32]>,
    saves: HashMap<[u8; 32], VecDeque<Instant>>,
    queries: HashMap<[u8; 32], QueryWindow>,
}

/// 一个配对最近查询过的站点，以及本时间窗内是否已经提示过。
#[derive(Debug, Default)]
struct QueryWindow {
    sites: VecDeque<(Instant, String)>,
    notified: bool,
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
            let _ = vault.delete_local_record(AUTHORIZATION_KIND, &pk);
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
        let mut authorizations = BTreeMap::new();
        let (rows, auth_skipped) = vault
            .local_records(AUTHORIZATION_KIND)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        skipped = skipped.saturating_add(auth_skipped);
        for (id, plain) in rows {
            let Ok(pk) = <[u8; 32]>::try_from(id.as_slice()) else {
                skipped = skipped.saturating_add(1);
                continue;
            };
            // 只保留仍然配对着的扩展的授权
            if !records
                .iter()
                .any(|r: &PairingRecord| r.extension_public == pk)
            {
                continue;
            }
            match serde_json::from_slice::<AuthorizationsJson>(&plain) {
                Ok(a) if a.v == 1 => {
                    authorizations.insert(pk, a.items.into_iter().collect());
                }
                _ => skipped = skipped.saturating_add(1),
            }
        }
        self.records = records;
        self.authorizations = authorizations;
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

    /// 某个配对的全部站点授权。
    #[must_use]
    pub fn authorizations(&self, extension_public: &[u8; 32]) -> Vec<Authorization> {
        self.authorizations
            .get(extension_public)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// 这个配对是否因频率限制被暂停。
    #[must_use]
    pub fn is_paused(&self, extension_public: &[u8; 32]) -> bool {
        self.paused.contains(extension_public)
    }

    /// 用户确认后恢复被暂停的配对，并清空它的计数。
    pub fn resume(&mut self, extension_public: &[u8; 32]) {
        self.paused.remove(extension_public);
        self.usage.remove(extension_public);
    }

    fn authorized(&self, pk: &[u8; 32], item_id: &str, site: &str) -> bool {
        self.authorizations
            .get(pk)
            .is_some_and(|s| s.iter().any(|a| a.item_id == item_id && a.site == site))
    }

    /// 授权检查与频率限制（`spec/ipc.md` §5.2）：先看是否暂停，再看是否已授权；允许时记下这次使用，
    /// 时间窗内不同条目数超过上限即暂停（包括已授权的条目）。
    fn gate(&mut self, pk: &[u8; 32], item_id: &str, site: &str, now: Instant) -> FillGate {
        if self.paused.contains(pk) {
            return FillGate::Paused;
        }
        if !self.authorized(pk, item_id, site) {
            return FillGate::NeedsAuthorization;
        }
        let window = self.usage.entry(*pk).or_default();
        while window
            .front()
            .is_some_and(|(t, _)| now.saturating_duration_since(*t) > FILL_WINDOW)
        {
            window.pop_front();
        }
        let distinct: HashSet<&str> = window
            .iter()
            .map(|(_, i)| i.as_str())
            .chain(std::iter::once(item_id))
            .collect();
        if distinct.len() > FILL_DISTINCT_LIMIT {
            self.paused.insert(*pk);
            return FillGate::Paused;
        }
        window.push_back((now, item_id.to_owned()));
        FillGate::Allowed
    }

    /// `candidates` 的频率限制：任意 10 分钟内最多 [`QUERY_DISTINCT_LIMIT`] 个不同站点，重复查询同一站点不计数。
    /// 计数只在内存中。超过时只在本时间窗内第一次被拒时要求提示。
    fn query_gate(
        &mut self,
        pk: &[u8; 32],
        site: &str,
        now: Instant,
    ) -> keevo_ipc::service::QueryGate {
        use keevo_ipc::service::QueryGate;
        let w = self.queries.entry(*pk).or_default();
        while w
            .sites
            .front()
            .is_some_and(|(t, _)| now.saturating_duration_since(*t) > FILL_WINDOW)
        {
            w.sites.pop_front();
        }
        if w.sites.iter().any(|(_, s)| s == site) {
            return QueryGate::Allowed;
        }
        let distinct: HashSet<&str> = w.sites.iter().map(|(_, s)| s.as_str()).collect();
        if distinct.len() >= QUERY_DISTINCT_LIMIT {
            let first = !w.notified;
            w.notified = true;
            return QueryGate::Limited { first };
        }
        if distinct.is_empty() {
            w.notified = false;
        }
        w.sites.push_back((now, site.to_owned()));
        QueryGate::Allowed
    }

    /// `save` 的频率限制：任意 10 分钟内最多 [`SAVE_LIMIT`] 次。允许时记下这次保存。计数只在内存中。
    fn save_gate(&mut self, pk: &[u8; 32], now: Instant) -> bool {
        let window = self.saves.entry(*pk).or_default();
        while window
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) > FILL_WINDOW)
        {
            window.pop_front();
        }
        if window.len() >= SAVE_LIMIT {
            return false;
        }
        window.push_back(now);
        true
    }
}

/// 可写但不接触保险库的视图：协议状态机处理普通帧时使用（查找与频率限制只改内存）。
pub(crate) struct Live<'a>(pub(crate) &'a mut PairingCache);

impl PairingStore for Live<'_> {
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

    fn fill_gate(&mut self, pk: &[u8; 32], item_id: &str, site: &str, now: Instant) -> FillGate {
        self.0.gate(pk, item_id, site, now)
    }

    fn save_gate(&mut self, pk: &[u8; 32], now: Instant) -> bool {
        self.0.save_gate(pk, now)
    }

    fn candidates_gate(
        &mut self,
        pk: &[u8; 32],
        site: &str,
        now: Instant,
    ) -> keevo_ipc::service::QueryGate {
        self.0.query_gate(pk, site, now)
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

impl Bound<'_> {
    fn persist_authorizations(&mut self, pk: &[u8; 32]) -> std::io::Result<()> {
        let items: Vec<Authorization> = self.cache.authorizations(pk);
        if items.is_empty() {
            return self
                .vault
                .delete_local_record(AUTHORIZATION_KIND, pk)
                .map_err(|e| std::io::Error::other(e.to_string()));
        }
        let bytes = serde_json::to_vec(&AuthorizationsJson { v: 1, items })
            .map_err(std::io::Error::other)?;
        self.vault
            .put_local_record(AUTHORIZATION_KIND, pk, &bytes)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    /// 记下用户的授权：先写数据库，成功后才生效（`spec/ipc.md` §5.2 第 2 条）。
    pub(crate) fn authorize(
        &mut self,
        pk: &[u8; 32],
        item_id: &str,
        site: &str,
    ) -> std::io::Result<()> {
        if find(self.cache, pk).is_none() {
            return Err(std::io::ErrorKind::NotFound.into());
        }
        let granted_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        let entry = Authorization {
            item_id: item_id.to_owned(),
            site: site.to_owned(),
            granted_at_ms,
        };
        let before = self.cache.authorizations.get(pk).cloned();
        self.cache
            .authorizations
            .entry(*pk)
            .or_default()
            .insert(entry);
        if let Err(e) = self.persist_authorizations(pk) {
            match before {
                Some(b) => self.cache.authorizations.insert(*pk, b),
                None => self.cache.authorizations.remove(pk),
            };
            return Err(e);
        }
        Ok(())
    }

    /// 撤销一项站点授权（"设置 → 浏览器"）。立即从内存删除。
    pub(crate) fn revoke_authorization(
        &mut self,
        pk: &[u8; 32],
        item_id: &str,
        site: &str,
    ) -> std::io::Result<()> {
        if let Some(set) = self.cache.authorizations.get_mut(pk) {
            set.retain(|a| !(a.item_id == item_id && a.site == site));
        }
        self.persist_authorizations(pk)
    }
}

impl PairingStore for Bound<'_> {
    fn is_loaded(&self) -> bool {
        self.cache.loaded
    }

    fn find(&self, extension_public: &[u8; 32]) -> Option<PairingRecord> {
        find(self.cache, extension_public)
    }

    fn fill_gate(&mut self, pk: &[u8; 32], item_id: &str, site: &str, now: Instant) -> FillGate {
        self.cache.gate(pk, item_id, site, now)
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
        // 重新配对不恢复旧授权（spec/ipc.md §5.2 第 2 条）：扩展通常沿用同一把静态密钥，撤销时若没能删掉
        // 授权记录，它会在下次读入时随新配对复活。先删除，删不掉就拒绝这次配对
        self.vault
            .delete_local_record(AUTHORIZATION_KIND, &record.extension_public)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        self.cache.authorizations.remove(&record.extension_public);
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

    /// 立即从内存删除（连同站点授权）；写入数据库失败时记为待提交的撤销，并返回错误。
    fn revoke(&mut self, extension_public: &[u8; 32]) -> std::io::Result<()> {
        self.cache
            .records
            .retain(|r| &r.extension_public != extension_public);
        self.cache.authorizations.remove(extension_public);
        self.cache.usage.remove(extension_public);
        self.cache.paused.remove(extension_public);
        self.cache.saves.remove(extension_public);
        self.cache.queries.remove(extension_public);
        let _ = self
            .vault
            .delete_local_record(AUTHORIZATION_KIND, extension_public);
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

    #[test]
    fn authorizations_and_rate_limit() {
        let params = KdfParams::new(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1, [5; 16]).unwrap();
        let (mut vault, _) =
            Vault::create_with_store(Store::open_in_memory().unwrap(), "pw", params).unwrap();
        let mut cache = PairingCache::default();
        cache.load(&mut vault).unwrap();
        Bound {
            cache: &mut cache,
            vault: &mut vault,
        }
        .save(record(1))
        .unwrap();
        let pk = [1u8; 32];
        let t0 = Instant::now();
        let site = "https://github.com";
        assert_eq!(
            Live(&mut cache).fill_gate(&pk, "i0", site, t0),
            FillGate::NeedsAuthorization
        );
        Bound {
            cache: &mut cache,
            vault: &mut vault,
        }
        .authorize(&pk, "i0", site)
        .unwrap();
        assert_eq!(
            Live(&mut cache).fill_gate(&pk, "i0", site, t0),
            FillGate::Allowed
        );
        assert_eq!(
            Live(&mut cache).fill_gate(&pk, "i0", "https://evil.example", t0),
            FillGate::NeedsAuthorization,
            "按站点授权"
        );
        assert!(
            Bound {
                cache: &mut cache,
                vault: &mut vault
            }
            .authorize(&[9; 32], "i0", site)
            .is_err(),
            "未配对的不能授权"
        );

        // 授权存入加密数据库
        let mut fresh = PairingCache::default();
        fresh.load(&mut vault).unwrap();
        assert_eq!(fresh.authorizations(&pk).len(), 1);

        // 频率限制：10 分钟内第 6 个不同条目暂停；重复取用同一条目不计为新条目
        for i in 1..5 {
            Bound {
                cache: &mut cache,
                vault: &mut vault,
            }
            .authorize(&pk, &format!("i{i}"), site)
            .unwrap();
            assert_eq!(
                Live(&mut cache).fill_gate(&pk, &format!("i{i}"), site, t0),
                FillGate::Allowed
            );
        }
        assert_eq!(
            Live(&mut cache).fill_gate(&pk, "i0", site, t0),
            FillGate::Allowed,
            "同一条目"
        );
        Bound {
            cache: &mut cache,
            vault: &mut vault,
        }
        .authorize(&pk, "i5", site)
        .unwrap();
        assert_eq!(
            Live(&mut cache).fill_gate(&pk, "i5", site, t0),
            FillGate::Paused,
            "第 6 个不同条目"
        );
        assert!(cache.is_paused(&pk));
        assert_eq!(
            Live(&mut cache).fill_gate(&pk, "i0", site, t0),
            FillGate::Paused,
            "暂停后全部拒绝"
        );
        cache.resume(&pk);
        assert_eq!(
            Live(&mut cache).fill_gate(&pk, "i5", site, t0),
            FillGate::Allowed,
            "恢复后清空计数"
        );
        // 时间窗过后计数清空
        let mut later = PairingCache::default();
        later.load(&mut vault).unwrap();
        for i in 0..5 {
            assert_eq!(
                Live(&mut later).fill_gate(&pk, &format!("i{i}"), site, t0),
                FillGate::Allowed
            );
        }
        let t1 = t0 + FILL_WINDOW + Duration::from_secs(1);
        assert_eq!(
            Live(&mut later).fill_gate(&pk, "i5", site, t1),
            FillGate::Allowed
        );

        // 撤销单项授权；撤销配对时一并删除
        Bound {
            cache: &mut cache,
            vault: &mut vault,
        }
        .revoke_authorization(&pk, "i0", site)
        .unwrap();
        assert_eq!(
            Live(&mut cache).fill_gate(&pk, "i0", site, t0),
            FillGate::NeedsAuthorization
        );
        Bound {
            cache: &mut cache,
            vault: &mut vault,
        }
        .revoke(&pk)
        .unwrap();
        Bound {
            cache: &mut cache,
            vault: &mut vault,
        }
        .save(record(1))
        .unwrap();
        assert!(cache.authorizations(&pk).is_empty(), "重新配对不恢复旧授权");
        let mut again = PairingCache::default();
        again.load(&mut vault).unwrap();
        assert!(again.authorizations(&pk).is_empty());

        // 撤销时没能删掉的授权记录（孤立记录）也不会随同一把公钥的新配对复活
        Bound {
            cache: &mut cache,
            vault: &mut vault,
        }
        .revoke(&pk)
        .unwrap();
        let orphan =
            br#"{"v":1,"items":[{"item_id":"i0","site":"https://github.com","granted_at_ms":1}]}"#;
        vault
            .put_local_record(AUTHORIZATION_KIND, &pk, orphan)
            .unwrap();
        Bound {
            cache: &mut cache,
            vault: &mut vault,
        }
        .save(record(1))
        .unwrap();
        let mut after = PairingCache::default();
        after.load(&mut vault).unwrap();
        assert!(after.authorizations(&pk).is_empty(), "孤立的授权记录不复活");
    }

    #[test]
    fn saves_are_rate_limited() {
        let mut cache = PairingCache::default();
        let pk = [7u8; 32];
        let t0 = Instant::now();
        for _ in 0..SAVE_LIMIT {
            assert!(Live(&mut cache).save_gate(&pk, t0));
        }
        assert!(
            !Live(&mut cache).save_gate(&pk, t0),
            "10 分钟内第 6 次保存被拒"
        );
        assert!(Live(&mut cache).save_gate(&[8; 32], t0), "按配对分别计数");
        let later = t0 + FILL_WINDOW + Duration::from_secs(1);
        assert!(Live(&mut cache).save_gate(&pk, later), "时间窗过后恢复");
    }

    #[test]
    fn candidate_queries_are_rate_limited() {
        use keevo_ipc::service::QueryGate;
        let mut cache = PairingCache::default();
        let pk = [7u8; 32];
        let t0 = Instant::now();
        let site = |i: usize| format!("https://site{i}.example");
        for i in 0..QUERY_DISTINCT_LIMIT {
            assert_eq!(
                Live(&mut cache).candidates_gate(&pk, &site(i), t0),
                QueryGate::Allowed
            );
            assert_eq!(
                Live(&mut cache).candidates_gate(&pk, &site(i), t0),
                QueryGate::Allowed,
                "重复查询不计数"
            );
        }
        let over = site(QUERY_DISTINCT_LIMIT);
        assert_eq!(
            Live(&mut cache).candidates_gate(&pk, &over, t0),
            QueryGate::Limited { first: true }
        );
        assert_eq!(
            Live(&mut cache).candidates_gate(&pk, &over, t0),
            QueryGate::Limited { first: false },
            "只提示一次"
        );
        assert_eq!(
            Live(&mut cache).candidates_gate(&pk, &site(0), t0),
            QueryGate::Allowed,
            "查过的站点仍可查询"
        );
        let later = t0 + FILL_WINDOW + Duration::from_secs(1);
        assert_eq!(
            Live(&mut cache).candidates_gate(&pk, &over, later),
            QueryGate::Allowed,
            "时间窗过后恢复"
        );
    }
}
