//! 条目的本机统计：创建时间、使用次数与最近一次使用（列表排序，设计稿"强度、双击复制、排序与检查更新"）。
//!
//! - 存成本机记录（`spec/crypto.md` §8.8），种类 [`ITEM_STATS_KIND`]。按条目 ID 的第一个字节分到 256 个桶里，每个桶
//!   一条记录（id 为这个字节）：同一种记录最多 4096 条，每个条目一条放不下大的保险库；1 万个条目时每桶约 40 个、
//!   约 4 KiB，远低于单条 64 KiB 的上限。与其他本机记录一样由账户密钥派生的密钥加密，不进入同步与导出。
//! - **创建时间**取条目最早留有内容的修订的时间。修订可能被历史清理去掉内容（`spec/revisions.md` §7.2），因此第一次
//!   算出后就记下来；记下之前最早的修订已被清理时，取到的是仍留有内容的最早修订，晚于真实的创建时间。
//! - **使用**：在 Keevo 或快速访问中复制、浏览器扩展取用、`keevo read` / `keevo run` 取用、SSH 签名。
//! - 解锁后第一次需要时读入内存，锁定时丢弃。读不出的桶当作空的：最多丢失其中条目的统计。

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use keevo_crypto::{Id128, Part};
use keevo_format::ItemOverview;
use keevo_store::{ObjectKind, RevisionRow};
use serde::{Deserialize, Serialize};

use super::Vault;
use crate::error::{CoreError, Result};

/// 本机记录的种类。
pub const ITEM_STATS_KIND: &str = "item_stats";

/// 缺少创建时间的条目多于这个数时，一次查询取出全部条目最早的修订；否则逐个查询。
const BULK_THRESHOLD: usize = 16;

/// 一个条目的本机统计。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ItemStats {
    /// 创建时间（Unix 毫秒）；算不出时为 `None`。
    pub created_ms: Option<u64>,
    /// 使用次数。
    pub uses: u64,
    /// 最近一次使用（Unix 毫秒）；从未使用时为 `None`。
    pub last_used_ms: Option<u64>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BucketJson {
    v: u32,
    /// 条目 ID（十六进制）→ 统计。
    items: BTreeMap<String, StatsJson>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StatsJson {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    created_ms: Option<u64>,
    #[serde(default)]
    uses: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_used_ms: Option<u64>,
}

/// 条目所在的桶：条目 ID 的第一个字节。
fn bucket(id: &Id128) -> u8 {
    id.as_bytes().first().copied().unwrap_or(0)
}

/// 32 位小写或大写十六进制 → ID。
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

impl Vault {
    /// `items` 中每个条目的本机统计。第一次调用时从本机记录读入；没有创建时间的条目按最早留有内容的修订补上
    /// 并保存；不在 `items` 中的条目（已永久删除）的统计随之删除。
    ///
    /// # Errors
    /// 已锁定时返回错误。算不出某个条目的创建时间、写入失败都不算错误（下次再试）。
    pub fn item_stats(&mut self, items: &[Id128]) -> Result<HashMap<Id128, ItemStats>> {
        self.load_stats()?;
        let mut stats = self.stats.take().unwrap_or_default();
        let mut dirty: BTreeSet<u8> = BTreeSet::new();

        let missing: Vec<Id128> = items
            .iter()
            .filter(|id| stats.get(*id).is_none_or(|s| s.created_ms.is_none()))
            .copied()
            .collect();
        if !missing.is_empty() {
            for (id, created) in self.created_times(&missing) {
                stats.entry(id).or_default().created_ms = Some(created);
                dirty.insert(bucket(&id));
            }
        }
        let keep: HashSet<Id128> = items.iter().copied().collect();
        let stale: Vec<Id128> = stats
            .keys()
            .filter(|id| !keep.contains(id))
            .copied()
            .collect();
        for id in stale {
            stats.remove(&id);
            dirty.insert(bucket(&id));
        }
        let out = items
            .iter()
            .map(|id| (*id, stats.get(id).copied().unwrap_or_default()))
            .collect();
        let _ = self.save_buckets(&stats, &dirty);
        self.stats = Some(stats);
        Ok(out)
    }

    /// 记一次使用（`now_ms` 为 Unix 毫秒）。
    ///
    /// # Errors
    /// 已锁定或写入失败时返回错误；调用方通常忽略它，不影响复制或填充本身。
    pub fn record_use(&mut self, item_id: Id128, now_ms: u64) -> Result<()> {
        self.load_stats()?;
        let mut stats = self.stats.take().unwrap_or_default();
        let entry = stats.entry(item_id).or_default();
        entry.uses = entry.uses.saturating_add(1);
        entry.last_used_ms = Some(now_ms);
        let result = self.save_buckets(&stats, &BTreeSet::from([bucket(&item_id)]));
        self.stats = Some(stats);
        result
    }

    fn load_stats(&mut self) -> Result<()> {
        if self.stats.is_some() {
            return Ok(());
        }
        let (rows, _skipped) = self.local_records(ITEM_STATS_KIND)?;
        let mut stats = HashMap::new();
        for (_, plain) in rows {
            // 格式不对的桶当作空的：最多丢失其中条目的统计
            let Ok(b) = serde_json::from_slice::<BucketJson>(&plain) else {
                continue;
            };
            if b.v != 1 {
                continue;
            }
            for (hex, s) in b.items {
                if let Some(id) = parse_id(&hex) {
                    stats.insert(
                        id,
                        ItemStats {
                            created_ms: s.created_ms,
                            uses: s.uses,
                            last_used_ms: s.last_used_ms,
                        },
                    );
                }
            }
        }
        self.stats = Some(stats);
        Ok(())
    }

    /// 在一个事务中重写这些桶；变空的桶删除。
    fn save_buckets(
        &mut self,
        stats: &HashMap<Id128, ItemStats>,
        buckets: &BTreeSet<u8>,
    ) -> Result<()> {
        if buckets.is_empty() {
            return Ok(());
        }
        let mut grouped: BTreeMap<u8, BTreeMap<String, StatsJson>> = BTreeMap::new();
        for (id, s) in stats {
            let b = bucket(id);
            if buckets.contains(&b) {
                grouped.entry(b).or_default().insert(
                    id.to_hex(),
                    StatsJson {
                        created_ms: s.created_ms,
                        uses: s.uses,
                        last_used_ms: s.last_used_ms,
                    },
                );
            }
        }
        let mut writes = Vec::new();
        for b in buckets {
            match grouped.remove(b) {
                Some(items) => {
                    let bytes = serde_json::to_vec(&BucketJson { v: 1, items })
                        .map_err(|_| CoreError::Tampered)?;
                    writes.push((vec![*b], bytes));
                }
                None => self.delete_local_record(ITEM_STATS_KIND, &[*b])?,
            }
        }
        if writes.is_empty() {
            return Ok(());
        }
        self.put_local_records(ITEM_STATS_KIND, &writes)
    }

    /// 这些条目的创建时间（最早留有内容的修订的时间）。算不出的不在结果中。
    fn created_times(&self, items: &[Id128]) -> Vec<(Id128, u64)> {
        let created = |row: &RevisionRow| {
            let plain = self.decrypt_part(row, Part::Overview).ok()?;
            ItemOverview::decode(&plain)
                .ok()
                .map(|o| o.updated.millis())
        };
        if items.len() <= BULK_THRESHOLD {
            return items
                .iter()
                .filter_map(|id| {
                    let row = self.store.earliest_content_revision(id).ok()??;
                    Some((*id, created(&row)?))
                })
                .collect();
        }
        let wanted: HashSet<Id128> = items.iter().copied().collect();
        let Ok(rows) = self.store.earliest_content_revisions(ObjectKind::Item) else {
            return Vec::new();
        };
        rows.iter()
            .filter(|row| wanted.contains(&row.object_id))
            .filter_map(|row| Some((row.object_id, created(row)?)))
            .collect()
    }
}
