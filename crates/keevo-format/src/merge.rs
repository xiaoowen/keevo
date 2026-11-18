//! 因果优先的确定性合并（`spec/revisions.md` §5）。

use std::collections::{BTreeSet, HashSet};

use keevo_crypto::Id128;
use zeroize::Zeroizing;

use crate::error::{FormatError, Result};
use crate::graph::RevisionGraph;
use crate::hlc::Hlc;
use crate::item::ItemDoc;
use crate::json::to_json;
use crate::record::{ConcurrentMap, RecordKey, RecordMap, RecordValue, RecordVersion};

/// 一个头修订的状态。
#[derive(Debug, Clone, Copy)]
pub enum HeadState<'a> {
    /// 正常修订。
    Live {
        /// 修订 ID。
        rev: Id128,
        /// 修订内容。
        doc: &'a ItemDoc,
    },
    /// 墓碑修订：对象已被永久删除（§6）。
    Deleted {
        /// 修订 ID。
        rev: Id128,
    },
}

/// 一个记录键上的并发冲突。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    /// 发生冲突的记录键。
    pub key: RecordKey,
    /// 胜出版本所在的修订。
    pub winner: Id128,
    /// 落选的并发版本。它们保存在合并视图的并发版本中（§4.3），直到用户处理，不会被历史清理删除。
    pub losers: Vec<RecordVersion>,
}

/// 合并结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Merged {
    /// 合并视图；`None` 表示对象已被删除。
    pub doc: Option<ItemDoc>,
    /// 各记录键上的并发冲突。
    pub conflicts: Vec<Conflict>,
    /// 是否因为删除与修改并发而撤销了删除（§5.2）。
    pub resurrected: bool,
    /// 出处不一致的记录键（§5.1 步骤 0）：记录声称写于一个不是其所在修订祖先的修订，或同一修订标识对应
    /// 不同内容。这类版本不参与因果判断，只可能来自损坏的数据或恶意的已登记设备，应提示用户查看历史。
    pub integrity_issues: Vec<RecordKey>,
}

impl Merged {
    /// 是否需要用户查看冲突或完整性问题。
    #[must_use]
    pub fn has_conflicts(&self) -> bool {
        self.resurrected || !self.conflicts.is_empty() || !self.integrity_issues.is_empty()
    }
}

/// 对象永久删除的保留键（`spec/revisions.md` §6）。每个墓碑头在合并时视为在该键上写了一个"已删除"版本；
/// 删除被撤销时，这些版本移入并发版本随合并状态保存，之后的合并仍能看到它们（第二轮评审 G2）。
pub const PURGED_ATTR: &str = "purged";
/// 回收站状态的属性名。
pub const TRASHED_ATTR: &str = "trashed";

/// 墓碑头 `rev` 在 `attr:purged` 上对应的版本。
fn purge_version(rev: Id128) -> RecordVersion {
    RecordVersion {
        hlc: Hlc(0),
        rev,
        value: Some(RecordValue::Bool(true)),
    }
}

/// 合并一个对象的全部头修订。结果与 `heads` 的顺序无关，重复的头会被忽略。
///
/// `graph` 必须包含所有头修订及其祖先的元数据；修订内容是否已被清理不影响结果。
///
/// # Errors
/// 没有头时返回 [`FormatError::NoHeads`]；各头的条目类型不一致时返回
/// [`FormatError::ItemTypeMismatch`]。
pub fn merge_heads(heads: &[HeadState<'_>], graph: &RevisionGraph) -> Result<Merged> {
    if heads.is_empty() {
        return Err(FormatError::NoHeads);
    }
    let mut live: Vec<(Id128, &ItemDoc)> = heads
        .iter()
        .filter_map(|h| match h {
            HeadState::Live { rev, doc } => Some((*rev, *doc)),
            HeadState::Deleted { .. } => None,
        })
        .collect();
    let deleted: BTreeSet<Id128> = heads
        .iter()
        .filter_map(|h| match h {
            HeadState::Deleted { rev } => Some(*rev),
            HeadState::Live { .. } => None,
        })
        .collect();

    let Some((_, first)) = live.first() else {
        return Ok(Merged {
            doc: None,
            conflicts: Vec::new(),
            resurrected: false,
            integrity_issues: Vec::new(),
        });
    };
    let item_type = first.item_type;
    if live.iter().any(|(_, d)| d.item_type != item_type) {
        return Err(FormatError::ItemTypeMismatch);
    }

    // §6：每个墓碑头视为只含 `attr:purged` 的文档，与普通记录一样参与"取极大元"
    let purged_key = RecordKey::attr(PURGED_ATTR);
    let tombstone_docs: Vec<(Id128, ItemDoc)> = deleted
        .iter()
        .map(|d| {
            let mut doc = ItemDoc::new(item_type);
            doc.records.insert(purged_key.clone(), purge_version(*d));
            (*d, doc)
        })
        .collect();
    live.extend(tombstone_docs.iter().map(|(rev, doc)| (*rev, doc)));

    // 每个头的祖先集合（含自身），用于校验记录版本声称的写入修订（§5.1 步骤 0）
    let ancestry: Vec<HashSet<Id128>> = live.iter().map(|(rev, _)| graph.ancestors(rev)).collect();
    let keys: BTreeSet<&RecordKey> = live
        .iter()
        .flat_map(|(_, d)| d.records.keys().chain(d.concurrent.keys()))
        .collect();
    let mut records = RecordMap::new();
    let mut concurrent = ConcurrentMap::new();
    let mut conflicts = Vec::new();
    let mut integrity_issues = Vec::new();
    for key in keys {
        let (candidates, suspicious) = candidates(&live, &ancestry, key);
        if suspicious {
            integrity_issues.push(key.clone());
        }
        if candidates.is_empty() {
            continue;
        }
        let (winner, others, conflict) = pick(key, candidates, graph);
        // 删除状态的冲突由 `resurrected` 表示，不作为字段冲突
        if let Some(c) = conflict.filter(|_| *key != purged_key) {
            conflicts.push(c);
        }
        records.insert(key.clone(), winner);
        if !others.is_empty() {
            concurrent.insert(key.clone(), others);
        }
    }

    let mut resurrected = false;
    let exempt = [RecordKey::attr(TRASHED_ATTR), purged_key.clone()];

    // §5.2：回收站状态与修改并发时撤销删除
    let trashed_key = RecordKey::attr(TRASHED_ATTR);
    if let Some(trash) = records.get(&trashed_key).filter(|v| !v.is_tombstone()) {
        let d = trash.rev;
        if has_concurrent_record(&records, &exempt, &d, graph) {
            suppress(&mut records, &mut concurrent, &trashed_key);
            resurrected = true;
        }
    }

    // §5.2、§6：永久删除。全部未被覆盖的"已删除"版本中，只要有一个没有与之并发的当前修改，删除即成立；
    // 否则撤销删除，并把这些版本移入并发版本保存
    let purges: Vec<Id128> = records
        .get(&purged_key)
        .into_iter()
        .chain(concurrent.get(&purged_key).into_iter().flatten())
        .filter(|v| !v.is_tombstone())
        .map(|v| v.rev)
        .collect();
    if !purges.is_empty() {
        let deletion_stands = purges
            .iter()
            .any(|d| !has_concurrent_record(&records, &exempt, d, graph));
        if deletion_stands {
            return Ok(Merged {
                doc: None,
                conflicts: Vec::new(),
                resurrected: false,
                integrity_issues,
            });
        }
        suppress(&mut records, &mut concurrent, &purged_key);
        resurrected = true;
    }

    Ok(Merged {
        doc: Some(ItemDoc {
            item_type,
            records,
            concurrent,
        }),
        conflicts,
        resurrected,
        integrity_issues,
    })
}

/// 收集某个键在各头中的版本（§5.1 步骤 0–1），返回候选与"是否发现出处不一致"。
///
/// - 版本声称的写入修订必须是其所在头的祖先（含自身），否则丢弃。
/// - 同一修订标识只保留一个版本；若出现内容不同的版本，按 (hlc, 值的规范 JSON) 取最大者，
///   保证结果与输入顺序无关。
fn candidates<'a>(
    live: &[(Id128, &'a ItemDoc)],
    ancestry: &[HashSet<Id128>],
    key: &RecordKey,
) -> (Vec<&'a RecordVersion>, bool) {
    let mut suspicious = false;
    let mut out: Vec<&RecordVersion> = Vec::new();
    for ((_, doc), ancestors) in live.iter().zip(ancestry) {
        for v in doc.versions(key) {
            if ancestors.contains(&v.rev) {
                out.push(v);
            } else {
                suspicious = true;
            }
        }
    }
    out.sort_by_key(|v| v.rev);
    let mut deduped: Vec<&RecordVersion> = Vec::with_capacity(out.len());
    for group in out.chunk_by(|a, b| a.rev == b.rev) {
        let Some(first) = group.first().copied() else {
            continue;
        };
        if group.iter().all(|v| *v == first) {
            deduped.push(first);
            continue;
        }
        // 同一修订出现不同内容：取 (hlc, 值的规范编码) 最大者。规范编码只在这种情况下计算，
        // 并保存在会清零的缓冲区中
        suspicious = true;
        let keyed: Vec<(Hlc, Zeroizing<Vec<u8>>, &RecordVersion)> = group
            .iter()
            .map(|v| (v.hlc, to_json(&v.value).unwrap_or_default(), *v))
            .collect();
        if let Some((_, _, best)) = keyed.into_iter().max_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| a.1.as_slice().cmp(b.1.as_slice()))
        }) {
            deduped.push(best);
        }
    }
    (deduped, suspicious)
}

/// 在候选中去掉被因果覆盖的版本，选出胜者（§5.1 步骤 2–4）。
///
/// 返回 (胜者, 其余仍互不覆盖的版本（按 `rev` 升序）, 冲突)。其余版本必须随合并视图一起保存：
/// 合并结果 = 全部候选的极大元集合，这一运算满足结合律，分组合并因此与一次合并结果相同。
fn pick(
    key: &RecordKey,
    candidates: Vec<&RecordVersion>,
    graph: &RevisionGraph,
) -> (RecordVersion, Vec<RecordVersion>, Option<Conflict>) {
    // 去掉被因果覆盖的版本：v.rev 是另一个候选 w.rev 的真祖先
    let maximal: Vec<&RecordVersion> = candidates
        .iter()
        .filter(|v| {
            !candidates
                .iter()
                .any(|w| w.rev != v.rev && graph.is_ancestor(&v.rev, &w.rev))
        })
        .copied()
        .collect();

    // 并发版本中优先保留非墓碑（"宁可多保留"），再按 (hlc, 来源设备) 取最大
    let pool: Vec<&RecordVersion> = if maximal.iter().any(|v| !v.is_tombstone()) {
        maximal
            .iter()
            .filter(|v| !v.is_tombstone())
            .copied()
            .collect()
    } else {
        maximal.clone()
    };
    let Some(winner) = pool
        .iter()
        .copied()
        // (hlc, 来源设备, rev) 构成全序：克隆设备或 HLC 饱和时前两者可能相同（§5.1 步骤 3）
        .max_by_key(|v| (v.hlc, graph.origin(&v.rev), v.rev))
        .cloned()
    else {
        // candidates 非空时 maximal 也非空（DAG 中总存在极大元），这里只是防御
        return (
            candidates
                .first()
                .map(|v| (*v).clone())
                .unwrap_or_else(tombstone),
            Vec::new(),
            None,
        );
    };

    let mut losers: Vec<RecordVersion> = maximal
        .iter()
        .filter(|v| v.rev != winner.rev)
        .map(|v| (*v).clone())
        .collect();
    losers.sort_by_key(|v| v.rev);
    // 版本并发但值相同不需要用户处理；仍保留这些版本，它们携带后续合并需要的因果信息（§5.5）
    let meaningful = losers.iter().any(|l| l.value != winner.value);
    let conflict = meaningful.then(|| Conflict {
        key: key.clone(),
        winner: winner.rev,
        losers: losers.clone(),
    });
    (winner, losers, conflict)
}

fn tombstone() -> RecordVersion {
    RecordVersion {
        hlc: crate::Hlc(0),
        rev: Id128::ZERO,
        value: None,
    }
}

/// 是否存在一个与 `d` 并发的非墓碑记录（`except` 除外）：其写入修订既不是 `d` 的祖先，
/// 也不是 `d` 的后代。后代表示修改发生在看到删除之后（例如在回收站中编辑），不算并发。
/// 撤销删除：该键的当前版本不再作为当前值，与其余极大元一起保存在并发版本中。
///
/// 不能直接删除这些版本：它们仍是之后合并的候选，否则分组合并时更早的删除版本会失去
/// "已被覆盖"的信息而重新生效（§5.2）。
fn suppress(records: &mut RecordMap, concurrent: &mut ConcurrentMap, key: &RecordKey) {
    if let Some(current) = records.remove(key) {
        let all = concurrent.entry(key.clone()).or_default();
        all.push(current);
        all.sort_by_key(|v| v.rev);
    }
}

fn has_concurrent_record(
    records: &RecordMap,
    exempt: &[RecordKey],
    d: &Id128,
    graph: &RevisionGraph,
) -> bool {
    records
        .iter()
        .filter(|(k, _)| !exempt.contains(k))
        .any(|(_, v)| {
            !v.is_tombstone() && !graph.is_ancestor(&v.rev, d) && !graph.is_ancestor(d, &v.rev)
        })
}

#[cfg(test)]
mod tests;
