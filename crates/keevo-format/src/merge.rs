//! 因果优先的确定性合并（`spec/revisions.md` §5）。

use std::collections::{BTreeSet, HashSet};

use keevo_crypto::Id128;

use crate::error::{FormatError, Result};
use crate::graph::RevisionGraph;
use crate::item::ItemDoc;
use crate::json::to_json;
use crate::record::{ConcurrentMap, RecordKey, RecordMap, RecordVersion};

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
    let live: Vec<(Id128, &ItemDoc)> = heads
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
        if let Some(c) = conflict {
            conflicts.push(c);
        }
        records.insert(key.clone(), winner);
        if !others.is_empty() {
            concurrent.insert(key.clone(), others);
        }
    }

    let mut resurrected = false;

    // §5.2：回收站状态与修改并发时撤销删除
    let trashed_key = RecordKey::attr("trashed");
    if let Some(trash) = records.get(&trashed_key).filter(|v| !v.is_tombstone()) {
        let d = trash.rev;
        if has_concurrent_record(&records, Some(&trashed_key), &d, graph)
            && let Some(current) = records.remove(&trashed_key)
        {
            // 不是删除这些版本，而是让它们不再作为当前值：它们仍是之后合并的候选，
            // 否则分组合并时更早的回收站版本会失去"已被覆盖"的信息而重新生效（§5.2）
            let all = concurrent.entry(trashed_key.clone()).or_default();
            all.push(current);
            all.sort_by_key(|v| v.rev);
            resurrected = true;
        }
    }

    // §5.2 / §6：对象墓碑与修改并发时撤销删除；只要有一个墓碑覆盖了全部记录，删除即成立
    if !deleted.is_empty() {
        let deletion_stands = deleted
            .iter()
            .any(|d| !has_concurrent_record(&records, None, d, graph));
        if deletion_stands {
            return Ok(Merged {
                doc: None,
                conflicts: Vec::new(),
                resurrected: false,
                integrity_issues,
            });
        }
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
    let canonical = |v: &RecordVersion| to_json(&v.value).map(|b| b.to_vec()).unwrap_or_default();
    out.sort_by(|a, b| {
        a.rev
            .cmp(&b.rev)
            .then(a.hlc.cmp(&b.hlc))
            .then_with(|| canonical(a).cmp(&canonical(b)))
    });
    let mut deduped: Vec<&RecordVersion> = Vec::with_capacity(out.len());
    for v in out {
        match deduped.last_mut() {
            Some(last) if last.rev == v.rev => {
                if *last != v {
                    suspicious = true;
                }
                // 排序后同一修订的最后一个即 (hlc, 规范 JSON) 最大者
                *last = v;
            }
            _ => deduped.push(v),
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
        .max_by_key(|v| (v.hlc, graph.origin(&v.rev)))
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
fn has_concurrent_record(
    records: &RecordMap,
    except: Option<&RecordKey>,
    d: &Id128,
    graph: &RevisionGraph,
) -> bool {
    records
        .iter()
        .filter(|(k, _)| Some(*k) != except)
        .any(|(_, v)| {
            !v.is_tombstone() && !graph.is_ancestor(&v.rev, d) && !graph.is_ancestor(d, &v.rev)
        })
}

#[cfg(test)]
mod tests;
