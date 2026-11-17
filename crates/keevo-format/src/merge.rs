//! 因果优先的确定性合并（`spec/revisions.md` §5）。

use std::collections::BTreeSet;

use keevo_crypto::Id128;

use crate::error::{FormatError, Result};
use crate::graph::RevisionGraph;
use crate::item::ItemDoc;
use crate::record::{RecordKey, RecordMap, RecordVersion};

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
    /// 落选的并发版本。它们仍保存在各自的修订中，可以恢复。
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
}

impl Merged {
    /// 是否需要用户查看冲突。
    #[must_use]
    pub fn has_conflicts(&self) -> bool {
        self.resurrected || !self.conflicts.is_empty()
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
        });
    };
    let item_type = first.item_type;
    if live.iter().any(|(_, d)| d.item_type != item_type) {
        return Err(FormatError::ItemTypeMismatch);
    }

    let keys: BTreeSet<&RecordKey> = live.iter().flat_map(|(_, d)| d.records.keys()).collect();
    let mut records = RecordMap::new();
    let mut conflicts = Vec::new();
    for key in keys {
        let candidates = candidates(&live, key);
        let (winner, conflict) = pick(key, candidates, graph);
        if let Some(c) = conflict {
            conflicts.push(c);
        }
        records.insert(key.clone(), winner);
    }

    let mut resurrected = false;

    // §5.2：回收站状态与修改并发时撤销删除
    let trashed_key = RecordKey::attr("trashed");
    if let Some(trash) = records.get(&trashed_key).filter(|v| !v.is_tombstone()) {
        let d = trash.rev;
        if has_concurrent_record(&records, Some(&trashed_key), &d, graph) {
            records.remove(&trashed_key);
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
            });
        }
        resurrected = true;
    }

    Ok(Merged {
        doc: Some(ItemDoc { item_type, records }),
        conflicts,
        resurrected,
    })
}

/// 收集某个键在各头中的版本，按修订去重并排序，保证结果与输入顺序无关。
fn candidates<'a>(live: &[(Id128, &'a ItemDoc)], key: &RecordKey) -> Vec<&'a RecordVersion> {
    let mut out: Vec<&RecordVersion> = live
        .iter()
        .filter_map(|(_, d)| d.records.get(key))
        .collect();
    out.sort_by(|a, b| a.rev.cmp(&b.rev).then(a.hlc.cmp(&b.hlc)));
    out.dedup_by(|a, b| a.rev == b.rev);
    out
}

fn pick(
    key: &RecordKey,
    candidates: Vec<&RecordVersion>,
    graph: &RevisionGraph,
) -> (RecordVersion, Option<Conflict>) {
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
            None,
        );
    };

    let losers: Vec<RecordVersion> = maximal
        .iter()
        .filter(|v| v.rev != winner.rev)
        .map(|v| (*v).clone())
        .collect();
    let meaningful = losers.iter().any(|l| l.value != winner.value);
    let conflict = meaningful.then(|| Conflict {
        key: key.clone(),
        winner: winner.rev,
        losers,
    });
    (winner, conflict)
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
