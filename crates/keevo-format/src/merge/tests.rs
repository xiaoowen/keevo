#![allow(
    clippy::arithmetic_side_effects,
    reason = "测试代码中的算术不涉及安全边界"
)]

use std::collections::{BTreeMap, BTreeSet};

use keevo_crypto::Id128;

use super::*;
use crate::hlc::Hlc;
use crate::item::ItemType;
use crate::record::RecordValue;

fn id(n: u8) -> Id128 {
    Id128::from_bytes([n; 16])
}

fn text(s: &str) -> RecordValue {
    RecordValue::Text(s.into())
}

fn title() -> RecordKey {
    RecordKey::attr("title")
}

/// 测试辅助：修订仓库，按 (rev, parents, origin, 内容) 构建修订图与头。
#[derive(Default)]
struct Repo {
    graph: RevisionGraph,
    docs: BTreeMap<Id128, Option<ItemDoc>>,
}

impl Repo {
    fn commit(&mut self, rev: Id128, parents: &[Id128], origin: Id128, doc: Option<ItemDoc>) {
        self.graph.insert(rev, parents.to_vec(), origin);
        self.docs.insert(rev, doc);
    }

    fn heads_of(&self, revs: &BTreeSet<Id128>) -> Vec<Id128> {
        revs.iter()
            .filter(|r| !revs.iter().any(|o| o != *r && self.graph.is_ancestor(r, o)))
            .copied()
            .collect()
    }

    fn states(&self, heads: &[Id128]) -> Vec<HeadState<'_>> {
        heads
            .iter()
            .map(|r| match self.docs.get(r).and_then(Option::as_ref) {
                Some(doc) => HeadState::Live { rev: *r, doc },
                None => HeadState::Deleted { rev: *r },
            })
            .collect()
    }

    fn merge(&self, heads: &[Id128]) -> Merged {
        merge_heads(&self.states(heads), &self.graph).unwrap()
    }
}

fn base_doc(rev: Id128) -> ItemDoc {
    let mut d = ItemDoc::new(ItemType::Login);
    d.set(title(), text("base"), Hlc(10), rev).unwrap();
    d
}

#[test]
fn causally_later_wins_even_with_smaller_hlc() {
    let mut repo = Repo::default();
    repo.commit(id(1), &[], id(100), Some(base_doc(id(1))));
    // 设备 B 时钟偏快，写入了大 HLC
    let mut b = base_doc(id(1));
    b.set(title(), text("from B"), Hlc(1_000_000), id(2))
        .unwrap();
    repo.commit(id(2), &[id(1)], id(101), Some(b.clone()));
    // 设备 A 看到 B 之后再修改，但时钟偏慢
    let mut a = b;
    a.set(title(), text("from A after B"), Hlc(20), id(3))
        .unwrap();
    repo.commit(id(3), &[id(2)], id(100), Some(a));
    // 同时让 B 的修订也作为头参与（模拟仍未收敛的视图）
    let m = repo.merge(&[id(3), id(2)]);
    assert_eq!(m.doc.unwrap().get(&title()), Some(&text("from A after B")));
    assert!(m.conflicts.is_empty());
}

#[test]
fn concurrent_edits_pick_higher_hlc_and_report_conflict() {
    let mut repo = Repo::default();
    repo.commit(id(1), &[], id(100), Some(base_doc(id(1))));
    let mut a = base_doc(id(1));
    a.set(title(), text("A"), Hlc(50), id(2)).unwrap();
    repo.commit(id(2), &[id(1)], id(100), Some(a));
    let mut b = base_doc(id(1));
    b.set(title(), text("B"), Hlc(60), id(3)).unwrap();
    repo.commit(id(3), &[id(1)], id(101), Some(b));

    let m = repo.merge(&[id(2), id(3)]);
    assert_eq!(m.doc.unwrap().get(&title()), Some(&text("B")));
    assert_eq!(m.conflicts.len(), 1);
    assert_eq!(m.conflicts[0].winner, id(3));
    assert_eq!(m.conflicts[0].losers[0].value, Some(text("A")));
}

#[test]
fn equal_hlc_is_broken_by_origin_device() {
    let mut repo = Repo::default();
    repo.commit(id(1), &[], id(100), Some(base_doc(id(1))));
    let mut a = base_doc(id(1));
    a.set(title(), text("low device"), Hlc(50), id(2)).unwrap();
    repo.commit(id(2), &[id(1)], id(100), Some(a));
    let mut b = base_doc(id(1));
    b.set(title(), text("high device"), Hlc(50), id(3)).unwrap();
    repo.commit(id(3), &[id(1)], id(200), Some(b));
    assert_eq!(
        repo.merge(&[id(3), id(2)]).doc.unwrap().get(&title()),
        Some(&text("high device"))
    );
}

#[test]
fn concurrent_delete_and_edit_keeps_the_edit() {
    let mut repo = Repo::default();
    repo.commit(id(1), &[], id(100), Some(base_doc(id(1))));
    let mut a = base_doc(id(1));
    a.delete(title(), Hlc(90), id(2));
    repo.commit(id(2), &[id(1)], id(100), Some(a));
    let mut b = base_doc(id(1));
    b.set(title(), text("edited"), Hlc(20), id(3)).unwrap();
    repo.commit(id(3), &[id(1)], id(101), Some(b));
    let m = repo.merge(&[id(2), id(3)]);
    assert_eq!(m.doc.unwrap().get(&title()), Some(&text("edited")));
    assert_eq!(m.conflicts.len(), 1);
}

#[test]
fn trash_concurrent_with_edit_is_undone_but_edit_in_trash_is_not() {
    let trashed = RecordKey::attr("trashed");
    let field = RecordKey::attr("note");
    let mut repo = Repo::default();
    repo.commit(id(1), &[], id(100), Some(base_doc(id(1))));

    let mut a = base_doc(id(1));
    a.set(trashed.clone(), RecordValue::Int(123), Hlc(50), id(2))
        .unwrap();
    repo.commit(id(2), &[id(1)], id(100), Some(a.clone()));
    let mut b = base_doc(id(1));
    b.set(field.clone(), text("concurrent"), Hlc(40), id(3))
        .unwrap();
    repo.commit(id(3), &[id(1)], id(101), Some(b));

    let m = repo.merge(&[id(2), id(3)]);
    assert!(m.resurrected);
    assert_eq!(m.doc.unwrap().trashed_at(), None);

    // 在回收站中编辑（看到删除之后）：保持删除状态
    let mut c = a;
    c.set(field, text("edited in trash"), Hlc(60), id(4))
        .unwrap();
    repo.commit(id(4), &[id(2)], id(100), Some(c));
    let m = repo.merge(&[id(4)]);
    assert!(!m.resurrected);
    assert_eq!(m.doc.unwrap().trashed_at(), Some(123));
}

#[test]
fn object_tombstone_vs_concurrent_edit() {
    let mut repo = Repo::default();
    repo.commit(id(1), &[], id(100), Some(base_doc(id(1))));
    repo.commit(id(2), &[id(1)], id(100), None); // 永久删除
    let mut b = base_doc(id(1));
    b.set(title(), text("still needed"), Hlc(30), id(3))
        .unwrap();
    repo.commit(id(3), &[id(1)], id(101), Some(b));

    let m = repo.merge(&[id(2), id(3)]);
    assert!(m.resurrected);
    assert_eq!(m.doc.unwrap().get(&title()), Some(&text("still needed")));

    // 只有墓碑：已删除
    assert_eq!(repo.merge(&[id(2)]).doc, None);

    // 并发的另一个头没有新修改（只是重新包装了旧记录）：删除成立
    repo.commit(id(4), &[id(1)], id(102), Some(base_doc(id(1))));
    assert_eq!(repo.merge(&[id(2), id(4)]).doc, None);
}

#[test]
fn mismatched_item_types_are_rejected() {
    let mut repo = Repo::default();
    repo.commit(id(1), &[], id(100), Some(base_doc(id(1))));
    repo.commit(
        id(2),
        &[],
        id(100),
        Some(ItemDoc::new(ItemType::SecureNote)),
    );
    assert_eq!(
        merge_heads(&repo.states(&[id(1), id(2)]), &repo.graph).err(),
        Some(FormatError::ItemTypeMismatch)
    );
    assert_eq!(
        merge_heads(&[], &repo.graph).err(),
        Some(FormatError::NoHeads)
    );
}

// ---------------------------------------------------------------- 随机模拟

/// splitmix64：测试专用的确定性伪随机数，不用于任何密码学用途。
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
    fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = usize::try_from(self.below(u64::try_from(i).unwrap() + 1)).unwrap();
            v.swap(i, j);
        }
    }
}

fn random_id(rng: &mut Rng) -> Id128 {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&rng.next().to_le_bytes());
    b[8..].copy_from_slice(&rng.next().to_le_bytes());
    Id128::from_bytes(b)
}

const KEYS: [&str; 6] = [
    "attr:title",
    "attr:favorite",
    "tag:work",
    "tag:home",
    "attr:note",
    "attr:trashed",
];

fn random_mutation(rng: &mut Rng, doc: &mut ItemDoc, hlc: Hlc, rev: Id128) {
    let edits = 1 + rng.below(3);
    for _ in 0..edits {
        let key: RecordKey = serde_json::from_str(&format!(
            "\"{}\"",
            KEYS[usize::try_from(rng.below(6)).unwrap()]
        ))
        .unwrap();
        if rng.chance(25) {
            doc.delete(key, hlc, rev);
            continue;
        }
        let value = match &key {
            RecordKey::Tag(_) => RecordValue::Tag,
            RecordKey::Attr(n) if n == "favorite" => RecordValue::Bool(rng.chance(50)),
            RecordKey::Attr(n) if n == "trashed" => {
                RecordValue::Int(i64::try_from(rng.below(1000)).unwrap())
            }
            _ => text(&format!("v{}", rng.below(1000))),
        };
        doc.set(key, value, hlc, rev).unwrap();
    }
}

/// 3 台设备随机编辑、随机两两同步，最后全部同步。断言：
/// 1. 所有设备得到相同的合并结果（收敛）；
/// 2. 合并结果与头的顺序无关，重复的头不影响结果（交换律、幂等）；
/// 3. 任意清理非头修订的内容不影响结果（清理无关性）。
#[test]
fn random_simulation_converges_deterministically() {
    for seed in 0..300u64 {
        let mut rng = Rng(seed);
        let devices = [id(201), id(202), id(203)];
        let mut repo = Repo::default();
        let root = id(1);
        repo.commit(root, &[], devices[0], Some(base_doc(root)));
        let mut known: Vec<BTreeSet<Id128>> = vec![BTreeSet::from([root]); 3];
        let mut clocks = [crate::HlcClock::default(); 3];
        // 每台设备的时钟偏移，用来模拟时钟不准
        let skew = [0u64, 7_000, 3_000];

        for step in 0..40u64 {
            let d = usize::try_from(rng.below(3)).unwrap();
            if rng.chance(30) {
                let other = usize::try_from(rng.below(3)).unwrap();
                let union: BTreeSet<Id128> = known[d].union(&known[other]).copied().collect();
                // 同步时观察对方的时间戳
                let max_hlc = union
                    .iter()
                    .filter_map(|r| repo.docs[r].as_ref())
                    .flat_map(|doc| doc.records.values().map(|v| v.hlc))
                    .max()
                    .unwrap_or_default();
                clocks[d].observe(max_hlc, 0);
                clocks[other].observe(max_hlc, 0);
                known[d] = union.clone();
                known[other] = union;
                continue;
            }
            let heads = repo.heads_of(&known[d]);
            let merged = repo.merge(&heads);
            let rev = random_id(&mut rng);
            let hlc = clocks[d].next(step * 1_000 + skew[d]);
            let doc = match merged.doc {
                Some(mut doc) if !rng.chance(3) => {
                    random_mutation(&mut rng, &mut doc, hlc, rev);
                    Some(doc)
                }
                Some(_) => None, // 少量永久删除
                None => continue,
            };
            repo.commit(rev, &heads, devices[d], doc);
            known[d].insert(rev);
        }

        let all: BTreeSet<Id128> = known.iter().flatten().copied().collect();
        let heads = repo.heads_of(&all);
        let reference = repo.merge(&heads);

        for _ in 0..5 {
            let mut shuffled = heads.clone();
            shuffled.extend(heads.iter().take(1).copied()); // 重复一个头
            rng.shuffle(&mut shuffled);
            assert_eq!(
                repo.merge(&shuffled),
                reference,
                "seed {seed}: 顺序或重复影响了结果"
            );
        }

        // 清理所有非头修订的内容（元数据保留在图中）
        let mut pruned = Repo {
            graph: repo.graph.clone(),
            docs: BTreeMap::new(),
        };
        for h in &heads {
            pruned.docs.insert(*h, repo.docs[h].clone());
        }
        assert_eq!(
            pruned.merge(&heads),
            reference,
            "seed {seed}: 清理历史影响了结果"
        );
    }
}
