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
        self.graph.insert(rev, parents.to_vec(), origin).unwrap();
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
    a.delete(title(), Hlc(90), id(2)).unwrap();
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
            doc.delete(key, hlc, rev).unwrap();
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
                    .flat_map(|doc| {
                        doc.records
                            .values()
                            .chain(doc.concurrent.values().flatten())
                            .map(|v| v.hlc)
                    })
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
            let hlc = clocks[d].next(step * 1_000 + skew[d]).unwrap();
            let doc = match merged.doc {
                Some(mut doc) if !rng.chance(3) => {
                    doc.settle_for_write(hlc, rev);
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
        assert!(
            reference.integrity_issues.is_empty(),
            "seed {seed}: 正常历史被误判为出处不一致"
        );

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

        // 结合律（评审 F4）：随机挑一组头合并并写成合并修订，再与其余头合并，反复直到只剩一个头。
        // 每一步的结果都必须与一次合并全部头相同。合并结果为"已删除"的组不写回（产品中删除视图不可编辑，
        // 墓碑只由用户的永久删除写入），换一组再试。
        let mut grouped = repo;
        let mut current = heads;
        let mut attempts = 0;
        while current.len() > 1 && attempts < 50 {
            attempts += 1;
            let mut pool = current.clone();
            rng.shuffle(&mut pool);
            let take =
                2 + usize::try_from(rng.below(u64::try_from(pool.len() - 1).unwrap())).unwrap();
            let group: Vec<Id128> = pool[..take.min(pool.len())].to_vec();
            let merged = grouped.merge(&group);
            if merged.doc.is_none() {
                continue;
            }
            let m = random_id(&mut rng);
            grouped.commit(m, &group, devices[0], merged.doc);
            current.retain(|h| !group.contains(h));
            current.push(m);
            let now = grouped.merge(&current);
            // 比较条目状态。`resurrected` 是对本次合并的提示：对象墓碑头被并入合并修订后成为祖先，
            // 提示随之消失，这是预期行为（产品中合并修订只在用户看过冲突面板后写入）
            assert_eq!(now.doc, reference.doc, "seed {seed}: 分组合并改变了结果");
            assert_eq!(
                now.integrity_issues, reference.integrity_issues,
                "seed {seed}"
            );
        }
    }
}

// ---------------------------------------------------------------- 评审 2026-11-18 F4、F5

/// F4：合并结果是完整头集合的函数。A 被 B（删除）因果覆盖，C 与 B 并发：删除与修改并发时保留修改，结果为 C。
#[test]
fn review_f4_full_head_set_merge_keeps_concurrent_edit_over_delete() {
    let mut repo = Repo::default();
    repo.commit(id(1), &[], id(100), Some(ItemDoc::new(ItemType::Login)));
    let mut a = ItemDoc::new(ItemType::Login);
    a.set(title(), text("A"), Hlc(20), id(2)).unwrap();
    repo.commit(id(2), &[id(1)], id(100), Some(a.clone()));
    let mut a2 = a.clone();
    a2.set(RecordKey::attr("note"), text("other"), Hlc(25), id(3))
        .unwrap();
    repo.commit(id(3), &[id(2)], id(100), Some(a2));
    let mut b = a;
    b.delete(title(), Hlc(30), id(4)).unwrap();
    repo.commit(id(4), &[id(2)], id(101), Some(b));
    let mut c = ItemDoc::new(ItemType::Login);
    c.set(title(), text("C"), Hlc(15), id(5)).unwrap();
    repo.commit(id(5), &[id(1)], id(102), Some(c));

    let m = repo.merge(&[id(3), id(4), id(5)]);
    assert_eq!(m.doc.unwrap().get(&title()), Some(&text("C")));
}

/// F5：两个头里出现"同一记录版本标识、不同值"。结果不得依赖输入顺序，且必须报告完整性问题。
#[test]
fn review_f5_forged_record_version_is_deterministic_and_reported() {
    let mut repo = Repo::default();
    repo.commit(id(1), &[], id(100), Some(base_doc(id(1))));
    repo.commit(id(2), &[id(1)], id(100), Some(base_doc(id(1))));
    let mut forged = ItemDoc::new(ItemType::Login);
    forged.records.insert(
        title(),
        RecordVersion {
            hlc: Hlc(10),
            rev: id(1),
            value: Some(text("forged")),
        },
    );
    repo.commit(id(3), &[id(1)], id(101), Some(forged));

    let x = repo.merge(&[id(2), id(3)]);
    let y = repo.merge(&[id(3), id(2)]);
    assert_eq!(x, y, "结果依赖输入顺序");
    assert!(x.integrity_issues.contains(&title()), "应报告完整性问题");
}

/// F5 延伸：记录声称写于一个不是其所在修订祖先的修订，不得参与因果判断。
#[test]
fn review_f5_record_claiming_unrelated_revision_is_rejected() {
    let mut repo = Repo::default();
    repo.commit(id(1), &[], id(100), Some(base_doc(id(1))));
    let mut honest = base_doc(id(1));
    honest.set(title(), text("honest"), Hlc(50), id(2)).unwrap();
    repo.commit(id(2), &[id(1)], id(100), Some(honest));
    // 并发分支伪造：声称自己的标题写于 id(2) 的后代 id(9)（并不存在于其祖先中）
    repo.graph.insert(id(9), vec![id(2)], id(100)).unwrap();
    let mut liar = base_doc(id(1));
    liar.records.insert(
        title(),
        RecordVersion {
            hlc: Hlc(1),
            rev: id(9),
            value: Some(text("liar")),
        },
    );
    repo.commit(id(3), &[id(1)], id(101), Some(liar));

    let m = repo.merge(&[id(2), id(3)]);
    assert_eq!(m.doc.unwrap().get(&title()), Some(&text("honest")));
    assert!(m.integrity_issues.contains(&title()));
}

/// F4：先把 B、C 合并并写成合并修订 M，再与 A′ 合并，结果必须与一次合并 A′、B、C 相同。
#[test]
fn review_f4_grouped_merge_through_merge_revision_matches_full_merge() {
    let mut repo = Repo::default();
    repo.commit(id(1), &[], id(100), Some(ItemDoc::new(ItemType::Login)));
    let mut a = ItemDoc::new(ItemType::Login);
    a.set(title(), text("A"), Hlc(20), id(2)).unwrap();
    repo.commit(id(2), &[id(1)], id(100), Some(a.clone()));
    let mut a2 = a.clone();
    a2.set(RecordKey::attr("note"), text("other"), Hlc(25), id(3))
        .unwrap();
    repo.commit(id(3), &[id(2)], id(100), Some(a2));
    let mut b = a;
    b.delete(title(), Hlc(30), id(4)).unwrap();
    repo.commit(id(4), &[id(2)], id(101), Some(b));
    let mut c = ItemDoc::new(ItemType::Login);
    c.set(title(), text("C"), Hlc(15), id(5)).unwrap();
    repo.commit(id(5), &[id(1)], id(102), Some(c));

    let full = repo.merge(&[id(3), id(4), id(5)]);
    let bc = repo.merge(&[id(4), id(5)]);
    repo.commit(id(6), &[id(4), id(5)], id(101), bc.doc);
    let grouped = repo.merge(&[id(3), id(6)]);
    assert_eq!(full.doc.as_ref().unwrap().get(&title()), Some(&text("C")));
    assert_eq!(grouped.doc, full.doc, "分组合并改变了结果");
}

/// 撤销删除并在其上编辑之后，即使引发撤销的并发修改后来被覆盖，条目也不会重新进入回收站（§5.2、§5.4）。
#[test]
fn restore_by_concurrent_edit_is_settled_when_written() {
    let mut repo = Repo::default();
    repo.commit(id(1), &[], id(100), Some(base_doc(id(1))));
    let mut trashed = base_doc(id(1));
    trashed
        .set(
            RecordKey::attr("trashed"),
            RecordValue::Int(1),
            Hlc(20),
            id(2),
        )
        .unwrap();
    repo.commit(id(2), &[id(1)], id(100), Some(trashed));
    let mut edited = base_doc(id(1));
    edited.set(title(), text("edited"), Hlc(15), id(3)).unwrap();
    repo.commit(id(3), &[id(1)], id(101), Some(edited));

    let m = repo.merge(&[id(2), id(3)]);
    assert!(m.resurrected);
    let mut base = m.doc.unwrap();
    assert_eq!(base.trashed_at(), None);
    // 设备 A 在撤销删除后的视图上把标题改回去（覆盖了引发撤销的那次修改）
    base.settle_for_write(Hlc(30), id(4));
    base.set(title(), text("final"), Hlc(30), id(4)).unwrap();
    repo.commit(id(4), &[id(2), id(3)], id(100), Some(base));
    // 设备 B 只看到删除，在回收站里改了别的字段
    let mut in_trash = repo.docs[&id(2)].clone().unwrap();
    in_trash
        .set(RecordKey::attr("note"), text("n"), Hlc(25), id(5))
        .unwrap();
    repo.commit(id(5), &[id(2)], id(102), Some(in_trash));

    let m = repo.merge(&[id(4), id(5)]);
    assert_eq!(
        m.doc.unwrap().trashed_at(),
        None,
        "已撤销的删除不应重新生效"
    );
}

/// 并发落选版本保存在之后的修订中，直到用户处理；处理后冲突消失（§4.3、§5.4）。
#[test]
fn concurrent_versions_survive_unrelated_edits_until_resolved() {
    let mut repo = Repo::default();
    repo.commit(id(1), &[], id(100), Some(base_doc(id(1))));
    let mut a = base_doc(id(1));
    a.set(title(), text("A"), Hlc(20), id(2)).unwrap();
    repo.commit(id(2), &[id(1)], id(100), Some(a));
    let mut b = base_doc(id(1));
    b.set(title(), text("B"), Hlc(30), id(3)).unwrap();
    repo.commit(id(3), &[id(1)], id(101), Some(b));

    // 30 次与标题无关的编辑（远超历史保留数），落选的 "A" 仍在头修订里
    let mut head = id(4);
    let mut doc = repo.merge(&[id(2), id(3)]).doc.unwrap();
    let mut parents = vec![id(2), id(3)];
    for i in 0..30u8 {
        let rev = Id128::from_bytes([i.wrapping_add(50); 16]);
        doc.set(
            RecordKey::attr("note"),
            text(&format!("n{i}")),
            Hlc(40 + u64::from(i)),
            rev,
        )
        .unwrap();
        repo.commit(rev, &parents, id(100), Some(doc.clone()));
        parents = vec![rev];
        head = rev;
    }
    let m = repo.merge(&[head]);
    assert_eq!(m.conflicts.len(), 1);
    assert_eq!(m.conflicts[0].losers[0].value, Some(text("A")));

    // 用户选择保留 "A"
    let mut doc = m.doc.unwrap();
    doc.resolve(&title(), id(2), Hlc(100), id(90)).unwrap();
    repo.commit(id(90), &[head], id(100), Some(doc));
    let m = repo.merge(&[id(90)]);
    assert!(m.conflicts.is_empty());
    assert!(m.doc.as_ref().unwrap().concurrent.is_empty());
    assert_eq!(m.doc.unwrap().get(&title()), Some(&text("A")));
}

// ---------------------------------------------------------------- 评审第二轮 G2

/// 第二轮 G2：对象墓碑也必须进入可持久化的合并状态。先合并 {D, A} 并写成纯合并修订，
/// 再与 C 合并，结果必须与一次合并 {D, C, A} 相同（都是已删除）。
#[test]
fn review2_g2_object_tombstone_survives_grouped_merge() {
    let mut repo = Repo::default();
    repo.commit(id(1), &[], id(100), Some(ItemDoc::new(ItemType::Login)));
    let mut w = ItemDoc::new(ItemType::Login);
    w.set(title(), text("W"), Hlc(20), id(2)).unwrap();
    repo.commit(id(2), &[id(1)], id(100), Some(w.clone()));
    repo.commit(id(3), &[id(2)], id(100), None); // D：永久删除
    repo.commit(id(4), &[id(2)], id(101), Some(w)); // C：仍携带写于 W 的标题
    let mut a = ItemDoc::new(ItemType::Login);
    a.set(title(), text("A"), Hlc(15), id(5)).unwrap();
    repo.commit(id(5), &[id(1)], id(102), Some(a));

    let full = repo.merge(&[id(3), id(4), id(5)]);
    assert!(full.doc.is_none(), "一次合并：删除成立");
    let da = repo.merge(&[id(3), id(5)]);
    assert!(da.resurrected);
    repo.commit(id(6), &[id(3), id(5)], id(102), da.doc);
    let grouped = repo.merge(&[id(6), id(4)]);
    assert_eq!(grouped.doc, full.doc, "分组合并改变了对象是否存在");
}

/// 第二轮 G2：回收站状态在纯合并（不写入恢复操作）下与一次合并相同。
#[test]
fn review2_g2_trash_survives_grouped_pure_merge() {
    let trashed = RecordKey::attr("trashed");
    let mut repo = Repo::default();
    repo.commit(id(1), &[], id(100), Some(base_doc(id(1))));
    let mut d = base_doc(id(1));
    d.set(trashed.clone(), RecordValue::Int(30), Hlc(30), id(2))
        .unwrap();
    repo.commit(id(2), &[id(1)], id(100), Some(d.clone()));
    let mut a = base_doc(id(1));
    a.set(title(), text("A"), Hlc(15), id(3)).unwrap();
    repo.commit(id(3), &[id(1)], id(101), Some(a));
    let mut c = d;
    c.set(title(), text("C"), Hlc(40), id(4)).unwrap();
    repo.commit(id(4), &[id(2)], id(100), Some(c));

    let full = repo.merge(&[id(3), id(4)]);
    assert!(
        full.doc.as_ref().unwrap().trashed_at().is_some(),
        "一次合并：仍在回收站"
    );
    let da = repo.merge(&[id(2), id(3)]);
    assert!(da.resurrected);
    repo.commit(id(5), &[id(2), id(3)], id(101), da.doc);
    let grouped = repo.merge(&[id(5), id(4)]);
    assert_eq!(grouped.doc, full.doc);
}

/// 第二轮评审 §4：(hlc, 来源设备) 完全相同时按 rev 决胜，结果与输入顺序无关。
#[test]
fn review2_equal_hlc_and_origin_break_ties_by_rev() {
    let mut repo = Repo::default();
    repo.commit(id(1), &[], id(100), Some(base_doc(id(1))));
    for (rev, v) in [(id(2), "low"), (id(3), "high")] {
        let mut d = base_doc(id(1));
        d.set(title(), text(v), Hlc(50), rev).unwrap();
        repo.commit(rev, &[id(1)], id(100), Some(d));
    }
    for heads in [[id(2), id(3)], [id(3), id(2)]] {
        let m = repo.merge(&heads);
        assert_eq!(m.doc.unwrap().get(&title()), Some(&text("high")));
    }
}

/// 第三轮评审 §4.1：两个并发的回收站时间被撤销后，不再作为字段冲突报告（§5.5）。
#[test]
fn review3_suppressed_trash_is_not_a_field_conflict() {
    let trashed = RecordKey::attr("trashed");
    let mut repo = Repo::default();
    repo.commit(id(1), &[], id(100), Some(base_doc(id(1))));
    for (rev, t, origin) in [(id(2), 10, id(100)), (id(3), 20, id(101))] {
        let mut d = base_doc(id(1));
        d.set(trashed.clone(), RecordValue::Int(t), Hlc(30), rev)
            .unwrap();
        repo.commit(rev, &[id(1)], origin, Some(d));
    }
    let mut e = base_doc(id(1));
    e.set(title(), text("edited"), Hlc(40), id(4)).unwrap();
    repo.commit(id(4), &[id(1)], id(102), Some(e));
    let m = repo.merge(&[id(2), id(3), id(4)]);
    assert!(m.resurrected);
    assert!(
        m.conflicts.iter().all(|c| c.key != trashed),
        "{:?}",
        m.conflicts
    );
    assert_eq!(m.doc.unwrap().trashed_at(), None);
}
