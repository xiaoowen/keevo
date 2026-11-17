//! 修订图（`spec/revisions.md` §2）。

use std::collections::{HashMap, HashSet};

use keevo_crypto::Id128;

#[derive(Debug, Clone)]
struct Node {
    parents: Vec<Id128>,
    origin: Id128,
}

/// 一个对象的修订图：修订 ID → 父修订与来源设备。
///
/// 只保存元数据，不保存内容；即使修订内容已被清理，图也必须完整保留。
#[derive(Debug, Clone, Default)]
pub struct RevisionGraph {
    nodes: HashMap<Id128, Node>,
}

impl RevisionGraph {
    /// 空图。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 加入一个修订。重复加入同一修订时以首次为准。
    pub fn insert(&mut self, rev: Id128, parents: Vec<Id128>, origin_device: Id128) {
        self.nodes.entry(rev).or_insert(Node {
            parents,
            origin: origin_device,
        });
    }

    /// 修订数量。
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// 是否包含某修订。
    #[must_use]
    pub fn contains(&self, rev: &Id128) -> bool {
        self.nodes.contains_key(rev)
    }

    /// 修订的来源设备。未知修订返回 [`Id128::ZERO`]。
    #[must_use]
    pub fn origin(&self, rev: &Id128) -> Id128 {
        self.nodes.get(rev).map_or(Id128::ZERO, |n| n.origin)
    }

    /// `a` 是否是 `b` 的祖先（含 `a == b`）。
    #[must_use]
    pub fn is_ancestor(&self, a: &Id128, b: &Id128) -> bool {
        if a == b {
            return true;
        }
        let mut stack = vec![*b];
        let mut seen = HashSet::new();
        while let Some(cur) = stack.pop() {
            if !seen.insert(cur) {
                continue;
            }
            if let Some(node) = self.nodes.get(&cur) {
                for p in &node.parents {
                    if p == a {
                        return true;
                    }
                    stack.push(*p);
                }
            }
        }
        false
    }

    /// 头修订：不是任何其他修订父修订的修订，按 ID 排序。
    #[must_use]
    pub fn heads(&self) -> Vec<Id128> {
        let parents: HashSet<&Id128> = self.nodes.values().flat_map(|n| n.parents.iter()).collect();
        let mut heads: Vec<Id128> = self
            .nodes
            .keys()
            .filter(|r| !parents.contains(r))
            .copied()
            .collect();
        heads.sort();
        heads
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> Id128 {
        Id128::from_bytes([n; 16])
    }

    #[test]
    fn ancestry_and_heads() {
        // 1 ← 2 ← 3
        //   ↖ 4
        let mut g = RevisionGraph::new();
        g.insert(id(1), vec![], id(100));
        g.insert(id(2), vec![id(1)], id(100));
        g.insert(id(3), vec![id(2)], id(100));
        g.insert(id(4), vec![id(1)], id(101));
        assert!(g.is_ancestor(&id(1), &id(3)));
        assert!(g.is_ancestor(&id(3), &id(3)));
        assert!(!g.is_ancestor(&id(3), &id(1)));
        assert!(!g.is_ancestor(&id(2), &id(4)));
        assert_eq!(g.heads(), vec![id(3), id(4)]);
        g.insert(id(5), vec![id(3), id(4)], id(100));
        assert_eq!(g.heads(), vec![id(5)]);
        assert_eq!(g.origin(&id(4)), id(101));
    }
}
