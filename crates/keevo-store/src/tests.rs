use super::*;

fn id(n: u8) -> Id128 {
    Id128::from_bytes([n; 16])
}

fn rev(rev_id: u8, parents: &[u8]) -> RevisionRow {
    RevisionRow {
        rev_id: id(rev_id),
        object_id: id(50),
        kind: ObjectKind::Item,
        vault_id: id(40),
        parents: parents.iter().map(|p| id(*p)).collect(),
        origin_device: id(9),
        origin_seq: None,
        wrapped_key_ct: Some(vec![rev_id; 8]),
        overview_ct: Some(vec![1, 2, 3]),
        details_ct: Some(vec![4, 5, 6]),
        deleted: false,
        pruned: false,
    }
}

fn head_ids(store: &Store) -> Vec<Id128> {
    store
        .heads(&id(50))
        .unwrap()
        .into_iter()
        .map(|r| r.rev_id)
        .collect()
}

#[test]
fn schema_is_created_once() {
    let store = Store::open_in_memory().unwrap();
    assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
}

#[test]
fn account_is_unique() {
    let mut store = Store::open_in_memory().unwrap();
    assert_eq!(store.account().unwrap(), None);
    let row = AccountRow {
        id: id(1),
        format_version: 1,
        epoch: 1,
        kdf_params: vec![1; 29],
        keyset_ct: vec![2; 400],
    };
    store.create_account(&row).unwrap();
    assert_eq!(store.account().unwrap(), Some(row.clone()));
    assert_eq!(store.create_account(&row), Err(StoreError::AccountExists));
}

#[test]
fn heads_follow_forks_and_merges() {
    let mut store = Store::open_in_memory().unwrap();
    store.insert_revision(&rev(1, &[])).unwrap();
    assert_eq!(head_ids(&store), vec![id(1)]);
    store.insert_revision(&rev(2, &[1])).unwrap();
    assert_eq!(head_ids(&store), vec![id(2)]);
    // 并发分叉
    store.insert_revision(&rev(3, &[1])).unwrap();
    assert_eq!(head_ids(&store), vec![id(2), id(3)]);
    // 编辑时收敛
    store.insert_revision(&rev(4, &[2, 3])).unwrap();
    assert_eq!(head_ids(&store), vec![id(4)]);
    assert_eq!(store.objects(ObjectKind::Item).unwrap(), vec![id(50)]);
    assert!(store.objects(ObjectKind::Vault).unwrap().is_empty());

    let graph = store.graph(&id(50)).unwrap();
    assert_eq!(graph.len(), 4);
    assert_eq!(graph[3].parents, vec![id(2), id(3)]);
    assert_eq!(store.revision(&id(3)).unwrap().unwrap(), rev(3, &[1]));
}

#[test]
fn revisions_must_be_topological_and_unique() {
    let mut store = Store::open_in_memory().unwrap();
    assert_eq!(
        store.insert_revision(&rev(2, &[1])),
        Err(StoreError::MissingParent)
    );
    store.insert_revision(&rev(1, &[])).unwrap();
    assert_eq!(
        store.insert_revision(&rev(1, &[])),
        Err(StoreError::DuplicateRevision)
    );
    // 失败的写入不会留下半截状态
    assert_eq!(head_ids(&store), vec![id(1)]);
}

#[test]
fn prune_keeps_heads_and_recent_revisions_but_not_graph() {
    let mut store = Store::open_in_memory().unwrap();
    store.insert_revision(&rev(1, &[])).unwrap();
    for n in 2..=10u8 {
        store.insert_revision(&rev(n, &[n - 1])).unwrap();
    }
    // 全部修订都是刚写入的：时间规则保护它们，一个也不清理
    assert_eq!(store.prune(&id(50), 3, 0).unwrap(), 0);
    // 模拟 90 天之后：只剩数量规则
    assert_eq!(store.prune(&id(50), 3, u64::MAX).unwrap(), 7);
    let history = store.history(&id(50)).unwrap();
    assert_eq!(history.iter().filter(|r| !r.pruned).count(), 3);
    let oldest = store.revision(&id(1)).unwrap().unwrap();
    assert!(oldest.pruned && oldest.details_ct.is_none() && oldest.wrapped_key_ct.is_none());
    assert_eq!(
        store.graph(&id(50)).unwrap().len(),
        10,
        "修订图必须完整保留"
    );
    assert_eq!(head_ids(&store), vec![id(10)]);
}

#[test]
fn data_survives_reopen() {
    let dir = std::env::temp_dir().join(format!(
        "keevo-store-test-{}",
        Id128::random().unwrap().to_hex()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("vault.sqlite");
    {
        let mut store = Store::open(&path).unwrap();
        store.set_meta("device_id", &[7; 16]).unwrap();
        store.insert_revision(&rev(1, &[])).unwrap();
    }
    let store = Store::open(&path).unwrap();
    assert_eq!(store.meta("device_id").unwrap(), Some(vec![7; 16]));
    assert_eq!(head_ids(&store), vec![id(1)]);
    drop(store);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn newer_schema_is_rejected() {
    let dir = std::env::temp_dir().join(format!(
        "keevo-store-test-{}",
        Id128::random().unwrap().to_hex()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("vault.sqlite");
    {
        let conn = Connection::open(&path).unwrap();
        conn.pragma_update(None, "user_version", 99).unwrap();
    }
    assert_eq!(
        Store::open(&path).err(),
        Some(StoreError::UnsupportedSchema(99))
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// 数量与时间两条规则取并集：只有"不在最近 keep 个之内"且"早于截止时间写入"的修订才清理。
#[test]
fn prune_keeps_revisions_stored_after_the_cutoff() {
    let mut store = Store::open_in_memory().unwrap();
    store.insert_revision(&rev(1, &[])).unwrap();
    for n in 2..=10u8 {
        store.insert_revision(&rev(n, &[n - 1])).unwrap();
    }
    // 1–5 是很久以前写入的，6–10 是最近写入的
    store
        .conn
        .execute("UPDATE revision SET stored_ms = 1000 WHERE seq <= 5", [])
        .unwrap();
    assert_eq!(store.prune(&id(50), 2, 2000).unwrap(), 5);
    let kept: Vec<bool> = (1..=10u8)
        .map(|n| !store.revision(&id(n)).unwrap().unwrap().pruned)
        .collect();
    assert_eq!(
        kept,
        [
            false, false, false, false, false, true, true, true, true, true
        ]
    );
}

/// v1 数据库升级到 v2：已有修订的写入时间记为 0，只按数量规则保留。
#[test]
fn migrates_schema_v1_to_v2() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(SCHEMA_V1).unwrap();
    conn.pragma_update(None, "user_version", 1).unwrap();
    let mut store = Store::init(conn, false).unwrap();
    assert_eq!(store.schema_version().unwrap(), 2);
    store.insert_revision(&rev(1, &[])).unwrap();
    let stored: i64 = store
        .conn
        .query_row("SELECT stored_ms FROM revision", [], |r| r.get(0))
        .unwrap();
    assert!(stored > 0);
}
