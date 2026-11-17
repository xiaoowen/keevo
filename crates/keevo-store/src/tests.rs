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
    assert_eq!(store.prune(&id(50), 3).unwrap(), 7);
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
