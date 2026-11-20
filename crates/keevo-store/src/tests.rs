use super::*;

#[test]
fn review5c_m5_restore_effective_clock_matches_documented_contract() {
    let dir = std::env::temp_dir().join(format!(
        "keevo-review5c-clock-{}",
        Id128::random().unwrap().to_hex()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let _cleanup = Cleanup(dir.clone());
    let mut store = Store::open(&dir.join("vault.sqlite")).unwrap();
    store
        .create_account(&AccountRow {
            id: id(1),
            format_version: 1,
            epoch: 1,
            kdf_params: vec![1; 29],
            keyset_ct: vec![2; 400],
        })
        .unwrap();
    store.insert_revision(&rev(1, &[])).unwrap();
    let backup = dir.join("old.sqlite");
    store.backup_to(&backup).unwrap();
    store.pass_running_time(100 * 86_400_000).unwrap();
    store.insert_revision(&rev(2, &[1])).unwrap();
    let before = store.effective_now().unwrap();
    store.restore_from(&backup).unwrap();
    let after = store.effective_now().unwrap();
    // docs/sync.md §2（按确认评审 M5 修改后）：恢复后的有效时间不会比恢复前大，可能变小，只会让清理更晚
    assert!(
        after <= before.saturating_add(60_000),
        "恢复后的有效时间不应超过恢复前：{before} -> {after}"
    );
    assert!(
        after < before,
        "恢复旧备份时有效时间可以回退（条文如实写明）"
    );
}

#[test]
fn review5_l2_restore_must_not_age_fresh_history() {
    let dir = std::env::temp_dir().join(format!(
        "keevo-review5-time-{}",
        Id128::random().unwrap().to_hex()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let _cleanup = Cleanup(dir.clone());
    let mut store = Store::open(&dir.join("vault.sqlite")).unwrap();
    store
        .create_account(&AccountRow {
            id: id(1),
            format_version: 1,
            epoch: 1,
            kdf_params: vec![1; 29],
            keyset_ct: vec![2; 400],
        })
        .unwrap();
    // 原库合法运行了 100 天，然后刚写下 25 个修订。
    store.pass_running_time(100 * 86_400_000).unwrap();
    for n in 1..=25 {
        let parents = if n == 1 { vec![] } else { vec![n - 1] };
        store.insert_revision(&rev(n, &parents)).unwrap();
    }
    assert_eq!(store.prune(&id(50), 20, 90 * 86_400_000).unwrap(), 0);
    let backup = dir.join("backup.sqlite");
    store.backup_to(&backup).unwrap();
    // 攻击者只降低一个时间；没有删除密文、修订或关系，没有密钥。
    Connection::open(&backup)
        .unwrap()
        .execute(
            "UPDATE revision SET stored_ms = 0 WHERE rev_id = ?1",
            params![id(1).as_bytes()],
        )
        .unwrap();
    store.restore_from(&backup).unwrap();
    assert_eq!(
        store.prune(&id(50), 20, 90 * 86_400_000).unwrap(),
        0,
        "未满 90 天的修订不能因备份的未认证时间而立即被清理"
    );
}

#[test]
fn review5_l3_restore_rejects_parent_cycle() {
    let dir = std::env::temp_dir().join(format!(
        "keevo-review5-cycle-{}",
        Id128::random().unwrap().to_hex()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let _cleanup = Cleanup(dir.clone());
    let mut store = Store::open(&dir.join("vault.sqlite")).unwrap();
    store
        .create_account(&AccountRow {
            id: id(1),
            format_version: 1,
            epoch: 1,
            kdf_params: vec![1; 29],
            keyset_ct: vec![2; 400],
        })
        .unwrap();
    store.insert_revision(&rev(1, &[])).unwrap();
    store.insert_revision(&rev(2, &[1])).unwrap();
    let backup = dir.join("backup.sqlite");
    store.backup_to(&backup).unwrap();
    Connection::open(&backup)
        .unwrap()
        .execute("UPDATE revision SET parents = rev_id", [])
        .unwrap();
    let result = store.restore_from(&backup);
    assert!(
        result.is_err(),
        "修订图必须是 DAG；父节点存在并不排除自环，恢复不得成功并使所有头消失"
    );
}

struct Cleanup(std::path::PathBuf);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

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
    assert_eq!(store.prune(&id(50), 3, DAYS_90).unwrap(), 0);
    // 不要求保存时长（相当于已过保留期）：只剩数量规则
    assert_eq!(store.prune(&id(50), 3, 0).unwrap(), 7);
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
    for n in 2..=5u8 {
        store.insert_revision(&rev(n, &[n - 1])).unwrap();
    }
    // 1–5 写入后，Keevo 又运行了 91 天，再写入 6–10
    store
        .pass_running_time(DAYS_90 + 24 * 60 * 60 * 1000)
        .unwrap();
    for n in 6..=10u8 {
        store.insert_revision(&rev(n, &[n - 1])).unwrap();
    }
    assert_eq!(store.prune(&id(50), 2, DAYS_90).unwrap(), 5);
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
fn migrates_schema_v1_to_current() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(SCHEMA_V1).unwrap();
    conn.pragma_update(None, "user_version", 1).unwrap();
    let mut store = Store::init(conn, false).unwrap();
    assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
    store.insert_revision(&rev(1, &[])).unwrap();
    let stored: i64 = store
        .conn
        .query_row("SELECT stored_ms FROM revision", [], |r| r.get(0))
        .unwrap();
    // 有效时间是 Keevo 的累计运行时间：新数据库从 0 开始，迁移前的修订也记为 0
    assert!((0..60_000).contains(&stored), "{stored}");
}

const DAYS_90: u64 = 90 * 24 * 60 * 60 * 1000;

/// 第三轮评审 H1：有效时间只按 Keevo 的运行时间推进，与墙上时钟无关；未满 90 天的运行时间不清理，
/// 满了才清理。重新打开数据库时，以已有修订中最大的保存时间为起点继续计时，不会把关机期间算进去。
#[test]
fn review3_h1_retention_follows_running_time_only() {
    let mut store = Store::open_in_memory().unwrap();
    store.insert_revision(&rev(1, &[])).unwrap();
    for n in 2..=25u8 {
        store.insert_revision(&rev(n, &[n - 1])).unwrap();
    }
    assert_eq!(store.prune(&id(50), 20, DAYS_90).unwrap(), 0);
    store.pass_running_time(DAYS_90 - 60_000).unwrap();
    assert_eq!(
        store.prune(&id(50), 20, DAYS_90).unwrap(),
        0,
        "运行时间还没满 90 天"
    );
    store.pass_running_time(120_000).unwrap();
    assert_eq!(store.prune(&id(50), 20, DAYS_90).unwrap(), 5);
}

/// 第三轮评审 H1：重新打开时以已有修订的最大保存时间为起点，关机期间不计入。
#[test]
fn review3_h1_restart_does_not_count_downtime() {
    let dir = std::env::temp_dir().join(format!("keevo-h1-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("v.sqlite");
    {
        let mut store = Store::open(&path).unwrap();
        store.insert_revision(&rev(1, &[])).unwrap();
        for n in 2..=25u8 {
            store.insert_revision(&rev(n, &[n - 1])).unwrap();
        }
    }
    // 无论关机多久（墙上时钟过了多少天），重新打开后有效时间都从最后一次写入处继续
    let mut store = Store::open(&path).unwrap();
    assert_eq!(store.prune(&id(50), 20, DAYS_90).unwrap(), 0);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// 第三轮评审 H1：被改写成不合理的保存时间时，暂停清理而不是把其余修订都当成"很旧"。
#[test]
fn review3_h1_unreasonable_stored_time_pauses_pruning() {
    let mut store = Store::open_in_memory().unwrap();
    store.insert_revision(&rev(1, &[])).unwrap();
    for n in 2..=25u8 {
        store.insert_revision(&rev(n, &[n - 1])).unwrap();
    }
    store
        .conn
        .execute(
            "UPDATE revision SET stored_ms = ?1 WHERE seq = 25",
            [i64::MAX],
        )
        .unwrap();
    store.clock = None;
    assert_eq!(store.prune(&id(50), 20, DAYS_90).unwrap(), 0);
}

/// 第二轮评审 G3：v1 数据库中已有的修订年龄未知，迁移后按迁移时间计，不会立即被清理。
#[test]
fn review2_g3_migration_keeps_existing_history() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(SCHEMA_V1).unwrap();
    conn.pragma_update(None, "user_version", 1).unwrap();
    // 直接按 v1 的列写入 25 个修订（v1 没有 stored_ms）
    for n in 1..=25u8 {
        let parents: Vec<u8> = if n == 1 {
            Vec::new()
        } else {
            id(n - 1).as_bytes().to_vec()
        };
        conn
            .execute(
                "INSERT INTO revision (rev_id, object_id, object_type, vault_id, parents, origin_device, details_ct)
                 VALUES (?1, ?2, 3, ?3, ?4, ?5, x'00')",
                rusqlite::params![
                    id(n).as_bytes().to_vec(),
                    id(50).as_bytes().to_vec(),
                    id(60).as_bytes().to_vec(),
                    parents,
                    id(70).as_bytes().to_vec()
                ],
            )
            .unwrap();
    }
    conn.execute(
        "INSERT INTO head (object_id, rev_id) VALUES (?1, ?2)",
        rusqlite::params![id(50).as_bytes().to_vec(), id(25).as_bytes().to_vec()],
    )
    .unwrap();
    let mut store = Store::init(conn, false).unwrap();
    assert_eq!(store.prune(&id(50), 20, DAYS_90).unwrap(), 0);
}

/// 第二轮评审 G4：超长的列在读入内存之前就被拒绝。
#[test]
fn review2_g4_oversized_columns_are_rejected_before_reading() {
    let mut store = Store::open_in_memory().unwrap();
    store.insert_revision(&rev(1, &[])).unwrap();
    store
        .conn
        .execute(
            "UPDATE revision SET details_ct = zeroblob(?1)",
            [i64::try_from(keevo_crypto::MAX_ENVELOPE_LEN + 1).unwrap()],
        )
        .unwrap();
    assert!(matches!(
        store.revision(&id(1)),
        Err(StoreError::Corrupt(_))
    ));
    assert!(matches!(store.heads(&id(50)), Err(StoreError::Corrupt(_))));
    assert!(matches!(
        store.history(&id(50)),
        Err(StoreError::Corrupt(_))
    ));
    // 恰好等于上限的仍可读取
    store
        .conn
        .execute(
            "UPDATE revision SET details_ct = zeroblob(?1)",
            [i64::try_from(keevo_crypto::MAX_ENVELOPE_LEN).unwrap()],
        )
        .unwrap();
    assert!(store.revision(&id(1)).unwrap().is_some());
}

/// 第三轮评审 H2：普通修订最多 4096 个父修订；墓碑修订最多 65536 个，保证重建后旧条目总能被删除。
#[test]
fn review3_h2_parent_limits_depend_on_revision_kind() {
    let mut store = Store::open_in_memory().unwrap();
    let mut roots = Vec::new();
    for i in 0..=MAX_PARENTS {
        let mut r = rev(0, &[]);
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&u64::try_from(i).unwrap().to_be_bytes());
        b[15] = 0xaa;
        r.rev_id = Id128::from_bytes(b);
        store.insert_revision(&r).unwrap();
        roots.push(r.rev_id);
    }
    let mut live = rev(1, &[]);
    live.parents = roots.clone();
    assert_eq!(store.insert_revision(&live), Err(StoreError::TooLarge));
    let mut tomb = rev(2, &[]);
    tomb.parents = roots;
    tomb.deleted = true;
    tomb.wrapped_key_ct = None;
    tomb.overview_ct = None;
    tomb.details_ct = None;
    store.insert_revision(&tomb).unwrap();
    assert_eq!(store.heads(&id(50)).unwrap().len(), 1, "墓碑以全部头为父");
}

/// 第三轮评审 H3：元数据与头表的超长值同样在取出前被拒绝；读取在同一快照中完成。
#[test]
fn review3_h3_meta_and_head_ids_are_length_checked() {
    let mut store = Store::open_in_memory().unwrap();
    store.set_meta("k", &[1u8; 8]).unwrap();
    assert_eq!(store.meta("k").unwrap(), Some(vec![1u8; 8]));
    store
        .conn
        .execute(
            "UPDATE meta SET value = zeroblob(?1) WHERE key = 'k'",
            [i64::try_from(MAX_META_LEN + 1).unwrap()],
        )
        .unwrap();
    assert!(matches!(store.meta("k"), Err(StoreError::Corrupt(_))));

    store.insert_revision(&rev(1, &[])).unwrap();
    assert_eq!(store.objects(ObjectKind::Item).unwrap(), vec![id(50)]);
    store
        .conn
        .execute("UPDATE head SET object_id = zeroblob(17)", [])
        .unwrap();
    assert!(matches!(
        store.objects(ObjectKind::Item),
        Err(StoreError::Corrupt(_))
    ));
}

/// 第四轮评审 J1：同一数据库同时只能有一个打开者；关闭后可以再打开。
#[test]
fn review4_j1_database_has_a_single_owner() {
    let dir = std::env::temp_dir().join(format!("keevo-j1-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("v.sqlite");
    let first = Store::open(&path).unwrap();
    assert_eq!(Store::open(&path).err(), Some(StoreError::InUse));
    drop(first);
    assert!(Store::open(&path).is_ok());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// 第四轮评审 J1：v2 数据库里的 `stored_ms` 是墙上时间，升级到 v3 时一律记为 0（年龄未知）。
#[test]
fn review4_j1_v2_wall_clock_ages_are_reset() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(SCHEMA_V1).unwrap();
    conn.execute_batch(MIGRATE_V2).unwrap();
    conn.pragma_update(None, "user_version", 2).unwrap();
    conn.execute(
        "INSERT INTO revision (rev_id, object_id, object_type, vault_id, parents, origin_device, stored_ms)
         VALUES (?1, ?2, 3, ?3, x'', ?4, 1763366400000)",
        rusqlite::params![
            id(1).as_bytes().to_vec(),
            id(50).as_bytes().to_vec(),
            id(60).as_bytes().to_vec(),
            id(70).as_bytes().to_vec()
        ],
    )
    .unwrap();
    let store = Store::init(conn, false).unwrap();
    let stored: i64 = store
        .conn
        .query_row("SELECT stored_ms FROM revision", [], |r| r.get(0))
        .unwrap();
    assert_eq!(stored, 0);
}

/// 第四轮评审 J2：多个修订在一个事务中写入，任何一个失败都整体回滚。
#[test]
fn review4_j2_batch_insert_is_atomic() {
    let mut store = Store::open_in_memory().unwrap();
    store.insert_revision(&rev(1, &[])).unwrap();
    let ok = rev(2, &[1]);
    let bad = rev(3, &[99]); // 父修订不存在
    assert_eq!(
        store.insert_revisions(&[ok, bad]),
        Err(StoreError::MissingParent)
    );
    assert!(
        store.revision(&id(2)).unwrap().is_none(),
        "失败时前面的修订也不应写入"
    );
    assert_eq!(head_ids(&store), vec![id(1)]);
    store
        .insert_revisions(&[rev(2, &[1]), rev(3, &[2])])
        .unwrap();
    assert_eq!(head_ids(&store), vec![id(3)]);
}

/// 第四轮评审 §5.2：父修订按集合计数与编码，重复的父修订只算一个。
#[test]
fn review4_parent_lists_are_normalized() {
    let mut store = Store::open_in_memory().unwrap();
    store.insert_revision(&rev(1, &[])).unwrap();
    let mut r = rev(2, &[]);
    r.parents = vec![id(1); MAX_PARENTS + 1];
    store.insert_revision(&r).unwrap();
    assert_eq!(
        store.revision(&id(2)).unwrap().unwrap().parents,
        vec![id(1)]
    );
}

/// 备份与恢复（docs/sync.md §2）：备份是一致的副本；恢复替换整个数据库，连接保持可用；
/// 不是 Keevo 数据库、来自更新版本的文件被拒绝，恢复失败时数据库保持原样。
#[test]
fn backup_and_restore() {
    let dir = std::env::temp_dir().join(format!(
        "keevo-store-backup-{}",
        Id128::random().unwrap().to_hex()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let _cleanup = Cleanup(dir.clone());
    let mut store = Store::open(&dir.join("vault.sqlite")).unwrap();
    store
        .create_account(&AccountRow {
            id: id(1),
            format_version: 1,
            epoch: 1,
            kdf_params: vec![1; 29],
            keyset_ct: vec![2; 400],
        })
        .unwrap();
    store.insert_revision(&rev(1, &[])).unwrap();
    let backup = dir.join("one.keevo-backup");
    store.backup_to(&backup).unwrap();
    assert!(store.backup_to(&backup).is_err(), "不覆盖已有的文件");
    assert_eq!(Store::inspect_backup(&backup).unwrap().account.id, id(1));

    store.insert_revision(&rev(2, &[1])).unwrap();
    store.set_meta("device_id", &[7; 16]).unwrap();
    store.put_local_record("pairing", &[1], &[9; 40]).unwrap();
    assert_eq!(head_ids(&store), [id(2)]);
    store.restore_from(&backup).unwrap();
    assert_eq!(head_ids(&store), [id(1)], "恢复到备份时的状态");
    assert_eq!(
        store.meta("device_id").unwrap(),
        Some(vec![7; 16]),
        "本机状态不回退"
    );
    assert_eq!(
        store.local_records("pairing").unwrap(),
        [(vec![1], vec![9; 40])]
    );
    store.insert_revision(&rev(3, &[1])).unwrap();
    assert_eq!(head_ids(&store), [id(3)], "连接照常可用");

    let junk = dir.join("junk");
    std::fs::write(&junk, b"not sqlite").unwrap();
    assert!(Store::inspect_backup(&junk).is_err());
    assert!(store.restore_from(&junk).is_err());
    assert_eq!(head_ids(&store), [id(3)], "失败时保持原样");

    let newer = dir.join("newer.keevo-backup");
    store.backup_to(&newer).unwrap();
    rusqlite::Connection::open(&newer)
        .unwrap()
        .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
        .unwrap();
    assert_eq!(
        Store::inspect_backup(&newer).err(),
        Some(StoreError::UnsupportedSchema(SCHEMA_VERSION + 1))
    );
}

#[test]
fn attachments_round_trip_and_checks() {
    let mut store = Store::open_in_memory().unwrap();
    let full = ATTACHMENT_CHUNK_CT_LEN;
    let min = keevo_crypto::MIN_ENVELOPE_LEN;
    let row = AttachmentRow {
        id: id(70),
        item_id: id(50),
        wrapped_key_ct: vec![1; ATTACHMENT_KEY_CT_LEN],
        meta_ct: vec![2; min],
        chunk_count: 2,
    };
    assert_eq!(
        store.insert_attachment(&row, &[vec![3; full]]),
        Err(StoreError::TooLarge),
        "块数必须与 chunk_count 一致"
    );
    // 各部分的长度按 §8.9 精确检查（第五轮预审 K3）
    for (bad, what) in [
        (
            vec![vec![3; full - 1], vec![4; min]],
            "非最后一块必须是完整长度",
        ),
        (
            vec![vec![3; full], vec![4; full + 1]],
            "最后一块不超过完整长度",
        ),
        (
            vec![vec![3; full], vec![4; min - 1]],
            "最后一块不短于最短的信封",
        ),
    ] {
        assert_eq!(
            store.insert_attachment(&row, &bad),
            Err(StoreError::TooLarge),
            "{what}"
        );
    }
    for bad_row in [
        AttachmentRow {
            wrapped_key_ct: vec![1; ATTACHMENT_KEY_CT_LEN + 1],
            ..row.clone()
        },
        AttachmentRow {
            meta_ct: vec![2; MAX_ATTACHMENT_META_CT_LEN + 1],
            ..row.clone()
        },
    ] {
        assert_eq!(
            store.insert_attachment(&bad_row, &[vec![3; full], vec![4; min]]),
            Err(StoreError::TooLarge)
        );
    }
    store
        .insert_attachment(&row, &[vec![3; full], vec![4; min]])
        .unwrap();
    let (got, chunks) = store.attachment(&id(70)).unwrap().unwrap();
    assert_eq!(got, row);
    assert_eq!(chunks, [vec![3; full], vec![4; min]]);
    assert_eq!(store.attachments_of(&id(50)).unwrap(), [id(70)]);
    assert_eq!(store.attachment(&id(71)).unwrap(), None);
    // 数据库中被改写的块：读入之前拒绝
    for sql in [
        format!(
            "UPDATE attachment_chunk SET ct = zeroblob({}) WHERE idx = 1",
            full + 1
        ),
        format!(
            "UPDATE attachment_chunk SET ct = zeroblob({}) WHERE idx = 0",
            full - 16
        ),
        format!(
            "UPDATE attachment SET wrapped_key_ct = zeroblob({})",
            ATTACHMENT_KEY_CT_LEN - 1
        ),
    ] {
        let mut copy = Store::open_in_memory().unwrap();
        copy.insert_attachment(&row, &[vec![3; full], vec![4; min]])
            .unwrap();
        copy.execute_for_tests_internal(&sql).unwrap();
        assert!(
            matches!(copy.attachment(&id(70)), Err(StoreError::Corrupt(_))),
            "{sql}"
        );
    }
    // 少了一块：读取时发现
    store
        .execute_for_tests_internal("DELETE FROM attachment_chunk WHERE idx = 1")
        .unwrap();
    assert!(matches!(
        store.attachment(&id(70)),
        Err(StoreError::Corrupt(_))
    ));
    store.delete_attachment(&id(70)).unwrap();
    assert_eq!(store.attachment(&id(70)).unwrap(), None);
    assert!(store.attachments_of(&id(50)).unwrap().is_empty());
}

/// 恢复只认 Keevo 自己的 schema，逐行检查后导入新建的数据库（第五轮预审 K1、K2）。
#[test]
fn restore_rejects_tampered_backups() {
    let dir = std::env::temp_dir().join(format!(
        "keevo-restore-{}",
        Id128::random().unwrap().to_hex()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let _cleanup = Cleanup(dir.clone());
    let mut store = Store::open(&dir.join("vault.sqlite")).unwrap();
    store
        .create_account(&AccountRow {
            id: id(1),
            format_version: 1,
            epoch: 1,
            kdf_params: vec![1; 29],
            keyset_ct: vec![2; 400],
        })
        .unwrap();
    store.insert_revision(&rev(1, &[])).unwrap();
    store.insert_revision(&rev(2, &[1])).unwrap();
    let full = ATTACHMENT_CHUNK_CT_LEN;
    let min = keevo_crypto::MIN_ENVELOPE_LEN;
    store
        .insert_attachment(
            &AttachmentRow {
                id: id(70),
                item_id: id(50),
                wrapped_key_ct: vec![1; ATTACHMENT_KEY_CT_LEN],
                meta_ct: vec![2; min],
                chunk_count: 2,
            },
            &[vec![3; full], vec![4; min]],
        )
        .unwrap();
    let good = dir.join("good.keevo-backup");
    store.backup_to(&good).unwrap();
    store.insert_revision(&rev(3, &[2])).unwrap();
    store.put_local_record("pairing", &[1], &[9; 40]).unwrap();

    let cases = [
        (
            "CREATE TRIGGER t AFTER INSERT ON head BEGIN DELETE FROM head WHERE rev_id = NEW.rev_id; END;",
            "触发器",
        ),
        ("CREATE VIEW v AS SELECT * FROM head;", "视图"),
        ("CREATE TABLE extra (x);", "多余的表不影响导入"),
        ("DELETE FROM head;", "头修订由修订图重算"),
        (
            "UPDATE revision SET parents = zeroblob(16) WHERE rev_id = x'02020202020202020202020202020202';",
            "缺少父修订",
        ),
        (
            "UPDATE revision SET details_ct = zeroblob(17301600) WHERE rev_id = x'01010101010101010101010101010101';",
            "超长的列",
        ),
        (
            "UPDATE revision SET deleted = 1 WHERE rev_id = x'02020202020202020202020202020202';",
            "墓碑带内容",
        ),
        (
            "UPDATE attachment_chunk SET ct = zeroblob(4194304) WHERE idx = 0;",
            "超长的块",
        ),
        ("DELETE FROM attachment_chunk WHERE idx = 1;", "少了一块"),
        (
            "UPDATE revision SET stored_ms = 9007199254740000;",
            "保存时间不超过恢复前的有效时间",
        ),
        ("DELETE FROM account;", "没有账户"),
    ];
    for (i, (sql, what)) in cases.iter().enumerate() {
        let copy = dir.join(format!("case-{i}.keevo-backup"));
        std::fs::copy(&good, &copy).unwrap();
        rusqlite::Connection::open(&copy)
            .unwrap()
            .execute_batch(sql)
            .unwrap();
        let accepted = matches!(
            *what,
            "多余的表不影响导入" | "头修订由修订图重算" | "保存时间不超过恢复前的有效时间"
        );
        let result = Store::inspect_backup(&copy).and_then(|_| store.restore_from(&copy));
        assert_eq!(result.is_ok(), accepted, "{what}: {result:?}");
        if accepted {
            assert_eq!(head_ids(&store), [id(2)], "{what}");
            let schema: i64 = store
                .conn
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE name = 'extra'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(
                schema, 0,
                "{what}：备份中的其他 schema 对象不进入当前数据库"
            );
            assert!(
                store.effective_now().unwrap() < 9_007_199_254_740_000,
                "{what}"
            );
            assert!(
                store.attachment(&id(70)).unwrap().is_some(),
                "{what}：附件随之恢复"
            );
        } else {
            assert_eq!(
                store.local_records("pairing").unwrap(),
                [(vec![1], vec![9; 40])],
                "{what}：失败时保持原样"
            );
        }
        store
            .insert_revision(&rev(10 + u8::try_from(i).unwrap(), &[]))
            .ok();
        assert!(store.integrity_check().unwrap().is_empty());
    }
    // 恢复之后没有遗留的临时数据库
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".restore-"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[test]
fn heads_of_kind_matches_heads() {
    let mut store = Store::open_in_memory().unwrap();
    store.insert_revision(&rev(1, &[])).unwrap();
    store.insert_revision(&rev(2, &[1])).unwrap();
    store.insert_revision(&rev(3, &[1])).unwrap();
    let all = store.heads_of_kind(ObjectKind::Item).unwrap();
    assert_eq!(all.len(), 1);
    let (object, heads) = &all[0];
    assert_eq!(*object, id(50));
    let mut expected = store.heads(&id(50)).unwrap();
    for h in &mut expected {
        h.details_ct = None;
    }
    assert_eq!(heads, &expected, "与逐个读取一致，只是不含详情");
    assert!(store.heads_of_kind(ObjectKind::Vault).unwrap().is_empty());
}
