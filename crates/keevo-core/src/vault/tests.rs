use std::path::PathBuf;

use super::*;
use keevo_format::KvEntry;

/// 测试使用规范允许的最小 KDF 参数，加快运行。
fn fast_params() -> KdfParams {
    KdfParams::new(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1, [3u8; 16]).unwrap()
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "keevo-core-test-{}",
            Id128::random().unwrap().to_hex()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
    fn db(&self) -> PathBuf {
        self.0.join("vault.sqlite")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn login_fields() -> Vec<NewField> {
    vec![
        NewField {
            kind: FieldKind::Text,
            label: "用户名".into(),
            purpose: Some(Purpose::Username),
            data: FieldData::Text("octocat".into()),
        },
        NewField {
            kind: FieldKind::Concealed,
            label: "密码".into(),
            purpose: Some(Purpose::Password),
            data: FieldData::Text("correct horse".into()),
        },
        NewField {
            kind: FieldKind::Url,
            label: "网站".into(),
            purpose: None,
            data: FieldData::Text("https://github.com".into()),
        },
    ]
}

fn password_field(view: &ItemView) -> (Id128, String) {
    view.doc
        .records
        .iter()
        .find_map(|(k, v)| match (k, &v.value) {
            (RecordKey::Field(id), Some(RecordValue::Field(f)))
                if f.purpose == Some(Purpose::Password) =>
            {
                Some((*id, f.text().unwrap().to_owned()))
            }
            _ => None,
        })
        .unwrap()
}

/// M0 退出标准：创建 → 锁定 → 解锁 → 读写条目，并且数据在重新打开后依然完整。
#[test]
fn create_lock_unlock_read_write_roundtrip() {
    let tmp = TempDir::new();
    let (mut vault, secret_key) =
        Vault::create(&tmp.db(), "主密码 correct horse", fast_params()).unwrap();
    let personal = vault.vaults().unwrap();
    assert_eq!(personal.len(), 1);
    assert_eq!(personal[0].name, "个人");

    let item_id = vault
        .create_item(personal[0].id, ItemType::Login, "GitHub", login_fields())
        .unwrap();
    let view = vault.item(item_id).unwrap();
    assert_eq!(view.doc.overview().subtitle, "octocat");
    assert_eq!(password_field(&view).1, "correct horse");

    // 锁定后什么都读不到
    vault.lock();
    assert!(!vault.is_unlocked());
    assert_eq!(vault.items().err(), Some(CoreError::Locked));
    assert_eq!(vault.item(item_id).err(), Some(CoreError::Locked));

    // 错误的主密码或账户密钥都无法解锁，且不区分是哪一个错了
    assert_eq!(
        vault.unlock("wrong", &secret_key).err(),
        Some(CoreError::WrongCredentials)
    );
    let other_key = AccountSecretKey::generate().unwrap();
    assert_eq!(
        vault.unlock("主密码 correct horse", &other_key).err(),
        Some(CoreError::WrongCredentials)
    );

    vault.unlock("主密码 correct horse", &secret_key).unwrap();
    let (field_id, _) = password_field(&vault.item(item_id).unwrap());
    vault
        .update_item(
            item_id,
            vec![
                Edit::SetTitle("GitHub（工作）".into()),
                Edit::SetFieldData {
                    field_id,
                    data: FieldData::Text("new password".into()),
                },
                Edit::AddTag("work".into()),
            ],
        )
        .unwrap();
    assert_eq!(vault.revision_count(item_id).unwrap(), 2);

    // 重新打开数据库文件（模拟应用重启）
    drop(vault);
    let mut reopened = Vault::open(&tmp.db()).unwrap();
    assert!(!reopened.is_unlocked());
    // 账户密钥通过显示形式往返，模拟从应急包手动输入
    let typed = AccountSecretKey::parse(&secret_key.to_display_string().to_lowercase()).unwrap();
    reopened.unlock("主密码 correct horse", &typed).unwrap();
    let items = reopened.items().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].overview.title, "GitHub（工作）");
    assert_eq!(items[0].overview.tags, vec!["work".to_owned()]);
    assert_eq!(
        password_field(&reopened.item(item_id).unwrap()).1,
        "new password"
    );
}

#[test]
fn trash_restore_and_purge() {
    let (mut vault, _) =
        Vault::create_with_store(Store::open_in_memory().unwrap(), "pw", fast_params()).unwrap();
    let vault_id = vault.vaults().unwrap()[0].id;
    let id = vault
        .create_item(vault_id, ItemType::SecureNote, "笔记", vec![])
        .unwrap();

    vault.trash_item(id).unwrap();
    assert!(vault.items().unwrap()[0].overview.trashed_at.is_some());
    vault.restore_item(id).unwrap();
    assert!(vault.items().unwrap()[0].overview.trashed_at.is_none());

    vault.purge_item(id).unwrap();
    assert!(vault.items().unwrap().is_empty());
    assert_eq!(vault.item(id).err(), Some(CoreError::NotFound));
}

#[test]
fn developer_items_with_structured_fields() {
    let (mut vault, _) =
        Vault::create_with_store(Store::open_in_memory().unwrap(), "pw", fast_params()).unwrap();
    let vault_id = vault.create_vault("开发").unwrap();
    let env = NewField {
        kind: FieldKind::KvList,
        label: "dev".into(),
        purpose: None,
        data: FieldData::Kv(vec![
            KvEntry {
                key: "DATABASE_URL".into(),
                value: "postgres://localhost/app".into(),
                concealed: false,
            },
            KvEntry {
                key: "OPENAI_API_KEY".into(),
                value: "sk-test".into(),
                concealed: true,
            },
        ]),
    };
    let id = vault
        .create_item(vault_id, ItemType::Environment, "my-app", vec![env])
        .unwrap();
    let view = vault.item(id).unwrap();
    assert_eq!(view.vault_id, vault_id);
    let has_secret = view.doc.records.values().any(|v| match &v.value {
        Some(RecordValue::Field(f)) => {
            matches!(&f.data, FieldData::Kv(e) if e[1].value.expose() == "sk-test")
        }
        _ => false,
    });
    assert!(has_secret);
    let names: Vec<String> = vault
        .vaults()
        .unwrap()
        .into_iter()
        .map(|v| v.name)
        .collect();
    assert_eq!(names, vec!["个人".to_owned(), "开发".to_owned()]);
}

#[test]
fn history_is_pruned_but_graph_is_kept() {
    let (mut vault, _) =
        Vault::create_with_store(Store::open_in_memory().unwrap(), "pw", fast_params()).unwrap();
    let vault_id = vault.vaults().unwrap()[0].id;
    let id = vault
        .create_item(vault_id, ItemType::Login, "t0", vec![])
        .unwrap();
    for i in 1..=30 {
        vault
            .update_item(id, vec![Edit::SetTitle(format!("t{i}"))])
            .unwrap();
    }
    assert_eq!(vault.revision_count(id).unwrap(), 31);
    let kept = |vault: &Vault| {
        vault
            .store
            .history(&id)
            .unwrap()
            .iter()
            .filter(|r| !r.pruned)
            .count()
    };
    // 90 天内的修订一律保留
    assert_eq!(kept(&vault), 31);
    // 模拟 90 天之后：只保留最近 20 个
    vault.store.prune(&id, HISTORY_KEEP, 0).unwrap();
    assert_eq!(kept(&vault), HISTORY_KEEP);
    assert_eq!(vault.item(id).unwrap().doc.overview().title, "t30");
}

#[test]
fn tampered_ciphertext_is_detected() {
    let tmp = TempDir::new();
    let (mut vault, sk) = Vault::create(&tmp.db(), "pw", fast_params()).unwrap();
    let vault_id = vault.vaults().unwrap()[0].id;
    let a = vault
        .create_item(vault_id, ItemType::Login, "A", login_fields())
        .unwrap();
    let b = vault
        .create_item(vault_id, ItemType::Login, "B", login_fields())
        .unwrap();
    drop(vault);

    // 攻击者把条目 B 的详情密文"移植"到条目 A 的头修订上
    {
        let conn = rusqlite::Connection::open(tmp.db()).unwrap();
        conn.execute(
            "UPDATE revision SET details_ct = (SELECT details_ct FROM revision WHERE object_id = ?2)
             WHERE object_id = ?1",
            [a.as_bytes().as_slice(), b.as_bytes().as_slice()],
        )
        .unwrap();
    }
    let mut vault = Vault::open(&tmp.db()).unwrap();
    vault.unlock("pw", &sk).unwrap();
    assert_eq!(vault.item(a).err(), Some(CoreError::Tampered));
    assert!(vault.item(b).is_ok());
}

/// 评审 F3：被篡改为极端值的 KDF 参数不会在未经确认时自动运行。
#[test]
fn review_f3_unusual_kdf_params_require_confirmation() {
    let tmp = TempDir::new();
    let (vault, sk) = Vault::create(&tmp.db(), "pw", fast_params()).unwrap();
    drop(vault);
    {
        let conn = rusqlite::Connection::open(tmp.db()).unwrap();
        let hostile = KdfParams::new(
            KdfParams::MAX_M_KIB,
            KdfParams::MAX_T,
            KdfParams::MAX_P,
            [3u8; 16],
        )
        .unwrap();
        conn.execute(
            "UPDATE account SET kdf_params = ?1",
            [hostile.encode().to_vec()],
        )
        .unwrap();
    }
    let mut vault = Vault::open(&tmp.db()).unwrap();
    let start = std::time::Instant::now();
    assert_eq!(
        vault.unlock("pw", &sk).err(),
        Some(CoreError::KdfNeedsConfirmation)
    );
    // 第二轮评审 G4：确认绑定到具体参数，确认的不是当前这一组时同样不执行派生
    let shown = vault.kdf_params().unwrap();
    let other = KdfParams::new(KdfParams::MAX_M_KIB, KdfParams::MAX_T, 8, [3u8; 16]).unwrap();
    assert_ne!(shown, other);
    assert_eq!(
        vault
            .unlock_confirmed_expensive_kdf("pw", &sk, &other)
            .err(),
        Some(CoreError::KdfNeedsConfirmation)
    );
    assert!(
        start.elapsed() < std::time::Duration::from_secs(1),
        "不应执行任何派生"
    );
}

/// 评审 F6：并发落选版本在用户处理前一直保留，不受"最近 20 个修订"清理影响；列表只解密概要也能看到冲突。
#[test]
fn review_f6_concurrent_loser_survives_pruning_until_resolved() {
    let (mut vault, _) =
        Vault::create_with_store(Store::open_in_memory().unwrap(), "pw", fast_params()).unwrap();
    let vault_id = vault.vaults().unwrap()[0].id;
    let id = vault
        .create_item(vault_id, ItemType::Login, "t0", vec![])
        .unwrap();
    let r0 = vault.store.heads(&id).unwrap()[0].rev_id;
    let doc0 = vault.item(id).unwrap().doc;
    vault
        .update_item(id, vec![Edit::SetTitle("A".into())])
        .unwrap();
    let r1 = vault.store.heads(&id).unwrap()[0].clone();

    // 模拟另一台设备：基于 r0 并发地把标题改成 "B"
    let mut doc_b = doc0;
    let hlc = vault.tick().unwrap();
    let rev_b = Id128::random().unwrap();
    doc_b
        .set(
            RecordKey::attr("title"),
            RecordValue::Text("B".into()),
            hlc,
            rev_b,
        )
        .unwrap();
    let ik = vault.item_key(vault.session().unwrap(), &r1).unwrap();
    vault
        .write_item_revision(vault_id, id, rev_b, vec![r0], &ik, Some(&doc_b))
        .unwrap();
    assert_eq!(vault.item(id).unwrap().head_count, 2);

    // 与标题无关的编辑远超保留数，再模拟 90 天之后的清理
    for i in 0..(HISTORY_KEEP + 5) {
        vault
            .update_item(id, vec![Edit::SetFavorite(i % 2 == 0)])
            .unwrap();
    }
    vault.store.prune(&id, HISTORY_KEEP, 0).unwrap();
    let written_in = vault.store.revision(&r1.rev_id).unwrap().unwrap();
    assert!(written_in.pruned, "落选版本最初所在的修订已被清理");
    let view = vault.item(id).unwrap();
    assert_eq!(view.head_count, 1);
    assert_eq!(view.doc.overview().title, "B");
    assert_eq!(view.conflicts.len(), 1);
    assert_eq!(view.conflicts[0].losers[0].rev, r1.rev_id);
    assert!(
        vault.items().unwrap()[0].has_conflicts,
        "单头条目也要在列表中标出冲突"
    );

    vault
        .resolve_conflict(id, &RecordKey::attr("title"), r1.rev_id)
        .unwrap();
    let view = vault.item(id).unwrap();
    assert_eq!(view.doc.overview().title, "A");
    assert!(view.conflicts.is_empty());
    assert!(!vault.items().unwrap()[0].has_conflicts);
}

/// 第二轮评审 G5：合并后超过单个信封的条目仍可读取；普通保存返回 `ItemTooLarge`，不静默丢弃版本；
/// 精简（一次写入中处理冲突）之后可以保存。
#[test]
fn review2_g5_oversized_merged_item_is_readable_and_can_be_compacted() {
    let (mut vault, _) =
        Vault::create_with_store(Store::open_in_memory().unwrap(), "pw", fast_params()).unwrap();
    let vault_id = vault.vaults().unwrap()[0].id;
    let id = vault
        .create_item(vault_id, ItemType::SecureNote, "big", vec![])
        .unwrap();
    let r0 = vault.store.heads(&id).unwrap()[0].clone();
    let doc0 = vault.item(id).unwrap().doc;
    let note = RecordKey::attr("note");
    // 70 台"设备"并发写入各自接近 256 KiB 的备注：每个修订都合法，合并后约 17.5 MiB
    let ik = vault.item_key(vault.session().unwrap(), &r0).unwrap();
    let mut revs = Vec::new();
    for i in 0..70u8 {
        let mut d = doc0.clone();
        let hlc = vault.tick().unwrap();
        let rev = Id128::random().unwrap();
        let body = format!("{i:03}{}", "x".repeat(keevo_format::MAX_VALUE_LEN - 64));
        d.set(
            note.clone(),
            RecordValue::Text(body.as_str().into()),
            hlc,
            rev,
        )
        .unwrap();
        vault
            .write_item_revision(vault_id, id, rev, vec![r0.rev_id], &ik, Some(&d))
            .unwrap();
        revs.push(rev);
    }
    let view = vault.item(id).unwrap();
    assert_eq!(view.head_count, 70);
    assert_eq!(view.conflicts.len(), 1);
    assert_eq!(
        vault.update_item(id, vec![Edit::SetFavorite(true)]).err(),
        Some(CoreError::ItemTooLarge)
    );
    assert_eq!(
        vault.item(id).unwrap().head_count,
        70,
        "保存失败时不写入任何东西"
    );

    vault
        .compact_item(id, &[(note.clone(), revs[3])], &[])
        .unwrap();
    let view = vault.item(id).unwrap();
    assert_eq!(view.head_count, 1);
    assert!(view.conflicts.is_empty());
    assert!(
        matches!(view.doc.get(&note), Some(RecordValue::Text(t)) if t.expose().starts_with("003"))
    );
    vault
        .update_item(id, vec![Edit::SetFavorite(true)])
        .unwrap();
}

/// 第三轮评审 H2：并发分支各自合法、合并后键数超过上限的条目不能再保存，精简也无济于事；
/// 重建为新条目后可以继续使用，旧条目被永久删除。
#[test]
fn review3_h2_item_beyond_key_limit_must_be_rebuilt() {
    let (mut vault, _) =
        Vault::create_with_store(Store::open_in_memory().unwrap(), "pw", fast_params()).unwrap();
    let vault_id = vault.vaults().unwrap()[0].id;
    let id = vault
        .create_item(vault_id, ItemType::Login, "t", vec![])
        .unwrap();
    let r0 = vault.store.heads(&id).unwrap()[0].clone();
    let doc0 = vault.item(id).unwrap().doc;
    let ik = vault.item_key(vault.session().unwrap(), &r0).unwrap();
    let per_branch = keevo_format::MAX_KEYS / 2 + 10;
    for branch in 0..2 {
        let mut d = doc0.clone();
        let hlc = vault.tick().unwrap();
        let rev = Id128::random().unwrap();
        for i in 0..per_branch {
            d.set(
                RecordKey::Tag(format!("b{branch}-{i}")),
                RecordValue::Tag,
                hlc,
                rev,
            )
            .unwrap();
        }
        vault
            .write_item_revision(vault_id, id, rev, vec![r0.rev_id], &ik, Some(&d))
            .unwrap();
    }
    let view = vault.item(id).unwrap();
    assert!(view.doc.key_count() > keevo_format::MAX_KEYS);
    assert_eq!(
        vault.update_item(id, vec![Edit::SetFavorite(true)]).err(),
        Some(CoreError::ItemNeedsRebuild)
    );
    assert_eq!(
        vault
            .compact_item(id, &[], &[RecordKey::Tag("b0-0".into())])
            .err(),
        Some(CoreError::ItemNeedsRebuild),
        "删除只留下墓碑，键数不减，精简无济于事"
    );
    let drop: Vec<RecordKey> = (0..per_branch)
        .map(|i| RecordKey::Tag(format!("b1-{i}")))
        .collect();
    let new_id = vault.rebuild_item(id, &drop).unwrap();
    assert_eq!(
        vault.item(id).err(),
        Some(CoreError::NotFound),
        "旧条目已永久删除"
    );
    let rebuilt = vault.item(new_id).unwrap();
    assert_eq!(rebuilt.doc.overview().title, "t");
    assert_eq!(rebuilt.doc.overview().tags.len(), per_branch);
    vault
        .update_item(new_id, vec![Edit::SetFavorite(true)])
        .unwrap();
}

/// 第四轮评审 J2：头多于单个墓碑的父修订上限时，分批写墓碑，最后只剩一个头。
#[test]
fn review4_j2_tombstones_are_batched() {
    let heads: Vec<Id128> = (0..10u8).map(|i| Id128::from_bytes([i; 16])).collect();
    let mut n = 100u8;
    let plan = tombstone_plan(heads.clone(), 3, || {
        n += 1;
        Ok(Id128::from_bytes([n; 16]))
    })
    .unwrap();
    assert!(plan.iter().all(|(_, parents)| parents.len() <= 3));
    let mut covered: Vec<Id128> = plan.iter().flat_map(|(_, p)| p.clone()).collect();
    covered.sort();
    let mut expected = heads;
    expected.extend(plan.iter().take(plan.len() - 1).map(|(id, _)| *id));
    expected.sort();
    assert_eq!(covered, expected, "每个头与每个中间墓碑恰好被覆盖一次");
    assert_eq!(plan.len(), 4 + 2 + 1);
    let single = tombstone_plan(vec![Id128::from_bytes([1; 16])], 3, || {
        Ok(Id128::from_bytes([9; 16]))
    })
    .unwrap();
    assert_eq!(single.len(), 1);
}

/// 第四轮评审 J2：重建是原子的。永久删除旧条目失败时，新条目也不会留下。
#[test]
fn review4_j2_failed_rebuild_leaves_nothing() {
    let (mut vault, _) =
        Vault::create_with_store(Store::open_in_memory().unwrap(), "pw", fast_params()).unwrap();
    let vault_id = vault.vaults().unwrap()[0].id;
    let id = vault
        .create_item(vault_id, ItemType::Login, "t", vec![])
        .unwrap();
    let before = vault.items().unwrap().len();
    vault
        .store
        .execute_for_tests(
            "CREATE TRIGGER no_tombstones BEFORE INSERT ON revision WHEN NEW.deleted = 1
             BEGIN SELECT RAISE(ABORT, 'injected'); END",
        )
        .unwrap();
    assert!(vault.rebuild_item(id, &[]).is_err());
    assert_eq!(
        vault.items().unwrap().len(),
        before,
        "失败的重建不应留下副本"
    );
    vault
        .store
        .execute_for_tests("DROP TRIGGER no_tombstones")
        .unwrap();
    let new_id = vault.rebuild_item(id, &[]).unwrap();
    assert_eq!(vault.items().unwrap().len(), before);
    assert_eq!(vault.item(new_id).unwrap().doc.overview().title, "t");
}

/// 第四轮评审 J3：非法的标签名在写入前被拒绝，条目仍可正常读取。
#[test]
fn review4_j3_invalid_tag_is_rejected_before_writing() {
    let (mut vault, _) =
        Vault::create_with_store(Store::open_in_memory().unwrap(), "pw", fast_params()).unwrap();
    let vault_id = vault.vaults().unwrap()[0].id;
    let id = vault
        .create_item(vault_id, ItemType::Login, "t", vec![])
        .unwrap();
    assert_eq!(
        vault
            .update_item(id, vec![Edit::AddTag(String::new())])
            .err(),
        Some(CoreError::Format(keevo_format::FormatError::InvalidKey))
    );
    assert_eq!(vault.revision_count(id).unwrap(), 1, "什么都没有写入");
    assert_eq!(vault.item(id).unwrap().doc.overview().title, "t");
}
