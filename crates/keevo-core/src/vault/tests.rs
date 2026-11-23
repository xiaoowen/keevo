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
    let new_id = vault.rebuild_item(id, &drop).unwrap().item_id;
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
    let new_id = vault.rebuild_item(id, &[]).unwrap().item_id;
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

/// 历史列出每次编辑；"恢复到此版本"写入一个新修订，恢复旧值，并删除之后新增的记录。
#[test]
fn history_and_restore_version() {
    let (mut vault, _) =
        Vault::create_with_store(Store::open_in_memory().unwrap(), "pw", fast_params()).unwrap();
    let vault_id = vault.vaults().unwrap()[0].id;
    let id = vault
        .create_item(vault_id, ItemType::Login, "v1", login_fields())
        .unwrap();
    let first = vault.history(id).unwrap()[0].rev_id;
    vault
        .update_item(id, vec![Edit::SetTitle("v2".into())])
        .unwrap();
    vault
        .update_item(
            id,
            vec![Edit::AddTag("work".into()), Edit::SetFavorite(true)],
        )
        .unwrap();

    let history = vault.history(id).unwrap();
    assert_eq!(history.len(), 3);
    let titles: Vec<String> = history
        .iter()
        .map(|h| h.overview.as_ref().unwrap().title.clone())
        .collect();
    assert_eq!(titles, ["v2", "v2", "v1"], "从新到旧");
    assert_eq!(
        vault.revision_doc(id, first).unwrap().overview().title,
        "v1"
    );

    vault.trash_item(id).unwrap();
    vault.restore_version(id, first).unwrap();
    let now = vault.item(id).unwrap().doc.overview();
    assert_eq!(now.title, "v1");
    assert!(now.tags.is_empty(), "之后新增的标签被删除");
    assert!(!now.favorite);
    assert!(now.trashed_at.is_some(), "回收站状态保持当前的样子");
    assert_eq!(
        vault.history(id).unwrap().len(),
        5,
        "创建、改名、加标签、移入回收站、恢复：恢复是一次新的编辑"
    );

    let other = vault
        .create_item(vault_id, ItemType::Login, "x", vec![])
        .unwrap();
    assert_eq!(
        vault.revision_doc(other, first).err(),
        Some(CoreError::NotFound),
        "修订不属于该条目"
    );
}

/// 一次性密码字段：按字段取验证码；不是一次性密码字段、配置不合法、字段不存在各有错误码。
#[test]
fn otp_code_of_field() {
    let (mut vault, _) =
        Vault::create_with_store(Store::open_in_memory().unwrap(), "pw", fast_params()).unwrap();
    let vault_id = vault.vaults().unwrap()[0].id;
    let otp = |label: &str, text: &str| NewField {
        kind: FieldKind::Totp,
        label: label.into(),
        purpose: Some(Purpose::Otp),
        data: FieldData::Text(text.into()),
    };
    let id = vault
        .create_item(
            vault_id,
            ItemType::TwoFactor,
            "GitHub",
            vec![
                otp("验证码", "otpauth://totp/GitHub:octocat?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8"),
                otp("坏的", "not base32!"),
            ],
        )
        .unwrap();
    let doc = vault.item(id).unwrap().doc;
    let field_id = |label: &str| {
        doc.records
            .iter()
            .find_map(|(k, v)| match (k, &v.value) {
                (RecordKey::Field(fid), Some(RecordValue::Field(f))) if f.label == label => {
                    Some(*fid)
                }
                _ => None,
            })
            .unwrap()
    };
    let code = vault.otp_code(id, field_id("验证码"), 59_000).unwrap();
    assert_eq!(code.code.as_str(), "94287082");
    assert_eq!(code.remaining_ms, 1_000);
    assert_eq!(
        vault.otp_code(id, field_id("坏的"), 0).err(),
        Some(CoreError::InvalidOtp)
    );
    assert_eq!(
        vault.otp_code(id, Id128::random().unwrap(), 0).err(),
        Some(CoreError::NotFound)
    );
}

/// 字段系统：按模板新建（分区与字段）、改名与用途、放进分区、移动、删除分区；排序键放不下时自动重新编号。
#[test]
fn field_system() {
    use crate::templates::{Preset, template};

    let (mut vault, _) =
        Vault::create_with_store(Store::open_in_memory().unwrap(), "pw", fast_params()).unwrap();
    let vault_id = vault.vaults().unwrap()[0].id;
    let id = vault
        .create_item_from_template(
            vault_id,
            "工作邮箱",
            template(ItemType::EmailAccount, Preset::Default),
        )
        .unwrap();

    // 读出：(分区名, [字段名…])，分区与字段都按排序键排列
    let layout = |vault: &Vault| -> Vec<(String, Vec<String>)> {
        let doc = vault.item(id).unwrap().doc;
        let mut sections: Vec<(String, Id128, String)> = doc
            .records
            .iter()
            .filter_map(|(k, v)| match (k, &v.value) {
                (RecordKey::Section(sid), Some(RecordValue::Section(s))) => {
                    Some((s.order.clone(), *sid, s.label.clone()))
                }
                _ => None,
            })
            .collect();
        sections.sort();
        let mut fields: Vec<(String, Id128, Option<Id128>, String)> = doc
            .records
            .iter()
            .filter_map(|(k, v)| match (k, &v.value) {
                (RecordKey::Field(fid), Some(RecordValue::Field(f))) => {
                    Some((f.order.clone(), *fid, f.section, f.label.clone()))
                }
                _ => None,
            })
            .collect();
        fields.sort();
        let names = |s: Option<Id128>| {
            fields
                .iter()
                .filter(|f| f.2 == s)
                .map(|f| f.3.clone())
                .collect::<Vec<_>>()
        };
        let mut out = vec![(String::new(), names(None))];
        out.extend(
            sections
                .iter()
                .map(|(_, sid, label)| (label.clone(), names(Some(*sid)))),
        );
        out
    };
    let field_id = |vault: &Vault, label: &str| {
        vault
            .item(id)
            .unwrap()
            .doc
            .records
            .iter()
            .find_map(|(k, v)| match (k, &v.value) {
                (RecordKey::Field(fid), Some(RecordValue::Field(f))) if f.label == label => {
                    Some(*fid)
                }
                _ => None,
            })
            .unwrap()
    };
    let section_id = |vault: &Vault, label: &str| {
        vault
            .item(id)
            .unwrap()
            .doc
            .records
            .iter()
            .find_map(|(k, v)| match (k, &v.value) {
                (RecordKey::Section(sid), Some(RecordValue::Section(s))) if s.label == label => {
                    Some(*sid)
                }
                _ => None,
            })
            .unwrap()
    };
    let l = layout(&vault);
    assert_eq!(l[0].1, ["邮箱地址", "密码", "提供商"]);
    assert_eq!(l[1].0, "服务器");
    assert_eq!(
        l[1].1,
        [
            "IMAP 服务器",
            "IMAP 端口",
            "SMTP 服务器",
            "SMTP 端口",
            "加密方式"
        ]
    );
    assert_eq!(
        l[2],
        (
            "恢复".to_owned(),
            vec![
                "恢复邮箱".to_owned(),
                "恢复手机".to_owned(),
                "恢复码".to_owned()
            ]
        )
    );

    // 改名、用途、移动到同一分区的某个字段之前、移动到另一个分区的末尾
    let server = section_id(&vault, "服务器");
    let smtp = field_id(&vault, "SMTP 服务器");
    let imap = field_id(&vault, "IMAP 服务器");
    let provider = field_id(&vault, "提供商");
    vault
        .update_item(
            id,
            vec![
                Edit::SetFieldLabel {
                    field_id: smtp,
                    label: "发信服务器".into(),
                },
                Edit::SetFieldPurpose {
                    field_id: provider,
                    purpose: Some(Purpose::Notes),
                },
                Edit::MoveField {
                    field_id: smtp,
                    section: Some(server),
                    before: Some(imap),
                },
                Edit::MoveField {
                    field_id: provider,
                    section: Some(server),
                    before: None,
                },
            ],
        )
        .unwrap();
    let l = layout(&vault);
    assert_eq!(l[0].1, ["邮箱地址", "密码"]);
    assert_eq!(
        l[1].1,
        [
            "发信服务器",
            "IMAP 服务器",
            "IMAP 端口",
            "SMTP 端口",
            "加密方式",
            "提供商"
        ]
    );

    // 新增分区并在同一次写入中放进字段；删除分区时字段移到默认分区末尾
    let notes = Id128::random().unwrap();
    vault
        .update_item(
            id,
            vec![
                Edit::AddSection {
                    section_id: notes,
                    label: "备注".into(),
                },
                Edit::AddFieldToSection {
                    section: Some(notes),
                    field: NewField {
                        kind: FieldKind::Multiline,
                        label: "说明".into(),
                        purpose: None,
                        data: FieldData::Text("x".into()),
                    },
                },
                Edit::RenameSection {
                    section_id: section_id(&vault, "恢复"),
                    label: "账户恢复".into(),
                },
            ],
        )
        .unwrap();
    assert_eq!(
        layout(&vault).last().unwrap(),
        &("备注".to_owned(), vec!["说明".to_owned()])
    );
    assert_eq!(layout(&vault)[2].0, "账户恢复");
    vault
        .update_item(id, vec![Edit::RemoveSection(server)])
        .unwrap();
    let l = layout(&vault);
    assert_eq!(
        l[0].1,
        [
            "邮箱地址",
            "密码",
            "发信服务器",
            "IMAP 服务器",
            "IMAP 端口",
            "SMTP 端口",
            "加密方式",
            "提供商"
        ]
    );
    assert_eq!(l.len(), 3, "分区已删除");

    // 不合法的移动
    let pass = field_id(&vault, "密码");
    let explain = field_id(&vault, "说明");
    for bad in [
        Edit::MoveField {
            field_id: pass,
            section: None,
            before: Some(pass),
        },
        Edit::MoveField {
            field_id: pass,
            section: None,
            before: Some(explain),
        },
        Edit::MoveField {
            field_id: pass,
            section: Some(server),
            before: None,
        },
        Edit::AddSection {
            section_id: notes,
            label: "重复".into(),
        },
    ] {
        assert!(vault.update_item(id, vec![bad.clone()]).is_err(), "{bad:?}");
    }

    // 放不下新键时（第一个字段的键是 "0"），先重新编号这个分区
    let first = field_id(&vault, "邮箱地址");
    let (doc, head) = {
        let view = vault.item(id).unwrap();
        (view.doc, vault.store.heads(&id).unwrap()[0].clone())
    };
    let mut doc = doc;
    let hlc = vault.tick().unwrap();
    let rev = Id128::random().unwrap();
    let Some(RecordValue::Field(mut f)) = doc.get(&RecordKey::Field(first)).cloned() else {
        panic!()
    };
    f.order = "0".into();
    doc.set(RecordKey::Field(first), RecordValue::Field(f), hlc, rev)
        .unwrap();
    let ik = vault.item_key(vault.session().unwrap(), &head).unwrap();
    vault
        .write_item_revision(vault_id, id, rev, vec![head.rev_id], &ik, Some(&doc))
        .unwrap();
    vault
        .update_item(
            id,
            vec![Edit::MoveField {
                field_id: pass,
                section: None,
                before: Some(first),
            }],
        )
        .unwrap();
    assert_eq!(&layout(&vault)[0].1[..2], ["密码", "邮箱地址"]);
}

/// 本机记录：加密存放；锁定时不可读写；被篡改的条目跳过并计数；可以删除。
#[test]
fn local_records() {
    let (mut vault, sk) =
        Vault::create_with_store(Store::open_in_memory().unwrap(), "pw", fast_params()).unwrap();
    vault
        .put_local_record("pairing", b"pk-a", br#"{"name":"a"}"#)
        .unwrap();
    vault
        .put_local_record("pairing", b"pk-b", br#"{"name":"b"}"#)
        .unwrap();
    vault
        .put_local_record("pairing", b"pk-a", br#"{"name":"a2"}"#)
        .unwrap();
    vault
        .put_local_record("authorization", b"x", b"{}")
        .unwrap();
    let (records, skipped) = vault.local_records("pairing").unwrap();
    assert_eq!(skipped, 0);
    let names: Vec<&[u8]> = records.iter().map(|(_, p)| p.as_slice()).collect();
    assert_eq!(
        names,
        [&br#"{"name":"a2"}"#[..], br#"{"name":"b"}"#],
        "按 id 排序，替换旧值"
    );

    // 换到另一条记录上的密文解不开：跳过并计数
    let stolen = vault.store.local_records("pairing").unwrap()[0].1.clone();
    vault
        .store
        .put_local_record("pairing", b"pk-c", &stolen)
        .unwrap();
    let (records, skipped) = vault.local_records("pairing").unwrap();
    assert_eq!((records.len(), skipped), (2, 1));

    vault.delete_local_record("pairing", b"pk-b").unwrap();
    vault.lock();
    assert_eq!(
        vault.local_records("pairing").err(),
        Some(CoreError::Locked)
    );
    assert_eq!(
        vault.put_local_record("pairing", b"x", b"{}").err(),
        Some(CoreError::Locked)
    );
    assert_eq!(
        vault.delete_local_record("pairing", b"pk-a").err(),
        Some(CoreError::Locked)
    );
    vault.unlock("pw", &sk).unwrap();
    assert_eq!(
        vault.local_records("pairing").unwrap().0.len(),
        1,
        "pk-b 已删除，pk-c 解不开"
    );
}

/// SSH Agent 的策略存在本机记录中（第五轮预审 K17）：M1.4 写在条目属性中的策略在解锁时迁移一次；
/// 之后恢复一份带旧属性的备份，授权也不会变宽；永久删除时本机授权随之删除。
#[test]
fn ssh_agent_policy_is_local_and_survives_restore() {
    use crate::ssh_agent::{ATTRIBUTE, AgentPolicy};
    let dir = TempDir::new();
    let (mut v, sk) = Vault::create(&dir.db(), "pw", fast_params()).unwrap();
    let vault_id = v.vaults().unwrap()[0].id;
    let key = v
        .create_item(vault_id, ItemType::SshKey, "部署密钥", vec![])
        .unwrap();
    // 模拟 M1.4 的数据：策略写在条目属性中，尚未迁移
    v.revise(key, |doc, hlc, rev| {
        Ok(doc.set(
            RecordKey::attr(ATTRIBUTE),
            RecordValue::Text("unlocked".into()),
            hlc,
            rev,
        )?)
    })
    .unwrap();
    v.store
        .execute_for_tests("DELETE FROM meta WHERE key = 'ssh_agent_local'")
        .unwrap();
    let old_backup = dir.0.join("old.keevo-backup");
    v.backup_to(&old_backup).unwrap();

    v.lock();
    v.unlock("pw", &sk).unwrap();
    assert_eq!(
        v.ssh_agent_policies().unwrap().get(&key),
        Some(&AgentPolicy::Unlocked)
    );
    assert!(
        v.item(key)
            .unwrap()
            .doc
            .get(&RecordKey::attr(ATTRIBUTE))
            .is_none(),
        "迁移后条目中不再有这个属性"
    );

    // 用户收紧授权，然后恢复迁移之前的备份：条目属性回来了，但本机授权不随之回退
    v.set_ssh_agent_policy(key, Some(AgentPolicy::Ask)).unwrap();
    crate::backup::restore(
        &mut v,
        &old_backup,
        &dir.0.join("backups"),
        1_795_105_920_000,
    )
    .unwrap();
    v.unlock("pw", &sk).unwrap();
    assert!(
        v.item(key)
            .unwrap()
            .doc
            .get(&RecordKey::attr(ATTRIBUTE))
            .is_some()
    );
    assert_eq!(
        v.ssh_agent_policies().unwrap().get(&key),
        Some(&AgentPolicy::Ask),
        "恢复不放宽授权"
    );

    // 永久删除：本机授权随之删除
    v.trash_item(key).unwrap();
    v.purge_item(key).unwrap();
    assert!(v.ssh_agent_policies().unwrap().is_empty());
    // 不是 SSH 密钥的条目不能设置
    let login = v
        .create_item(vault_id, ItemType::Login, "x", vec![])
        .unwrap();
    assert_eq!(
        v.set_ssh_agent_policy(login, Some(AgentPolicy::Ask)).err(),
        Some(CoreError::NotFound)
    );
}

#[test]
fn review5_l4_failed_migration_does_not_regrant_revoked_policy() {
    use crate::ssh_agent::{ATTRIBUTE, AgentPolicy};
    let dir = TempDir::new();
    let (mut v, sk) = Vault::create(&dir.db(), "pw", fast_params()).unwrap();
    let key = v
        .create_item(
            v.vaults().unwrap()[0].id,
            ItemType::SshKey,
            "fixture key",
            vec![],
        )
        .unwrap();
    v.revise(key, |doc, hlc, rev| {
        Ok(doc.set(
            RecordKey::attr(ATTRIBUTE),
            RecordValue::Text("unlocked".into()),
            hlc,
            rev,
        )?)
    })
    .unwrap();
    v.store.execute_for_tests("DELETE FROM meta WHERE key = 'ssh_agent_local'; CREATE TRIGGER review5_fail BEFORE INSERT ON revision BEGIN SELECT RAISE(ABORT, 'injected failure'); END;").unwrap();
    v.lock();
    v.unlock("pw", &sk).unwrap(); // 本机记录写入成功，清理属性失败，迁移总标记尚未写入。
    assert_eq!(
        v.ssh_agent_policies().unwrap().get(&key),
        Some(&AgentPolicy::Unlocked)
    );
    v.set_ssh_agent_policy(key, None).unwrap(); // 用户明确选择不在 Agent 中提供。
    v.store
        .execute_for_tests("DROP TRIGGER review5_fail")
        .unwrap();
    v.lock();
    v.unlock("pw", &sk).unwrap();
    assert!(
        !v.ssh_agent_policies().unwrap().contains_key(&key),
        "重试迁移不能复活用户已经撤销的授权"
    );
}

#[test]
fn review5c_m3_purge_during_incomplete_migration_survives_restore() {
    use crate::ssh_agent::{ATTRIBUTE, AgentPolicy};
    let dir = TempDir::new();
    let (mut v, sk) = Vault::create(&dir.db(), "pw", fast_params()).unwrap();
    let key = v
        .create_item(
            v.vaults().unwrap()[0].id,
            ItemType::SshKey,
            "legacy key",
            vec![],
        )
        .unwrap();
    v.revise(key, |doc, hlc, rev| {
        Ok(doc.set(
            RecordKey::attr(ATTRIBUTE),
            RecordValue::Text("unlocked".into()),
            hlc,
            rev,
        )?)
    })
    .unwrap();
    let backup = dir.0.join("legacy.sqlite");
    v.backup_to(&backup).unwrap();
    v.store.execute_for_tests("DELETE FROM meta WHERE key = 'ssh_agent_local'; CREATE TRIGGER review5c_fail BEFORE INSERT ON revision BEGIN SELECT RAISE(ABORT, 'injected migration failure'); END;").unwrap();
    v.lock();
    v.unlock("pw", &sk).unwrap();
    assert_eq!(
        v.ssh_agent_policies().unwrap().get(&key),
        Some(&AgentPolicy::Unlocked)
    );
    assert!(v.store.meta(META_SSH_AGENT_LOCAL).unwrap().is_none());
    v.store
        .execute_for_tests("DROP TRIGGER review5c_fail")
        .unwrap();
    v.set_ssh_agent_policy(key, None).unwrap();
    v.purge_item(key).unwrap();
    assert!(!v.ssh_agent_policies().unwrap().contains_key(&key));
    v.restore_from(&backup).unwrap();
    v.unlock("pw", &sk).unwrap();
    assert!(
        !v.ssh_agent_policies().unwrap().contains_key(&key),
        "迁移未完成时永久删除的旧密钥，也不得在恢复后重新授权"
    );
}

#[test]
fn review5_a1_attachment_context_and_chunk_binding_controls() {
    let dir = TempDir::new();
    let (mut v, _) = Vault::create(&dir.db(), "pw", fast_params()).unwrap();
    let vault_id = v.vaults().unwrap()[0].id;
    let item_id = v
        .create_item(vault_id, ItemType::SecureNote, "fixture", vec![])
        .unwrap();
    let data: Vec<u8> = (0..crate::attachment::CHUNK_LEN + 7)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    let (row, chunks) = v
        .seal_attachment(vault_id, item_id, "fixture.bin", &data)
        .unwrap();
    let reference = keevo_format::AttachmentRef {
        id: row.id,
        name: "fixture.bin".into(),
        size: i64::try_from(data.len()).unwrap(),
        added: 0,
        sha256: Some(keevo_crypto::sha256(&data)),
    };
    let session = v.session().unwrap();
    let vk = session.vault_keys.get(&vault_id).unwrap();
    let open = |acct,
                vault,
                item,
                row: &keevo_store::AttachmentRow,
                chunks: &[Vec<u8>],
                reference: &keevo_format::AttachmentRef| {
        crate::attachment::open_parts(vk, acct, vault, item, row, chunks, reference)
    };
    assert_eq!(
        open(
            session.account_id,
            vault_id,
            item_id,
            &row,
            &chunks,
            &reference
        )
        .unwrap()
        .as_slice(),
        data
    );
    let other = Id128::random().unwrap();
    for (acct, vault, item) in [
        (other, vault_id, item_id),
        (session.account_id, other, item_id),
        (session.account_id, vault_id, other),
    ] {
        assert!(open(acct, vault, item, &row, &chunks, &reference).is_err());
    }
    let mut swapped = chunks.clone();
    swapped.swap(0, 1);
    let mut appended = chunks.clone();
    appended.push(chunks[0].clone());
    let replayed = vec![chunks[0].clone(), chunks[0].clone()];
    for changed in [swapped, chunks[..1].to_vec(), appended, replayed] {
        assert!(
            open(
                session.account_id,
                vault_id,
                item_id,
                &row,
                &changed,
                &reference
            )
            .is_err()
        );
    }
    let mut different_row = row.clone();
    different_row.id = other;
    let mut different_ref = reference.clone();
    different_ref.id = other;
    assert!(
        open(
            session.account_id,
            vault_id,
            item_id,
            &different_row,
            &chunks,
            &different_ref
        )
        .is_err()
    );
    let mut wrong_digest = reference.clone();
    wrong_digest.sha256 = Some([0; 32]);
    assert!(
        open(
            session.account_id,
            vault_id,
            item_id,
            &row,
            &chunks,
            &wrong_digest
        )
        .is_err()
    );
}

/// 重建时内容已损坏的附件不保留，名称返回给界面告诉用户，而不是静默丢弃（第五轮评审问题 5）。
#[test]
fn rebuild_reports_unreadable_attachments() {
    let dir = TempDir::new();
    let (mut v, _) = Vault::create(&dir.db(), "pw", fast_params()).unwrap();
    let vault_id = v.vaults().unwrap()[0].id;
    let item = v
        .create_item(vault_id, ItemType::SecureNote, "带附件", vec![])
        .unwrap();
    let good = v.add_attachment(item, "good.txt", b"fine", 1).unwrap();
    let bad = v.add_attachment(item, "bad.txt", b"broken", 1).unwrap();
    // 长度不变、内容被改：认证失败，永远读不出
    v.store
        .execute_for_tests(&format!(
            "UPDATE attachment_chunk SET ct = zeroblob(length(ct)) WHERE attachment_id = x'{}'",
            bad.id.to_hex()
        ))
        .unwrap();
    let rebuilt = v.rebuild_item(item, &[]).unwrap();
    assert_eq!(rebuilt.skipped_attachments, ["bad.txt"]);
    let names: Vec<String> = v
        .item(rebuilt.item_id)
        .unwrap()
        .doc
        .records
        .values()
        .filter_map(|r| match &r.value {
            Some(RecordValue::Field(FieldValue {
                data: FieldData::Attachment(a),
                ..
            })) => Some(a.name.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(names, [good.name]);
}

/// 条目的本机统计（列表排序）：创建时间取最早的修订，使用次数与最近使用逐次累加；存成加密的本机记录，
/// 重新打开后仍在；锁定时丢弃内存中的副本；永久删除的条目的记录随之删除。
#[test]
fn item_stats_created_uses_and_cleanup() {
    let tmp = TempDir::new();
    let (mut vault, secret_key) = Vault::create(&tmp.db(), "pw stats", fast_params()).unwrap();
    let vault_id = vault.vaults().unwrap()[0].id;
    let before = vault_now_ms_for_tests();
    let a = vault
        .create_item(vault_id, ItemType::Login, "A", login_fields())
        .unwrap();
    let b = vault
        .create_item(vault_id, ItemType::Login, "B", vec![])
        .unwrap();
    let after = vault_now_ms_for_tests();
    // 修改之后，创建时间仍是第一个修订的时间
    vault
        .update_item(a, vec![Edit::SetTitle("A2".into())])
        .unwrap();

    let stats = vault.item_stats(&[a, b]).unwrap();
    let created = stats[&a].created_ms.unwrap();
    assert!(
        (before..=after).contains(&created),
        "{before} ≤ {created} ≤ {after}"
    );
    assert_eq!((stats[&a].uses, stats[&a].last_used_ms), (0, None));

    vault.record_use(a, 1_000).unwrap();
    vault.record_use(a, 2_000).unwrap();
    vault.record_use(b, 1_500).unwrap();
    let stats = vault.item_stats(&[a, b]).unwrap();
    assert_eq!((stats[&a].uses, stats[&a].last_used_ms), (2, Some(2_000)));
    assert_eq!((stats[&b].uses, stats[&b].last_used_ms), (1, Some(1_500)));

    // 锁定时不可用；重新打开、解锁后从本机记录读回
    vault.lock();
    assert_eq!(vault.record_use(a, 3_000).err(), Some(CoreError::Locked));
    drop(vault);
    let mut vault = Vault::open(&tmp.db()).unwrap();
    vault.unlock("pw stats", &secret_key).unwrap();
    let stats = vault.item_stats(&[a, b]).unwrap();
    assert_eq!(stats[&a].created_ms, Some(created));
    assert_eq!((stats[&a].uses, stats[&a].last_used_ms), (2, Some(2_000)));

    // 不再存在的条目：记录删除
    vault.purge_item(b).unwrap();
    let stats = vault.item_stats(&[a]).unwrap();
    assert!(!stats.contains_key(&b));
    let (rows, _) = vault.local_records(ITEM_STATS_KIND).unwrap();
    assert_eq!(rows.len(), 1);
}
