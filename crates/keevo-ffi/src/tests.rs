use std::path::PathBuf;

use super::*;

/// 规范允许的最小 KDF 参数，加快测试。
fn fast_params() -> KdfParams {
    KdfParams::new(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1, [5u8; 16]).unwrap()
}

struct Fixture {
    dir: PathBuf,
    vault: KeevoVault,
    vault_id: String,
    secret_key: String,
}

impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "keevo-ffi-test-{}",
            Id128::random().unwrap().to_hex()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let (vault, sk) = Vault::create(&dir.join("vault.sqlite"), "pw", fast_params()).unwrap();
        let secret_key = sk.to_display_string().as_str().to_owned();
        let vault = KeevoVault::new(vault);
        let vault_id = vault.vaults().unwrap()[0].id.clone();
        Self {
            dir,
            vault,
            vault_id,
            secret_key,
        }
    }

    fn login(&self, title: &str) -> String {
        self.vault
            .create_login(
                self.vault_id.clone(),
                LoginInput {
                    title: title.into(),
                    username: "octocat".into(),
                    password: "hunter2".into(),
                    url: "https://example.com".into(),
                },
            )
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// 详情包含字段、用途与标签；一次 `update_item` 应用多个编辑。
#[test]
fn detail_and_edits() {
    let f = Fixture::new();
    let id = f.login("GitHub");
    let detail = f.vault.item(id.clone()).unwrap();
    assert_eq!(detail.title, "GitHub");
    assert_eq!(detail.item_type, "login");
    assert_eq!(detail.head_count, 1);
    assert!(detail.conflicts.is_empty() && !detail.resurrected);
    let password = detail
        .fields
        .iter()
        .find(|x| x.purpose.as_deref() == Some("password"))
        .unwrap();
    assert!(password.concealed);
    assert_eq!(password.value.expose(), "hunter2");
    assert!(password.value.equals("hunter2".into()) && !password.value.is_empty());
    assert_eq!(
        format!("{:?}", password.value),
        "SecretValue(…)",
        "调试输出不含明文"
    );

    f.vault
        .update_item(
            id.clone(),
            vec![
                ItemEdit::SetTitle {
                    title: "GitHub 工作".into(),
                },
                ItemEdit::SetFavorite { favorite: true },
                ItemEdit::AddTag { tag: "work".into() },
                ItemEdit::SetFieldValue {
                    field_id: password.id.clone(),
                    value: "correct horse".into(),
                },
                ItemEdit::AddField {
                    kind: "text".into(),
                    label: "备注".into(),
                    purpose: None,
                    value: "两步验证在手机上".into(),
                },
            ],
        )
        .unwrap();
    let detail = f.vault.item(id.clone()).unwrap();
    assert_eq!(detail.title, "GitHub 工作");
    assert!(detail.favorite);
    assert_eq!(detail.tags, ["work"]);
    assert_eq!(detail.fields.len(), 4);
    assert!(
        detail
            .fields
            .iter()
            .any(|x| x.id == password.id && x.value.expose() == "correct horse")
    );

    let note = detail.fields.iter().find(|x| x.label == "备注").unwrap();
    f.vault
        .update_item(
            id.clone(),
            vec![
                ItemEdit::RemoveField {
                    field_id: note.id.clone(),
                },
                ItemEdit::RemoveTag { tag: "work".into() },
            ],
        )
        .unwrap();
    let detail = f.vault.item(id).unwrap();
    assert_eq!(detail.fields.len(), 3);
    assert!(detail.tags.is_empty());
}

/// 不合法的输入在写入前被拒绝，条目不变。
#[test]
fn invalid_edits_are_rejected() {
    let f = Fixture::new();
    let id = f.login("x");
    let bad = [
        ItemEdit::AddField {
            kind: "file".into(),
            label: "附件".into(),
            purpose: None,
            value: String::new(),
        },
        ItemEdit::AddField {
            kind: "kv_list".into(),
            label: "环境变量".into(),
            purpose: None,
            value: String::new(),
        },
        ItemEdit::AddField {
            kind: "text".into(),
            label: "x".into(),
            purpose: Some("pin".into()),
            value: String::new(),
        },
        ItemEdit::SetFieldValue {
            field_id: "not-an-id".into(),
            value: String::new(),
        },
    ];
    for edit in bad {
        assert!(matches!(
            f.vault.update_item(id.clone(), vec![edit]),
            Err(KeevoError::InvalidInput { .. })
        ));
    }
    assert_eq!(
        f.vault.history(id.clone()).unwrap().len(),
        1,
        "没有写入任何修订"
    );
    assert!(matches!(
        f.vault
            .resolve_conflict(id, "attr:".into(), Id128::random().unwrap().to_hex()),
        Err(KeevoError::InvalidInput { .. })
    ));
}

/// 回收站、恢复、永久删除。
#[test]
fn trash_restore_purge() {
    let f = Fixture::new();
    let id = f.login("x");
    f.vault.trash_item(id.clone()).unwrap();
    assert!(f.vault.item(id.clone()).unwrap().trashed);
    f.vault.restore_item(id.clone()).unwrap();
    assert!(!f.vault.item(id.clone()).unwrap().trashed);
    f.vault.purge_item(id.clone()).unwrap();
    assert!(matches!(
        f.vault.item(id.clone()),
        Err(KeevoError::NotFound)
    ));
    assert!(f.vault.items().unwrap().iter().all(|i| i.id != id));
    let history = f.vault.history(id).unwrap();
    assert!(history[0].deleted, "永久删除留下墓碑");
}

/// 历史从新到旧；可以查看旧版本的字段并恢复。
#[test]
fn history_and_restore_version() {
    let f = Fixture::new();
    let id = f.login("v1");
    f.vault.rename_item(id.clone(), "v2".into()).unwrap();
    let history = f.vault.history(id.clone()).unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].title.as_deref(), Some("v2"));
    assert_eq!(history[1].title.as_deref(), Some("v1"));
    assert!(history.iter().all(|h| !h.deleted && !h.pruned && !h.merge));
    assert!(history[0].updated_ms >= history[1].updated_ms);
    let first = history[1].rev_id.clone();
    assert_eq!(
        f.vault
            .revision_fields(id.clone(), first.clone())
            .unwrap()
            .len(),
        3
    );
    f.vault.restore_version(id.clone(), first).unwrap();
    assert_eq!(f.vault.item(id.clone()).unwrap().title, "v1");
    assert_eq!(f.vault.history(id).unwrap().len(), 3);
}

/// KDF 参数确认：只有确认的正是当前这组参数才执行派生。
#[test]
fn kdf_confirmation_is_bound_to_params() {
    let f = Fixture::new();
    let info = f.vault.kdf_params().unwrap();
    assert_eq!(info.memory_kib, KdfParams::MIN_M_KIB);
    f.vault.lock();
    let other = KdfInfo {
        iterations: info.iterations + 1,
        ..info
    };
    assert!(matches!(
        f.vault
            .unlock_confirming_kdf("pw".into(), Some(f.secret_key.clone()), other),
        Err(KeevoError::KdfNeedsConfirmation)
    ));
    assert!(!f.vault.is_unlocked(), "确认的不是当前参数，不执行派生");
    f.vault
        .unlock_confirming_kdf("pw".into(), Some(f.secret_key.clone()), info)
        .unwrap();
    assert!(f.vault.is_unlocked());
}

/// 冲突的显示：字段冲突取字段名，密码类版本标为隐藏，删除记录的版本值为 `None`；
/// 当前版本在前，其余版本在后，`rev_id` 可原样传回 `resolve_conflict`。
#[test]
fn conflict_entries_describe_each_version() {
    use keevo_format::{FieldValue, Hlc};

    let rev = |n: u8| Id128::from_bytes([n; 16]);
    let version = |n: u8, value: Option<RecordValue>| RecordVersion {
        hlc: Hlc(u64::from(n) << 16),
        rev: rev(n),
        value,
    };
    let password = |s: &str| {
        Some(RecordValue::Field(FieldValue {
            section: None,
            order: "1".into(),
            kind: FieldKind::Concealed,
            label: "密码".into(),
            purpose: Some(Purpose::Password),
            data: FieldData::Text(s.into()),
        }))
    };
    let field = RecordKey::Field(rev(9));
    let title = RecordKey::attr("title");
    let mut doc = ItemDoc {
        item_type: ItemType::Login,
        records: Default::default(),
        concurrent: Default::default(),
    };
    doc.records
        .insert(field.clone(), version(3, password("new")));
    doc.concurrent.insert(
        field.clone(),
        vec![version(1, password("old")), version(2, None)],
    );
    doc.records.insert(
        title.clone(),
        version(4, Some(RecordValue::Text("A".into()))),
    );
    doc.concurrent.insert(
        title.clone(),
        vec![version(5, Some(RecordValue::Text("B".into())))],
    );

    let c = conflict_entry(&doc, &field, &SecretRegistry::default());
    assert_eq!(c.key, field.to_string());
    assert_eq!(
        (c.kind.as_str(), c.label.as_deref()),
        ("field", Some("密码"))
    );
    assert_eq!(c.current.rev_id, rev(3).to_hex());
    assert_eq!(
        c.current.value.as_ref().map(|v| v.expose()).as_deref(),
        Some("new")
    );
    assert!(c.current.concealed);
    assert_eq!(c.others.len(), 2);
    assert_eq!(
        c.others[0].value.as_ref().map(|v| v.expose()).as_deref(),
        Some("old")
    );
    assert!(
        c.others[1].value.is_none() && !c.others[1].concealed,
        "这个版本删除了字段"
    );
    assert_eq!(parse_key(&c.key).unwrap(), field, "键可以原样传回");

    let c = conflict_entry(&doc, &title, &SecretRegistry::default());
    assert_eq!((c.kind.as_str(), c.label), ("title", None));
    assert_eq!(
        c.current.value.as_ref().map(|v| v.expose()).as_deref(),
        Some("A")
    );
    assert_eq!(
        c.others[0].value.as_ref().map(|v| v.expose()).as_deref(),
        Some("B")
    );
    assert!(!c.current.concealed);
}

/// 锁定时，这个保险库发出的全部秘密值句柄被清零（docs/architecture.md §4.2）。
#[test]
fn lock_wipes_issued_secrets() {
    let f = Fixture::new();
    let id = f.login("x");
    let fields = f.vault.fields(id).unwrap();
    let password = fields.iter().find(|x| x.concealed).unwrap();
    assert_eq!(password.value.expose(), "hunter2");
    f.vault.lock();
    assert_eq!(password.value.expose(), "", "锁定后取不出明文");
    assert!(password.value.is_empty());
    assert!(!password.value.equals("hunter2".into()));
}

/// 一次性密码：添加前解析预览（不含密钥）；按字段取验证码，锁定后句柄清零。
#[test]
fn otp_fields() {
    let info = parse_otp(
        "otpauth://totp/GitHub:octocat?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA256&digits=8&period=60".into(),
    )
    .unwrap();
    assert_eq!(info.issuer.as_deref(), Some("GitHub"));
    assert_eq!(info.account.as_deref(), Some("octocat"));
    assert_eq!(
        (info.algorithm.as_str(), info.digits, info.period),
        ("SHA256", 8, 60)
    );
    assert!(matches!(
        parse_otp("nope!".into()),
        Err(KeevoError::InvalidOtp)
    ));

    let f = Fixture::new();
    let id = f.login("GitHub");
    f.vault
        .update_item(
            id.clone(),
            vec![ItemEdit::AddField {
                kind: "totp".into(),
                label: "一次性密码".into(),
                purpose: Some("otp".into()),
                value: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
            }],
        )
        .unwrap();
    let detail = f.vault.item(id.clone()).unwrap();
    let field = detail.fields.iter().find(|x| x.kind == "totp").unwrap();
    let code = f.vault.otp_code(id.clone(), field.id.clone()).unwrap();
    assert_eq!(code.code.expose().len(), 6);
    assert!(code.code.expose().bytes().all(|b| b.is_ascii_digit()));
    assert_eq!(code.period, 30);
    assert!(code.remaining_ms <= 30_000 && code.remaining_ms > 0);
    let user = detail.fields.iter().find(|x| x.kind == "text").unwrap();
    assert!(matches!(
        f.vault.otp_code(id, user.id.clone()),
        Err(KeevoError::InvalidOtp)
    ));
    f.vault.lock();
    assert!(code.code.is_empty(), "锁定后验证码句柄清零");
}
