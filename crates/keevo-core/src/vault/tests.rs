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
    let kept = vault
        .store
        .history(&id)
        .unwrap()
        .iter()
        .filter(|r| !r.pruned)
        .count();
    assert_eq!(kept, HISTORY_KEEP);
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
