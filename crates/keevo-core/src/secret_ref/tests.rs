use std::path::PathBuf;

use keevo_crypto::KdfParams;
use keevo_format::{KvEntry, Purpose};

use super::*;
use crate::templates::{Preset, template};
use crate::vault::{Edit, NewField};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "keevo-ref-test-{}",
            Id128::random().unwrap().to_hex()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn text(kind: FieldKind, label: &str, value: &str) -> NewField {
    NewField {
        kind,
        label: label.into(),
        purpose: None,
        data: FieldData::Text(value.into()),
    }
}

struct Fixture {
    _dir: TempDir,
    vault: Vault,
    vault_name: String,
    github: Id128,
    env: Id128,
    db: Id128,
}

const OTP_SECRET: &str = "JBSWY3DPEHPK3PXP";

fn fixture() -> Fixture {
    let dir = TempDir::new();
    let params = KdfParams::new(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1, [3u8; 16]).unwrap();
    let (mut vault, _) = Vault::create(&dir.0.join("v.sqlite"), "pw", params).unwrap();
    let info = vault.vaults().unwrap().remove(0);
    let github = vault
        .create_item(
            info.id,
            ItemType::Login,
            "GitHub",
            vec![
                NewField {
                    purpose: Some(Purpose::Username),
                    ..text(FieldKind::Text, "用户名", "octocat")
                },
                text(FieldKind::Concealed, "密码", "correct horse"),
                text(FieldKind::Totp, "一次性密码", OTP_SECRET),
            ],
        )
        .unwrap();
    for _ in 0..2 {
        vault
            .create_item(
                info.id,
                ItemType::Login,
                "Dup",
                vec![text(FieldKind::Text, "x", "1")],
            )
            .unwrap();
    }
    let trashed = vault
        .create_item(
            info.id,
            ItemType::Login,
            "Trashed",
            vec![text(FieldKind::Text, "x", "1")],
        )
        .unwrap();
    vault.trash_item(trashed).unwrap();

    let env = vault
        .create_item_from_template(
            info.id,
            "my-app",
            template(ItemType::Environment, Preset::Default),
        )
        .unwrap();
    let doc = vault.item(env).unwrap().doc;
    let mut edits = Vec::new();
    for (id, f) in fields(&doc) {
        if let (FieldData::Kv(_), Some(s)) = (&f.data, f.section) {
            let label = section_label(&doc, Some(s));
            edits.push(Edit::SetFieldData {
                field_id: id,
                data: FieldData::Kv(vec![
                    KvEntry {
                        key: "DATABASE_URL".into(),
                        value: format!("postgres://{label}").as_str().into(),
                        concealed: true,
                    },
                    KvEntry {
                        key: "database_url".into(),
                        value: "lower".into(),
                        concealed: false,
                    },
                ]),
            });
        }
    }
    vault.update_item(env, edits).unwrap();

    let db = vault
        .create_item(
            info.id,
            ItemType::Database,
            "生产数据库",
            vec![
                text(FieldKind::Select, "引擎", "PostgreSQL"),
                text(FieldKind::Text, "主机", "db.internal"),
                text(FieldKind::Text, "端口", "5432"),
                text(FieldKind::Text, "数据库", "app"),
                text(FieldKind::Text, "用户名", "app"),
                text(FieldKind::Concealed, "密码", "p@ss/word"),
                text(FieldKind::Select, "SSL 模式", "require"),
            ],
        )
        .unwrap();
    Fixture {
        _dir: dir,
        vault,
        vault_name: info.name,
        github,
        env,
        db,
    }
}

fn get(f: &Fixture, r: &str) -> Result<String, RefError> {
    SecretRef::parse(r)?
        .resolve(&f.vault, 1_700_000_000_000)
        .map(|v| v.to_string())
}

#[test]
fn parses_forms_and_rejects_bad_syntax() {
    let r = SecretRef::parse("keevo://dev/OpenAI%20API/Secret").unwrap();
    assert_eq!(r.item, "OpenAI API");
    assert_eq!(r.section, None);
    let r = SecretRef::parse("keevo://dev/my-app/DATABASE_URL?profile=%E7%94%9F%E4%BA%A7").unwrap();
    assert_eq!(r.section.as_deref(), Some("生产"));
    let r = SecretRef::parse("keevo://个人/GitHub/一次性密码?attribute=otp").unwrap();
    assert_eq!(r.attribute, Attribute::Otp);

    for bad in [
        "keevo:/a/b/c",
        "KEEVO://a/b/c",
        "keevo://a/b",
        "keevo://a/b/c/d/e",
        "keevo://a//c",
        "keevo://a/b/c%2",
        "keevo://a/b/c%ZZ",
        "keevo://a/b/%FF",
        "keevo://a/b/c%0A",
        "keevo://a/b/c#frag",
        "keevo://a/b/c?x=1",
        "keevo://a/b/c?attribute=otp&attribute=value",
        "keevo://a/b/c?attribute=password",
        "keevo://a/b/s/c?profile=p",
        "keevo://a/b/c?profile",
    ] {
        assert!(
            matches!(SecretRef::parse(bad), Err(RefError::BadRef(_))),
            "{bad}"
        );
    }
    let long = format!("keevo://a/b/{}", "x".repeat(MAX_SEGMENT_LEN + 1));
    assert!(SecretRef::parse(&long).is_err());
}

#[test]
fn resolves_by_name_and_never_guesses() {
    let f = fixture();
    let v = &f.vault_name;
    assert_eq!(
        get(&f, &format!("keevo://{v}/GitHub/密码")).unwrap(),
        "correct horse"
    );
    // 忽略大小写
    assert_eq!(
        get(&f, &format!("keevo://{v}/github/密码")).unwrap(),
        "correct horse"
    );
    // ID
    assert_eq!(
        get(&f, &format!("keevo://{v}/{}/密码", f.github.to_hex())).unwrap(),
        "correct horse"
    );
    assert!(matches!(
        get(&f, &format!("keevo://{v}/Dup/x")),
        Err(RefError::Ambiguous { segment: Segment::Item, ref candidates, .. }) if candidates.len() == 2
    ));
    assert!(matches!(
        get(&f, "keevo://没有这个/GitHub/密码"),
        Err(RefError::NotFound {
            segment: Segment::Vault,
            ..
        })
    ));
    // 回收站中的条目不参与解析
    assert!(matches!(
        get(&f, &format!("keevo://{v}/Trashed/x")),
        Err(RefError::NotFound {
            segment: Segment::Item,
            ..
        })
    ));
    assert!(matches!(
        get(&f, &format!("keevo://{v}/GitHub/没有")),
        Err(RefError::NotFound {
            segment: Segment::Field,
            ..
        })
    ));
}

#[test]
fn one_time_passwords() {
    let f = fixture();
    let v = &f.vault_name;
    let code = get(&f, &format!("keevo://{v}/GitHub/一次性密码?attribute=otp")).unwrap();
    let doc = f.vault.item(f.github).unwrap().doc;
    let field = fields(&doc)
        .into_iter()
        .find(|(_, x)| x.kind == FieldKind::Totp)
        .unwrap()
        .0;
    let expected = f
        .vault
        .otp_code(f.github, field, 1_700_000_000_000)
        .unwrap();
    assert_eq!(code, expected.code.as_str());
    // 原文
    assert_eq!(
        get(&f, &format!("keevo://{v}/GitHub/一次性密码")).unwrap(),
        OTP_SECRET
    );
    assert_eq!(
        get(&f, &format!("keevo://{v}/GitHub/密码?attribute=otp")),
        Err(RefError::UnsupportedField)
    );
}

#[test]
fn environment_profiles_and_keys() {
    let f = fixture();
    let v = &f.vault_name;
    assert_eq!(
        get(&f, &format!("keevo://{v}/my-app/生产/DATABASE_URL")).unwrap(),
        "postgres://生产"
    );
    assert_eq!(
        get(&f, &format!("keevo://{v}/my-app/DATABASE_URL?profile=开发")).unwrap(),
        "postgres://开发"
    );
    // 没有分区时三个分区都有这个键：歧义
    assert!(matches!(
        get(&f, &format!("keevo://{v}/my-app/DATABASE_URL")),
        Err(RefError::Ambiguous { segment: Segment::Field, ref candidates, .. }) if candidates.len() == 3
    ));
    // 键只做完全相同的比较：小写的键是另一项
    assert_eq!(
        get(&f, &format!("keevo://{v}/my-app/生产/database_url")).unwrap(),
        "lower"
    );
    // 整个键值对字段不能直接取值
    assert_eq!(
        get(&f, &format!("keevo://{v}/my-app/生产/变量")),
        Err(RefError::UnsupportedField)
    );
}

#[test]
fn connection_strings() {
    let f = fixture();
    let v = &f.vault_name;
    assert_eq!(
        get(&f, &format!("keevo://{v}/生产数据库/connection_string")).unwrap(),
        "postgresql://app:p%40ss%2Fword@db.internal:5432/app?sslmode=require"
    );
    assert_eq!(
        get(&f, &format!("keevo://{v}/生产数据库/连接串")).unwrap(),
        "postgresql://app:p%40ss%2Fword@db.internal:5432/app?sslmode=require"
    );
    assert!(get(&f, &format!("keevo://{v}/GitHub/connection_string")).is_err());
    let _ = f.db;
}

#[test]
fn generated_references_resolve_to_the_same_value() {
    let f = fixture();
    for item in [f.github, f.env, f.db] {
        let doc = f.vault.item(item).unwrap().doc;
        for (id, field) in fields(&doc) {
            match &field.data {
                FieldData::Text(t) => {
                    let r = reference_for(&f.vault, item, id, None).unwrap();
                    assert_eq!(get(&f, &r).unwrap(), t.expose(), "{r}");
                }
                FieldData::Kv(entries) => {
                    for e in entries {
                        let r = reference_for(&f.vault, item, id, Some(&e.key)).unwrap();
                        assert_eq!(get(&f, &r).unwrap(), e.value.expose(), "{r}");
                    }
                }
                FieldData::Codes(_) | FieldData::Attachment(_) => {}
            }
        }
    }
    // 名称中的空格与斜杠被编码，汉字保留
    let r = reference_for(
        &f.vault,
        f.github,
        fields(&f.vault.item(f.github).unwrap().doc)[0].0,
        None,
    )
    .unwrap();
    assert!(r.starts_with("keevo://"), "{r}");
}
