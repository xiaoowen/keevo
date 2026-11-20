use keevo_crypto::KdfParams;

use super::*;

fn sample(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/import/testdata")
        .join(name);
    std::fs::read(path).unwrap()
}

fn field<'a>(item: &'a Imported, label: &str) -> Option<&'a str> {
    item.fields.iter().find_map(|(_, f)| match &f.data {
        FieldData::Text(t) if f.label == label => Some(t.expose()),
        _ => None,
    })
}

fn by_title<'a>(parsed: &'a Parsed, title: &str) -> &'a Imported {
    parsed.items.iter().find(|i| i.title == title).unwrap()
}

#[test]
fn browsers() {
    let chrome = parse(Source::Chrome, &sample("chrome.csv"), None).unwrap();
    assert_eq!(chrome.items.len(), 2);
    let e = by_title(&chrome, "example.com");
    assert_eq!(field(e, "用户名"), Some("me, myself"));
    assert_eq!(field(e, "密码"), Some("pa\"ss,word"));
    assert_eq!(field(e, "备注"), Some("line one\nline two"));

    let safari = parse(Source::Safari, &sample("safari.csv"), None).unwrap();
    let apple = &safari.items[0];
    assert_eq!(apple.title, "Apple ID (appleid.apple.com)");
    assert!(apple.fields.iter().any(|(_, f)| f.kind == FieldKind::Totp));

    let firefox = parse(Source::Firefox, &sample("firefox.csv"), None).unwrap();
    assert_eq!(
        firefox.items[0].title, "accounts.firefox.com",
        "没有标题时取主机"
    );

    let lastpass = parse(Source::LastPass, &sample("lastpass.csv"), None).unwrap();
    let figma = by_title(&lastpass, "Figma");
    assert_eq!(figma.tags, ["Work/Design"]);
    assert!(figma.favorite);
    assert!(figma.fields.iter().any(|(_, f)| f.kind == FieldKind::Totp));
    let note = by_title(&lastpass, "Router notes");
    assert_eq!(note.item_type, ItemType::SecureNote);
    assert_eq!(
        field(note, "正文"),
        Some("NoteType:Server\nHostname:10.0.0.1")
    );

    // 不是密码导出文件
    assert_eq!(
        parse(Source::Chrome, b"a,b,c\n1,2,3\n", None).err(),
        Some(ImportError::NotRecognized)
    );
    assert_eq!(
        parse(Source::Chrome, b"name,url,username,password\n", None).err(),
        Some(ImportError::Empty)
    );
}

#[test]
fn bitwarden_plain_and_encrypted() {
    let plain = parse(Source::Bitwarden, &sample("bitwarden.json"), None).unwrap();
    check_bitwarden(&plain);

    let encrypted = sample("bitwarden-encrypted.json");
    assert_eq!(
        parse(Source::Bitwarden, &encrypted, None).err(),
        Some(ImportError::PasswordRequired)
    );
    assert_eq!(
        parse(Source::Bitwarden, &encrypted, Some("wrong")).err(),
        Some(ImportError::WrongPassword)
    );
    // 由 make_samples.py（openssl + Python）独立生成：与 Rust 的解密结果一致
    let decrypted = parse(Source::Bitwarden, &encrypted, Some("correct horse battery")).unwrap();
    check_bitwarden(&decrypted);

    assert_eq!(
        parse(
            Source::Bitwarden,
            br#"{"encrypted": true, "data": "2.x|y|z"}"#,
            None
        )
        .err(),
        Some(ImportError::AccountRestricted)
    );
    assert_eq!(
        parse(Source::Bitwarden, b"not json", None).err(),
        Some(ImportError::NotRecognized)
    );
}

fn check_bitwarden(p: &Parsed) {
    assert_eq!(p.items.len(), 6);
    let gh = by_title(p, "GitHub");
    assert_eq!(gh.item_type, ItemType::Login);
    assert!(gh.favorite);
    assert_eq!(gh.tags, ["Work"]);
    assert_eq!(
        gh.fields
            .iter()
            .filter(|(_, f)| f.kind == FieldKind::Url)
            .count(),
        2
    );
    assert_eq!(field(gh, "PIN"), Some("1234"));
    assert_eq!(gh.sections, ["自定义字段"]);
    assert_eq!(field(gh, "备注"), Some("dev account"));
    let visa = by_title(p, "Visa");
    assert_eq!(
        (visa.item_type, visa.original),
        (ItemType::SecureNote, Some("credit_card"))
    );
    assert_eq!(field(visa, "有效期"), Some("03/2029"));
    assert_eq!(by_title(p, "Me").original, Some("identity"));
    let key = by_title(p, "Deploy key");
    assert_eq!(key.item_type, ItemType::SshKey);
    assert!(
        field(key, "私钥")
            .unwrap()
            .starts_with("-----BEGIN OPENSSH")
    );
    // Steam 令牌不是 TOTP：保留为秘密文本
    let steam = by_title(p, "Steam");
    assert!(!steam.fields.iter().any(|(_, f)| f.kind == FieldKind::Totp));
    assert_eq!(
        field(steam, "一次性密码（无法识别）"),
        Some("steam://ABCDEFGH")
    );
}

#[test]
fn one_password() {
    let p = parse(Source::OnePassword, &sample("sample.1pux"), None).unwrap();
    assert_eq!(p.items.len(), 7);
    let gh = by_title(&p, "GitHub");
    assert_eq!(field(gh, "用户名"), Some("octocat"));
    assert_eq!(field(gh, "密码"), Some("Tr0ub4dor&3-horse"));
    assert!(field(gh, "remember").is_none(), "复选框之类的表单字段跳过");
    assert!(gh.favorite);
    assert_eq!(gh.tags, ["work", "dev", "1Password · Private"]);
    assert_eq!(field(gh, "recovery email"), Some("oct@example.com"));
    assert_eq!(field(gh, "PIN"), Some("2468"));
    assert_eq!(field(gh, "since"), Some("2023-11-14"));
    assert_eq!(gh.sections, ["Security"]);
    assert!(gh.fields.iter().any(|(_, f)| f.kind == FieldKind::Totp));

    let visa = by_title(&p, "Visa");
    assert_eq!(visa.original, Some("credit_card"));
    assert_eq!(field(visa, "expiry date"), Some("2029-03"));

    let db = by_title(&p, "Prod DB");
    assert_eq!(db.item_type, ItemType::Database);
    assert_eq!(field(db, "主机"), Some("db.internal"));
    assert_eq!(field(db, "密码"), Some("pg-pass"));

    let key = by_title(&p, "Deploy key");
    assert_eq!(key.item_type, ItemType::SshKey);
    assert_eq!(field(key, "公钥"), Some("ssh-ed25519 AAAAC3Nza deploy"));

    let doc = by_title(&p, "Passport scan");
    assert_eq!((doc.original, doc.attachments), (Some("document"), 1));
    assert!(field(doc, "正文").unwrap().contains("附件"));

    assert!(
        by_title(&p, "Old forum")
            .tags
            .contains(&"已归档".to_owned())
    );

    assert_eq!(
        parse(Source::OnePassword, b"PK not really", None).err(),
        Some(ImportError::NotRecognized)
    );
    let no_data = zip::write_for_tests(&[("export.attributes", b"{}")]);
    assert_eq!(
        parse(Source::OnePassword, &no_data, None).err(),
        Some(ImportError::NotRecognized)
    );
}

fn fast_params() -> KdfParams {
    KdfParams::new(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1, [7; 16]).unwrap()
}

struct TempVault {
    dir: std::path::PathBuf,
    vault: Vault,
}

impl Drop for TempVault {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn temp_vault() -> TempVault {
    let dir = std::env::temp_dir().join(format!(
        "keevo-import-{}",
        crate::Id128::random().unwrap().to_hex()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let (vault, _) = Vault::create(&dir.join("vault.sqlite"), "pw", fast_params()).unwrap();
    TempVault { dir, vault }
}

#[test]
fn write_dedupe_and_round_trip() {
    let mut t = temp_vault();
    let v = &mut t.vault;
    let vault_id = v.vaults().unwrap()[0].id;
    let parsed = parse(Source::Bitwarden, &sample("bitwarden.json"), None).unwrap();
    assert!(duplicates(v, &parsed.items).unwrap().iter().all(|d| !d));
    let ids = v
        .import_items(vault_id, parsed.items, Some("导入 · Bitwarden"))
        .unwrap();
    assert_eq!(ids.len(), 6);
    let gh = v.item(ids[0]).unwrap().doc.overview();
    assert_eq!(gh.title, "GitHub");
    assert!(gh.favorite);
    assert_eq!(gh.tags, ["Work", "导入 · Bitwarden"]);
    assert_eq!(gh.urls.len(), 2);

    // 再次导入：GitHub 与 Steam 两个登录与已有的完全相同；Chrome 中的 github.com 也相同（主机、用户名、密码）
    let again = parse(Source::Bitwarden, &sample("bitwarden.json"), None).unwrap();
    let dup = duplicates(v, &again.items).unwrap();
    assert_eq!(dup, [true, false, false, false, false, true]);
    let chrome = parse(Source::Chrome, &sample("chrome.csv"), None).unwrap();
    assert_eq!(duplicates(v, &chrome.items).unwrap(), [true, false]);
    // 主机、用户名、密码相同，但带有已有登录没有的内容：不算重复，否则跳过它会丢掉这些内容（第五轮预审 K8）
    let mut extra = chrome.items[0].clone();
    extra.fields.push((
        None,
        NewField {
            kind: FieldKind::Multiline,
            label: "备注".into(),
            purpose: Some(Purpose::Notes),
            data: FieldData::Text(SecretString::new("只在新文件里的备注".into())),
        },
    ));
    assert_eq!(duplicates(v, &[extra]).unwrap(), [false]);

    // 导出为 Keevo 加密文件，再导入：内容一致
    let exported = crate::export::export(
        v,
        crate::export::Format::Keevo,
        None,
        Some("plum orbit cactus velvet 41"),
    )
    .unwrap();
    assert_eq!(exported.count, 6);
    assert!(keevo_crypto::is_export(&exported.bytes));
    assert_eq!(
        parse(Source::Keevo, &exported.bytes, None).err(),
        Some(ImportError::PasswordRequired)
    );
    assert_eq!(
        parse(Source::Keevo, &exported.bytes, Some("export passworD")).err(),
        Some(ImportError::WrongPassword)
    );
    let back = parse(
        Source::Keevo,
        &exported.bytes,
        Some("plum orbit cactus velvet 41"),
    )
    .unwrap();
    assert_eq!(back.items.len(), 6);
    let gh2 = by_title(&back, "GitHub");
    assert_eq!(field(gh2, "密码"), Some("Tr0ub4dor&3-horse"));
    assert_eq!(gh2.tags, ["Work", "导入 · Bitwarden"]);
    assert_eq!(gh2.sections, ["自定义字段"]);
    assert!(
        duplicates(v, &back.items).unwrap()[..]
            .iter()
            .filter(|d| **d)
            .count()
            >= 2
    );
    for weak in [
        "short",
        "          ",
        "aaaaaaaaaa",
        "password123",
        "export password",
    ] {
        assert_eq!(
            crate::export::export(v, crate::export::Format::Keevo, None, Some(weak)).err(),
            Some(crate::CoreError::OutOfRange),
            "导出密码至少 10 个字符、不全是空白、强度达到很强：{weak:?}"
        );
    }

    // 明文 JSON 与 CSV
    let json = crate::export::export(v, crate::export::Format::Json, None, None).unwrap();
    let back = parse(Source::Keevo, &json.bytes, None).unwrap();
    assert_eq!(back.items.len(), 6);
    let csv = crate::export::export(v, crate::export::Format::Csv, None, None).unwrap();
    let text = core::str::from_utf8(&csv.bytes).unwrap();
    assert!(text.starts_with("name,url,username,password,note,totp\n"));
    let logins = parse(Source::Chrome, &csv.bytes, None).unwrap();
    assert_eq!(logins.items.len(), 2, "CSV 只有登录");
    assert_eq!(
        field(by_title(&logins, "GitHub"), "密码"),
        Some("Tr0ub4dor&3-horse")
    );

    // 一个过大的条目让整次导入失败，什么都不写
    let before = v.items().unwrap().len();
    let mut huge = Builder::new(ItemType::SecureNote, "大");
    for i in 0..100 {
        huge.add(
            None,
            FieldKind::Multiline,
            &format!("段 {i}"),
            None,
            &"x".repeat(200_000),
        );
    }
    let ok = Builder::new(ItemType::SecureNote, "小").finish();
    assert!(
        v.import_items(vault_id, vec![ok, huge.finish()], None)
            .is_err()
    );
    assert_eq!(v.items().unwrap().len(), before);
}

#[test]
fn builder_limits() {
    let mut b = Builder::new(ItemType::Login, &"t".repeat(1000));
    b.add(
        None,
        FieldKind::Concealed,
        "密码",
        Some(Purpose::Password),
        "a",
    );
    b.add(
        None,
        FieldKind::Concealed,
        "第二个密码",
        Some(Purpose::Password),
        "b",
    );
    b.add(None, FieldKind::Text, "空", None, "   ");
    b.tag("x");
    b.tag("x");
    let item = b.finish();
    assert_eq!(item.title.len(), MAX_LABEL);
    assert_eq!(item.fields.len(), 3, "两个密码，加上说明截断的备注");
    assert_eq!(item.fields[1].1.purpose, None, "同一用途只保留第一个");
    assert!(
        item.text_of(Purpose::Notes)
            .is_some_and(|n| n.contains("1 个名称或值超过长度上限")),
        "截断不是静默的（第五轮评审 L6）"
    );
    assert_eq!(item.tags, ["x"]);
    assert_eq!(clip("你好世界", 7), "你好");
    assert_eq!(date_from_days(0), "1970-01-01");
    assert_eq!(date_from_days(20_776), "2026-11-19");
}

/// 导入后条目中的全部文本（标题、字段、标签），用于"字段零丢失"的检查。
fn all_text(p: &Parsed) -> String {
    let mut out = String::new();
    for i in &p.items {
        out.push_str(&i.title);
        out.push('\n');
        for t in &i.tags {
            out.push_str(t);
            out.push('\n');
        }
        for s in &i.sections {
            out.push_str(s);
            out.push('\n');
        }
        for (_, f) in &i.fields {
            out.push_str(&f.label);
            out.push('\n');
            if let FieldData::Text(t) = &f.data {
                out.push_str(t.expose());
                out.push('\n');
            }
        }
    }
    out
}

/// 验收（docs/roadmap.md §3.8）：导入 Bitwarden 与 1Password 样例时字段零丢失。样例中每个有内容的值
/// 都必须出现在导入后的条目里（ID、类型代码等结构信息除外；日期等按约定换了写法的值单独检查）。
#[test]
fn imports_lose_no_fields() {
    use serde_json::Value;
    fn leaves<'a>(v: &'a Value, key: &str, skip: &[&str], out: &mut Vec<(String, &'a str)>) {
        match v {
            Value::String(s) if !s.trim().is_empty() && !skip.contains(&key) => {
                out.push((key.to_owned(), s))
            }
            Value::Array(a) => a.iter().for_each(|x| leaves(x, key, skip, out)),
            Value::Object(o) => o.iter().for_each(|(k, x)| leaves(x, k, skip, out)),
            _ => {}
        }
    }

    // Bitwarden：id、folderId、collectionIds、type 等是结构信息；Steam 令牌原样保留为秘密文本
    let mut bw: Value = serde_json::from_slice(&sample("bitwarden.json")).unwrap();
    // 链接字段（type 3）只指向本条目中的另一个字段，自身没有值
    for item in bw["items"].as_array_mut().unwrap() {
        if let Some(fields) = item.get_mut("fields").and_then(Value::as_array_mut) {
            fields.retain(|f| f["type"] != 3);
        }
    }
    let parsed = parse(Source::Bitwarden, &sample("bitwarden.json"), None).unwrap();
    let text = all_text(&parsed);
    let mut values = Vec::new();
    leaves(&bw["items"], "", &["id", "folderId", "match"], &mut values);
    leaves(&bw["folders"], "", &["id"], &mut values);
    assert!(values.len() > 30);
    for (key, v) in values {
        // 银行卡有效期合并为 MM/YYYY
        if key == "expMonth" || key == "expYear" {
            continue;
        }
        assert!(text.contains(v), "Bitwarden：{key} = {v:?} 没有导入");
    }
    assert!(text.contains("03/2029"));

    // 1PUX：uuid、类别代码、状态、表单字段的元信息与"记住我"之类的复选框不是用户数据
    let zip = sample("sample.1pux");
    let data = zip::read(&zip, "export.data", 1 << 20).unwrap().unwrap();
    let px: Value = serde_json::from_slice(&data).unwrap();
    let parsed = parse(Source::OnePassword, &zip, None).unwrap();
    let text = all_text(&parsed);
    let mut values = Vec::new();
    for item in px["accounts"][0]["vaults"][0]["items"].as_array().unwrap() {
        leaves(&item["overview"], "", &["subtitle"], &mut values);
        for f in item["details"]["loginFields"]
            .as_array()
            .into_iter()
            .flatten()
        {
            if f["fieldType"] != "C" {
                values.push(("loginFields".into(), f["value"].as_str().unwrap()));
            }
        }
        leaves(
            &item["details"]["notesPlain"],
            "notesPlain",
            &[],
            &mut values,
        );
        for s in item["details"]["sections"].as_array().into_iter().flatten() {
            leaves(&s["title"], "section", &[], &mut values);
            for f in s["fields"].as_array().into_iter().flatten() {
                leaves(&f["value"], "value", &["keyType"], &mut values);
            }
        }
    }
    leaves(
        &px["accounts"][0]["vaults"][0]["attrs"]["name"],
        "vault",
        &[],
        &mut values,
    );
    assert!(values.len() > 20);
    for (key, v) in values {
        assert!(text.contains(v), "1Password：{key} = {v:?} 没有导入");
    }
    // 换了写法的值：日期、年月
    assert!(text.contains("2023-11-14") && text.contains("2029-03"));
}

/// Keevo 导出文件中数据与字段类型不符的字段：跳过并在备注中说明，其余照常导入（第五轮预审 K20）。
#[test]
fn keevo_export_mismatched_fields_are_skipped() {
    let doc = br#"{"format":"keevo-export","version":1,"exported_at":"x","vaults":[{"name":"v","items":[{"type":"login","title":"t","fields":[
        {"kind":"text","label":"user","purpose":"username","value":"octocat"},
        {"kind":"kv_list","label":"env","value":"x"},
        {"kind":"attachment","label":"a","value":"x"},
        {"kind":"text","label":"two","value":"x","codes":[]},
        {"kind":"recovery_codes","label":"c","entries":[]}
    ]}]}]}"#;
    let parsed = parse(Source::Keevo, doc, None).unwrap();
    let item = &parsed.items[0];
    assert_eq!(item.text_of(Purpose::Username), Some("octocat"));
    let notes = item.text_of(Purpose::Notes).unwrap();
    assert!(notes.contains("4 个字段的格式不对"), "{notes}");
}
