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
        ItemEdit::AddFieldToSection {
            section_id: Some("00".repeat(16)),
            kind: "text".into(),
            label: "不存在的分区".into(),
            purpose: None,
            value: String::new(),
            kv: vec![],
            codes: vec![],
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
            Err(KeevoError::InvalidInput { .. } | KeevoError::NotFound)
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

/// 生成器：三种方式都能生成；参数超出范围返回输入错误。
#[test]
fn generator() {
    let g = generate_password(GeneratorRecipe::Password {
        length: 20,
        lowercase: true,
        uppercase: true,
        digits: true,
        symbols: false,
        avoid_ambiguous: true,
    })
    .unwrap();
    assert_eq!(g.value.expose().chars().count(), 20);
    assert!(g.entropy_bits > 100.0 && g.entropy_bits < 20.0 * 62f64.log2());
    let p = generate_password(GeneratorRecipe::Passphrase {
        words: 5,
        separator: "-".into(),
        capitalize: false,
        include_number: false,
    })
    .unwrap();
    assert!(p.value.expose().split('-').count() >= 5);
    let pin = generate_password(GeneratorRecipe::Pin { length: 6 }).unwrap();
    assert_eq!(pin.value.expose().len(), 6);
    assert!(matches!(
        generate_password(GeneratorRecipe::Pin { length: 2 }),
        Err(KeevoError::InvalidInput { .. })
    ));
}

/// 搜索：使用列表建立的索引；写入后重新列出即更新；锁定后不可用。
#[test]
fn search_uses_index_and_requires_unlock() {
    let f = Fixture::new();
    let github = f.login("GitHub");
    let gitlab = f.login("GitLab");
    f.login("Gmail");
    assert_eq!(
        f.vault.search("git".into()).unwrap(),
        [github.clone(), gitlab.clone()],
        "还没有索引时先建立"
    );
    f.vault
        .update_item(
            gitlab.clone(),
            vec![
                ItemEdit::AddTag { tag: "work".into() },
                ItemEdit::SetFavorite { favorite: true },
            ],
        )
        .unwrap();
    f.vault.items().unwrap();
    assert_eq!(f.vault.search("tag:work is:fav".into()).unwrap(), [gitlab]);
    assert_eq!(
        f.vault
            .search("type:login -tag:work github".into())
            .unwrap(),
        [github]
    );
    f.vault.lock();
    assert!(matches!(
        f.vault.search("git".into()),
        Err(KeevoError::Locked)
    ));
}

/// 按模板新建；分区与字段按顺序列出；键值对与恢复码的读写；移动字段、分区的增删改。
#[test]
fn templates_sections_and_structured_fields() {
    let f = Fixture::new();
    let id = f
        .vault
        .create_item(
            f.vault_id.clone(),
            "environment".into(),
            None,
            "后端".into(),
        )
        .unwrap();
    let d = f.vault.item(id.clone()).unwrap();
    assert_eq!(d.item_type, "environment");
    let sections: Vec<&str> = d.sections.iter().map(|s| s.label.as_str()).collect();
    assert_eq!(sections, ["开发", "预发布", "生产"]);
    assert_eq!(d.fields[0].label, "项目", "默认分区在前");
    assert_eq!(d.fields[0].section_id, None);
    let dev_vars = &d.fields[1];
    assert_eq!(
        (dev_vars.kind.as_str(), dev_vars.section_id.as_deref()),
        ("kv_list", Some(d.sections[0].id.as_str()))
    );

    f.vault
        .update_item(
            id.clone(),
            vec![ItemEdit::SetFieldKv {
                field_id: dev_vars.id.clone(),
                entries: vec![
                    KvInput {
                        key: "DATABASE_URL".into(),
                        value: "postgres://dev".into(),
                        concealed: true,
                    },
                    KvInput {
                        key: "DEBUG".into(),
                        value: "1".into(),
                        concealed: false,
                    },
                ],
            }],
        )
        .unwrap();
    let d = f.vault.item(id.clone()).unwrap();
    let kv = &d.fields[1].kv;
    assert_eq!(kv.len(), 2);
    assert_eq!(
        (
            kv[0].key.as_str(),
            kv[0].value.expose().as_str(),
            kv[0].concealed
        ),
        ("DATABASE_URL", "postgres://dev", true)
    );

    // 双因素条目的恢复码：标记已使用
    let tf = f
        .vault
        .create_item(
            f.vault_id.clone(),
            "two_factor".into(),
            None,
            "GitHub".into(),
        )
        .unwrap();
    let codes_field = f
        .vault
        .item(tf.clone())
        .unwrap()
        .fields
        .into_iter()
        .find(|x| x.kind == "recovery_codes")
        .unwrap();
    let set = |used: bool| ItemEdit::SetFieldCodes {
        field_id: codes_field.id.clone(),
        codes: vec![
            CodeInput {
                code: "aaaa-bbbb".into(),
                used,
            },
            CodeInput {
                code: "cccc-dddd".into(),
                used: false,
            },
        ],
    };
    f.vault.update_item(tf.clone(), vec![set(false)]).unwrap();
    f.vault.update_item(tf.clone(), vec![set(true)]).unwrap();
    let codes = f
        .vault
        .item(tf)
        .unwrap()
        .fields
        .into_iter()
        .find(|x| x.kind == "recovery_codes")
        .unwrap()
        .codes;
    assert!(codes[0].used && !codes[1].used);
    assert_eq!(codes[1].code.expose(), "cccc-dddd");

    // 新增分区并放进字段、移动字段、删除分区
    let section = new_id().unwrap();
    f.vault
        .update_item(
            id.clone(),
            vec![
                ItemEdit::AddSection {
                    section_id: section.clone(),
                    label: "测试".into(),
                },
                ItemEdit::AddFieldToSection {
                    section_id: Some(section.clone()),
                    kind: "url".into(),
                    label: "地址".into(),
                    purpose: None,
                    value: "https://test.example.com".into(),
                    kv: vec![],
                    codes: vec![],
                },
                ItemEdit::AddFieldToSection {
                    section_id: Some(section.clone()),
                    kind: "kv_list".into(),
                    label: "额外变量".into(),
                    purpose: None,
                    value: String::new(),
                    kv: vec![KvInput {
                        key: "A".into(),
                        value: "1".into(),
                        concealed: false,
                    }],
                    codes: vec![],
                },
                ItemEdit::SetFieldLabel {
                    field_id: d.fields[0].id.clone(),
                    label: "项目名".into(),
                },
            ],
        )
        .unwrap();
    let d = f.vault.item(id.clone()).unwrap();
    assert_eq!(d.sections.last().unwrap().label, "测试");
    let extra = d.fields.last().unwrap();
    assert_eq!(
        (extra.label.as_str(), extra.kv.len()),
        ("额外变量", 1),
        "新建时带初始内容"
    );
    let url = &d.fields[d.fields.len() - 2];
    assert_eq!(
        (url.label.as_str(), url.section_id.as_deref()),
        ("地址", Some(section.as_str()))
    );
    assert_eq!(d.fields[0].label, "项目名");
    f.vault
        .update_item(
            id.clone(),
            vec![ItemEdit::MoveField {
                field_id: url.id.clone(),
                section_id: None,
                before_field_id: Some(d.fields[0].id.clone()),
            }],
        )
        .unwrap();
    let d = f.vault.item(id.clone()).unwrap();
    assert_eq!(d.fields[0].label, "地址", "移到默认分区的最前面");
    f.vault
        .update_item(
            id.clone(),
            vec![ItemEdit::RemoveSection {
                section_id: section,
            }],
        )
        .unwrap();
    assert_eq!(f.vault.item(id).unwrap().sections.len(), 3);
    assert!(matches!(
        f.vault
            .create_item(f.vault_id.clone(), "passkey".into(), None, "x".into()),
        Err(KeevoError::InvalidInput { .. })
    ));
}

/// 浏览器服务（debug 构建，只靠目录权限）：经真实 socket 配对；确认界面收到"开始"与短认证串；
/// 配对记录存入加密数据库并列出；撤销后新的会话被拒绝。
#[test]
fn browser_service_pairs_lists_and_revokes() {
    use keevo_crypto::StaticKeypair;
    use keevo_ipc::client::{ClientEvent, ExtensionClient};
    use keevo_ipc::frame::{read_socket_frame, write_socket_frame};
    use keevo_ipc::message::HostHello;
    use std::os::unix::net::UnixStream;

    struct Accept(Mutex<Vec<String>>, Mutex<std::collections::VecDeque<bool>>);
    impl BrowserPrompt for Accept {
        fn pairing_started(&self, browser: String) {
            self.0.lock().unwrap().push(format!("started {browser}"));
        }
        fn confirm_pairing(&self, sas: String, name: String, _: String, timeout_ms: u64) -> bool {
            assert!(timeout_ms > 0 && timeout_ms <= 60_000);
            self.0.lock().unwrap().push(format!("confirm {name} {sas}"));
            true
        }
        fn authorize_fill(&self, r: BrowserFillRequest, timeout_ms: u64) -> bool {
            assert!(timeout_ms > 0 && timeout_ms <= 60_000);
            self.0.lock().unwrap().push(format!(
                "authorize {} {} {} {}",
                r.pairing_name, r.title, r.username, r.site
            ));
            self.1.lock().unwrap().pop_front().unwrap_or(false)
        }
        fn fill_paused(&self, _: String, name: String, _: String) {
            self.0.lock().unwrap().push(format!("paused {name}"));
        }
    }

    let f = Fixture::new();
    // Unix socket 路径有长度上限（SUN_LEN），系统临时目录太深，改用 /tmp 下的短路径
    let short = std::path::PathBuf::from(format!(
        "/tmp/kv-{}",
        &Id128::random().unwrap().to_hex()[..8]
    ));
    let socket = short.join("s");
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(short.clone());
    let prompt = Arc::new(Accept(Mutex::new(Vec::new()), Mutex::default()));
    let info = f.vault.start_service_at(prompt.clone(), &socket).unwrap();
    assert!(info.new_identity);
    let again = f.vault.start_service_at(prompt.clone(), &socket).unwrap();
    assert!(!again.new_identity, "重复启动直接返回");

    let origin = "chrome-extension://abcdefghijklmnopabcdefghijklmnop/";
    let connect = || {
        let mut stream = UnixStream::connect(&socket).unwrap();
        let hello = serde_json::to_vec(&HostHello {
            v: 1,
            client: "native-host".into(),
            extension_origin: origin.into(),
            browser: "com.google.Chrome".into(),
        })
        .unwrap();
        write_socket_frame(&mut stream, &hello).unwrap();
        stream
    };
    let key = StaticKeypair::generate().unwrap();
    let private = key.export_private();
    let mut client = ExtensionClient::new(key, origin, "测试扩展");
    let mut stream = connect();
    write_socket_frame(&mut stream, &client.start_pairing().unwrap()).unwrap();
    let mut service_public = None;
    while service_public.is_none() {
        let frame = read_socket_frame(&mut stream).unwrap();
        let (out, events) = client.on_frame(&frame).unwrap();
        for o in out {
            write_socket_frame(&mut stream, &o).unwrap();
        }
        for e in events {
            if let ClientEvent::Paired { service_public: pk } = e {
                service_public = Some(pk);
            }
        }
    }
    let log = prompt.0.lock().unwrap().clone();
    assert_eq!(log[0], "started com.google.Chrome");
    assert!(log[1].starts_with("confirm 测试扩展 "), "{log:?}");
    let pairings = f.vault.browser_pairings();
    assert_eq!(pairings.len(), 1);
    assert_eq!(
        (
            pairings[0].name.as_str(),
            pairings[0].extension_origin.as_str()
        ),
        ("测试扩展", origin)
    );

    // fill 的按站点授权（spec/ipc.md §5.2）：第一次在原生界面确认，之后不再询问；撤销授权后重新询问
    let gh = f
        .vault
        .create_login(
            f.vault_id.clone(),
            LoginInput {
                title: "GitHub".into(),
                username: "octocat".into(),
                password: "hunter2".into(),
                url: "https://github.com".into(),
            },
        )
        .unwrap();
    let fill = |client: &mut ExtensionClient, stream: &mut UnixStream| {
        let (_, frame) = client
            .request(keevo_ipc::message::Call::Fill {
                item_id: gh.clone(),
                url: "https://github.com/login".into(),
            })
            .unwrap();
        write_socket_frame(stream, &frame).unwrap();
        let frame = read_socket_frame(stream).unwrap();
        let (_, mut events) = client.on_frame(&frame).unwrap();
        match events.remove(0) {
            ClientEvent::Message(m) => m,
            other => panic!("{other:?}"),
        }
    };
    let is_fill = |m: &keevo_ipc::message::ServerMessage| {
        matches!(m, keevo_ipc::message::ServerMessage::Ok {
            result: keevo_ipc::message::CallResult::Fill(d), ..
        } if d.username == "octocat" && d.password == "hunter2")
    };
    let is_denied = |m: &keevo_ipc::message::ServerMessage| {
        matches!(m, keevo_ipc::message::ServerMessage::Err { error, .. }
            if error.code == keevo_ipc::message::ErrorCode::NotAuthorized)
    };
    prompt.1.lock().unwrap().push_back(true);
    assert!(is_fill(&fill(&mut client, &mut stream)), "确认后返回凭据");
    assert!(is_fill(&fill(&mut client, &mut stream)), "已授权：不再询问");
    let asked = |p: &Accept| {
        p.0.lock()
            .unwrap()
            .iter()
            .filter(|l| l.starts_with("authorize"))
            .count()
    };
    assert_eq!(asked(&prompt), 1);
    assert_eq!(
        prompt.0.lock().unwrap()[2],
        "authorize 测试扩展 GitHub octocat https://github.com"
    );
    let auths = f
        .vault
        .browser_authorizations(pairings[0].id.clone())
        .unwrap();
    assert_eq!(auths.len(), 1);
    assert_eq!(
        (auths[0].title.as_deref(), auths[0].site.as_str()),
        (Some("GitHub"), "https://github.com")
    );
    assert!(
        f.vault
            .revoke_browser_authorization(pairings[0].id.clone(), gh.clone(), auths[0].site.clone())
            .unwrap()
    );
    assert!(
        is_denied(&fill(&mut client, &mut stream)),
        "撤销授权后重新询问，拒绝时不返回秘密"
    );
    assert_eq!(asked(&prompt), 2);
    assert!(!f.vault.browser_pairings()[0].paused);

    assert!(
        f.vault
            .revoke_browser_pairing(pairings[0].id.clone())
            .unwrap(),
        "写入数据库成功"
    );
    assert!(f.vault.browser_pairings().is_empty());
    let mut again = ExtensionClient::new(StaticKeypair::from_private(private), origin, "测试扩展");
    let mut stream = connect();
    write_socket_frame(
        &mut stream,
        &again.start_session(&service_public.unwrap()).unwrap(),
    )
    .unwrap();
    let frame = read_socket_frame(&mut stream).unwrap();
    let (_, events) = again.on_frame(&frame).unwrap();
    assert!(
        matches!(
            events.as_slice(),
            [ClientEvent::Error(keevo_ipc::message::ErrorCode::NotPaired)]
        ),
        "撤销后不能再建立会话"
    );
}
