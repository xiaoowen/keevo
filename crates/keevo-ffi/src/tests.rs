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
        fn confirm_pairing(
            &self,
            words: Vec<SasWord>,
            name: String,
            _: String,
            timeout_ms: u64,
        ) -> bool {
            assert!(timeout_ms > 0 && timeout_ms <= 60_000);
            assert_eq!(words.len(), 6);
            let zh: Vec<String> = words.into_iter().map(|w| w.zh).collect();
            self.0
                .lock()
                .unwrap()
                .push(format!("confirm {name} {}", zh.join(" ")));
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
        fn confirm_update(&self, r: BrowserUpdateRequest, changed: bool, timeout_ms: u64) -> bool {
            assert!(timeout_ms > 0 && timeout_ms <= 60_000);
            self.0.lock().unwrap().push(format!(
                "update {} {} {} {changed}",
                r.title, r.username, r.site
            ));
            self.1.lock().unwrap().pop_front().unwrap_or(false)
        }
        fn login_saved(&self, name: String, _: String, title: String) {
            self.0.lock().unwrap().push(format!("saved {name} {title}"));
        }
        fn queries_limited(&self, _: String, name: String, _: String) {
            self.0.lock().unwrap().push(format!("limited {name}"));
        }
        fn authorize_search(&self, r: BrowserSearchRequest, timeout_ms: u64) -> bool {
            assert!(timeout_ms > 0 && timeout_ms <= 60_000);
            self.0.lock().unwrap().push(format!(
                "search {} {} {}",
                r.pairing_name, r.browser, r.query
            ));
            self.1.lock().unwrap().pop_front().unwrap_or(false)
        }
        fn open_requested(&self, name: String, _: String, item_id: Option<String>) {
            self.0
                .lock()
                .unwrap()
                .push(format!("open {name} {}", item_id.unwrap_or_default()));
        }
        fn browser_unlock_requested(&self, name: String, browser: String) {
            self.0
                .lock()
                .unwrap()
                .push(format!("unlock {name} {browser}"));
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
            v: keevo_ipc::message::PROTOCOL_VERSION,
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
    let mut shown = None;
    while service_public.is_none() {
        let frame = read_socket_frame(&mut stream).unwrap();
        let (out, events) = client.on_frame(&frame).unwrap();
        for o in out {
            write_socket_frame(&mut stream, &o).unwrap();
        }
        for e in events {
            match e {
                ClientEvent::Paired { service_public: pk } => service_public = Some(pk),
                ClientEvent::ShowSas(sas) => shown = Some(sas),
                _ => {}
            }
        }
    }
    let log = prompt.0.lock().unwrap().clone();
    assert_eq!(log[0], "started com.google.Chrome");
    // 两端显示同一组词：扩展一侧的 SAS 字节经同一份词表映射，与应用确认界面收到的一致
    let zh: Vec<&str> = keevo_ipc::sas::sas_words(&shown.unwrap())
        .iter()
        .map(|w| w.zh)
        .collect();
    assert_eq!(log[1], format!("confirm 测试扩展 {}", zh.join(" ")));
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

    // 协议 v2（§5.5）：保存新登录不需要确认，保存后可以直接填充（凭据本来就是扩展提供的）；
    // 更新每次都要确认，拒绝时不改动，确认后填充得到新密码
    let call = |client: &mut ExtensionClient, stream: &mut UnixStream, c| {
        let (_, frame) = client.request(c).unwrap();
        write_socket_frame(stream, &frame).unwrap();
        let frame = read_socket_frame(stream).unwrap();
        let (_, mut events) = client.on_frame(&frame).unwrap();
        match events.remove(0) {
            ClientEvent::Message(m) => m,
            other => panic!("{other:?}"),
        }
    };
    let written = |m: &keevo_ipc::message::ServerMessage| match m {
        keevo_ipc::message::ServerMessage::Ok {
            result: keevo_ipc::message::CallResult::Written { item_id },
            ..
        } => Some(item_id.clone()),
        _ => None,
    };
    let secret = |s: &str| keevo_ipc::message::SecretText::new(s);
    let saved = call(
        &mut client,
        &mut stream,
        keevo_ipc::message::Call::Save {
            url: "https://news.example/login".into(),
            username: "reader".into(),
            password: secret("saved-pass"),
        },
    );
    let new_id = written(&saved).expect("保存成功");
    assert!(
        prompt
            .0
            .lock()
            .unwrap()
            .iter()
            .any(|l| l == "saved 测试扩展 news.example")
    );
    let fill_new = call(
        &mut client,
        &mut stream,
        keevo_ipc::message::Call::Fill {
            item_id: new_id.clone(),
            url: "https://news.example/".into(),
        },
    );
    assert!(
        matches!(&fill_new, keevo_ipc::message::ServerMessage::Ok { result: keevo_ipc::message::CallResult::Fill(d), .. } if d.password == "saved-pass"),
        "{fill_new:?}"
    );
    assert_eq!(asked(&prompt), 2, "保存的条目不再询问授权");
    let update = |pw: &str| keevo_ipc::message::Call::Update {
        item_id: gh.clone(),
        url: "https://github.com/settings".into(),
        password: secret(pw),
    };
    prompt.1.lock().unwrap().push_back(false);
    assert!(
        is_denied(&call(&mut client, &mut stream, update("rotated"))),
        "拒绝更新"
    );
    prompt.1.lock().unwrap().push_back(true);
    assert_eq!(
        written(&call(&mut client, &mut stream, update("rotated"))),
        Some(gh.clone())
    );
    assert!(
        prompt
            .0
            .lock()
            .unwrap()
            .iter()
            .any(|l| l == "update GitHub octocat https://github.com true")
    );
    prompt.1.lock().unwrap().push_back(true);
    let after = fill(&mut client, &mut stream);
    assert!(
        matches!(&after, keevo_ipc::message::ServerMessage::Ok { result: keevo_ipc::message::CallResult::Fill(d), .. } if d.password == "rotated"),
        "{after:?}"
    );

    // 协议 v3（§5.6）：搜索全部条目第一次需要允许，之后直接返回；open 转给 Keevo.app，条目已核对存在
    let titles = |m: &keevo_ipc::message::ServerMessage| match m {
        keevo_ipc::message::ServerMessage::Ok {
            result: keevo_ipc::message::CallResult::Candidates { items },
            ..
        } => items.iter().map(|c| c.title.clone()).collect::<Vec<_>>(),
        other => panic!("{other:?}"),
    };
    let search = |ask| keevo_ipc::message::Call::Search {
        query: "news".into(),
        ask,
    };
    assert!(
        is_denied(&call(&mut client, &mut stream, search(false))),
        "没有允许时不询问"
    );
    prompt.1.lock().unwrap().push_back(true);
    assert_eq!(
        titles(&call(&mut client, &mut stream, search(true))),
        ["news.example"]
    );
    assert_eq!(
        titles(&call(&mut client, &mut stream, search(false))),
        ["news.example"]
    );
    let searched = |p: &Accept| {
        p.0.lock()
            .unwrap()
            .iter()
            .filter(|l| l.starts_with("search"))
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(
        searched(&prompt),
        ["search 测试扩展 com.google.Chrome news"]
    );
    let opened = call(
        &mut client,
        &mut stream,
        keevo_ipc::message::Call::Open {
            item_id: Some(new_id.clone()),
        },
    );
    assert!(
        matches!(
            &opened,
            keevo_ipc::message::ServerMessage::Ok {
                result: keevo_ipc::message::CallResult::Status {
                    locked: false,
                    touch_id: Some(false)
                },
                ..
            }
        ),
        "{opened:?}"
    );
    // 输出在回复之后发出：等它出现在日志里
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !prompt
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|l| l == &format!("open 测试扩展 {new_id}"))
    {
        assert!(std::time::Instant::now() < deadline, "没有收到 open");
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    // 锁定时：unlock 请 Keevo.app 解锁（30 秒内只请求一次），open 只显示锁屏；解锁后搜索需要重新允许
    f.vault.lock();
    let wait_for = |line: String| {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !prompt.0.lock().unwrap().contains(&line) {
            assert!(std::time::Instant::now() < deadline, "没有收到 {line}");
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    };
    let locked_status = |m: &keevo_ipc::message::ServerMessage| {
        matches!(
            m,
            keevo_ipc::message::ServerMessage::Ok {
                result: keevo_ipc::message::CallResult::Status { locked: true, .. },
                ..
            }
        )
    };
    for _ in 0..2 {
        let m = call(&mut client, &mut stream, keevo_ipc::message::Call::Unlock);
        assert!(locked_status(&m), "{m:?}");
    }
    wait_for("unlock 测试扩展 com.google.Chrome".into());
    std::thread::sleep(std::time::Duration::from_millis(200));
    let unlocks = prompt
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|l| l.starts_with("unlock"))
        .count();
    assert_eq!(unlocks, 1, "30 秒内只请求一次解锁");
    std::thread::sleep(std::time::Duration::from_millis(1000));
    let m = call(
        &mut client,
        &mut stream,
        keevo_ipc::message::Call::Open {
            item_id: Some(new_id.clone()),
        },
    );
    assert!(locked_status(&m), "{m:?}");
    wait_for("open 测试扩展 ".into());
    f.vault.unlock("pw".into(), f.secret_key.clone()).unwrap();
    assert!(
        is_denied(&call(&mut client, &mut stream, search(false))),
        "再次解锁后需要重新允许搜索"
    );

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

/// SSH 密钥：生成与导入写入私钥、公钥、指纹等字段，默认"每次确认"；私钥有问题时说明原因。
#[test]
fn ssh_keys_are_generated_imported_and_listed() {
    let f = Fixture::new();
    let id = f
        .vault
        .create_item(f.vault_id.clone(), "ssh_key".into(), None, "GitHub".into())
        .unwrap();
    let fingerprint = f.vault.generate_ssh_key(id.clone()).unwrap();
    let keys = f.vault.ssh_keys().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].fingerprint.as_deref(), Some(fingerprint.as_str()));
    assert_eq!(keys[0].policy.as_deref(), Some("ask"));
    assert!(
        keys[0]
            .public_key
            .as_deref()
            .unwrap()
            .starts_with("ssh-ed25519 ")
    );
    let detail = f.vault.item(id.clone()).unwrap();
    let field = |label: &str| {
        detail
            .fields
            .iter()
            .find(|x| x.label == label)
            .map(|x| x.value.expose())
            .unwrap()
    };
    assert!(field("私钥").starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
    assert_eq!(field("指纹"), fingerprint);
    assert_eq!(field("算法"), "Ed25519");

    f.vault
        .set_ssh_agent_policy(id.clone(), Some("unlocked".into()))
        .unwrap();
    assert_eq!(
        f.vault.ssh_keys().unwrap()[0].policy.as_deref(),
        Some("unlocked")
    );
    f.vault.set_ssh_agent_policy(id.clone(), None).unwrap();
    assert_eq!(f.vault.ssh_keys().unwrap()[0].policy, None);
    assert!(
        f.vault
            .set_ssh_agent_policy(id.clone(), Some("always".into()))
            .is_err()
    );

    // 导入：同一把密钥导入另一个条目，指纹相同
    let other = f
        .vault
        .create_item(f.vault_id.clone(), "ssh_key".into(), None, "副本".into())
        .unwrap();
    let text = field("私钥").to_owned();
    assert_eq!(
        f.vault
            .import_ssh_private_key(other.clone(), text, None)
            .unwrap(),
        fingerprint
    );
    let code_of = |r: Result<String, KeevoError>| match r {
        Err(KeevoError::SshKey { code, detail }) => format!("{code} {detail}"),
        other => panic!("{other:?}"),
    };
    assert_eq!(
        code_of(f.vault.import_ssh_private_key(
            other.clone(),
            "-----BEGIN RSA PRIVATE KEY-----\nAA\n-----END RSA PRIVATE KEY-----".into(),
            None
        )),
        "unsupported ssh-rsa"
    );
    // 有口令保护的私钥（keevo-ssh 的测试数据，口令 correct horse）：先说明需要口令，口令不对单独说明，
    // 正确时导入；条目中保存的是未加密的 OpenSSH 格式（由保险库加密）
    let encrypted = include_str!("../../keevo-ssh/src/testdata/ed25519-aes256-ctr").to_owned();
    assert_eq!(
        code_of(
            f.vault
                .import_ssh_private_key(other.clone(), encrypted.clone(), None)
        ),
        "encrypted "
    );
    assert_eq!(
        code_of(f.vault.import_ssh_private_key(
            other.clone(),
            encrypted.clone(),
            Some("wrong".into())
        )),
        "wrong_passphrase "
    );
    assert_eq!(
        f.vault
            .import_ssh_private_key(other.clone(), encrypted, Some("correct horse".into()))
            .unwrap(),
        "SHA256:no/e8WdACPEYj7f3n0KxqP6g4k7PJnw0N95kIGpQmVg"
    );
    let stored = f.vault.item(other.clone()).unwrap();
    let private = stored.fields.iter().find(|x| x.label == "私钥").unwrap();
    let private = private.value.expose();
    assert!(private.contains("BEGIN OPENSSH PRIVATE KEY"));
    assert!(
        keevo_ssh::PrivateKey::parse(&private).is_ok(),
        "保存的私钥不需要口令"
    );
    assert_eq!(
        code_of(f.vault.import_ssh_private_key(
            other.clone(),
            include_str!("../../keevo-ssh/src/testdata/ed25519-aes256-gcm").into(),
            Some("correct horse".into())
        )),
        "cipher aes256-gcm@openssh.com"
    );
    // PKCS#8 没有注释：用条目标题
    f.vault
        .import_ssh_private_key(
            other.clone(),
            include_str!("../../keevo-ssh/src/testdata/ed25519-pkcs8.pem").into(),
            None,
        )
        .unwrap();
    let keys = f.vault.ssh_keys().unwrap();
    let imported = keys.iter().find(|k| k.item_id == other).unwrap();
    assert!(
        imported
            .public_key
            .as_deref()
            .unwrap_or("")
            .ends_with(" 副本"),
        "{imported:?}"
    );
    // 不是 SSH 密钥条目
    let login = f.login("网站");
    assert!(f.vault.generate_ssh_key(login).is_err());
}

/// 复制引用：生成的引用指向这个字段。
#[test]
fn secret_references_point_at_the_field() {
    let f = Fixture::new();
    let id = f.login("GitHub");
    let detail = f.vault.item(id.clone()).unwrap();
    let password = detail.fields.iter().find(|x| x.label == "密码").unwrap();
    let r = f
        .vault
        .secret_reference(id, password.id.clone(), None)
        .unwrap();
    let vault_name = f.vault.vaults().unwrap()[0].name.clone();
    assert_eq!(r, format!("keevo://{vault_name}/GitHub/密码"));
}

/// 安全中心（docs/product.md §5.6）：检查结果、搜索 `is:weak`、条目的安全概况、忽略、泄露检查；锁定时丢弃。
#[test]
fn security_center() {
    let f = Fixture::new();
    // Fixture::login 的密码都是 hunter2：弱密码，且彼此重复
    let a = f.login("论坛");
    let b = f.login("旧账户");
    assert!(f.vault.security_report().unwrap().is_none(), "还没有检查");
    assert!(f.vault.item_security(a.clone()).unwrap().is_none());

    let report = f.vault.run_security_check().unwrap();
    let checks_of = |id: &str| {
        let mut c: Vec<String> = report
            .findings
            .iter()
            .filter(|x| x.item_id == id)
            .map(|x| x.check.clone())
            .collect();
        c.sort();
        c
    };
    assert_eq!(checks_of(&a), ["reused", "weak"]);
    assert_eq!(report.affected_items, 2);
    assert!(!report.breach_checked);
    let mut weak = f.vault.search("is:weak".into()).unwrap();
    weak.sort();
    let mut both = vec![a.clone(), b.clone()];
    both.sort();
    assert_eq!(weak, both);
    f.vault.items().unwrap();
    assert_eq!(
        f.vault.search("is:weak".into()).unwrap().len(),
        2,
        "重建索引后仍然标记"
    );

    let sec = f.vault.item_security(a.clone()).unwrap().unwrap();
    assert!(sec.strength.as_ref().unwrap().score <= 1);
    assert_eq!(sec.reused_with, ["旧账户"]);
    assert_eq!(sec.breach_count, None, "没有开启泄露检查");
    assert!(!sec.ignored);

    // 忽略：不再出现在结果中，但概况仍然给出
    f.vault.set_security_alerts(b.clone(), false).unwrap();
    let report = f.vault.run_security_check().unwrap();
    assert!(report.findings.iter().all(|x| x.item_id != b));
    assert!(f.vault.item_security(b.clone()).unwrap().unwrap().ignored);

    // 泄露检查：前缀交给界面查询，响应在这里比对
    let prefixes = f.vault.prepare_breach_check().unwrap();
    assert_eq!(prefixes.len(), 1, "只有一个不同的密码");
    let hash: String = keevo_crypto::sha1_for_breach_check(b"hunter2")
        .iter()
        .map(|x| format!("{x:02X}"))
        .collect();
    assert_eq!(prefixes[0], hash[..5]);
    assert!(
        f.vault
            .record_breach_range(prefixes[0].clone(), format!("{}:17043\r\n", &hash[5..]))
    );
    let report = f.vault.run_security_check().unwrap();
    assert!(report.breach_checked);
    assert!(
        report
            .findings
            .iter()
            .any(|x| x.item_id == a && x.check == "breached" && x.number == 17_043)
    );
    assert_eq!(
        f.vault
            .item_security(a.clone())
            .unwrap()
            .unwrap()
            .breach_count,
        Some(17_043)
    );
    f.vault.clear_breach_results();

    let s = password_strength("violin-maple-orbit-cactus-ember".into());
    assert_eq!((s.score, s.warning), (4, None));
    assert_eq!(
        password_strength("password".into()).warning.as_deref(),
        Some("top10")
    );
    assert_eq!(security_checks().len(), 8);

    f.vault.lock();
    assert!(matches!(f.vault.security_report(), Ok(None)), "锁定时丢弃");
}

#[test]
fn backup_and_restore() {
    let f = Fixture::new();
    let dir = f.dir.join("backups").to_string_lossy().into_owned();
    assert!(auto_backup_due(dir.clone()));
    assert!(list_backups(dir.clone()).is_empty());
    let first = f.vault.create_backup(dir.clone(), "auto".into()).unwrap();
    assert_eq!(first.kind, "auto");
    assert!(!auto_backup_due(dir.clone()));
    assert!(matches!(
        f.vault.create_backup(dir.clone(), "restore".into()),
        Err(KeevoError::InvalidInput { .. })
    ));
    f.vault.check_backup(first.path.clone()).unwrap();

    let later = f.login("备份之后");
    _ = f.vault.search(String::new()).unwrap();
    let safety = f
        .vault
        .restore_backup(first.path.clone(), dir.clone())
        .unwrap();
    assert_eq!(safety.kind, "restore");
    assert!(
        matches!(f.vault.items(), Err(KeevoError::Locked)),
        "恢复后锁定"
    );
    f.vault.unlock("pw".into(), f.secret_key.clone()).unwrap();
    assert!(f.vault.items().unwrap().iter().all(|i| i.id != later));
    assert_eq!(list_backups(dir.clone()).len(), 2);
    assert_eq!(prune_backups(dir.clone(), 1).unwrap(), 1);

    let junk = f.dir.join("junk.keevo-backup");
    std::fs::write(&junk, b"junk").unwrap();
    let junk = junk.to_string_lossy().into_owned();
    assert!(
        matches!(f.vault.check_backup(junk.clone()), Err(KeevoError::Backup { code }) if code == "not_backup")
    );
    assert!(matches!(
        f.vault.restore_backup(junk, dir.clone()),
        Err(KeevoError::Backup { .. })
    ));
    assert!(f.vault.items().is_ok(), "无效的备份不改变任何东西");

    // 另一个账户的备份
    let other = Fixture::new();
    let theirs = other
        .vault
        .create_backup(dir.clone(), "manual".into())
        .unwrap();
    assert!(
        matches!(f.vault.check_backup(theirs.path), Err(KeevoError::Backup { code }) if code == "other_account")
    );
}

#[test]
fn import_and_export() {
    let f = Fixture::new();
    let sample = |name: &str| {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../keevo-core/src/import/testdata")
            .join(name)
            .to_string_lossy()
            .into_owned()
    };
    assert!(import_sources().contains(&"1password".to_owned()));
    assert!(matches!(
        f.vault.prepare_import(sample("bitwarden-encrypted.json"), "bitwarden".into(), None),
        Err(KeevoError::Import { code }) if code == "password_required"
    ));
    let preview = f
        .vault
        .prepare_import(
            sample("bitwarden-encrypted.json"),
            "bitwarden".into(),
            Some("correct horse battery".into()),
        )
        .unwrap();
    assert_eq!((preview.total, preview.duplicates), (6, 0));
    assert!(preview.groups.contains(&ImportGroup {
        item_type: "secure_note".into(),
        original: Some("credit_card".into()),
        count: 1
    }));
    let result = f
        .vault
        .commit_import(f.vault_id.clone(), Some("导入 · Bitwarden".into()))
        .unwrap();
    assert_eq!(result.item_ids.len(), 6);
    assert!(
        f.vault.commit_import(f.vault_id.clone(), None).is_err(),
        "只能写入一次"
    );
    assert_eq!(f.vault.items().unwrap().len(), 6);

    // 再导入同一个文件：两个登录重复
    let again = f
        .vault
        .prepare_import(sample("bitwarden.json"), "bitwarden".into(), None)
        .unwrap();
    assert_eq!((again.total, again.duplicates), (4, 2));
    f.vault.cancel_import();

    // 明文导出要求刚刚重新验证过，且只能用一次
    let out = f.dir.join("out.csv").to_string_lossy().into_owned();
    assert!(matches!(
        f.vault.export_vault(out.clone(), "csv".into(), None, None),
        Err(KeevoError::InvalidInput { message }) if message == "reverify"
    ));
    // 夹具没有本机密钥，无法走主密码验证；这里直接记下"刚刚验证过"（reverify 成功时做的就是这件事）
    f.vault.note_reverified();
    assert_eq!(
        f.vault
            .export_vault(out.clone(), "csv".into(), None, None)
            .unwrap(),
        2,
        "CSV 只有登录"
    );
    assert!(
        f.vault
            .export_vault(out.clone(), "csv".into(), None, None)
            .is_err()
    );
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    // 加密导出不需要重新验证；再导入另一个账户
    let enc = f
        .dir
        .join("all.keevo-export")
        .to_string_lossy()
        .into_owned();
    assert_eq!(
        f.vault
            .export_vault(
                enc.clone(),
                "keevo".into(),
                None,
                Some("export password".into())
            )
            .unwrap(),
        6
    );
    assert!(is_keevo_export(enc.clone()));
    let other = Fixture::new();
    let preview = other
        .vault
        .prepare_import(enc, "keevo".into(), Some("export password".into()))
        .unwrap();
    assert_eq!(preview.total, 6);
    other
        .vault
        .commit_import(other.vault_id.clone(), None)
        .unwrap();
    assert_eq!(other.vault.items().unwrap().len(), 6);

    // 撤销：移到最近删除
    assert_eq!(f.vault.undo_import(result.item_ids.clone()).unwrap(), 6);
    assert!(f.vault.items().unwrap().iter().all(|i| i.trashed));
}

#[test]
fn attachments() {
    let f = Fixture::new();
    let item = f.login("带附件");
    let src = f.dir.join("ca-certificate.pem");
    let content = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".repeat(2000);
    std::fs::write(&src, &content).unwrap();
    let entry = f
        .vault
        .add_attachment(item.clone(), src.to_string_lossy().into_owned())
        .unwrap();
    assert_eq!(entry.name, "ca-certificate.pem");
    assert_eq!(entry.size, u64::try_from(content.len()).unwrap());
    let detail = f.vault.item(item.clone()).unwrap();
    let field = detail
        .fields
        .iter()
        .find(|x| x.kind == "attachment")
        .unwrap();
    assert_eq!(field.attachment.as_ref().unwrap(), &entry);

    let out = f.dir.join("saved.pem");
    f.vault
        .save_attachment(
            item.clone(),
            entry.id.clone(),
            out.to_string_lossy().into_owned(),
        )
        .unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), content);
    let preview_dir = f.dir.join("preview");
    let preview = f
        .vault
        .preview_attachment(
            item.clone(),
            entry.id.clone(),
            preview_dir.to_string_lossy().into_owned(),
            "../escape.pem".into(),
        )
        .unwrap();
    assert!(
        preview.starts_with(&*preview_dir.to_string_lossy()),
        "文件名中的路径被去掉"
    );
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&preview_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    // 超过 50 MB：读取前就拒绝
    let big = f.dir.join("big.bin");
    std::fs::File::create(&big)
        .unwrap()
        .set_len(50 * 1024 * 1024 + 1)
        .unwrap();
    assert!(matches!(
        f.vault.add_attachment(item.clone(), big.to_string_lossy().into_owned()),
        Err(KeevoError::Attachment { code }) if code == "too_large"
    ));
    assert!(matches!(
        f.vault.add_attachment(item, f.dir.to_string_lossy().into_owned()),
        Err(KeevoError::Attachment { code }) if code == "unreadable"
    ));
}
