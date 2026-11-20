//! 第五轮正式评审（2026-11-20，外部模型，`docs/reviews/2026-11-20-model-review-round5.md`）的反例测试。
//! 每个测试断言"应当成立"的行为：在修复之前的实现上失败，证实了对应的发现；修复之后作为回归测试。
//! 与评审补丁的差异见处理记录（L5、L8 按处理记录选择的语义调整了断言）。`review5c_`、`review5d_`、`review5e_`
//! 开头的测试来自第五轮的确认评审（`docs/reviews/2026-11-20-model-review-round5-confirmation*.md`）；`review5f_`
//! 开头的在 `strength.rs` 的测试模块中。
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::print_stderr)]

use crate::{Edit, NewField, Vault};
use keevo_crypto::{AccountSecretKey, Id128, KdfParams};
use keevo_format::{FieldData, FieldKind, ItemType, Purpose, RecordKey, RecordValue};

struct Temp(std::path::PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn fixture() -> (Temp, Vault, AccountSecretKey) {
    let dir = std::env::temp_dir().join(format!(
        "keevo-review5-{}",
        Id128::random().unwrap().to_hex()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let params = KdfParams::new(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1, [17; 16]).unwrap();
    let (v, sk) = Vault::create(&dir.join("vault.sqlite"), "pw", params).unwrap();
    (Temp(dir), v, sk)
}
fn item(v: &mut Vault, kind: ItemType) -> Id128 {
    v.create_item(v.vaults().unwrap()[0].id, kind, "review fixture", vec![])
        .unwrap()
}

#[test]
fn review5e_p1_single_insertion_in_repeated_common_password_is_cheap() {
    let mut failures = Vec::new();
    for base in ["password", "password123", "qwerty123456", "abc123"] {
        let base_guesses = crate::strength::estimate(base).guesses;
        for repeats in [10_u32, 20, 50] {
            let plain = base.repeat(usize::try_from(repeats).unwrap());
            for pos in 0..=base.len() {
                let mut password = plain.clone();
                password.insert(pos, '!');
                let strength = crate::export::export_password_strength(&password);
                let allowed = crate::export::export_password_ok(&password);
                // 枚举基础口令、重复次数、插入位置及 95 种可打印字符。
                let bound = base_guesses
                    * f64::from(repeats)
                    * f64::from(u32::try_from(password.len()).unwrap())
                    * 95.0;
                if bound < 1e10 && allowed {
                    assert_eq!(strength.score, 4);
                    failures.push((base, repeats, pos, bound, strength.guesses));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "一次插入的低成本变体不应达到 4 分：(基础、重复、位置、模型代价、实际估计) {failures:?}"
    );
}

#[test]
fn review5e_c1_random_long_passwords_remain_strong() {
    let mut slowest = std::time::Duration::ZERO;
    for len in [65, 96, 256, 1024] {
        for alphabet in [10_u8, 95] {
            for _ in 0..3 {
                let mut password = String::new();
                while password.len() < len {
                    for &b in Id128::random().unwrap().as_bytes() {
                        // 拒绝采样，均匀选取数字或可打印 ASCII。
                        if u16::from(b) < 256 / u16::from(alphabet) * u16::from(alphabet) {
                            let start = if alphabet == 10 { b'0' } else { b' ' };
                            password.push(char::from(start + b % alphabet));
                            if password.len() == len {
                                break;
                            }
                        }
                    }
                }
                let started = std::time::Instant::now();
                let strength = crate::strength::estimate(&password);
                slowest = slowest.max(started.elapsed());
                assert_eq!(
                    strength.score, 4,
                    "len={len}, alphabet={alphabet}, {password:?}: {strength:?}"
                );
            }
        }
    }
    eprintln!("24 CSPRNG samples; slowest={slowest:?}");
}

#[test]
fn review5e_p2_adversarial_inputs_finish_within_five_seconds() {
    let unique: String = (0..1024)
        .map(|i| char::from_u32(0x4e00 + i).unwrap())
        .collect();
    let mut cases = vec![
        ("distinct_unicode", unique),
        (
            "near_periodic",
            (0..5000)
                .map(|i| if i % 37 == 0 { 'b' } else { 'a' })
                .collect(),
        ),
        (
            "almost_unary",
            format!(
                "{}b{}c{}d{}e",
                "a".repeat(251),
                "a".repeat(251),
                "a".repeat(251),
                "a".repeat(251)
            ),
        ),
    ];
    // 64 字符窗口含大量 l33t 替换，且窗与窗间无固定周期。
    let symbols = b"4@8({[<3691!|70$5+%2";
    let mut l33t = String::new();
    for i in 0_u32..32 {
        for b in keevo_crypto::sha256(&i.to_le_bytes()) {
            l33t.push(char::from(symbols[usize::from(b) % symbols.len()]));
        }
    }
    cases.push(("l33t_dense", l33t));
    let _ = crate::strength::estimate("warm up dictionaries");
    for (label, password) in cases {
        let started = std::time::Instant::now();
        let strength = crate::strength::estimate(&password);
        let elapsed = started.elapsed();
        eprintln!("{label}: {elapsed:?}, score={}", strength.score);
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "{label}: {elapsed:?}"
        );
        assert!(strength.guesses.is_finite());
    }
}

#[test]
fn review5d_n1_near_repetition_does_not_reach_export_threshold() {
    let mut changed = "password123".repeat(20);
    changed.replace_range(110..111, "!");
    let cases = [
        ("suffix", format!("{}!", "password123".repeat(10))),
        (
            "insertion",
            format!("{}!{}", "password123".repeat(5), "password123".repeat(5)),
        ),
        ("substitution", changed),
        (
            "alternating_blocks",
            format!("{}{}", "password123".repeat(3), "qwerty123456".repeat(3)).repeat(3),
        ),
        ("alternating_words", "password123qwerty123456".repeat(10)),
    ];
    let mut accepted = Vec::new();
    for (name, password) in cases {
        let strength = crate::export::export_password_strength(&password);
        let allowed = crate::export::export_password_ok(&password);
        eprintln!(
            "{name}: len={}, {strength:?}, export={allowed}",
            password.len()
        );
        if allowed {
            accepted.push((name, strength));
        }
    }
    assert!(
        accepted.is_empty(),
        "常见口令的廉价重复变体不应达到导出门槛：{accepted:?}"
    );
}

#[test]
fn review5d_n2_own_export_preserves_structured_field_purpose() {
    let (_t, mut v, _) = fixture();
    let vault_id = v.vaults().unwrap()[0].id;
    v.create_item(
        vault_id,
        ItemType::SecureNote,
        "structured fields",
        vec![
            NewField {
                kind: FieldKind::KvList,
                label: "environment".into(),
                purpose: Some(Purpose::Notes),
                data: FieldData::Kv(vec![keevo_format::KvEntry {
                    key: "TOKEN".into(),
                    value: "example".into(),
                    concealed: true,
                }]),
            },
            NewField {
                kind: FieldKind::RecoveryCodes,
                label: "recovery".into(),
                purpose: Some(Purpose::Notes),
                data: FieldData::Codes(vec![keevo_format::CodeEntry {
                    code: "1234-5678".into(),
                    used: false,
                }]),
            },
        ],
    )
    .unwrap();
    let exported = crate::export::export(&v, crate::export::Format::Json, None, None).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&exported.bytes).unwrap();
    for f in json["vaults"][0]["items"][0]["fields"].as_array().unwrap() {
        assert_eq!(f["purpose"], "notes");
    }
    let parsed = crate::import::parse(crate::import::Source::Keevo, &exported.bytes, None).unwrap();
    let purposes: Vec<_> = parsed.items[0]
        .fields
        .iter()
        .map(|(_, f)| f.purpose)
        .collect();
    assert_eq!(
        purposes,
        vec![Some(Purpose::Notes), Some(Purpose::Notes)],
        "原样导入应保留合法结构化字段的 purpose"
    );
}

#[test]
fn review5c_m1_repetition_does_not_reach_export_threshold() {
    let mut accepted = Vec::new();
    for base in [
        "password",
        "password123",
        "password1234567890",
        "qwerty123456",
        "abc123!",
        "letmein123!",
    ] {
        let pw = base.repeat(1024 / base.len());
        if crate::export::export_password_ok(&pw) {
            accepted.push((base, crate::strength::estimate(&pw)));
        }
    }
    assert!(
        accepted.is_empty(),
        "重复常见弱口令不应达到导出门槛：{accepted:?}"
    );
}

#[test]
fn review5c_m2_own_export_preserves_empty_title() {
    let (_t, mut v, _) = fixture();
    let vault_id = v.vaults().unwrap()[0].id;
    let id = v
        .create_item(vault_id, ItemType::SecureNote, "", vec![])
        .unwrap();
    assert_eq!(v.item(id).unwrap().doc.overview().title, "");
    let exported = crate::export::export(&v, crate::export::Format::Json, None, None).unwrap();
    let parsed = crate::import::parse(crate::import::Source::Keevo, &exported.bytes, None).unwrap();
    assert_eq!(parsed.items[0].title, "", "原样模式不能补写合法的空标题");
}

#[test]
fn review5c_m6_gc_continues_after_an_unreadable_item() {
    let (_t, mut v, sk) = fixture();
    let mut ids = [
        item(&mut v, ItemType::SecureNote),
        item(&mut v, ItemType::SecureNote),
    ];
    ids.sort_by_key(|id| *id.as_bytes());
    let blocked = ids[0];
    let healthy = ids[1];
    v.add_attachment(blocked, "retained.txt", b"retain", 1)
        .unwrap();
    // 使损坏只影响历史：当前头仍能读取。
    v.update_item(blocked, vec![Edit::SetTitle("current readable".into())])
        .unwrap();
    let attachment = v
        .add_attachment(healthy, "garbage.txt", b"garbage", 1)
        .unwrap();
    let field = v
        .item(healthy)
        .unwrap()
        .doc
        .records
        .iter()
        .find_map(|(k, r)| match (k, &r.value) {
            (RecordKey::Field(id), Some(RecordValue::Field(f)))
                if f.kind == FieldKind::Attachment =>
            {
                Some(*id)
            }
            _ => None,
        })
        .unwrap();
    v.update_item(healthy, vec![Edit::RemoveField(field)])
        .unwrap();
    // 夹具模拟历史清理已提交，进程在附件回收前中断；另一条目的旧密文损坏。
    v.store_for_tests().execute_for_tests(&format!(
        "UPDATE revision SET pruned=1, wrapped_key_ct=NULL, overview_ct=NULL, details_ct=NULL WHERE object_id=x'{}' AND rev_id NOT IN (SELECT rev_id FROM head); UPDATE revision SET details_ct=x'00' WHERE object_id=x'{}' AND rev_id NOT IN (SELECT rev_id FROM head);",
        healthy.to_hex(), blocked.to_hex(),
    )).unwrap();
    assert!(v.item(blocked).is_ok());
    assert!(v.item(healthy).is_ok());
    for _ in 0..2 {
        v.lock();
        v.unlock("pw", &sk).unwrap();
    }
    assert!(
        v.store_for_tests()
            .attachment(&attachment.id)
            .unwrap()
            .is_none(),
        "一个条目的历史损坏，不能阻止后续健康条目回收无引用附件"
    );
}

#[test]
fn review5_l1_repeated_tail_is_not_export_entropy() {
    let pw = "a".repeat(80);
    assert!(
        !crate::export::export_password_ok(&pw),
        "80 个相同字符应拒绝，不能把第 65 字符以后的重复当作暴力枚举熵"
    );
}

#[test]
fn review5_l1_export_strength_uses_kdf_normalization() {
    use unicode_normalization::UnicodeNormalization;
    // 兼容字符交替拼写，NFKD 后只是常见口令 password123。
    let normalized = "password123";
    let pw = "ｐaｓsｗoｒd１２３";
    assert_eq!(pw.nfkd().collect::<String>(), normalized);
    assert!(!crate::export::export_password_ok(normalized));
    assert!(
        !crate::export::export_password_ok(pw),
        "强度应按实际进入 KDF 的 NFKD 口令判断"
    );
}

#[test]
fn review5_l3_restore_does_not_trust_revision_sequence() {
    let (t, mut v, sk) = fixture();
    let id = item(&mut v, ItemType::SecureNote);
    v.update_item(id, vec![Edit::SetTitle("latest fixture".into())])
        .unwrap();
    let backup = t.0.join("reverse.keevo-backup");
    v.backup_to(&backup).unwrap();
    rusqlite::Connection::open(&backup)
        .unwrap()
        .execute("UPDATE revision SET seq = -seq", [])
        .unwrap();
    if v.restore_from(&backup).is_err() {
        return;
    } // 可以拒绝；接受则必须按 DAG 重建顺序。
    v.unlock("pw", &sk).unwrap();
    assert!(
        v.item(id).is_ok(),
        "未改变任何密文或父关系，仅改变未认证 seq，不得恢复成功后令条目不可读"
    );
}

#[test]
fn review5_l4_purge_revokes_policy_atomically() {
    use crate::ssh_agent::AgentPolicy;
    let (t, mut v, sk) = fixture();
    let key = item(&mut v, ItemType::SshKey);
    v.set_ssh_agent_policy(key, Some(AgentPolicy::Unlocked))
        .unwrap();
    let backup = t.0.join("before.keevo-backup");
    v.backup_to(&backup).unwrap();
    // 仅故障注入：模拟删除本机授权的语句失败，不是把触发器交给恢复。
    v.store_for_tests().execute_for_tests("CREATE TRIGGER review5_fail BEFORE DELETE ON local_record BEGIN SELECT RAISE(ABORT, 'injected failure'); END;").unwrap();
    let result = v.purge_item(key);
    v.store_for_tests()
        .execute_for_tests("DROP TRIGGER review5_fail")
        .unwrap();
    if result.is_err() {
        return;
    } // 允许整个操作拒绝，不能成功后保留授权。
    v.restore_from(&backup).unwrap();
    v.unlock("pw", &sk).unwrap();
    assert!(
        !v.ssh_agent_policies().unwrap().contains_key(&key),
        "永久删除成功后，恢复旧备份不得复活自动签名授权"
    );
}

#[test]
fn review5_l4_rebuild_revokes_old_policy() {
    use crate::ssh_agent::AgentPolicy;
    let (t, mut v, sk) = fixture();
    let key = item(&mut v, ItemType::SshKey);
    v.set_ssh_agent_policy(key, Some(AgentPolicy::Unlocked))
        .unwrap();
    let backup = t.0.join("before.keevo-backup");
    v.backup_to(&backup).unwrap();
    v.rebuild_item(key, &[]).unwrap();
    v.restore_from(&backup).unwrap();
    v.unlock("pw", &sk).unwrap();
    assert!(
        !v.ssh_agent_policies().unwrap().contains_key(&key),
        "重建中的永久删除也应删除旧条目的授权"
    );
}

#[test]
fn review5_l5_attachment_gc_retries_after_failure() {
    let (t, mut v, sk) = fixture();
    let id = item(&mut v, ItemType::SecureNote);
    let a = v
        .add_attachment(id, "fixture.txt", b"review fixture", 1)
        .unwrap();
    let field = v
        .item(id)
        .unwrap()
        .doc
        .records
        .iter()
        .find_map(|(k, r)| match (k, &r.value) {
            (RecordKey::Field(id), Some(RecordValue::Field(f)))
                if matches!(f.data, FieldData::Attachment(_)) =>
            {
                Some(*id)
            }
            _ => None,
        })
        .unwrap();
    v.update_item(id, vec![Edit::RemoveField(field)]).unwrap();
    for i in 0..22 {
        v.update_item(id, vec![Edit::SetTitle(format!("revision {i}"))])
            .unwrap();
    }
    // 将夹具的时间轴移到 91 天；最后 20 个修订刚刚写入，其余已有 91 天。
    v.store_for_tests().execute_for_tests(&format!(
        "UPDATE revision SET stored_ms = 0; UPDATE revision SET stored_ms = {} WHERE seq IN (SELECT seq FROM revision WHERE object_id = x'{}' ORDER BY seq DESC LIMIT 20);",
        91u64 * 86_400_000, id.to_hex())).unwrap();
    drop(v);
    let mut v = Vault::open(&t.0.join("vault.sqlite")).unwrap();
    v.unlock("pw", &sk).unwrap();
    v.store_for_tests().execute_for_tests("CREATE TRIGGER review5_fail BEFORE DELETE ON attachment BEGIN SELECT RAISE(ABORT, 'injected failure'); END;").unwrap();
    // 处理记录选择的语义：编辑已经提交，回收失败不让编辑报错；附件这时仍在，由之后的解锁重试回收
    v.update_item(id, vec![Edit::SetTitle("first GC".into())])
        .unwrap();
    assert!(v.store_for_tests().attachment(&a.id).unwrap().is_some());
    v.store_for_tests()
        .execute_for_tests("DROP TRIGGER review5_fail")
        .unwrap();
    for row in v.store_for_tests().history(&id).unwrap() {
        if !row.pruned && !row.deleted {
            let doc = v.revision_doc(id, row.rev_id).unwrap();
            assert!(!doc.records.values().chain(doc.concurrent.values().flatten()).any(|r| matches!(&r.value,
                Some(RecordValue::Field(f)) if matches!(&f.data, FieldData::Attachment(r) if r.id == a.id))));
        }
    }
    drop(v);
    let mut v = Vault::open(&t.0.join("vault.sqlite")).unwrap();
    v.unlock("pw", &sk).unwrap();
    v.update_item(id, vec![Edit::SetTitle("retry GC".into())])
        .unwrap();
    assert!(
        v.store_for_tests().attachment(&a.id).unwrap().is_none(),
        "已无任何内容修订引用的附件，在重开并成功编辑后应重试回收"
    );
}

#[test]
fn review5_l6_own_export_preserves_field_labels() {
    let (_t, mut v, _) = fixture();
    let label = "x".repeat(201);
    v.create_item(
        v.vaults().unwrap()[0].id,
        ItemType::SecureNote,
        "fixture",
        vec![NewField {
            kind: FieldKind::Concealed,
            label: label.clone(),
            purpose: None,
            data: FieldData::Text("fixture secret".into()),
        }],
    )
    .unwrap();
    let exported = crate::export::export(&v, crate::export::Format::Json, None, None).unwrap();
    let imported =
        crate::import::parse(crate::import::Source::Keevo, &exported.bytes, None).unwrap();
    assert_eq!(
        imported.items[0].fields[0].1.label, label,
        "本机合法字段经自有格式往返，不应静默截断标签"
    );
}

#[test]
fn review5_l6_csv_rejects_data_after_closing_quote() {
    let result = crate::import::parse(
        crate::import::Source::Chrome,
        b"url,username,password\nhttps://example.test,user,\"abc\"def\n",
        None,
    );
    assert!(
        result.is_err(),
        "非法 CSV 应拒绝，不能把两个片段静默拼成新密码 abcdef"
    );
}

#[test]
fn review5_l6_export_section_indices_preserve_distinct_sections() {
    let json = br#"{"format":"keevo-export","version":1,"exported_at":"2026-11-20T00:00:00Z","vaults":[{"name":"fixture","items":[{"type":"secure_note","title":"fixture","sections":["same","same"],"fields":[{"section":0,"kind":"text","label":"first","value":"a"},{"section":1,"kind":"text","label":"second","value":"b"}]}]}]}"#;
    let parsed = crate::import::parse(crate::import::Source::Keevo, json, None).unwrap();
    let item = &parsed.items[0];
    assert_eq!(
        item.sections.len(),
        2,
        "sections 数组中的两个位置代表不同分区，名称相同不能合并"
    );
    assert_ne!(item.fields[0].0, item.fields[1].0);
}

#[test]
fn review5_l6_bitwarden_multiline_whitespace_is_preserved() {
    let source = serde_json::json!({"encrypted":false,"items":[{"type":2,"name":"fixture","notes":"  fixture note \n"}]});
    let parsed = crate::import::parse(
        crate::import::Source::Bitwarden,
        &serde_json::to_vec(&source).unwrap(),
        None,
    )
    .unwrap();
    let note = parsed.items[0]
        .fields
        .iter()
        .find_map(|(_, f)| match &f.data {
            FieldData::Text(t) if f.kind == FieldKind::Multiline => Some(t.expose()),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        note, "  fixture note \n",
        "notes 进入 Builder::note 的路径也应原样保留多行文本空白"
    );
}

#[test]
fn review5_l7_changed_password_is_not_already_checked() {
    let (_t, mut v, _) = fixture();
    let id = item(&mut v, ItemType::Login);
    v.update_item(
        id,
        vec![Edit::AddField(NewField {
            kind: FieldKind::Concealed,
            label: "password".into(),
            purpose: Some(Purpose::Password),
            data: FieldData::Text("fixture-before".into()),
        })],
    )
    .unwrap();
    let mut breaches = crate::security::Breaches::default();
    for prefix in breaches.prepare(&v).unwrap() {
        assert!(breaches.record(&prefix, "00000000000000000000000000000000000:0\n"));
    }
    assert!(breaches.complete());
    v.update_item(
        id,
        vec![Edit::AddField(NewField {
            kind: FieldKind::Concealed,
            label: "new password".into(),
            purpose: Some(Purpose::Password),
            data: FieldData::Text("fixture-after".into()),
        })],
    )
    .unwrap();
    let report = crate::security::analyze(&v, Some(&breaches)).unwrap();
    assert!(
        !report.breach_checked,
        "新增或改变的密码尚未查询，不能显示全部已查完"
    );
}

#[test]
fn review5_l7_malformed_range_is_not_success() {
    let (_t, mut v, _) = fixture();
    let id = item(&mut v, ItemType::Login);
    v.update_item(
        id,
        vec![Edit::AddField(NewField {
            kind: FieldKind::Concealed,
            label: "password".into(),
            purpose: Some(Purpose::Password),
            data: FieldData::Text("fixture".into()),
        })],
    )
    .unwrap();
    let mut breaches = crate::security::Breaches::default();
    let prefixes = breaches.prepare(&v).unwrap();
    assert!(
        !breaches.record(&prefixes[0], "not-a-sha1-suffix:1\n"),
        "格式错误的非零条目不得被接受为已完成查询"
    );
}
