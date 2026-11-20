//! 第五轮预审（2026-11-20，由 Claude 子代理完成，`docs/reviews/2026-11-20-pre-review.md`）的反例测试。
//! 每个测试断言"应当成立"的行为：在修复之前的实现上失败，证实了对应的发现；修复之后作为回归测试。
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::print_stdout)]

use std::path::{Path, PathBuf};

use keevo_crypto::{Id128, KdfParams};
use keevo_format::{FieldData, FieldKind, ItemType, Purpose, RecordKey, RecordValue, SecretString};

use crate::import::{self, Source};
use crate::{Edit, NewField, Vault};

struct Temp {
    dir: PathBuf,
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn setup() -> (Temp, Vault, keevo_crypto::AccountSecretKey) {
    let dir = std::env::temp_dir().join(format!("keevo-r5-{}", Id128::random().unwrap().to_hex()));
    std::fs::create_dir_all(&dir).unwrap();
    let params = KdfParams::new(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1, [7; 16]).unwrap();
    let (v, sk) = Vault::create(&dir.join("vault.sqlite"), "pw", params).unwrap();
    (Temp { dir }, v, sk)
}

fn exec(path: &Path, sql: &str) {
    let c = rusqlite::Connection::open(path).unwrap();
    c.execute_batch(sql).unwrap();
}

// ---------------------------------------------------------------- A1：块长度上限

/// crypto.md §8.5 要求在读入内存之前按单列检查长度。一块的合法信封至多 42 + Padmé(4 + 65536) + 16 = 67642 字节，
/// 但存储层用通用的 MAX_ENVELOPE_LEN（17 MB）检查，800 块最坏可以在认证前读入约 13.8 GB。
#[test]
fn r5_oversized_chunk_rejected_before_read() {
    let (_t, mut v, _) = setup();
    let vault_id = v.vaults().unwrap()[0].id;
    let item = v
        .create_item(vault_id, ItemType::SecureNote, "x", vec![])
        .unwrap();
    let r = v.add_attachment(item, "a.bin", &[1u8; 10], 1).unwrap();
    v.store_for_tests()
        .execute_for_tests(&format!(
            "UPDATE attachment_chunk SET ct = zeroblob(4194304) WHERE attachment_id = x'{}'",
            r.id.to_hex()
        ))
        .unwrap();
    let res = v.store_for_tests().attachment(&r.id);
    println!(
        "r5: store.attachment() 对 4 MiB 的块返回 {:?}（块数 {}）",
        res.as_ref().map(|_| "Ok"),
        res.as_ref()
            .map_or(0, |x| x.as_ref().map_or(0, |(_, c)| c.len()))
    );
    assert!(
        res.is_err(),
        "超过一块信封上限（67642 字节）的块应在读入前被拒绝"
    );
}

// ---------------------------------------------------------------- A2：回收

fn attachment_ids_in(v: &Vault, item: Id128) -> Vec<Id128> {
    v.item(item)
        .unwrap()
        .doc
        .records
        .values()
        .filter_map(|r| match &r.value {
            Some(RecordValue::Field(f)) => match &f.data {
                FieldData::Attachment(a) => Some(a.id),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// 重建（revisions.md §7.1）包含一次永久删除，crypto.md §8.9 规定"条目永久删除时删除全部附件"；
/// 实现把附件引用复制进新条目（读不出来），旧条目的附件内容永远不再被回收。
#[test]
fn r5_rebuild_leaves_attachment_content() {
    let (_t, mut v, _) = setup();
    let vault_id = v.vaults().unwrap()[0].id;
    let old = v
        .create_item(vault_id, ItemType::SecureNote, "x", vec![])
        .unwrap();
    let r = v
        .add_attachment(old, "id_ed25519", b"-----BEGIN OPENSSH PRIVATE KEY-----", 1)
        .unwrap();
    let new = v.rebuild_item(old, &[]).unwrap().item_id;
    let refs = attachment_ids_in(&v, new);
    let residue = v.store_for_tests().attachments_of(&old).unwrap();
    println!(
        "r5: 新条目中的附件引用 {:?}；读取 = {:?}；旧条目残留的附件 {}",
        refs.iter().map(Id128::to_hex).collect::<Vec<_>>(),
        v.attachment_data(new, r.id).err(),
        residue.len()
    );
    assert!(
        residue.is_empty(),
        "重建永久删除了旧条目，其附件内容应被删除"
    );
    // 附件复制为新条目的新附件，内容不变
    assert_eq!(refs.len(), 1);
    assert_ne!(refs[0], r.id, "复制品是新的附件");
    assert_eq!(
        v.attachment_data(new, refs[0]).unwrap().as_slice(),
        b"-----BEGIN OPENSSH PRIVATE KEY-----"
    );
}

/// 永久删除先写墓碑、再逐个删除附件，不在一个事务中：两步之间失败（崩溃、断电、磁盘满）时，
/// 条目已删除而附件内容永远留在数据库与之后的每份备份中——之后没有任何路径会回收它。
#[test]
fn r5_failed_purge_leaves_attachments_forever() {
    let (_t, mut v, _) = setup();
    let vault_id = v.vaults().unwrap()[0].id;
    let item = v
        .create_item(vault_id, ItemType::SecureNote, "x", vec![])
        .unwrap();
    v.add_attachment(item, "secret.txt", b"top secret", 1)
        .unwrap();
    // 故障注入：第二步失败
    v.store_for_tests()
        .execute_for_tests(
            "CREATE TRIGGER r5_fail BEFORE DELETE ON attachment_chunk BEGIN SELECT RAISE(ABORT, 'r5'); END;",
        )
        .unwrap();
    let first = v.purge_item(item);
    v.store_for_tests()
        .execute_for_tests("DROP TRIGGER r5_fail;")
        .unwrap();
    // 再试一次也无济于事：条目已不存在
    let second = v.purge_item(item);
    let gone = v.item(item).is_err();
    let residue = v.store_for_tests().attachments_of(&item).unwrap().len();
    println!("r5: 第一次 {first:?}，第二次 {second:?}；条目已删除 = {gone}；残留附件 {residue}");
    assert!(
        !gone || residue == 0,
        "要么永久删除整体失败，要么附件随之删除，不应留下无法回收的附件"
    );
}

// ---------------------------------------------------------------- B1：恢复

/// 恢复用 SQLite 在线备份接口逐页复制，备份文件中的 schema 对象（触发器、视图、索引）原样进入当前数据库。
/// 能改写备份文件（例如放在同步盘中的备份文件夹）而没有任何密钥的人，可以让此后的每次编辑静默消失。
#[test]
fn r5_restore_rejects_foreign_schema_objects() {
    let (t, mut v, sk) = setup();
    let vault_id = v.vaults().unwrap()[0].id;
    let item = v
        .create_item(vault_id, ItemType::SecureNote, "备份前", vec![])
        .unwrap();
    let backup = t.dir.join("keevo-20261120-000000-auto.keevo-backup");
    v.backup_to(&backup).unwrap();
    exec(
        &backup,
        "CREATE TRIGGER r5_evil AFTER INSERT ON head BEGIN DELETE FROM head WHERE rev_id = NEW.rev_id; END;",
    );
    let restored =
        crate::backup::restore(&mut v, &backup, &t.dir.join("backups"), 1_795_105_920_000);
    println!(
        "r5: 恢复被篡改的备份：{:?}",
        restored.as_ref().map(|_| "Ok")
    );
    if restored.is_ok() {
        v.unlock("pw", &sk).unwrap();
        let edit = v.update_item(item, vec![Edit::SetTitle("编辑之后".into())]);
        let after = v.item(item).map(|i| i.doc.overview().title);
        let created = v.create_item(vault_id, ItemType::SecureNote, "新条目", vec![]);
        let listed = v.items().unwrap().len();
        println!(
            "r5: 编辑返回 {:?}，之后读取条目 = {:?}；新建返回 {:?}，列表中的条目数 = {listed}",
            edit.as_ref().map(|()| "Ok"),
            after,
            created.as_ref().map(|_| "Ok")
        );
    }
    assert!(
        restored.is_err(),
        "带有非 Keevo schema 对象（触发器）的备份应被拒绝"
    );
}

/// 恢复分两步：在线备份接口替换整个数据库（提交），再在另一个事务中写回恢复前的 meta 与 local_record。
/// 第二步失败（这里用备份中的触发器注入；崩溃、断电、磁盘满同理）时，数据库停在"备份内容 + 备份中的本机状态"：
/// 已撤销的配对重新生效，恢复前新增的配对丢失。与 store 文档"替换失败时数据库保持原样"、sync.md §2 不符。
#[test]
fn r5_failed_restore_keeps_revoked_pairing_revoked() {
    let (t, mut v, sk) = setup();
    v.put_local_record("pairing", b"pk-old", br#"{"name":"old"}"#)
        .unwrap();
    let backup = t.dir.join("keevo-20261120-000000-auto.keevo-backup");
    v.backup_to(&backup).unwrap();
    // 备份之后：撤销旧配对，新增一个配对
    v.delete_local_record("pairing", b"pk-old").unwrap();
    v.put_local_record("pairing", b"pk-new", br#"{"name":"new"}"#)
        .unwrap();
    exec(
        &backup,
        "CREATE TRIGGER r5_fail BEFORE INSERT ON local_record BEGIN SELECT RAISE(ABORT, 'r5'); END;",
    );
    let restored =
        crate::backup::restore(&mut v, &backup, &t.dir.join("backups"), 1_795_105_920_000);
    v.unlock("pw", &sk).unwrap();
    let (records, _) = v.local_records("pairing").unwrap();
    let ids: Vec<String> = records
        .iter()
        .map(|(id, _)| String::from_utf8_lossy(id).into_owned())
        .collect();
    println!(
        "r5: 恢复返回 {:?}；之后的配对记录 = {ids:?}",
        restored.as_ref().map(|_| "Ok")
    );
    assert!(
        !ids.iter().any(|i| i == "pk-old"),
        "恢复失败时已撤销的配对不应重新生效"
    );
}

/// 备份列表与清理只看文件名中的时间。文件夹中有 30 个"未来时间"的文件（同步盘中的他人写入，或曾经的时钟错误）时，
/// 每次清理都会删掉刚刚创建的真实备份，界面却显示有 30 份备份。
#[test]
fn r5_prune_keeps_newly_created_backup() {
    let (t, v, _) = setup();
    let dir = t.dir.join("backups");
    std::fs::create_dir_all(&dir).unwrap();
    for i in 0..30 {
        std::fs::write(
            dir.join(format!("keevo-20990101-0000{i:02}-auto.keevo-backup")),
            b"junk",
        )
        .unwrap();
    }
    let real =
        crate::backup::create(&v, &dir, crate::backup::Kind::Manual, 1_795_105_920_000).unwrap();
    let removed = crate::backup::prune(&dir, 30, 1_795_105_920_000).unwrap();
    println!(
        "r5: 清理删除 {removed} 份；刚创建的备份仍在 = {}",
        real.path.exists()
    );
    assert!(real.path.exists(), "刚创建的真实备份不应被清理");
}

// ---------------------------------------------------------------- I1 / E1：导入导出

fn password_of(item: &crate::import::Imported) -> Option<String> {
    item.fields.iter().find_map(|(_, f)| match &f.data {
        FieldData::Text(t) if f.purpose == Some(Purpose::Password) => Some(t.expose().to_owned()),
        _ => None,
    })
}

/// 导入时，除多行文本与 SSH 私钥外的值一律 trim：首尾带空格的密码被静默改变。
/// Keevo 自己的导出再导入（JSON 或加密文件）也是如此，product.md §5.7 承诺"字段保留"。
#[test]
fn r5_export_import_round_trip_keeps_password() {
    let (_t, mut v, _) = setup();
    let vault_id = v.vaults().unwrap()[0].id;
    let pw = "  correct horse battery  ";
    v.create_item(
        vault_id,
        ItemType::Login,
        "带空格的密码",
        vec![NewField {
            kind: FieldKind::Concealed,
            label: "密码".into(),
            purpose: Some(Purpose::Password),
            data: FieldData::Text(SecretString::new(pw.to_owned())),
        }],
    )
    .unwrap();
    let json = crate::export::export(&v, crate::export::Format::Json, None, None).unwrap();
    let back = import::parse(Source::Keevo, &json.bytes, None).unwrap();
    let got = password_of(&back.items[0]);
    println!("r5: 导出前 {pw:?}，导入后 {got:?}");
    assert_eq!(got.as_deref(), Some(pw));
}

/// export.md：导出密码"至少 10 个字符"。实现只数 Unicode 标量，不做强度评估：10 个空格或 10 个相同字母都被接受。
#[test]
fn r5_export_rejects_trivial_password() {
    let (_t, v, _) = setup();
    let spaces = crate::export::export(&v, crate::export::Format::Keevo, None, Some("          "));
    let same = crate::export::export(&v, crate::export::Format::Keevo, None, Some("aaaaaaaaaa"));
    println!(
        "r5: 10 个空格 → {:?}；aaaaaaaaaa → {:?}",
        spaces.as_ref().map(|_| "Ok"),
        same.as_ref().map(|_| "Ok")
    );
    assert!(
        spaces.is_err() && same.is_err(),
        "显然无保护作用的导出密码应被拒绝"
    );
}

/// 导入时分区与标签按名称去重用线性查找，且没有个数上限：一个条目中 n 个不同的分区名需要 O(n²) 次比较。
/// 记录 n 与耗时，倍增 n 时耗时约为 4 倍即为平方增长。断言一个只有 1 MB 的文件应在 2 秒内被处理（或被拒绝）。
#[test]
fn r5_import_sections_are_bounded() {
    let make = |n: usize| -> Vec<u8> {
        let names: Vec<String> = (0..n).map(|i| format!("\"s{i}\"")).collect();
        format!(
            r#"{{"format":"keevo-export","version":1,"exported_at":"x","vaults":[{{"name":"v","items":[{{"type":"secure_note","title":"t","sections":[{}],"fields":[]}}]}}]}}"#,
            names.join(",")
        )
        .into_bytes()
    };
    let mut last = 0.0;
    let mut sizes = vec![10_000usize, 20_000, 40_000];
    if let Some(extra) = std::env::var("R5_SECTIONS")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        sizes.push(extra);
    }
    for n in sizes {
        let data = make(n);
        let start = std::time::Instant::now();
        let r = import::parse(Source::Keevo, &data, None);
        let secs = start.elapsed().as_secs_f64();
        println!(
            "r5: {n} 个分区（文件 {} KiB）→ {:?}，{secs:.2} s",
            data.len() / 1024,
            r.as_ref().map(|p| p.items[0].sections.len())
        );
        last = secs;
    }
    let data = make(100_000);
    println!("r5: 100000 个分区的文件只有 {} KiB", data.len() / 1024);
    assert!(last < 2.0, "40000 个分区（约 0.3 MB）的解析不应接近秒级");
}

/// 1PUX：zip 解压上限 256 MiB 只限制了解压后的字节数，`serde_json::Value` 的树每个数字约 32 字节以上。
/// 修复后（第五轮预审 K10）：解析之前数节点，超过 `MAX_JSON_NODES` 即拒绝，不建立解析树。
#[test]
fn r5_onepux_memory_amplification() {
    let n = crate::import::MAX_JSON_NODES + 1;
    let mut json = String::with_capacity(n * 2 + 32);
    json.push_str("{\"accounts\":[");
    for _ in 0..n {
        json.push_str("0,");
    }
    json.push_str("0]}");
    let zip = crate::import::zip::write_for_tests(&[("export.data", json.as_bytes())]);
    drop(json);
    let start = std::time::Instant::now();
    let r = import::parse(Source::OnePassword, &zip, None);
    println!(
        "r5: 1PUX 文件 {} KiB → {:?}，{:.2} s",
        zip.len() / 1024,
        r.as_ref().err(),
        start.elapsed().as_secs_f64()
    );
    assert_eq!(r.err(), Some(crate::import::ImportError::TooLarge));
    // 字符串中的分隔符不计数
    let quoted = format!(
        "{{\"accounts\":[\"{}\"]}}",
        ",".repeat(crate::import::MAX_JSON_NODES + 1)
    );
    assert!(crate::import::check_json_nodes(quoted.as_bytes()).is_ok());
}

// ---------------------------------------------------------------- V1

/// vault-format §2.5：v2 读取方对一个 `"v":1` 文档（kind = text、data = attachment）返回 value_kind_mismatch，
/// 而 1.0 的 v1 读取方返回 malformed（未知的 data 变体属于结构错误）。同一 v1 文档的错误码随读取方版本变化。
#[test]
fn r5_v1_document_error_code_unchanged() {
    let doc = r#"{"v":1,"type":"secure_note","records":{"field:00000000000000000000000000000001":{"hlc":"0000000000000001","rev":"00000000000000000000000000000002","val":{"field":{"order":"0","kind":"text","label":"x","data":{"attachment":{"id":"00000000000000000000000000000003","name":"a","size":1,"added":1}}}}}}}"#;
    let r = keevo_format::ItemDoc::decode(doc.as_bytes());
    println!(
        "r5: v1 文档（text + attachment 数据）→ {:?}",
        r.as_ref().err()
    );
    assert!(
        matches!(r, Err(keevo_format::FormatError::Malformed(_))),
        "v1 文档的错误码应与 1.0 的 v1 读取方一致（malformed）"
    );
}

#[allow(dead_code)]
fn _unused(_: RecordKey) {}
