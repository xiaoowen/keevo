//! M1 验收（`docs/roadmap.md` §3.8）中能自动化的可靠性与安全检查：
//!
//! - **`kill -9`**：另一个进程不停地写入，在随机时刻被 SIGKILL；每次之后数据库完整，已确认写入的条目都在、都能解密。
//! - **秘密泄露检测**：保险库、WAL、备份、加密导出与附件写到磁盘的全部文件中，都找不到明文秘密。
//!
//! `kill -9` 测试较慢，默认不运行：`cargo test -p keevo-core --release --test acceptance -- --ignored`
//! （scripts/acceptance.sh）。
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::indexing_slicing
)]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use keevo_core::{
    AccountSecretKey, FieldData, FieldKind, ItemType, KdfParams, NewField, Purpose, Vault,
};

fn params() -> KdfParams {
    KdfParams::new(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1, [9; 16]).unwrap()
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "keevo-acceptance-{tag}-{}",
            keevo_core::Id128::random().unwrap().to_hex()
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

fn secret_field(label: &str, value: &str) -> NewField {
    NewField {
        kind: FieldKind::Concealed,
        label: label.into(),
        purpose: Some(Purpose::Password),
        data: FieldData::Text(value.into()),
    }
}

// ---------------------------------------------------------------------------
// kill -9
// ---------------------------------------------------------------------------

/// 子进程：打开已有的保险库，不停地新建并修改条目；每次写入提交后在标准输出打印已提交的条目数。
#[test]
#[ignore = "由 kill_nine_never_corrupts 作为子进程启动"]
fn kill_nine_writer() {
    let Ok(dir) = std::env::var("KEEVO_KILL9_DIR") else {
        return;
    };
    let dir = PathBuf::from(dir);
    let sk =
        AccountSecretKey::parse(&std::fs::read_to_string(dir.join("secret-key")).unwrap()).unwrap();
    let mut v = Vault::open(&dir.join("vault.sqlite")).unwrap();
    v.unlock("pw", &sk).unwrap();
    let vault_id = v.vaults().unwrap()[0].id;
    let mut out = std::io::stdout().lock();
    let start = v.items().unwrap().len();
    for n in 0.. {
        let id = v
            .create_item(
                vault_id,
                ItemType::Login,
                &format!("条目 {}", start + n),
                vec![secret_field("密码", &"x".repeat(n % 300 + 1))],
            )
            .unwrap();
        v.update_item(id, vec![keevo_core::Edit::AddTag(format!("tag-{}", n % 7))])
            .unwrap();
        if n % 10 == 0 {
            // 偶尔做一次备份，让 kill 也可能落在备份中间
            let _ = v.backup_to(&dir.join(format!("backup-{n}.keevo-backup")));
        }
        writeln!(out, "{}", start + n + 1).unwrap();
        out.flush().unwrap();
    }
}

#[test]
#[ignore = "较慢：scripts/acceptance.sh 中运行"]
fn kill_nine_never_corrupts() {
    let tmp = TempDir::new("kill9");
    let dir = &tmp.0;
    {
        let (_, sk) = Vault::create(&dir.join("vault.sqlite"), "pw", params()).unwrap();
        std::fs::write(dir.join("secret-key"), sk.to_display_string().as_str()).unwrap();
    }
    let sk =
        AccountSecretKey::parse(&std::fs::read_to_string(dir.join("secret-key")).unwrap()).unwrap();
    let exe = std::env::current_exe().unwrap();
    let rounds: u32 = std::env::var("KEEVO_KILL9_ROUNDS")
        .ok()
        .and_then(|r| r.parse().ok())
        .unwrap_or(25);
    let mut acknowledged = 0usize;
    for round in 0..rounds {
        let mut child = Command::new(&exe)
            .args([
                "--exact",
                "kill_nine_writer",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("KEEVO_KILL9_DIR", dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        // 读到若干次确认后，在一个随机的时刻 kill -9
        let stdout = child.stdout.take().unwrap();
        let reader = std::thread::spawn(move || {
            let mut last = 0usize;
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if let Ok(n) = line.trim().parse() {
                    last = n;
                }
            }
            last
        });
        let wait_ms = 300
            + u64::from(keevo_core::Id128::random().unwrap().as_bytes()[0]) * 4
            + u64::from(round % 5) * 7;
        std::thread::sleep(Duration::from_millis(wait_ms));
        // SAFETY 之外的方式：用 kill 命令发 SIGKILL
        let pid = child.id().to_string();
        Command::new("kill").args(["-9", &pid]).status().unwrap();
        let _ = child.wait();
        let confirmed = reader.join().unwrap();
        acknowledged = acknowledged.max(confirmed);

        // 重新打开：数据库完整，已确认的条目都在、都能解密
        let mut v = Vault::open(&dir.join("vault.sqlite")).unwrap();
        assert!(
            v.integrity_check().unwrap().is_empty(),
            "第 {round} 轮：SQLite 完整性检查失败"
        );
        v.unlock("pw", &sk).unwrap();
        let items = v.items().unwrap();
        assert!(
            items.len() >= acknowledged,
            "第 {round} 轮：已确认 {acknowledged} 个条目，只找到 {}",
            items.len()
        );
        for item in &items {
            v.item(item.id)
                .unwrap_or_else(|e| panic!("第 {round} 轮：条目无法读取：{e}"));
        }
        acknowledged = items.len();
        println!("第 {round} 轮：{} 个条目，完整", items.len());
    }
    assert!(acknowledged > 0, "写入进程没有完成任何写入");
}

// ---------------------------------------------------------------------------
// 秘密泄露检测
// ---------------------------------------------------------------------------

/// `haystack` 中是否出现 `needle`（UTF-8 或 UTF-16LE）。
fn contains_secret(haystack: &[u8], needle: &str) -> bool {
    let utf8 = needle.as_bytes();
    let utf16: Vec<u8> = needle.encode_utf16().flat_map(u16::to_le_bytes).collect();
    haystack.windows(utf8.len()).any(|w| w == utf8)
        || haystack.windows(utf16.len()).any(|w| w == utf16)
}

fn all_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            all_files(&p, out);
        } else {
            out.push(p);
        }
    }
}

#[test]
fn no_plaintext_secrets_on_disk() {
    let tmp = TempDir::new("leak");
    let dir = &tmp.0;
    // 每个秘密都是独一无二的标记，在磁盘上找到它即是泄露
    let password = "Leak-Marker-Password-7f3a9c";
    let note = "Leak-Marker-Note-41d2e8 银行卡背面";
    let totp = "JBSWY3DPEHPK3PXPLEAKMARK";
    let title = "Leak-Marker-Title-0b6e11";
    let attachment = "Leak-Marker-Attachment-c90f2a";
    let master = "Leak-Marker-Master-5e7d03";
    let (mut v, sk) = Vault::create(&dir.join("vault.sqlite"), master, params()).unwrap();
    let vault_id = v.vaults().unwrap()[0].id;
    let id = v
        .create_item(
            vault_id,
            ItemType::Login,
            title,
            vec![
                secret_field("密码", password),
                NewField {
                    kind: FieldKind::Multiline,
                    label: "备注".into(),
                    purpose: Some(Purpose::Notes),
                    data: FieldData::Text(note.into()),
                },
                NewField {
                    kind: FieldKind::Totp,
                    label: "一次性密码".into(),
                    purpose: Some(Purpose::Otp),
                    data: FieldData::Text(totp.into()),
                },
            ],
        )
        .unwrap();
    // 修改几次，留下历史版本
    for i in 0..3 {
        v.update_item(id, vec![keevo_core::Edit::AddTag(format!("t{i}"))])
            .unwrap();
    }
    v.add_attachment(id, "secret.txt", attachment.repeat(3000).as_bytes(), 1)
        .unwrap();
    keevo_core::backup::create(
        &v,
        &dir.join("backups"),
        keevo_core::backup::Kind::Manual,
        1_795_105_920_000,
    )
    .unwrap();
    let export = keevo_core::export::export(
        &v,
        keevo_core::export::Format::Keevo,
        None,
        Some("export password"),
    )
    .unwrap();
    std::fs::write(dir.join("export.keevo-export"), &*export.bytes).unwrap();
    // 锁定再解锁一次，确保 WAL 与检查点都写过
    v.lock();
    v.unlock(master, &sk).unwrap();
    drop(v);

    let mut files = Vec::new();
    all_files(dir, &mut files);
    assert!(files.len() >= 3, "{files:?}");
    let secrets = [
        password,
        note,
        totp,
        title,
        attachment,
        master,
        &sk.to_display_string(),
    ];
    for f in &files {
        let data = std::fs::read(f).unwrap();
        for s in secrets {
            assert!(
                !contains_secret(&data, s),
                "{} 中出现了明文秘密 {s:?}",
                f.display()
            );
        }
    }
}
