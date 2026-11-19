//! 与 OpenSSH 的互通：Keevo 生成的私钥能被 `ssh-keygen` 读取，算出相同的公钥与指纹。
//! 系统中没有 `ssh-keygen` 时跳过（macOS 自带 /usr/bin/ssh-keygen）。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stderr)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use keevo_ssh::{PrivateKey, PublicKey};

const SSH_KEYGEN: &str = "/usr/bin/ssh-keygen";

#[test]
fn ssh_keygen_reads_keys_generated_by_keevo() {
    if !Path::new(SSH_KEYGEN).exists() {
        eprintln!("没有 {SSH_KEYGEN}，跳过");
        return;
    }
    let dir = std::env::temp_dir().join(format!("keevo-ssh-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for comment in ["", "me@mac", "中文 注释"] {
        let key = PrivateKey::generate_ed25519(comment).unwrap();
        let path = dir.join("id");
        std::fs::write(&path, key.to_openssh().unwrap().as_bytes()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let out = Command::new(SSH_KEYGEN)
            .arg("-y")
            .arg("-f")
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let line = String::from_utf8(out.stdout).unwrap();
        let (public, parsed_comment) = PublicKey::parse_line(&line).unwrap();
        assert_eq!(public, key.public_key());
        assert_eq!(parsed_comment, comment.trim());

        let out = Command::new(SSH_KEYGEN)
            .arg("-l")
            .arg("-f")
            .arg(&path)
            .output()
            .unwrap();
        assert!(out.status.success());
        let listed = String::from_utf8(out.stdout).unwrap();
        assert!(
            listed.contains(&key.public_key().fingerprint()),
            "{listed} 不含 {}",
            key.public_key().fingerprint()
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
