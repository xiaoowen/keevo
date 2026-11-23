//! `keevo` 二进制的端到端测试：在测试进程中启动 CLI 服务（开发构建，只依赖目录权限），用
//! `KEEVO_DEV_CLI_SOCKET` 指向它，逐个运行命令，核对输出与退出码（`spec/cli.md` §7）。
//! 只在 macOS 上运行：服务由内核读取对端进程。
#![cfg(target_os = "macos")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use keevo_core::{FieldData, FieldKind, ItemType, NewField, Vault};
use keevo_crypto::{Id128, KdfParams};
use keevo_service::PeerPolicy;
use keevo_service::cli::CliService;
use keevo_service::developer::{Developer, DeveloperPrompt};
use keevo_service::origin::Origin;

struct Prompt {
    accept: AtomicBool,
    asked: AtomicUsize,
}

impl DeveloperPrompt for Prompt {
    fn authorize_cli(&self, _: &Origin, _: Instant) -> bool {
        self.asked.fetch_add(1, Ordering::SeqCst);
        self.accept.load(Ordering::SeqCst)
    }
}

struct Env {
    dir: PathBuf,
    sock: PathBuf,
    vault: Arc<Mutex<Vault>>,
    prompt: Arc<Prompt>,
    vault_name: String,
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

const OTP: &str = "JBSWY3DPEHPK3PXP";

fn env(accept: bool) -> Env {
    let dir = std::env::temp_dir().join(format!("kc{}", &Id128::random().unwrap().to_hex()[..8]));
    std::fs::create_dir_all(&dir).unwrap();
    let params = KdfParams::new(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1, [3u8; 16]).unwrap();
    let (mut vault, _) = Vault::create(&dir.join("v.sqlite"), "pw", params).unwrap();
    let info = vault.vaults().unwrap().remove(0);
    let text = |kind, label: &str, value: &str| NewField {
        kind,
        label: label.into(),
        purpose: None,
        data: FieldData::Text(value.into()),
    };
    vault
        .create_item(
            info.id,
            ItemType::Login,
            "GitHub",
            vec![
                text(FieldKind::Text, "用户名", "octocat"),
                text(FieldKind::Concealed, "密码", "correct horse battery"),
                text(FieldKind::Totp, "一次性密码", OTP),
            ],
        )
        .unwrap();
    let vault = Arc::new(Mutex::new(vault));
    let prompt = Arc::new(Prompt {
        accept: AtomicBool::new(accept),
        asked: AtomicUsize::new(0),
    });
    let dev = Developer::with_unlock_waits(
        Arc::clone(&vault),
        Arc::clone(&prompt) as Arc<dyn DeveloperPrompt>,
        Duration::from_millis(300),
        Duration::from_millis(300),
    );
    let sock = dir.join("cli.sock");
    let listener = keevo_service::bind(&sock).unwrap();
    let svc = CliService::new(dev, PeerPolicy::DevSameUserOnly).unwrap();
    std::thread::spawn(move || svc.serve(&listener));
    Env {
        dir,
        sock,
        vault,
        prompt,
        vault_name: info.name,
    }
}

fn keevo(env: &Env, args: &[&str]) -> Output {
    keevo_at(&env.sock, args)
}

fn keevo_at(sock: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_keevo"))
        .args(args)
        .env("KEEVO_DEV_CLI_SOCKET", sock)
        .output()
        .unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn read_run_inject_and_items() {
    let env = env(true);
    let v = env.vault_name.clone();
    let pw_ref = format!("keevo://{v}/GitHub/密码");

    let o = keevo(&env, &["status"]);
    assert_eq!(o.status.code(), Some(0));
    assert!(stdout(&o).contains("已解锁"), "{}", stdout(&o));

    // 输出到管道：原样输出，不加换行
    let o = keevo(&env, &["read", &pw_ref]);
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(stdout(&o), "correct horse battery");
    let o = keevo(&env, &["read", &pw_ref, "--newline"]);
    assert_eq!(stdout(&o), "correct horse battery\n");

    // 引用无法解析：6；语法错误同样是 6。都附上获取引用的方法
    let o = keevo(&env, &["read", &format!("keevo://{v}/没有/密码")]);
    assert_eq!(o.status.code(), Some(6));
    let hint = "复制 keevo:// 引用";
    assert!(String::from_utf8_lossy(&o.stderr).contains(hint));
    let o = keevo(&env, &["read", "keevo://x"]);
    assert_eq!(o.status.code(), Some(6));
    assert!(String::from_utf8_lossy(&o.stderr).contains(hint));
    // 帮助中说明引用的格式与获取方法
    let o = keevo(&env, &["--help"]);
    assert_eq!(o.status.code(), Some(0));
    assert!(stdout(&o).contains("获取引用：在 Keevo 中右键点字段"));

    // run：注入并遮蔽；--no-masking 直接继承
    let env_file = env.dir.join(".env.keevo");
    std::fs::write(&env_file, format!("# 测试\nSECRET={pw_ref}\nPLAIN=hello\n")).unwrap();
    let o = keevo(
        &env,
        &[
            "run",
            "--env-file",
            env_file.to_str().unwrap(),
            "--",
            "sh",
            "-c",
            "echo \"$SECRET|$PLAIN\"; echo \"$SECRET\" >&2",
        ],
    );
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(stdout(&o), "<concealed by keevo>|hello\n");
    assert_eq!(String::from_utf8_lossy(&o.stderr), "<concealed by keevo>\n");
    let o = keevo(
        &env,
        &[
            "run",
            "--no-masking",
            "--env",
            &format!("SECRET={pw_ref}"),
            "--",
            "sh",
            "-c",
            "echo $SECRET",
        ],
    );
    assert_eq!(stdout(&o), "correct horse battery\n");
    // 子进程的退出码原样返回
    let o = keevo(&env, &["run", "--", "sh", "-c", "exit 7"]);
    assert_eq!(o.status.code(), Some(7));
    // 引用失败时不启动子进程
    let marker = env.dir.join("ran");
    let o = keevo(
        &env,
        &[
            "run",
            "--env",
            "X=keevo://nope/a/b",
            "--",
            "touch",
            marker.to_str().unwrap(),
        ],
    );
    assert_eq!(o.status.code(), Some(6));
    assert!(!marker.exists());

    // inject：输出文件 0600，已存在时需要 --force
    let tpl = env.dir.join("config.tpl");
    std::fs::write(
        &tpl,
        format!("user: octocat\npassword: {{{{ {pw_ref} }}}}\n"),
    )
    .unwrap();
    let out_file = env.dir.join("config.yml");
    let args = [
        "inject",
        "-i",
        tpl.to_str().unwrap(),
        "-o",
        out_file.to_str().unwrap(),
    ];
    assert_eq!(keevo(&env, &args).status.code(), Some(0));
    assert_eq!(
        std::fs::read_to_string(&out_file).unwrap(),
        "user: octocat\npassword: correct horse battery\n"
    );
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&out_file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(keevo(&env, &args).status.code(), Some(2));

    // item 与 totp
    let o = keevo(&env, &["item", "list", "--format", "json"]);
    let list: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(list["items"][0]["title"], "GitHub");
    let o = keevo(&env, &["item", "get", &format!("{v}/GitHub")]);
    let shown = stdout(&o);
    assert!(
        shown.contains("octocat") && !shown.contains("correct horse"),
        "{shown}"
    );
    let o = keevo(&env, &["item", "get", &format!("{v}/GitHub"), "--reveal"]);
    assert!(stdout(&o).contains("correct horse battery"));
    let o = keevo(&env, &["totp", &format!("{v}/GitHub")]);
    let code = stdout(&o);
    assert_eq!(code.trim().len(), 6, "{code}");
    assert!(code.trim().bytes().all(|b| b.is_ascii_digit()));

    // create 与 edit
    let o = keevo(
        &env,
        &[
            "item",
            "create",
            "--vault",
            &v,
            "--type",
            "login",
            "--title",
            "新登录",
            "--field",
            "用户名=me",
            "--field",
            "密码=first",
        ],
    );
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(
        stdout(&keevo(&env, &["read", &format!("keevo://{v}/新登录/密码")])),
        "first"
    );
    let o = keevo(
        &env,
        &[
            "item",
            "edit",
            &format!("{v}/新登录"),
            "--set",
            "密码=second",
        ],
    );
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(
        stdout(&keevo(&env, &["read", &format!("keevo://{v}/新登录/密码")])),
        "second"
    );
    assert_eq!(
        keevo(
            &env,
            &[
                "item", "create", "--vault", &v, "--type", "nope", "--title", "x"
            ]
        )
        .status
        .code(),
        Some(2)
    );

    // 同一个父进程启动的 keevo 属于同一会话：只确认了一次
    assert_eq!(env.prompt.asked.load(Ordering::SeqCst), 1);

    // lock：之后读取返回 4
    assert_eq!(keevo(&env, &["lock"]).status.code(), Some(0));
    assert!(!env.vault.lock().unwrap().is_unlocked());
    assert_eq!(keevo(&env, &["read", &pw_ref]).status.code(), Some(4));
}

#[test]
fn exit_codes_for_denied_and_not_running() {
    let env = env(false);
    let o = keevo(
        &env,
        &["read", &format!("keevo://{}/GitHub/密码", env.vault_name)],
    );
    assert_eq!(o.status.code(), Some(5));
    assert_eq!(
        keevo_at(&env.dir.join("none.sock"), &["status"])
            .status
            .code(),
        Some(3)
    );
    assert_eq!(keevo(&env, &["nope"]).status.code(), Some(2));
    let o = keevo(&env, &["generate", "--pin", "6"]);
    assert_eq!(stdout(&o).trim().len(), 6);
    let o = keevo(&env, &["generate", "--words", "5"]);
    assert_eq!(stdout(&o).trim().split('-').count(), 5);
    let o = keevo(&env, &["ssh", "config"]);
    assert!(stdout(&o).contains("IdentityAgent"));
}
