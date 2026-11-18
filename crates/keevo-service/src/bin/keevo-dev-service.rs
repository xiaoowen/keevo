//! 开发服务：在没有 Keevo.app 的情况下运行 Vault Service，供浏览器扩展原型联调。
//!
//! **只用于开发，切勿存放真实数据**：
//! - 演示保险库的主密码固定，账户密钥以明文保存在数据目录中；
//! - socket 对端只依赖目录权限校验（release 构建拒绝运行）。
//!
//! 用法：
//! ```text
//! cargo run -p keevo-service --bin keevo-dev-service              # 交互确认配对
//! cargo run -p keevo-service --bin keevo-dev-service -- --auto-confirm --dir <目录>   # 自动化测试
//! ```

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "开发用命令行工具，终端输出就是它的界面"
)]

use std::fs;
use std::io::{BufRead, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use keevo_core::{
    AccountSecretKey, FieldData, FieldKind, ItemType, KdfParams, NewField, Purpose, Vault,
};
use keevo_crypto::StaticKeypair;
use keevo_service::{FilePairingStore, PairingPrompt, PeerPolicy, VaultService, bind};
use zeroize::Zeroizing;

const DEMO_PASSWORD: &str = "keevo-dev-only-password";

struct TerminalPrompt;

impl PairingPrompt for TerminalPrompt {
    fn started(&self, browser: &str) {
        eprintln!("\n[配对] 收到来自 {browser} 的配对请求，等待扩展完成握手……");
    }

    fn confirm(
        &self,
        sas: [u8; 6],
        name: &str,
        browser: &str,
        deadline: std::time::Instant,
    ) -> bool {
        let code: Vec<String> = sas.iter().map(|b| format!("{b:02x}")).collect();
        eprintln!("\n浏览器「{name}」（{browser}）请求配对。");
        eprintln!("请确认扩展弹窗中显示的验证码与此一致：  {}", code.join(" "));
        eprint!("一致吗？[y/N] ");
        let _ = std::io::stderr().flush();
        // 在另一个线程读终端，到截止时间仍未回答即按拒绝处理
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let ok = std::io::stdin().lock().read_line(&mut line).is_ok()
                && line.trim().eq_ignore_ascii_case("y");
            let _ = tx.send(ok);
        });
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        let ok = rx.recv_timeout(left).unwrap_or(false);
        eprintln!(
            "{}",
            if ok {
                "已配对。"
            } else {
                "已拒绝（或超时）。"
            }
        );
        ok
    }
}

struct AutoConfirm;

impl PairingPrompt for AutoConfirm {
    fn confirm(&self, _: [u8; 6], name: &str, _: &str, _: std::time::Instant) -> bool {
        eprintln!("[auto-confirm] 已自动确认「{name}」的配对");
        true
    }
}

fn main() -> ExitCode {
    if !cfg!(debug_assertions) {
        eprintln!("keevo-dev-service 只能以 debug 构建运行。");
        return ExitCode::FAILURE;
    }
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("错误：{e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let auto_confirm = args.iter().any(|a| a == "--auto-confirm");
    let dir = match args
        .iter()
        .position(|a| a == "--dir")
        .and_then(|i| args.get(i.saturating_add(1)))
    {
        Some(d) => PathBuf::from(d),
        None => PathBuf::from(std::env::var("HOME")?).join("Library/Application Support/Keevo-Dev"),
    };
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)?;

    eprintln!(
        "⚠️  Keevo 开发服务：仅供开发，账户密钥以明文保存在 {}，切勿存放真实数据。",
        dir.display()
    );
    let vault = open_or_create_demo(&dir)?;
    let key = load_or_create_service_key(&dir.join("service-key"))?;
    let pairings = FilePairingStore::open(&dir.join("pairings.json"))?;
    let prompt: Arc<dyn PairingPrompt> = if auto_confirm {
        Arc::new(AutoConfirm)
    } else {
        Arc::new(TerminalPrompt)
    };

    let svc = VaultService::new(
        Arc::new(Mutex::new(vault)),
        key,
        Arc::new(Mutex::new(pairings)),
        prompt,
        PeerPolicy::DevSameUserOnly,
    )?;
    let socket = keevo_ipc::paths::socket_path()?;
    let listener = bind(&socket)?;
    eprintln!("正在监听 {}", socket.display());
    // 自动化测试据此判断服务已就绪
    println!("READY");
    std::io::stdout().flush()?;
    svc.serve(&listener);
    Ok(())
}

fn open_or_create_demo(dir: &Path) -> Result<Vault, Box<dyn std::error::Error>> {
    let db = dir.join("vault.sqlite");
    let sk_path = dir.join("dev-secret-key.txt");
    if db.exists() {
        let mut vault = Vault::open(&db)?;
        let sk = AccountSecretKey::parse(fs::read_to_string(&sk_path)?.trim())?;
        vault.unlock(DEMO_PASSWORD, &sk)?;
        return Ok(vault);
    }
    // 演示保险库使用规范允许的最小 KDF 参数，启动更快
    let params = KdfParams::new(
        KdfParams::MIN_M_KIB,
        KdfParams::MIN_T,
        1,
        keevo_crypto::Id128::random()?.as_bytes().to_owned(),
    )?;
    let (mut vault, sk) = Vault::create(&db, DEMO_PASSWORD, params)?;
    write_private(&sk_path, sk.to_display_string().as_bytes())?;

    let vault_id = vault
        .vaults()?
        .first()
        .map(|v| v.id)
        .ok_or("no default vault")?;
    let field = |kind, label: &str, purpose, value: &str| NewField {
        kind,
        label: label.into(),
        purpose,
        data: FieldData::Text(value.into()),
    };
    for (title, user, pw, url) in [
        (
            "GitHub（演示）",
            "octocat",
            "demo-github-password",
            "https://github.com",
        ),
        (
            "Example（演示）",
            "demo@example.com",
            "demo-example-password",
            "https://example.com",
        ),
        (
            "本地开发（演示）",
            "admin",
            "demo-local-password",
            "http://localhost:3000",
        ),
    ] {
        vault.create_item(
            vault_id,
            ItemType::Login,
            title,
            vec![
                field(FieldKind::Text, "用户名", Some(Purpose::Username), user),
                field(FieldKind::Concealed, "密码", Some(Purpose::Password), pw),
                field(FieldKind::Url, "网站", None, url),
            ],
        )?;
    }
    eprintln!("已创建演示保险库：{}", db.display());
    Ok(vault)
}

fn load_or_create_service_key(path: &Path) -> Result<StaticKeypair, Box<dyn std::error::Error>> {
    if let Ok(hex) = fs::read_to_string(path) {
        let hex = hex.trim();
        let mut bytes = Zeroizing::new([0u8; 32]);
        if hex.len() != 64 {
            return Err("service-key 格式错误".into());
        }
        for (slot, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
            *slot = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
        }
        return Ok(StaticKeypair::from_private(bytes));
    }
    // M1 中服务静态密钥由 Secure Enclave 包裹后存成文件（ADR-0003）
    let key = StaticKeypair::generate()?;
    let hex: String = key
        .export_private()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    write_private(path, hex.as_bytes())?;
    Ok(key)
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}
