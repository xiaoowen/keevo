//! 开发者服务的集成测试：真实的 Unix socket；SSH Agent 由系统的 `ssh-add`、`ssh-keygen` 驱动。
//! 只在 macOS 上运行：服务由内核读取对端进程（audit token、进程表），其他平台没有实现。
#![cfg(target_os = "macos")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use keevo_core::ssh_agent::AgentPolicy;
use keevo_core::{FieldData, FieldKind, ItemType, NewField, Vault};
use keevo_crypto::{Id128, KdfParams};
use keevo_ipc::cli::{
    CLI_CLIENT, CLI_PROTOCOL_VERSION, ClientHello, ErrorBody, ItemResult, ItemsResult, Request,
    ResolveResult, ServerHello, StatusResult, decode_response,
};
use keevo_ipc::frame::{read_socket_frame, write_socket_frame};
use keevo_service::PeerPolicy;
use keevo_service::agent::SshAgent;
use keevo_service::cli::CliService;
use keevo_service::developer::{Developer, DeveloperPrompt, SshRequest, UnlockReason};
use keevo_service::origin::Origin;
use keevo_ssh::PrivateKey;

#[derive(Default)]
struct TestPrompt {
    accept: AtomicBool,
    cli: AtomicUsize,
    ssh: AtomicUsize,
    unlock: AtomicUsize,
    last_ssh: Mutex<Option<SshRequest>>,
}

impl DeveloperPrompt for TestPrompt {
    fn unlock_requested(&self, _: UnlockReason) {
        self.unlock.fetch_add(1, Ordering::SeqCst);
    }
    fn authorize_cli(&self, origin: &Origin, _: Instant) -> bool {
        assert_eq!(origin.pid, std::process::id());
        self.cli.fetch_add(1, Ordering::SeqCst);
        self.accept.load(Ordering::SeqCst)
    }
    fn authorize_ssh(&self, request: &SshRequest, _: Instant) -> bool {
        self.ssh.fetch_add(1, Ordering::SeqCst);
        *self.last_ssh.lock().unwrap() = Some(request.clone());
        self.accept.load(Ordering::SeqCst)
    }
}

struct Env {
    dir: PathBuf,
    vault: Arc<Mutex<Vault>>,
    prompt: Arc<TestPrompt>,
    dev: Arc<Developer>,
    vault_name: String,
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn env() -> Env {
    // socket 路径不能超过 104 字节：目录名保持很短
    let dir = std::env::temp_dir().join(format!("kd{}", &Id128::random().unwrap().to_hex()[..8]));
    std::fs::create_dir_all(&dir).unwrap();
    let params = KdfParams::new(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1, [3u8; 16]).unwrap();
    let (mut vault, _) = Vault::create(&dir.join("v.sqlite"), "pw", params).unwrap();
    let info = vault.vaults().unwrap().remove(0);
    vault
        .create_item(
            info.id,
            ItemType::Login,
            "GitHub",
            vec![NewField {
                kind: FieldKind::Concealed,
                label: "密码".into(),
                purpose: None,
                data: FieldData::Text("correct horse".into()),
            }],
        )
        .unwrap();
    let vault = Arc::new(Mutex::new(vault));
    let prompt = Arc::new(TestPrompt::default());
    let dev = Developer::with_unlock_waits(
        Arc::clone(&vault),
        Arc::clone(&prompt) as Arc<dyn DeveloperPrompt>,
        Duration::from_millis(300),
        Duration::from_millis(300),
    );
    Env {
        dir,
        vault,
        prompt,
        dev,
        vault_name: info.name,
    }
}

// ---- CLI

struct Client {
    stream: UnixStream,
    next: u32,
}

impl Client {
    fn connect(path: &Path) -> Self {
        let mut stream = UnixStream::connect(path).unwrap();
        let hello = serde_json::to_vec(&ClientHello {
            v: CLI_PROTOCOL_VERSION,
            client: CLI_CLIENT.into(),
            version: "test".into(),
        })
        .unwrap();
        write_socket_frame(&mut stream, &hello).unwrap();
        let reply: ServerHello =
            serde_json::from_slice(&read_socket_frame(&mut stream).unwrap()).unwrap();
        assert!(reply.ok);
        Self { stream, next: 1 }
    }

    fn call<T: for<'de> serde::Deserialize<'de>>(
        &mut self,
        make: impl FnOnce(u32) -> Request,
    ) -> Result<T, ErrorBody> {
        let id = self.next;
        self.next += 1;
        let req = serde_json::to_vec(&make(id)).unwrap();
        write_socket_frame(&mut self.stream, &req).unwrap();
        decode_response(&read_socket_frame(&mut self.stream).unwrap(), id).unwrap()
    }
}

fn start_cli(env: &Env) -> PathBuf {
    let path = env.dir.join("cli.sock");
    let listener = keevo_service::bind(&path).unwrap();
    let svc = CliService::new(Arc::clone(&env.dev), PeerPolicy::DevSameUserOnly).unwrap();
    std::thread::spawn(move || svc.serve(&listener));
    path
}

#[test]
fn cli_sessions_are_authorized_once_and_reads_work() {
    let env = env();
    let path = start_cli(&env);
    env.prompt.accept.store(true, Ordering::SeqCst);
    let mut c = Client::connect(&path);
    let status: StatusResult = c.call(|id| Request::Status { id }).unwrap();
    assert!(!status.locked);
    assert!(!status.authorized);
    assert_eq!(
        env.prompt.cli.load(Ordering::SeqCst),
        0,
        "status 不需要授权"
    );

    let v = &env.vault_name;
    let r: ResolveResult = c
        .call(|id| Request::Resolve {
            id,
            refs: vec![format!("keevo://{v}/GitHub/密码"), "keevo://x/y".into()],
        })
        .unwrap();
    assert_eq!(r.values[0].value.as_deref(), Some("correct horse"));
    assert_eq!(r.values[1].error.as_deref(), Some("bad_ref"));
    assert_eq!(env.prompt.cli.load(Ordering::SeqCst), 1);

    // 同一个进程的另一个连接属于同一会话：不再询问
    let mut c2 = Client::connect(&path);
    let items: ItemsResult = c2
        .call(|id| Request::Items {
            id,
            vault: None,
            query: Some("git".into()),
        })
        .unwrap();
    assert_eq!(items.items.len(), 1);
    let detail: ItemResult = c2
        .call(|id| Request::Item {
            id,
            item: format!("{v}/GitHub"),
            reveal: false,
        })
        .unwrap();
    assert_eq!(detail.fields[0].value, None, "隐藏字段默认不含值");
    let detail: ItemResult = c2
        .call(|id| Request::Item {
            id,
            item: format!("{v}/GitHub"),
            reveal: true,
        })
        .unwrap();
    assert_eq!(detail.fields[0].value.as_deref(), Some("correct horse"));
    assert_eq!(env.prompt.cli.load(Ordering::SeqCst), 1);
    let status: StatusResult = c2.call(|id| Request::Status { id }).unwrap();
    assert!(status.authorized);
    assert!(status.expires_in.unwrap() > 500);
    assert_eq!(env.dev.cli_sessions().len(), 1);

    // keevo lock：锁定并清除授权
    let () = c2.call(|id| Request::Lock { id }).unwrap();
    assert!(!env.vault.lock().unwrap().is_unlocked());
    let e = c2
        .call::<ResolveResult>(|id| Request::Resolve {
            id,
            refs: vec![format!("keevo://{v}/GitHub/密码")],
        })
        .unwrap_err();
    assert_eq!(e.error, "locked");
    assert!(env.prompt.unlock.load(Ordering::SeqCst) >= 1);
}

#[test]
fn cli_denials_are_remembered_briefly() {
    let env = env();
    let path = start_cli(&env);
    let mut c = Client::connect(&path);
    let e = c
        .call::<ItemsResult>(|id| Request::Items {
            id,
            vault: None,
            query: None,
        })
        .unwrap_err();
    assert_eq!(e.error, "denied");
    // 冷却期内直接拒绝，不再弹窗
    env.prompt.accept.store(true, Ordering::SeqCst);
    let e = c
        .call::<ItemsResult>(|id| Request::Items {
            id,
            vault: None,
            query: None,
        })
        .unwrap_err();
    assert_eq!(e.error, "denied");
    assert_eq!(env.prompt.cli.load(Ordering::SeqCst), 1);
}

#[test]
fn cli_rejects_bad_hello_and_unknown_fields() {
    let env = env();
    let path = start_cli(&env);
    let mut s = UnixStream::connect(&path).unwrap();
    write_socket_frame(&mut s, br#"{"v":2,"client":"keevo-cli","version":"x"}"#).unwrap();
    let reply: ServerHello = serde_json::from_slice(&read_socket_frame(&mut s).unwrap()).unwrap();
    assert!(!reply.ok);
    assert_eq!(reply.error.as_deref(), Some("unsupported_version"));

    let mut c = Client::connect(&path);
    write_socket_frame(&mut c.stream, br#"{"op":"status","id":9,"extra":1}"#).unwrap();
    let e = decode_response::<StatusResult>(&read_socket_frame(&mut c.stream).unwrap(), 9)
        .unwrap()
        .unwrap_err();
    assert_eq!(e.error, "bad_request");
}

// ---- SSH Agent

const SSH_ADD: &str = "/usr/bin/ssh-add";
const SSH_KEYGEN: &str = "/usr/bin/ssh-keygen";

fn add_key(env: &Env, title: &str, policy: Option<AgentPolicy>) -> (Id128, String) {
    let key = PrivateKey::generate_ed25519("me@test").unwrap();
    let mut vault = env.vault.lock().unwrap();
    let vid = vault.vaults().unwrap()[0].id;
    let id = vault
        .create_item(
            vid,
            ItemType::SshKey,
            title,
            vec![NewField {
                kind: FieldKind::SshPrivateKey,
                label: "私钥".into(),
                purpose: None,
                data: FieldData::Text(key.to_openssh().unwrap().as_str().into()),
            }],
        )
        .unwrap();
    vault.set_ssh_agent_policy(id, policy).unwrap();
    (id, key.public_key().to_line(""))
}

fn start_agent(env: &Env) -> (SshAgent, PathBuf) {
    let path = env.dir.join("agent.sock");
    let (agent, listener) = SshAgent::bind(Arc::clone(&env.dev), &path).unwrap();
    let serving = agent.clone();
    std::thread::spawn(move || serving.serve(&listener));
    (agent, path)
}

fn ssh_add_list(sock: &Path) -> (bool, String) {
    let out = Command::new(SSH_ADD)
        .arg("-L")
        .env("SSH_AUTH_SOCK", sock)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// 经 Agent 用 `ssh-keygen -Y sign` 签名，再用 `ssh-keygen -Y verify` 验证。
fn sign_and_verify(env: &Env, sock: &Path, public_line: &str) -> bool {
    let pub_file = env.dir.join("key.pub");
    std::fs::write(&pub_file, format!("{public_line}\n")).unwrap();
    let data = env.dir.join("data.txt");
    std::fs::write(&data, b"keevo signs this").unwrap();
    let sig = env.dir.join("data.txt.sig");
    let _ = std::fs::remove_file(&sig);
    let out = Command::new(SSH_KEYGEN)
        .args(["-Y", "sign", "-n", "file", "-f"])
        .arg(&pub_file)
        .arg(&data)
        .env("SSH_AUTH_SOCK", sock)
        .output()
        .unwrap();
    if !out.status.success() {
        return false;
    }
    let signers = env.dir.join("allowed_signers");
    std::fs::write(&signers, format!("me {public_line}\n")).unwrap();
    let verify = Command::new(SSH_KEYGEN)
        .args(["-Y", "verify", "-n", "file", "-I", "me", "-f"])
        .arg(&signers)
        .arg("-s")
        .arg(&sig)
        .stdin(std::fs::File::open(&data).unwrap())
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
    true
}

#[test]
fn ssh_agent_works_with_openssh() {
    if !Path::new(SSH_ADD).exists() || !Path::new(SSH_KEYGEN).exists() {
        eprintln!("没有 OpenSSH 工具，跳过");
        return;
    }
    let env = env();
    let (_, unlocked_line) = add_key(&env, "自动", Some(AgentPolicy::Unlocked));
    let (ask_id, ask_line) = add_key(&env, "每次确认", Some(AgentPolicy::Ask));
    let (_, off_line) = add_key(&env, "未开启", None);
    let (agent, sock) = start_agent(&env);

    // 只列出开启了 Agent 的密钥，注释为条目标题
    let (ok, listed) = ssh_add_list(&sock);
    assert!(ok);
    let key_part = |line: &str| {
        line.split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ")
    };
    assert!(listed.contains(&key_part(&unlocked_line)));
    assert!(listed.contains(&key_part(&ask_line)));
    assert!(!listed.contains(&key_part(&off_line)));
    assert!(listed.contains(" 自动"), "{listed}");

    // 解锁期间自动：不弹窗
    assert!(sign_and_verify(&env, &sock, &unlocked_line));
    assert_eq!(env.prompt.ssh.load(Ordering::SeqCst), 0);

    // 每次确认：拒绝时签名失败，同意时成功；请求中带有来源与密钥
    assert!(!sign_and_verify(&env, &sock, &ask_line));
    env.prompt.accept.store(true, Ordering::SeqCst);
    assert!(sign_and_verify(&env, &sock, &ask_line));
    assert_eq!(env.prompt.ssh.load(Ordering::SeqCst), 2);
    let last = env.prompt.last_ssh.lock().unwrap().clone().unwrap();
    assert_eq!(last.item_id, ask_id.to_hex());
    assert_eq!(last.key_title, "每次确认");
    assert!(
        last.origin.command.contains("ssh-keygen"),
        "{}",
        last.origin.command
    );
    assert!(!last.forwarded);

    // 未开启的密钥不能签名
    assert!(!sign_and_verify(&env, &sock, &off_line));

    // 锁定后：请求解锁，超时后返回空列表
    env.vault.lock().unwrap().lock();
    let (ok, listed) = ssh_add_list(&sock);
    assert!(!ok, "{listed}");
    assert!(env.prompt.unlock.load(Ordering::SeqCst) >= 1);

    agent.stop();
    assert!(!sock.exists());
}

#[test]
fn ssh_agent_refuses_to_add_keys() {
    if !Path::new(SSH_ADD).exists() || !Path::new(SSH_KEYGEN).exists() {
        return;
    }
    let env = env();
    let (_agent, sock) = start_agent(&env);
    let key = env.dir.join("id_ed25519");
    let out = Command::new(SSH_KEYGEN)
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .output()
        .unwrap();
    assert!(out.status.success());
    let out = Command::new(SSH_ADD)
        .arg(&key)
        .env("SSH_AUTH_SOCK", &sock)
        .output()
        .unwrap();
    assert!(!out.status.success(), "Agent 不接受外部密钥");
}

#[test]
fn link_is_created_once_and_never_overwritten() {
    let env = env();
    let target = env.dir.join("agent.sock");
    let link = env.dir.join("k").join("agent.sock");
    use keevo_service::agent::{LinkStatus, ensure_link};
    assert_eq!(ensure_link(&link, &target), LinkStatus::Ready);
    assert_eq!(ensure_link(&link, &target), LinkStatus::Ready);
    let other = env.dir.join("other");
    assert!(
        matches!(ensure_link(&link, &other), LinkStatus::Conflict(t) if t == target.display().to_string())
    );
    let file = env.dir.join("plain");
    std::fs::write(&file, b"x").unwrap();
    assert_eq!(
        ensure_link(&file, &target),
        LinkStatus::Conflict(String::new())
    );
}
