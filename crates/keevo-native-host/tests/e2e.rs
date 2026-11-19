//! 全链路端到端测试：模拟 Chrome 启动真实的 native host 二进制，经真实的 Unix socket 连接
//! Vault Service，后端是真实的加密保险库数据库。
//!
//! 测试进程扮演"浏览器 + 扩展"：用 Native Messaging 帧与 host 通信，用 `ExtensionClient` 完成
//! Noise 配对与会话。由于测试进程不是 Chrome，需要用仅 debug 构建生效的环境变量跳过父进程校验。

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "集成测试：辅助函数中的失败即测试失败"
)]

use std::io::{BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

use keevo_core::{FieldData, FieldKind, ItemType, KdfParams, NewField, Purpose, Vault};
use keevo_crypto::{Id128, StaticKeypair};
use keevo_ipc::client::{ClientEvent, ExtensionClient};
use keevo_ipc::frame::{read_native_frame, write_native_frame};
use keevo_ipc::message::{Call, CallResult, ControlFrame, ErrorCode, ServerMessage};
use keevo_service::{PairingPrompt, PeerPolicy, VaultService, bind};

const ORIGIN: &str = "chrome-extension://abcdefghijklmnopabcdefghijklmnop/";
const HOST: &str = env!("CARGO_BIN_EXE_keevo-native-host");

struct AutoConfirm(Mutex<Vec<[u8; 6]>>);

impl PairingPrompt for AutoConfirm {
    fn confirm(&self, sas: [u8; 6], name: &str, browser: &str, _: std::time::Instant) -> bool {
        assert_eq!(name, "Chrome · 测试");
        assert_eq!(browser, "dev");
        self.0.lock().unwrap().push(sas);
        true
    }

    /// 首次取用的授权（spec/ipc.md §5.2）：界面收到规范化后的站点与条目概要。
    fn authorize_fill(&self, r: &keevo_ipc::service::FillRequest, _: std::time::Instant) -> bool {
        assert_eq!(
            (
                r.site.as_str(),
                r.title.as_str(),
                r.username.as_str(),
                r.pairing_name.as_str()
            ),
            ("https://github.com", "GitHub", "octocat", "Chrome · 测试")
        );
        true
    }
}

struct World {
    dir: PathBuf,
    socket: PathBuf,
    vault: Arc<Mutex<Vault>>,
    prompt: Arc<AutoConfirm>,
    svc: VaultService,
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn login(title: &str, user: &str, pw: &str, url: &str) -> (String, Vec<NewField>) {
    let f = |kind, label: &str, purpose, v: &str| NewField {
        kind,
        label: label.into(),
        purpose,
        data: FieldData::Text(v.into()),
    };
    (
        title.into(),
        vec![
            f(FieldKind::Text, "用户名", Some(Purpose::Username), user),
            f(FieldKind::Concealed, "密码", Some(Purpose::Password), pw),
            f(FieldKind::Url, "网站", None, url),
        ],
    )
}

fn start() -> World {
    // socket 路径不能超过 104 字节，目录名尽量短
    let dir = std::env::temp_dir().join(format!("kv{}", &Id128::random().unwrap().to_hex()[..8]));
    std::fs::create_dir_all(&dir).unwrap();
    let params = KdfParams::new(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1, [5; 16]).unwrap();
    let (mut vault, _) = Vault::create(&dir.join("vault.sqlite"), "pw", params).unwrap();
    let vault_id = vault.vaults().unwrap()[0].id;
    for (title, fields) in [
        login("GitHub", "octocat", "gh-secret", "https://github.com"),
        login(
            "Local dev",
            "admin",
            "local-secret",
            "http://localhost:3000",
        ),
    ] {
        vault
            .create_item(vault_id, ItemType::Login, &title, fields)
            .unwrap();
    }

    let vault = Arc::new(Mutex::new(vault));
    let prompt = Arc::new(AutoConfirm(Mutex::new(Vec::new())));
    let svc = VaultService::new(
        Arc::clone(&vault),
        StaticKeypair::generate().unwrap(),
        prompt.clone(),
        PeerPolicy::DevSameUserOnly,
    )
    .unwrap();
    svc.load_pairings().unwrap();
    let socket = dir.join("ipc").join("keevo.sock");
    let listener = bind(&socket).unwrap();
    let server = svc.clone();
    thread::spawn(move || server.serve(&listener));
    World {
        dir,
        socket,
        vault,
        prompt,
        svc,
    }
}

/// 完成一次配对，返回服务公钥。
fn pair(browser: &mut Browser, client: &mut ExtensionClient) -> [u8; 32] {
    browser.send(&ExtensionClient::hello().unwrap());
    browser.send(&client.start_pairing().unwrap());
    let (frames, _) = client.on_frame(&browser.recv()).unwrap();
    browser.send(&frames[0]);
    let (_, events) = client.on_frame(&browser.recv()).unwrap();
    let ClientEvent::Paired { service_public } = events[0] else {
        panic!("{events:?}")
    };
    service_public
}

struct Browser {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Browser {
    fn launch(world: &World, allow_any_parent: bool) -> Self {
        let mut cmd = Command::new(HOST);
        cmd.arg(ORIGIN)
            .env("KEEVO_DEV_SOCKET", &world.socket)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if allow_any_parent {
            cmd.env("KEEVO_DEV_ALLOW_ANY_PARENT", "1");
        }
        let mut child = cmd.spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            stdin,
            stdout,
        }
    }

    fn send(&mut self, frame: &[u8]) {
        write_native_frame(&mut self.stdin, frame).unwrap();
        self.stdin.flush().unwrap();
    }

    fn recv(&mut self) -> Vec<u8> {
        read_native_frame(&mut self.stdout).unwrap()
    }

    fn call(&mut self, client: &mut ExtensionClient, call: Call) -> ServerMessage {
        let (_, frame) = client.request(call).unwrap();
        self.send(&frame);
        let reply = self.recv();
        let (_, mut events) = client.on_frame(&reply).unwrap();
        match events.remove(0) {
            ClientEvent::Message(m) => m,
            other => panic!("{other:?}"),
        }
    }

    fn close(mut self) {
        drop(self.stdin);
        let status = self.child.wait().unwrap();
        assert!(status.success(), "浏览器关闭端口后 host 应正常退出");
    }
}

fn error_code(m: &ServerMessage) -> Option<ErrorCode> {
    match m {
        ServerMessage::Err { error, .. } => Some(error.code),
        _ => None,
    }
}

#[test]
fn pair_then_fill_through_real_native_host_and_socket() {
    let world = start();
    let ext_private = StaticKeypair::generate().unwrap().export_private();

    // ---- 首次配对
    let mut browser = Browser::launch(&world, true);
    let mut client = ExtensionClient::new(
        StaticKeypair::from_private(ext_private.clone()),
        ORIGIN,
        "Chrome · 测试",
    );
    browser.send(&ExtensionClient::hello().unwrap());
    browser.send(&client.start_pairing().unwrap());
    let (frames, events) = client.on_frame(&browser.recv()).unwrap();
    let ClientEvent::ShowSas(sas) = events[0] else {
        panic!("{events:?}")
    };
    browser.send(&frames[0]);
    let (_, events) = client.on_frame(&browser.recv()).unwrap();
    let ClientEvent::Paired { service_public } = events[0] else {
        panic!("{events:?}")
    };
    assert_eq!(
        world.prompt.0.lock().unwrap().as_slice(),
        &[sas],
        "Keevo.app 与扩展显示的 SAS 一致"
    );

    // ---- 候选与填充
    let c = browser.call(
        &mut client,
        Call::Candidates {
            url: "https://github.com/login".into(),
        },
    );
    let ServerMessage::Ok {
        result: CallResult::Candidates { items },
        ..
    } = c
    else {
        panic!("{c:?}")
    };
    assert_eq!(items.len(), 1);
    assert_eq!(
        (items[0].title.as_str(), items[0].subtitle.as_str()),
        ("GitHub", "octocat")
    );
    let item_id = items[0].item_id.clone();

    let fill = browser.call(
        &mut client,
        Call::Fill {
            item_id: item_id.clone(),
            url: "https://github.com/login".into(),
        },
    );
    let ServerMessage::Ok {
        result: CallResult::Fill(data),
        ..
    } = fill
    else {
        panic!("{fill:?}")
    };
    assert_eq!(
        (data.username.as_str(), data.password.as_str()),
        ("octocat", "gh-secret")
    );

    // ---- 钓鱼与降级：拿不到秘密
    for url in [
        "https://github.com.evil.example/login",
        "http://github.com/login",
    ] {
        let c = browser.call(&mut client, Call::Candidates { url: url.into() });
        assert!(
            matches!(&c, ServerMessage::Ok { result: CallResult::Candidates { items }, .. } if items.is_empty()),
            "{url}"
        );
        let f = browser.call(
            &mut client,
            Call::Fill {
                item_id: item_id.clone(),
                url: url.into(),
            },
        );
        assert_eq!(error_code(&f), Some(ErrorCode::UrlMismatch), "{url}");
    }
    // 本地开发服务按端口区分
    let local = browser.call(
        &mut client,
        Call::Candidates {
            url: "http://localhost:3000/".into(),
        },
    );
    assert!(
        matches!(&local, ServerMessage::Ok { result: CallResult::Candidates { items }, .. } if items.len() == 1)
    );
    let other_port = browser.call(
        &mut client,
        Call::Candidates {
            url: "http://localhost:8080/".into(),
        },
    );
    assert!(
        matches!(&other_port, ServerMessage::Ok { result: CallResult::Candidates { items }, .. } if items.is_empty())
    );

    // ---- 锁定后只回答 status
    world.vault.lock().unwrap().lock();
    let locked = browser.call(
        &mut client,
        Call::Candidates {
            url: "https://github.com".into(),
        },
    );
    assert_eq!(error_code(&locked), Some(ErrorCode::Locked));
    browser.close();

    // ---- 浏览器重启：用保存的服务公钥建立 IK 会话
    let mut browser = Browser::launch(&world, true);
    let mut client = ExtensionClient::new(
        StaticKeypair::from_private(ext_private),
        ORIGIN,
        "Chrome · 测试",
    );
    browser.send(&ExtensionClient::hello().unwrap());
    browser.send(&client.start_session(&service_public).unwrap());
    let (_, events) = client.on_frame(&browser.recv()).unwrap();
    assert!(matches!(events[0], ClientEvent::Established));
    let status = browser.call(&mut client, Call::Status);
    assert_eq!(
        status,
        ServerMessage::Ok {
            id: 1,
            result: CallResult::Status { locked: true }
        }
    );
    browser.close();
}

#[test]
fn host_refuses_to_run_when_parent_is_not_a_known_browser() {
    let world = start();
    // 不设置跳过变量：父进程是测试运行器，不是 Chrome
    let mut browser = Browser::launch(&world, false);
    let frame = browser.recv();
    assert_eq!(
        ControlFrame::from_json(&frame).unwrap(),
        ControlFrame::Error {
            code: ErrorCode::BadRequest
        }
    );
    assert!(!browser.child.wait().unwrap().success());
}

#[test]
fn host_reports_when_service_is_not_running() {
    let world = start();
    let missing = World {
        dir: world.dir.join("nothing"),
        socket: world.dir.join("nothing").join("keevo.sock"),
        vault: Arc::clone(&world.vault),
        prompt: Arc::clone(&world.prompt),
        svc: world.svc.clone(),
    };
    let mut browser = Browser::launch(&missing, true);
    browser.send(&ExtensionClient::hello().unwrap());
    let frame = browser.recv();
    assert_eq!(
        ControlFrame::from_json(&frame).unwrap(),
        ControlFrame::Error {
            code: ErrorCode::ServiceUnavailable
        }
    );
}

#[test]
fn unpaired_extension_is_rejected_end_to_end() {
    let world = start();
    let mut browser = Browser::launch(&world, true);
    let mut stranger = ExtensionClient::new(StaticKeypair::generate().unwrap(), ORIGIN, "x");
    browser.send(&ExtensionClient::hello().unwrap());
    // 攻击者知道服务公钥也没用：它的静态密钥不在配对记录中
    let fake_service = StaticKeypair::generate().unwrap().public_key();
    browser.send(&stranger.start_session(&fake_service).unwrap());
    let (_, events) = stranger.on_frame(&browser.recv()).unwrap();
    assert!(
        matches!(events[0], ClientEvent::Error(ErrorCode::NotPaired)),
        "{events:?}"
    );
}

/// 评审 2026-11-18 F1：撤销配对立即断开已建立的会话，之后也无法用原密钥重新建立会话。
#[test]
fn revoking_a_pairing_disconnects_live_sessions_end_to_end() {
    let world = start();
    let ext = StaticKeypair::generate().unwrap();
    let ext_public = ext.public_key();
    let ext_private = ext.export_private();

    let mut browser = Browser::launch(&world, true);
    let mut client = ExtensionClient::new(
        StaticKeypair::from_private(ext_private.clone()),
        ORIGIN,
        "Chrome · 测试",
    );
    let service_public = pair(&mut browser, &mut client);
    let status = browser.call(&mut client, Call::Status);
    assert!(matches!(status, ServerMessage::Ok { .. }), "{status:?}");

    world.svc.revoke(&ext_public).unwrap();
    // 服务主动断开 socket，host 随之退出，浏览器端口收到 EOF
    assert!(read_native_frame(&mut browser.stdout).is_err());
    assert!(browser.child.wait().unwrap().success());

    let mut browser = Browser::launch(&world, true);
    let mut client = ExtensionClient::new(
        StaticKeypair::from_private(ext_private),
        ORIGIN,
        "Chrome · 测试",
    );
    browser.send(&ExtensionClient::hello().unwrap());
    browser.send(&client.start_session(&service_public).unwrap());
    let (_, events) = client.on_frame(&browser.recv()).unwrap();
    assert!(
        matches!(events[0], ClientEvent::Error(ErrorCode::NotPaired)),
        "{events:?}"
    );
}
