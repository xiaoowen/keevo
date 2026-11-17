//! 端到端测试：扩展 → native host（只转发）→ Vault Service，全部在内存中进行。

use std::cell::Cell;
use std::sync::Arc;

use keevo_crypto::StaticKeypair;

use crate::client::{ClientEvent, ExtensionClient};
use crate::message::{
    Call, CallResult, Candidate, ControlFrame, ErrorCode, Event, FillData, HostHello, ServerMessage,
};
use crate::service::{MemoryPairingStore, Output, PairingStore, ServiceConnection, VaultBackend};

const ORIGIN: &str = "chrome-extension://keevoextensionidkeevoextensioni/";

struct Backend {
    locked: Cell<bool>,
}

impl Backend {
    fn host(url: &str) -> &str {
        url.split("://")
            .nth(1)
            .unwrap_or("")
            .split('/')
            .next()
            .unwrap_or("")
    }
}

impl VaultBackend for Backend {
    fn is_locked(&self) -> bool {
        self.locked.get()
    }
    fn candidates(&self, url: &str) -> Vec<Candidate> {
        if Self::host(url) == "github.com" {
            vec![Candidate {
                item_id: "gh".into(),
                title: "GitHub".into(),
                subtitle: "octocat".into(),
            }]
        } else {
            Vec::new()
        }
    }
    fn item_matches(&self, item_id: &str, url: &str) -> Option<bool> {
        (item_id == "gh").then(|| Self::host(url) == "github.com")
    }
    fn fill(&self, item_id: &str) -> Option<FillData> {
        (item_id == "gh").then(|| FillData {
            username: "octocat".into(),
            password: "s3cret".into(),
            totp: None,
        })
    }
}

/// Vault Service 一侧的世界：服务密钥、配对存储、后端。
struct Service {
    key: Arc<StaticKeypair>,
    store: MemoryPairingStore,
    backend: Backend,
}

impl Service {
    fn new() -> Self {
        Self {
            key: Arc::new(StaticKeypair::generate().unwrap()),
            store: MemoryPairingStore::default(),
            backend: Backend {
                locked: Cell::new(false),
            },
        }
    }

    /// 模拟 native host：先发 HostHello，再原样转发扩展的帧。
    fn connect(&self, origin: &str) -> ServiceConnection {
        let mut conn = ServiceConnection::new(self.key.clone());
        let hello = serde_json::to_vec(&HostHello {
            v: 1,
            client: "native-host".into(),
            extension_origin: origin.into(),
            browser: "com.google.Chrome".into(),
        })
        .unwrap();
        assert!(conn.on_frame(&hello, &self.store, &self.backend).is_empty());
        conn
    }
}

#[derive(Default)]
struct Delivered {
    to_client: Vec<Vec<u8>>,
    confirm: Option<[u8; 6]>,
    closed: bool,
}

fn deliver(svc: &Service, conn: &mut ServiceConnection, frame: &[u8]) -> Delivered {
    collect(conn.on_frame(frame, &svc.store, &svc.backend))
}

fn collect(outputs: Vec<Output>) -> Delivered {
    let mut d = Delivered::default();
    for o in outputs {
        match o {
            Output::Send(f) => d.to_client.push(f),
            Output::ConfirmPairing { sas, .. } => d.confirm = Some(sas),
            Output::Close => d.closed = true,
        }
    }
    d
}

/// 完整配对流程，返回扩展客户端与保存下来的服务公钥。
fn pair(svc: &mut Service, accept: bool) -> (ExtensionClient, Option<[u8; 32]>, ServiceConnection) {
    let mut client =
        ExtensionClient::new(StaticKeypair::generate().unwrap(), ORIGIN, "Chrome · 个人");
    let mut conn = svc.connect(ORIGIN);

    let d = deliver(svc, &mut conn, &client.start_pairing().unwrap());
    let (frames, events) = client.on_frame(&d.to_client[0]).unwrap();
    let ClientEvent::ShowSas(client_sas) = events[0] else {
        panic!("{events:?}")
    };

    let d = deliver(svc, &mut conn, &frames[0]);
    assert_eq!(d.confirm, Some(client_sas), "两端的 SAS 必须一致");

    let d = collect(conn.confirm_pairing(accept, &mut svc.store));
    let (_, events) = client.on_frame(&d.to_client[0]).unwrap();
    match &events[0] {
        ClientEvent::Paired { service_public } => {
            assert_eq!(*service_public, svc.key.public_key());
            (client, Some(*service_public), conn)
        }
        ClientEvent::Error(code) => {
            assert_eq!(*code, ErrorCode::PairingRejected);
            assert!(d.closed);
            (client, None, conn)
        }
        other => panic!("{other:?}"),
    }
}

fn call(
    svc: &Service,
    conn: &mut ServiceConnection,
    client: &mut ExtensionClient,
    c: Call,
) -> ServerMessage {
    let (id, frame) = client.request(c).unwrap();
    let d = deliver(svc, conn, &frame);
    let (_, mut events) = client.on_frame(&d.to_client[0]).unwrap();
    match events.remove(0) {
        ClientEvent::Message(m) => {
            if let ServerMessage::Ok { id: rid, .. } | ServerMessage::Err { id: rid, .. } = &m {
                assert_eq!(*rid, id);
            }
            m
        }
        other => panic!("{other:?}"),
    }
}

fn error_code(m: &ServerMessage) -> Option<ErrorCode> {
    match m {
        ServerMessage::Err { error, .. } => Some(error.code),
        _ => None,
    }
}

#[test]
fn pairing_then_requests_with_minimal_disclosure() {
    let mut svc = Service::new();
    let (mut client, service_public, mut conn) = pair(&mut svc, true);
    assert!(service_public.is_some());
    assert_eq!(svc.store.len(), 1);
    assert!(conn.is_established());

    let status = call(&svc, &mut conn, &mut client, Call::Status);
    assert_eq!(
        status,
        ServerMessage::Ok {
            id: 1,
            result: CallResult::Status { locked: false }
        }
    );

    let c = call(
        &svc,
        &mut conn,
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

    let fill = call(
        &svc,
        &mut conn,
        &mut client,
        Call::Fill {
            item_id: "gh".into(),
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
    assert_eq!(data.password, "s3cret");

    // 钓鱼网站：即便扩展被攻破、直接请求填充，也拿不到秘密
    let phish = call(
        &svc,
        &mut conn,
        &mut client,
        Call::Fill {
            item_id: "gh".into(),
            url: "https://github.com.evil.example/login".into(),
        },
    );
    assert_eq!(error_code(&phish), Some(ErrorCode::UrlMismatch));

    // 锁定后只回答 status
    svc.backend.locked.set(true);
    let pushed = collect(conn.push_event(Event::Locked));
    let (_, events) = client.on_frame(&pushed.to_client[0]).unwrap();
    assert!(matches!(
        &events[0],
        ClientEvent::Message(ServerMessage::Event {
            event: Event::Locked
        })
    ));
    let locked = call(
        &svc,
        &mut conn,
        &mut client,
        Call::Candidates {
            url: "https://github.com".into(),
        },
    );
    assert_eq!(error_code(&locked), Some(ErrorCode::Locked));
    let status = call(&svc, &mut conn, &mut client, Call::Status);
    assert!(matches!(
        status,
        ServerMessage::Ok {
            result: CallResult::Status { locked: true },
            ..
        }
    ));
}

#[test]
fn reconnect_with_ik_session() {
    let mut svc = Service::new();
    let (client, service_public, _) = pair(&mut svc, true);
    let public = client.public_key();

    // 模拟扩展重启：从存储读回同一把静态密钥，用 IK 重新建立会话
    let mut client = client_with_same_key(client);
    assert_eq!(client.public_key(), public);
    let mut conn = svc.connect(ORIGIN);
    let d = deliver(
        &svc,
        &mut conn,
        &client.start_session(&service_public.unwrap()).unwrap(),
    );
    let (_, events) = client.on_frame(&d.to_client[0]).unwrap();
    assert!(matches!(events[0], ClientEvent::Established));
    let status = call(&svc, &mut conn, &mut client, Call::Status);
    assert!(matches!(status, ServerMessage::Ok { .. }));
}

/// 测试辅助：用已有客户端的密钥构造一个处于初始状态的新客户端（模拟扩展重启）。
fn client_with_same_key(old: ExtensionClient) -> ExtensionClient {
    let private = old.export_key_for_tests();
    ExtensionClient::new(
        StaticKeypair::from_private(private),
        ORIGIN,
        "Chrome · 个人",
    )
}

#[test]
fn unpaired_extension_cannot_open_a_session() {
    let svc = Service::new();
    let mut stranger = ExtensionClient::new(StaticKeypair::generate().unwrap(), ORIGIN, "x");
    let mut conn = svc.connect(ORIGIN);
    let d = deliver(
        &svc,
        &mut conn,
        &stranger.start_session(&svc.key.public_key()).unwrap(),
    );
    assert!(d.closed);
    let (_, events) = stranger.on_frame(&d.to_client[0]).unwrap();
    assert!(matches!(
        events[0],
        ClientEvent::Error(ErrorCode::NotPaired)
    ));
}

#[test]
fn paired_key_from_another_extension_origin_is_rejected() {
    let mut svc = Service::new();
    let (client, service_public, _) = pair(&mut svc, true);
    let mut client = client_with_same_key(client);
    // 同一把密钥被另一个扩展（另一个来源）拿去用：host 报告的来源与配对记录不符
    let mut conn = svc.connect("chrome-extension://someotherextensionid/");
    let d = deliver(
        &svc,
        &mut conn,
        &client.start_session(&service_public.unwrap()).unwrap(),
    );
    assert!(d.closed);
    // 扩展侧的 prologue 用的是自己的来源，双方 prologue 不同，服务端握手必然失败
    assert!(conn.is_closed());

    // 更强的攻击：偷到私钥的另一个扩展在 prologue 与 host 两处都使用自己的来源，握手本身会成功，
    // 必须靠配对记录中的来源比对拦下（spec/ipc.md §4.3 第 2 步）
    let other = "chrome-extension://someotherextensionid/";
    let mut thief = ExtensionClient::new(
        StaticKeypair::from_private(client.export_key_for_tests()),
        other,
        "x",
    );
    let mut conn = svc.connect(other);
    let d = deliver(
        &svc,
        &mut conn,
        &thief.start_session(&service_public.unwrap()).unwrap(),
    );
    assert!(d.closed);
    let (_, events) = thief.on_frame(&d.to_client[0]).unwrap();
    assert!(matches!(
        events[0],
        ClientEvent::Error(ErrorCode::NotPaired)
    ));
}

#[test]
fn rejected_pairing_saves_nothing() {
    let mut svc = Service::new();
    let (_, service_public, conn) = pair(&mut svc, false);
    assert!(service_public.is_none());
    assert!(svc.store.is_empty());
    assert!(conn.is_closed());
}

#[test]
fn requests_before_confirmation_and_garbage_close_the_connection() {
    let svc = Service::new();
    let mut client = ExtensionClient::new(StaticKeypair::generate().unwrap(), ORIGIN, "x");
    let mut conn = svc.connect(ORIGIN);
    let d = deliver(&svc, &mut conn, &client.start_pairing().unwrap());
    let (frames, _) = client.on_frame(&d.to_client[0]).unwrap();
    let d = deliver(&svc, &mut conn, &frames[0]);
    assert!(d.confirm.is_some());
    // 用户确认之前发送任何东西都会断开
    let d = deliver(
        &svc,
        &mut conn,
        &ControlFrame::Noise { d: "AAAA".into() }.to_json().unwrap(),
    );
    assert!(d.closed && conn.is_closed());

    let mut conn = svc.connect(ORIGIN);
    let d = deliver(&svc, &mut conn, b"not json");
    assert!(d.closed);

    // 第一帧必须是 HostHello
    let mut conn = ServiceConnection::new(svc.key.clone());
    let d = deliver(
        &svc,
        &mut conn,
        &ControlFrame::Hello { v: 1 }.to_json().unwrap(),
    );
    assert!(d.closed);
}

#[test]
fn revoked_pairing_blocks_new_sessions() {
    let mut svc = Service::new();
    let (client, service_public, _) = pair(&mut svc, true);
    svc.store.revoke(&client.public_key());
    assert!(svc.store.find(&client.public_key()).is_none());
    let mut client = client_with_same_key(client);
    let mut conn = svc.connect(ORIGIN);
    let d = deliver(
        &svc,
        &mut conn,
        &client.start_session(&service_public.unwrap()).unwrap(),
    );
    assert!(d.closed);
}
