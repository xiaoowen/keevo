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
    store: std::cell::RefCell<MemoryPairingStore>,
    backend: Backend,
}

impl Service {
    fn new() -> Self {
        Self {
            key: Arc::new(StaticKeypair::generate().unwrap()),
            store: std::cell::RefCell::default(),
            backend: Backend {
                locked: Cell::new(false),
            },
        }
    }

    /// 模拟 native host：先发 HostHello，再原样转发扩展的帧。按最新的协议版本。
    fn connect(&self, origin: &str) -> ServiceConnection {
        self.connect_v(origin, crate::message::PROTOCOL_VERSION)
    }

    /// 按指定的协议版本连接（host 把扩展 hello 中的版本原样转进 HostHello）。
    fn connect_v(&self, origin: &str, v: u32) -> ServiceConnection {
        let mut conn = ServiceConnection::new(self.key.clone());
        let hello = serde_json::to_vec(&HostHello {
            v,
            client: "native-host".into(),
            extension_origin: origin.into(),
            browser: "com.google.Chrome".into(),
        })
        .unwrap();
        assert!(
            conn.on_frame(&hello, &mut *self.store.borrow_mut(), &self.backend)
                .is_empty()
        );
        conn
    }
}

#[derive(Default)]
struct Delivered {
    to_client: Vec<Vec<u8>>,
    confirm: Option<[u8; 6]>,
    closed: bool,
    started: bool,
    authorize: Option<crate::service::FillRequest>,
    write: Option<crate::service::WriteRequest>,
    paused: bool,
}

fn deliver(svc: &Service, conn: &mut ServiceConnection, frame: &[u8]) -> Delivered {
    collect(conn.on_frame(frame, &mut *svc.store.borrow_mut(), &svc.backend))
}

fn collect(outputs: Vec<Output>) -> Delivered {
    let mut d = Delivered::default();
    for o in outputs {
        match o {
            Output::Send(f) => d.to_client.push(f),
            Output::ConfirmPairing { sas, .. } => d.confirm = Some(sas),
            Output::PairingStarted { .. } => d.started = true,
            Output::AuthorizeFill(req) => d.authorize = Some(req),
            Output::Write(req) => d.write = Some(req),
            Output::FillPaused { .. } => d.paused = true,
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

    let d = collect(conn.confirm_pairing(
        accept,
        &mut *svc.store.borrow_mut(),
        svc.backend.unlock_epoch(),
    ));
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
    assert_eq!(svc.store.borrow_mut().len(), 1);
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
    let private = old.export_private_key();
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
        StaticKeypair::from_private(client.export_private_key()),
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
    assert!(svc.store.borrow_mut().is_empty());
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
    svc.store.borrow_mut().revoke(&client.public_key()).unwrap();
    assert!(svc.store.borrow_mut().find(&client.public_key()).is_none());
    let mut client = client_with_same_key(client);
    let mut conn = svc.connect(ORIGIN);
    let d = deliver(
        &svc,
        &mut conn,
        &client.start_session(&service_public.unwrap()).unwrap(),
    );
    assert!(d.closed);
}

// ---------------------------------------------------------------- 评审 2026-11-18 F1

#[test]
fn review_f1_revoking_a_pairing_cuts_off_established_sessions() {
    let mut svc = Service::new();
    let (mut client, _, mut conn) = pair(&mut svc, true);
    let before = call(
        &svc,
        &mut conn,
        &mut client,
        Call::Fill {
            item_id: "gh".into(),
            url: "https://github.com/login".into(),
        },
    );
    assert!(matches!(before, ServerMessage::Ok { .. }));

    svc.store.borrow_mut().revoke(&client.public_key()).unwrap();

    // 撤销之后，已建立的会话也不能再取得任何数据，且连接被关闭
    let (_, frame) = client
        .request(Call::Fill {
            item_id: "gh".into(),
            url: "https://github.com/login".into(),
        })
        .unwrap();
    let d = deliver(&svc, &mut conn, &frame);
    assert!(d.closed, "撤销后连接应被关闭");
    let (_, events) = client.on_frame(&d.to_client[0]).unwrap();
    assert!(
        matches!(events[0], ClientEvent::Error(ErrorCode::NotPaired)),
        "{events:?}"
    );
}

// ---------------------------------------------------------------- 评审 2026-11-18 I1 与规范一致性

/// 手工构造配对第 1–3 条消息，便于模拟不守规矩的发起方。返回第 3 条消息送达后的结果。
fn manual_pairing(
    conn_timeout: Option<std::time::Duration>,
    msg1_payload: impl FnOnce(&StaticKeypair) -> Vec<u8>,
    msg3_payload: &[u8],
) -> Delivered {
    use crate::message::{b64, unb64};
    let svc = Service::new();
    let ext = StaticKeypair::generate().unwrap();
    let mut conn = match conn_timeout {
        Some(t) => {
            let mut c = ServiceConnection::new(svc.key.clone()).with_pairing_timeout(t);
            let hello = serde_json::to_vec(&HostHello {
                v: 1,
                client: "native-host".into(),
                extension_origin: ORIGIN.into(),
                browser: "com.google.Chrome".into(),
            })
            .unwrap();
            assert!(
                c.on_frame(&hello, &mut *svc.store.borrow_mut(), &svc.backend)
                    .is_empty()
            );
            c
        }
        None => svc.connect_v(ORIGIN, 1),
    };
    let mut hs = keevo_crypto::Handshake::pair_initiator(&ext, ORIGIN, 1).unwrap();
    let msg1 = hs.write(&msg1_payload(&ext)).unwrap();
    let d = deliver(
        &svc,
        &mut conn,
        &ControlFrame::Pair { d: b64(&msg1) }.to_json().unwrap(),
    );
    if d.closed {
        return d;
    }
    let ControlFrame::Noise { d: m2 } = ControlFrame::from_json(&d.to_client[0]).unwrap() else {
        panic!("应收到第 2 条消息")
    };
    assert!(hs.read(&unb64(&m2).unwrap()).unwrap().is_empty());
    std::thread::sleep(std::time::Duration::from_millis(5));
    let msg3 = hs.write(msg3_payload).unwrap();
    deliver(
        &svc,
        &mut conn,
        &ControlFrame::Noise { d: b64(&msg3) }.to_json().unwrap(),
    )
}

/// 第 3 条消息的负载：nonce ‖ 显示名的 UTF-8 字节（§4.2）。
fn msg3(nonce: [u8; 32], name: &str) -> Vec<u8> {
    let mut p = nonce.to_vec();
    p.extend_from_slice(name.as_bytes());
    p
}

fn honest_commitment(
    nonce: [u8; 32],
    name: &'static str,
) -> impl FnOnce(&StaticKeypair) -> Vec<u8> {
    move |ext| keevo_crypto::pairing_commitment(&ext.public_key(), &msg3(nonce, name)).to_vec()
}

#[test]
fn review_i1_honest_manual_pairing_reaches_confirmation() {
    let d = manual_pairing(None, honest_commitment([1; 32], "x"), &msg3([1; 32], "x"));
    assert!(d.confirm.is_some() && !d.closed);
}

/// 第 3 条消息与第 1 条消息的承诺不符（换了随机数、显示名或静态密钥）时拒绝，攻击者因此无法在看到
/// 对方贡献后再调整自己的消息来搜索 SAS。
#[test]
fn review_i1_third_message_must_match_commitment() {
    let other_nonce = manual_pairing(None, honest_commitment([1; 32], "x"), &msg3([2; 32], "x"));
    assert!(other_nonce.closed && other_nonce.confirm.is_none());
    let other_name = manual_pairing(None, honest_commitment([1; 32], "x"), &msg3([1; 32], "y"));
    assert!(other_name.closed && other_name.confirm.is_none());
    let other_key = manual_pairing(
        None,
        |_| {
            let k = StaticKeypair::generate().unwrap().public_key();
            keevo_crypto::pairing_commitment(&k, &msg3([1; 32], "x")).to_vec()
        },
        &msg3([1; 32], "x"),
    );
    assert!(other_key.closed && other_key.confirm.is_none());
}

/// 第 1 条消息的负载必须恰好是 32 字节的承诺。
#[test]
fn first_pairing_message_must_carry_exactly_a_commitment() {
    for payload in [Vec::new(), vec![0u8; 31], vec![0u8; 33]] {
        let d = manual_pairing(None, move |_| payload, &msg3([1; 32], "x"));
        assert!(d.closed && d.confirm.is_none());
    }
}

/// 60 秒时限从收到第 1 条消息起算：第 3 条消息超时到达即拒绝，不进入用户确认。
#[test]
fn pairing_deadline_starts_at_first_message() {
    let d = manual_pairing(
        Some(std::time::Duration::ZERO),
        honest_commitment([1; 32], "x"),
        &msg3([1; 32], "x"),
    );
    assert!(d.closed && d.confirm.is_none());
}

/// 用户确认超过时限时视为拒绝，不保存配对。
#[test]
fn late_confirmation_is_treated_as_rejection() {
    let svc = Service::new();
    let mut client =
        ExtensionClient::new(StaticKeypair::generate().unwrap(), ORIGIN, "Chrome · 个人")
            .with_version(1)
            .unwrap();
    let mut conn = ServiceConnection::new(svc.key.clone())
        .with_pairing_timeout(std::time::Duration::from_millis(200));
    let hello = serde_json::to_vec(&HostHello {
        v: 1,
        client: "native-host".into(),
        extension_origin: ORIGIN.into(),
        browser: "com.google.Chrome".into(),
    })
    .unwrap();
    assert!(
        conn.on_frame(&hello, &mut *svc.store.borrow_mut(), &svc.backend)
            .is_empty()
    );
    let d = deliver(&svc, &mut conn, &client.start_pairing().unwrap());
    let (frames, _) = client.on_frame(&d.to_client[0]).unwrap();
    let d = deliver(&svc, &mut conn, &frames[0]);
    assert!(d.confirm.is_some());
    std::thread::sleep(std::time::Duration::from_millis(250));
    let d = collect(conn.confirm_pairing(
        true,
        &mut *svc.store.borrow_mut(),
        svc.backend.unlock_epoch(),
    ));
    assert!(d.closed);
    assert!(
        svc.store.borrow_mut().find(&client.public_key()).is_none(),
        "超时后不得保存配对"
    );
}

/// IK 第 1 条消息的负载必须为空。
#[test]
fn session_first_message_payload_must_be_empty() {
    use crate::message::b64;
    let svc = Service::new();
    let ext_private = StaticKeypair::generate().unwrap().export_private();
    let mut client = ExtensionClient::new(
        StaticKeypair::from_private(ext_private.clone()),
        ORIGIN,
        "Chrome · 个人",
    );
    let mut conn = svc.connect(ORIGIN);
    let d = deliver(&svc, &mut conn, &client.start_pairing().unwrap());
    let (frames, _) = client.on_frame(&d.to_client[0]).unwrap();
    deliver(&svc, &mut conn, &frames[0]);
    collect(conn.confirm_pairing(
        true,
        &mut *svc.store.borrow_mut(),
        svc.backend.unlock_epoch(),
    ));
    assert!(svc.store.borrow_mut().find(&client.public_key()).is_some());

    let ext = StaticKeypair::from_private(ext_private);
    let mut hs =
        keevo_crypto::Handshake::session_initiator(&ext, &svc.key.public_key(), ORIGIN, 1).unwrap();
    let msg1 = hs.write(b"smuggled").unwrap();
    let mut conn = svc.connect_v(ORIGIN, 1);
    let d = deliver(
        &svc,
        &mut conn,
        &ControlFrame::Session { d: b64(&msg1) }.to_json().unwrap(),
    );
    assert!(d.closed);
}

// ---------------------------------------------------------------- 评审第二轮 G1

/// 第二轮 G1：第 3 条消息只要与承诺的原始字节有一个字节不同就拒绝，不存在"同语义、不同编码"。
#[test]
fn review2_g1_any_byte_change_in_third_message_is_rejected() {
    let trailing = manual_pairing(
        None,
        honest_commitment([1; 32], "Chrome"),
        &msg3([1; 32], "Chrome "),
    );
    assert!(trailing.closed && trailing.confirm.is_none());
    let mut bad_utf8 = msg3([1; 32], "");
    bad_utf8.push(0xff);
    let invalid = manual_pairing(
        None,
        {
            let b = bad_utf8.clone();
            move |ext| keevo_crypto::pairing_commitment(&ext.public_key(), &b).to_vec()
        },
        &bad_utf8,
    );
    assert!(
        invalid.closed && invalid.confirm.is_none(),
        "显示名必须是合法 UTF-8"
    );
    let honest = manual_pairing(
        None,
        honest_commitment([1; 32], "Chrome"),
        &msg3([1; 32], "Chrome"),
    );
    assert!(honest.confirm.is_some());
}

/// 第二轮 G1：同一时刻最多一个配对；每小时最多开始 10 次。计数点是服务发出第 2 条消息，
/// 中途放弃的尝试同样计数。
#[test]
fn review2_g1_pairing_attempts_are_limited() {
    use crate::service::{MAX_PAIRING_STARTS_PER_HOUR, PairingGate};
    let svc = Service::new();
    let gate = Arc::new(PairingGate::default());
    let start = |gate: &Arc<PairingGate>| {
        let mut conn = ServiceConnection::new(svc.key.clone()).with_pairing_gate(gate.clone());
        let hello = serde_json::to_vec(&HostHello {
            v: 1,
            client: "native-host".into(),
            extension_origin: ORIGIN.into(),
            browser: "com.google.Chrome".into(),
        })
        .unwrap();
        assert!(
            conn.on_frame(&hello, &mut *svc.store.borrow_mut(), &svc.backend)
                .is_empty()
        );
        let mut client = ExtensionClient::new(StaticKeypair::generate().unwrap(), ORIGIN, "x")
            .with_version(1)
            .unwrap();
        let d = deliver(&svc, &mut conn, &client.start_pairing().unwrap());
        (conn, client, d)
    };
    let (first, _, d) = start(&gate);
    assert!(d.started && !d.closed);
    // 第一个配对进行中，第二个被拒绝
    let (_, mut client2, d2) = start(&gate);
    assert!(d2.closed);
    let (_, events) = client2.on_frame(&d2.to_client[0]).unwrap();
    assert!(
        matches!(events[0], ClientEvent::Error(ErrorCode::PairingLimited)),
        "{events:?}"
    );
    // 放弃（断开）后释放；放弃的尝试仍然计数
    drop(first);
    for _ in 1..MAX_PAIRING_STARTS_PER_HOUR {
        let (conn, _, d) = start(&gate);
        assert!(!d.closed);
        drop(conn);
    }
    let (_, _, d) = start(&gate);
    assert!(d.closed, "超过每小时次数上限");
}

/// 第二轮 G1：显示名去掉控制字符与格式字符（双向文字控制符、零宽字符），按 Unicode 标量截断到 64 个。
#[test]
fn review2_g1_display_name_is_sanitized_consistently() {
    use crate::message::sanitize_display_name;
    assert_eq!(
        sanitize_display_name("Chrome\u{202e}emorhC\u{200b}\n"),
        "ChromeemorhC"
    );
    assert_eq!(sanitize_display_name(&"界".repeat(100)).chars().count(), 64);
    let client = ExtensionClient::new(StaticKeypair::generate().unwrap(), ORIGIN, "A\u{2066}B");
    assert_eq!(client.display_name(), "AB");
}

// ---------------------------------------------------------------- 评审第三轮 §4.4

/// 第三轮 §4.4：配对记录保存失败时按拒绝处理，扩展收不到 `paired`。
#[test]
fn review3_pairing_save_failure_is_a_rejection() {
    struct FailingStore;
    impl PairingStore for FailingStore {
        fn find(&self, _: &[u8; 32]) -> Option<crate::service::PairingRecord> {
            None
        }
        fn save(&mut self, _: crate::service::PairingRecord) -> std::io::Result<()> {
            Err(std::io::Error::other("disk full"))
        }
        fn revoke(&mut self, _: &[u8; 32]) -> std::io::Result<()> {
            Ok(())
        }
    }
    let svc = Service::new();
    let mut client =
        ExtensionClient::new(StaticKeypair::generate().unwrap(), ORIGIN, "Chrome · 个人");
    let mut conn = svc.connect(ORIGIN);
    let d = deliver(&svc, &mut conn, &client.start_pairing().unwrap());
    let (frames, _) = client.on_frame(&d.to_client[0]).unwrap();
    let d = deliver(&svc, &mut conn, &frames[0]);
    assert!(d.confirm.is_some());
    let d = collect(conn.confirm_pairing(true, &mut FailingStore, svc.backend.unlock_epoch()));
    assert!(d.closed);
    let (_, events) = client.on_frame(&d.to_client[0]).unwrap();
    assert!(
        matches!(events[0], ClientEvent::Error(ErrorCode::PairingRejected)),
        "{events:?}"
    );
}

/// 第三轮 §4.4：保险库锁定时不接受配对，返回 `locked`，也不占用配对闸门。
#[test]
fn review3_pairing_requires_unlocked_vault() {
    let svc = Service::new();
    svc.backend.locked.set(true);
    let mut client = ExtensionClient::new(StaticKeypair::generate().unwrap(), ORIGIN, "x");
    let mut conn = svc.connect(ORIGIN);
    let d = deliver(&svc, &mut conn, &client.start_pairing().unwrap());
    assert!(d.closed && !d.started);
    let (_, events) = client.on_frame(&d.to_client[0]).unwrap();
    assert!(
        matches!(events[0], ClientEvent::Error(ErrorCode::Locked)),
        "{events:?}"
    );
}

// ---------------------------------------------------------------- 评审第四轮

/// 第四轮 J5：配对开始后保险库被锁定（或锁定后又解锁），确认时按拒绝处理，不保存配对。
#[test]
fn review4_j5_lock_during_pairing_prevents_save() {
    let svc = Service::new();
    let mut client = ExtensionClient::new(StaticKeypair::generate().unwrap(), ORIGIN, "x");
    let mut conn = svc.connect(ORIGIN);
    let d = deliver(&svc, &mut conn, &client.start_pairing().unwrap());
    let (frames, _) = client.on_frame(&d.to_client[0]).unwrap();
    svc.backend.locked.set(true);
    let d = deliver(&svc, &mut conn, &frames[0]);
    assert!(d.confirm.is_some());
    let d = collect(conn.confirm_pairing(
        true,
        &mut *svc.store.borrow_mut(),
        svc.backend.unlock_epoch(),
    ));
    assert!(d.closed);
    assert!(
        svc.store.borrow_mut().find(&client.public_key()).is_none(),
        "锁定时不得保存配对"
    );
    // 锁定后又解锁：代次已变，旧的确认同样无效
    let (_, events) = client.on_frame(&d.to_client[0]).unwrap();
    assert!(
        matches!(events[0], ClientEvent::Error(ErrorCode::Locked)),
        "{events:?}"
    );
    svc.backend.locked.set(false);
    let mut client = ExtensionClient::new(StaticKeypair::generate().unwrap(), ORIGIN, "x");
    let mut conn = svc.connect(ORIGIN);
    let d = deliver(&svc, &mut conn, &client.start_pairing().unwrap());
    let (frames, _) = client.on_frame(&d.to_client[0]).unwrap();
    deliver(&svc, &mut conn, &frames[0]);
    let d = collect(conn.confirm_pairing(true, &mut *svc.store.borrow_mut(), Some(99)));
    assert!(d.closed);
    assert!(
        svc.store.borrow_mut().find(&client.public_key()).is_none(),
        "不是同一次解锁"
    );
}

/// 第四轮 J7（IPC 部分）：消息只接受规范编码。多余空白、调换字段顺序、未知字段都拒绝。
#[test]
fn review4_ipc_messages_must_be_canonical() {
    let ok = br#"{"t":"hello","v":1}"#;
    assert_eq!(
        ControlFrame::from_json(ok).unwrap().to_json().unwrap(),
        ok.to_vec()
    );
    // 语义相同、但不是规范编码：多余空白、调换字段顺序。Serde 本身接受它们，规范编码检查拒绝
    for bad in [
        &br#"{"t":"hello", "v":1}"#[..],
        br#"{"v":1,"t":"hello"}"#,
        br#"{"t":"hello","v":1.0}"#,
    ] {
        assert!(
            ControlFrame::from_json(bad).is_err(),
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
    assert!(
        serde_json::from_slice::<ControlFrame>(br#"{"v":1,"t":"hello"}"#).is_ok(),
        "前提：Serde 接受调换顺序"
    );
}

/// 第四轮 J4：放不进一条 Noise 消息的 `fill` 响应返回 `response_too_large`，连接保持可用；
/// `candidates` 最多 20 个，标题截短。
#[test]
fn review4_j4_responses_are_bounded() {
    struct Big;
    impl VaultBackend for Big {
        fn is_locked(&self) -> bool {
            false
        }
        fn candidates(&self, _: &str) -> Vec<Candidate> {
            (0..50)
                .map(|i| Candidate {
                    item_id: format!("i{i}"),
                    title: "长".repeat(5000),
                    subtitle: "s".into(),
                })
                .collect()
        }
        fn item_matches(&self, _: &str, _: &str) -> Option<bool> {
            Some(true)
        }
        fn fill(&self, _: &str) -> Option<FillData> {
            Some(FillData {
                username: "u".into(),
                password: "p".repeat(70_000),
                totp: None,
            })
        }
    }
    let mut svc = Service::new();
    let (mut client, _, mut conn) = pair(&mut svc, true);
    let mut send = |conn: &mut ServiceConnection, c: Call| {
        let (_, frame) = client.request(c).unwrap();
        let d = collect(conn.on_frame(&frame, &mut *svc.store.borrow_mut(), &Big));
        assert!(!d.closed, "超大响应不应断开连接");
        let (_, mut events) = client.on_frame(&d.to_client[0]).unwrap();
        match events.remove(0) {
            ClientEvent::Message(m) => m,
            other => panic!("{other:?}"),
        }
    };
    let fill = send(
        &mut conn,
        Call::Fill {
            item_id: "i".into(),
            url: "https://a.example".into(),
        },
    );
    assert_eq!(error_code(&fill), Some(ErrorCode::ResponseTooLarge));
    let c = send(
        &mut conn,
        Call::Candidates {
            url: "https://a.example".into(),
        },
    );
    let ServerMessage::Ok {
        result: CallResult::Candidates { items },
        ..
    } = c
    else {
        panic!("{c:?}")
    };
    assert_eq!(items.len(), crate::message::MAX_CANDIDATES);
    assert!(
        items
            .iter()
            .all(|i| i.title.chars().count() == crate::message::MAX_CANDIDATE_TEXT)
    );
}

/// 第四轮：规范已定义的 `not_authorized` 与新的 `response_too_large` 都能解码。
#[test]
fn review4_declared_error_codes_are_decodable() {
    for code in ["not_authorized", "response_too_large", "pairing_limited"] {
        let json = format!(r#"{{"t":"error","code":"{code}"}}"#);
        let frame = ControlFrame::from_json(json.as_bytes()).unwrap();
        assert_eq!(frame.to_json().unwrap(), json.into_bytes());
    }
}

/// 首次解锁前配对记录还不可读（它们存在加密数据库中）：IK 握手返回 `locked`，而不是 `not_paired`
/// （spec/ipc.md §4.2 第 6 步、§4.3 第 2 步）。
#[test]
fn ik_before_pairings_are_loaded_returns_locked() {
    struct NotLoaded<'a>(&'a MemoryPairingStore);
    impl PairingStore for NotLoaded<'_> {
        fn is_loaded(&self) -> bool {
            false
        }
        fn find(&self, pk: &[u8; 32]) -> Option<crate::service::PairingRecord> {
            self.0.find(pk)
        }
        fn save(&mut self, _: crate::service::PairingRecord) -> std::io::Result<()> {
            Ok(())
        }
        fn revoke(&mut self, _: &[u8; 32]) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut svc = Service::new();
    let (client, service_public, _) = pair(&mut svc, true);
    let mut client = client_with_same_key(client);
    let mut conn = svc.connect(ORIGIN);
    let frame = client.start_session(&service_public.unwrap()).unwrap();
    let out = collect(conn.on_frame(&frame, &mut NotLoaded(&svc.store.borrow()), &svc.backend));
    assert!(out.closed);
    let err: ControlFrame = ControlFrame::from_json(&out.to_client[0]).unwrap();
    assert!(
        matches!(
            err,
            ControlFrame::Error {
                code: ErrorCode::Locked
            }
        ),
        "{err:?}"
    );
}

/// fill 的按站点授权（spec/ipc.md §5.2）：未授权时挂起请求并请用户确认，确认前不返回任何秘密；
/// 挂起期间的第二个 fill 被拒；确认后返回凭据；拒绝、等待期间锁定都不返回秘密；暂停时拒绝并通知应用。
#[test]
fn fill_requires_site_authorization() {
    use crate::service::{FillGate, PairingRecord};
    use std::collections::VecDeque;

    struct Gated<'a> {
        inner: &'a mut MemoryPairingStore,
        decisions: &'a mut VecDeque<FillGate>,
    }
    impl PairingStore for Gated<'_> {
        fn find(&self, pk: &[u8; 32]) -> Option<PairingRecord> {
            self.inner.find(pk)
        }
        fn save(&mut self, r: PairingRecord) -> std::io::Result<()> {
            self.inner.save(r)
        }
        fn revoke(&mut self, pk: &[u8; 32]) -> std::io::Result<()> {
            self.inner.revoke(pk)
        }
        fn fill_gate(
            &mut self,
            _: &[u8; 32],
            item: &str,
            site: &str,
            _: std::time::Instant,
        ) -> FillGate {
            assert_eq!(
                (item, site),
                ("gh", "https://github.com"),
                "站点规范化为 scheme://host"
            );
            self.decisions.pop_front().unwrap_or(FillGate::Allowed)
        }
    }

    let mut svc = Service::new();
    let (mut client, _, mut conn) = pair(&mut svc, true);
    let mut decisions = VecDeque::new();
    let fill = Call::Fill {
        item_id: "gh".into(),
        url: "https://github.com/login?x=1#y".into(),
    };
    let send = |svc: &Service,
                conn: &mut ServiceConnection,
                client: &mut ExtensionClient,
                decisions: &mut VecDeque<FillGate>,
                c: Call| {
        let (_, frame) = client.request(c).unwrap();
        collect(conn.on_frame(
            &frame,
            &mut Gated {
                inner: &mut svc.store.borrow_mut(),
                decisions,
            },
            &svc.backend,
        ))
    };
    let reply = |client: &mut ExtensionClient, d: &Delivered, i: usize| {
        let (_, mut events) = client.on_frame(&d.to_client[i]).unwrap();
        match events.remove(0) {
            ClientEvent::Message(m) => m,
            other => panic!("{other:?}"),
        }
    };

    // 1. 未授权：挂起，不回复
    decisions.push_back(FillGate::NeedsAuthorization);
    let d = send(&svc, &mut conn, &mut client, &mut decisions, fill.clone());
    let req = d.authorize.expect("应请求授权");
    assert!(d.to_client.is_empty(), "确认前不返回任何东西");
    assert_eq!(
        (
            req.title.as_str(),
            req.site.as_str(),
            req.pairing_name.as_str()
        ),
        ("", "https://github.com", "Chrome · 个人")
    );
    // 挂起期间的第二个 fill 直接拒绝；其他请求照常
    decisions.push_back(FillGate::NeedsAuthorization);
    let d = send(&svc, &mut conn, &mut client, &mut decisions, fill.clone());
    assert_eq!(
        error_code(&reply(&mut client, &d, 0)),
        Some(ErrorCode::NotAuthorized)
    );
    let d = send(&svc, &mut conn, &mut client, &mut decisions, Call::Status);
    assert!(matches!(
        reply(&mut client, &d, 0),
        ServerMessage::Ok { .. }
    ));
    // 用户确认：返回凭据
    let d = collect(conn.resolve_fill(
        true,
        &mut Gated {
            inner: &mut svc.store.borrow_mut(),
            decisions: &mut decisions,
        },
        &svc.backend,
    ));
    assert!(matches!(
        reply(&mut client, &d, 0),
        ServerMessage::Ok {
            result: CallResult::Fill(_),
            ..
        }
    ));

    // 2. 用户拒绝
    decisions.push_back(FillGate::NeedsAuthorization);
    send(&svc, &mut conn, &mut client, &mut decisions, fill.clone());
    let d = collect(conn.resolve_fill(
        false,
        &mut Gated {
            inner: &mut svc.store.borrow_mut(),
            decisions: &mut decisions,
        },
        &svc.backend,
    ));
    assert_eq!(
        error_code(&reply(&mut client, &d, 0)),
        Some(ErrorCode::NotAuthorized)
    );

    // 3. 等待期间锁定
    decisions.push_back(FillGate::NeedsAuthorization);
    send(&svc, &mut conn, &mut client, &mut decisions, fill.clone());
    svc.backend.locked.set(true);
    let d = collect(conn.resolve_fill(
        true,
        &mut Gated {
            inner: &mut svc.store.borrow_mut(),
            decisions: &mut decisions,
        },
        &svc.backend,
    ));
    assert_eq!(
        error_code(&reply(&mut client, &d, 0)),
        Some(ErrorCode::Locked)
    );
    svc.backend.locked.set(false);

    // 4. 频率限制暂停
    decisions.push_back(FillGate::Paused);
    let d = send(&svc, &mut conn, &mut client, &mut decisions, fill.clone());
    assert!(d.paused, "通知应用");
    assert_eq!(
        error_code(&reply(&mut client, &d, 0)),
        Some(ErrorCode::NotAuthorized)
    );

    // 5. 网址不匹配时不做授权检查
    let d = send(
        &svc,
        &mut conn,
        &mut client,
        &mut decisions,
        Call::Fill {
            item_id: "gh".into(),
            url: "https://evil.example/".into(),
        },
    );
    assert!(d.authorize.is_none());
    assert_eq!(
        error_code(&reply(&mut client, &d, 0)),
        Some(ErrorCode::UrlMismatch)
    );
}

#[test]
fn sites_are_normalized() {
    use crate::service::site_of;
    assert_eq!(
        site_of("https://GitHub.com/login").as_deref(),
        Some("https://github.com")
    );
    assert_eq!(
        site_of("http://user:pw@example.com:8080/a?b#c").as_deref(),
        Some("http://example.com:8080")
    );
    for bad in [
        "ftp://example.com",
        "github.com",
        "https://",
        "javascript:alert(1)",
    ] {
        assert_eq!(site_of(bad), None, "{bad}");
    }
}

// ---- 协议 v2（spec/ipc.md §5.5）

fn secret(s: &str) -> crate::message::SecretText {
    crate::message::SecretText::new(s)
}

/// 版本协商：服务同时支持 v1 与 v2；不支持的版本返回 unsupported_version；版本写在 prologue 中，
/// 扩展按 v2、host 转来 v1（中间人改动版本）时握手失败。
#[test]
fn v2_negotiation_and_downgrade_protection() {
    use crate::message::ErrorCode;
    let svc = Service::new();
    // v1 扩展照常配对
    let mut v1 = ExtensionClient::new(StaticKeypair::generate().unwrap(), ORIGIN, "v1")
        .with_version(1)
        .unwrap();
    assert_eq!(v1.hello().unwrap(), br#"{"t":"hello","v":1}"#);
    let mut conn = svc.connect_v(ORIGIN, 1);
    let d = deliver(&svc, &mut conn, &v1.start_pairing().unwrap());
    let (frames, _) = v1.on_frame(&d.to_client[0]).unwrap();
    assert!(deliver(&svc, &mut conn, &frames[0]).confirm.is_some());

    // 不支持的版本
    let mut conn = ServiceConnection::new(svc.key.clone());
    let hello = br#"{"v":3,"client":"native-host","extension_origin":"chrome-extension://abcdefghijklmnopabcdefghijklmnop/","browser":"x"}"#;
    let d = collect(conn.on_frame(hello, &mut *svc.store.borrow_mut(), &svc.backend));
    assert!(d.closed);
    assert_eq!(
        control_error(&d.to_client[0]),
        Some(ErrorCode::UnsupportedVersion)
    );

    // 降级：扩展按 v2，服务看到 v1
    let mut v2 = ExtensionClient::new(StaticKeypair::generate().unwrap(), ORIGIN, "v2");
    assert_eq!(v2.version(), 2);
    let mut conn = svc.connect_v(ORIGIN, 1);
    let d = deliver(&svc, &mut conn, &v2.start_pairing().unwrap());
    assert!(
        v2.on_frame(&d.to_client[0]).is_err(),
        "prologue 不同，第 2 条消息认证失败"
    );
    assert!(
        ExtensionClient::new(StaticKeypair::generate().unwrap(), ORIGIN, "x")
            .with_version(3)
            .is_err()
    );
}

fn control_error(frame: &[u8]) -> Option<crate::message::ErrorCode> {
    match ControlFrame::from_json(frame).ok()? {
        ControlFrame::Error { code } => Some(code),
        _ => None,
    }
}

/// v1 的消息集合是封闭的：v1 会话中客户端不发送 save；手工构造的 save 被服务按 bad_request 拒绝并断开。
#[test]
fn v1_sessions_reject_v2_methods() {
    let mut svc = Service::new();
    let (client, service_public, _) = pair(&mut svc, true);
    let key = StaticKeypair::from_private(client.export_private_key());
    let mut v1 = ExtensionClient::new(key, ORIGIN, "x")
        .with_version(1)
        .unwrap();
    let mut conn = svc.connect_v(ORIGIN, 1);
    let d = deliver(
        &svc,
        &mut conn,
        &v1.start_session(&service_public.unwrap()).unwrap(),
    );
    v1.on_frame(&d.to_client[0]).unwrap();
    let save = Call::Save {
        url: "https://github.com/".into(),
        username: "u".into(),
        password: secret("p"),
    };
    assert!(
        v1.request(save.clone()).is_err(),
        "客户端不发送 v1 中没有的方法"
    );
    // 绕过客户端：用 v2 客户端的加密层构造同样的请求，发到 v1 会话里
    let key = StaticKeypair::from_private(client.export_private_key());
    let mut forged = ExtensionClient::new(key, ORIGIN, "x")
        .with_version(1)
        .unwrap();
    let mut conn = svc.connect_v(ORIGIN, 1);
    let d = deliver(
        &svc,
        &mut conn,
        &forged.start_session(&service_public.unwrap()).unwrap(),
    );
    forged.on_frame(&d.to_client[0]).unwrap();
    let (_, frame) = forged.request_unchecked(save).unwrap();
    let d = deliver(&svc, &mut conn, &frame);
    assert!(d.closed);
    assert_eq!(
        control_error(&d.to_client[0]),
        Some(crate::message::ErrorCode::BadRequest)
    );
}

/// save：通过检查后交给调用方执行（不需要确认），条目标题取站点主机名；结果只含条目 ID。
/// 等待期间同一连接上的写操作被拒；参数越界、非 http(s) 网址按 bad_request；频率限制按 not_authorized。
#[test]
fn v2_save_flow() {
    use crate::message::{CallResult, ErrorCode};
    use crate::service::WriteOp;
    let mut svc = Service::new();
    let (mut client, _, mut conn) = pair(&mut svc, true);
    let save = |url: &str, user: &str, pw: &str| Call::Save {
        url: url.into(),
        username: user.into(),
        password: secret(pw),
    };

    let (_, frame) = client
        .request(save(
            "https://www.GitHub.com/login?next=/",
            "octocat",
            "new-pass",
        ))
        .unwrap();
    let d = deliver(&svc, &mut conn, &frame);
    let w = d.write.expect("交给调用方执行");
    assert!(d.to_client.is_empty() && !w.needs_confirmation());
    assert_eq!(w.site, "https://www.github.com");
    match &w.op {
        WriteOp::Save {
            title,
            username,
            password,
        } => {
            assert_eq!(
                (title.as_str(), username.as_str(), password.expose()),
                ("github.com", "octocat", "new-pass")
            );
        }
        other => panic!("{other:?}"),
    }
    assert!(!format!("{w:?}").contains("new-pass"), "调试输出不含密码");
    // 等待期间的第二个写操作
    let (_, frame) = client
        .request(save("https://github.com/", "x", "y"))
        .unwrap();
    let d = deliver(&svc, &mut conn, &frame);
    assert_eq!(
        error_code(&reply_of(&mut client, &d)),
        Some(ErrorCode::NotAuthorized)
    );
    let d = collect(conn.resolve_write(Ok("new-item".into()), &mut *svc.store.borrow_mut()));
    match reply_of(&mut client, &d) {
        ServerMessage::Ok {
            result: CallResult::Written { item_id },
            ..
        } => assert_eq!(item_id, "new-item"),
        other => panic!("{other:?}"),
    }

    for (call, code) in [
        (save("https://github.com/", "u", ""), ErrorCode::BadRequest),
        (
            save("https://github.com/", "u", &"x".repeat(4097)),
            ErrorCode::BadRequest,
        ),
        (
            save("https://github.com/", &"u".repeat(1025), "p"),
            ErrorCode::BadRequest,
        ),
        (save("ftp://github.com/", "u", "p"), ErrorCode::BadRequest),
    ] {
        let (_, frame) = client.request(call).unwrap();
        let d = deliver(&svc, &mut conn, &frame);
        assert!(d.write.is_none());
        assert_eq!(error_code(&reply_of(&mut client, &d)), Some(code));
    }
    // 锁定时
    svc.backend.locked.set(true);
    let (_, frame) = client
        .request(save("https://github.com/", "u", "p"))
        .unwrap();
    let d = deliver(&svc, &mut conn, &frame);
    assert_eq!(
        error_code(&reply_of(&mut client, &d)),
        Some(ErrorCode::Locked)
    );
}

/// update：网址必须与条目匹配，每次都要求确认；用户拒绝时返回 not_authorized。
#[test]
fn v2_update_flow() {
    use crate::message::ErrorCode;
    use crate::service::WriteOp;
    let mut svc = Service::new();
    let (mut client, _, mut conn) = pair(&mut svc, true);
    let update = |item: &str, url: &str| Call::Update {
        item_id: item.into(),
        url: url.into(),
        password: secret("changed"),
    };
    for (call, code) in [
        (
            update("gh", "https://evil.example/"),
            ErrorCode::UrlMismatch,
        ),
        (
            update("missing", "https://github.com/"),
            ErrorCode::NotFound,
        ),
    ] {
        let (_, frame) = client.request(call).unwrap();
        let d = deliver(&svc, &mut conn, &frame);
        assert!(d.write.is_none());
        assert_eq!(error_code(&reply_of(&mut client, &d)), Some(code));
    }
    let (_, frame) = client
        .request(update("gh", "https://github.com/settings"))
        .unwrap();
    let d = deliver(&svc, &mut conn, &frame);
    let w = d.write.expect("交给调用方确认并执行");
    assert!(w.needs_confirmation());
    assert!(
        matches!(&w.op, WriteOp::Update { item_id, password, .. } if item_id == "gh" && password.expose() == "changed")
    );
    let d =
        collect(conn.resolve_write(Err(ErrorCode::NotAuthorized), &mut *svc.store.borrow_mut()));
    assert_eq!(
        error_code(&reply_of(&mut client, &d)),
        Some(ErrorCode::NotAuthorized)
    );
}

fn reply_of(client: &mut ExtensionClient, d: &Delivered) -> ServerMessage {
    let (_, mut events) = client.on_frame(&d.to_client[0]).unwrap();
    match events.remove(0) {
        ClientEvent::Message(m) => m,
        other => panic!("{other:?}"),
    }
}
