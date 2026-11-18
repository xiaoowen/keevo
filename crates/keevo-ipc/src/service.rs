//! Vault Service 一侧的协议状态机（`spec/ipc.md` §4–§5）。
//!
//! 一条连接对应一个 [`ServiceConnection`]。调用方把 native host 转来的每一帧交给
//! [`ServiceConnection::on_frame`]，再按返回的 [`Output`] 发帧、请求用户确认或断开连接。

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use keevo_crypto::{Handshake, PAIR_NONCE_LEN, StaticKeypair, Transport, pairing_commitment};

use crate::error::IpcError;
use crate::message::{
    Call, CallResult, ControlFrame, ErrorBody, ErrorCode, Event, HostHello, MAX_NAME_BYTES,
    PROTOCOL_VERSION, Request, ServerMessage, b64, sanitize_display_name, unb64,
};

/// 配对的时限（`spec/ipc.md` §4.2）：从收到第 1 条消息起算，覆盖握手与用户确认，超时视为拒绝。
pub const PAIRING_TIMEOUT: Duration = Duration::from_secs(60);
/// 每小时最多开始的配对次数（§4.2）。
pub const MAX_PAIRING_STARTS_PER_HOUR: usize = 10;

/// 配对尝试的闸门（§4.2，第二轮评审 G1）：同一时刻最多一个配对；每小时最多开始
/// [`MAX_PAIRING_STARTS_PER_HOUR`] 次。Vault Service 的所有连接共用一个。
///
/// 计数点是"服务发出第 2 条消息"：每一次都给了对方一个新的服务端贡献，无论之后是否发送第 3 条消息。
#[derive(Debug, Default)]
pub struct PairingGate {
    inner: Mutex<GateState>,
}

#[derive(Debug, Default)]
struct GateState {
    active: bool,
    starts: VecDeque<Instant>,
}

impl PairingGate {
    fn begin(&self, now: Instant) -> bool {
        let mut g = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let hour = Duration::from_secs(3600);
        while g
            .starts
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= hour)
        {
            g.starts.pop_front();
        }
        if g.active || g.starts.len() >= MAX_PAIRING_STARTS_PER_HOUR {
            return false;
        }
        g.active = true;
        g.starts.push_back(now);
        true
    }

    fn end(&self) {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .active = false;
    }
}

/// 配对记录（§4.2 第 4 步）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingRecord {
    /// 扩展的静态公钥。
    pub extension_public: [u8; 32],
    /// 扩展来源。
    pub extension_origin: String,
    /// 浏览器标识。
    pub browser: String,
    /// 显示名（已去除控制字符，最多 64 个字符）。
    pub name: String,
    /// 配对时间（Unix 毫秒）。
    pub paired_at_ms: u64,
}

/// 配对记录的存储。正式实现保存在加密数据库中；撤销配对即删除记录。
pub trait PairingStore {
    /// 按扩展的静态公钥查找。
    fn find(&self, extension_public: &[u8; 32]) -> Option<PairingRecord>;
    /// 保存配对记录。
    fn save(&mut self, record: PairingRecord);
    /// 删除配对记录（撤销）。会话层在每个请求前重新核对记录，撤销对已建立的会话立即生效。
    ///
    /// # Errors
    /// 持久化失败时返回错误：调用方必须告知用户撤销可能在重启后失效。
    fn revoke(&mut self, extension_public: &[u8; 32]) -> std::io::Result<()>;
}

/// 内存中的配对存储，用于测试与开发服务。
#[derive(Debug, Default)]
pub struct MemoryPairingStore {
    records: Vec<PairingRecord>,
}

impl MemoryPairingStore {
    /// 记录数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

impl PairingStore for MemoryPairingStore {
    fn find(&self, extension_public: &[u8; 32]) -> Option<PairingRecord> {
        self.records
            .iter()
            .find(|r| &r.extension_public == extension_public)
            .cloned()
    }

    fn save(&mut self, record: PairingRecord) {
        self.records
            .retain(|r| r.extension_public != record.extension_public);
        self.records.push(record);
    }

    fn revoke(&mut self, extension_public: &[u8; 32]) -> std::io::Result<()> {
        self.records
            .retain(|r| &r.extension_public != extension_public);
        Ok(())
    }
}

/// 保险库后端。协议层只通过这个接口取数据，最小披露规则由本状态机强制执行。
pub trait VaultBackend {
    /// 是否已锁定。
    fn is_locked(&self) -> bool;
    /// 与网址匹配的条目概要。
    fn candidates(&self, url: &str) -> Vec<crate::message::Candidate>;
    /// 条目是否与网址匹配；条目不存在时返回 `None`。
    fn item_matches(&self, item_id: &str, url: &str) -> Option<bool>;
    /// 条目的填充凭据。只会在 [`VaultBackend::item_matches`] 返回 `Some(true)` 之后调用。
    fn fill(&self, item_id: &str) -> Option<crate::message::FillData>;
}

/// 状态机的输出。
#[derive(Debug)]
pub enum Output {
    /// 发送一个控制层帧（JSON）。
    Send(Vec<u8>),
    /// 收到配对请求的第 1 条消息：Keevo.app 应立即显示"有浏览器正在请求配对"，
    /// 让每一次尝试都对用户可见（§4.2）。
    PairingStarted {
        /// 浏览器标识。
        browser: String,
    },
    /// 请用户比对短认证串并确认配对，然后调用 [`ServiceConnection::confirm_pairing`]。
    /// 应在 60 秒内未确认时以拒绝处理。
    ConfirmPairing {
        /// 短认证串。
        sas: [u8; 6],
        /// 扩展报告的显示名。
        name: String,
        /// 浏览器标识。
        browser: String,
    },
    /// 发送完前面的帧后断开连接。
    Close,
}

enum State {
    AwaitHostHello,
    AwaitFirst {
        hello: HostHello,
    },
    Pairing {
        hello: HostHello,
        hs: Box<Handshake>,
        commitment: [u8; 32],
        deadline: Instant,
    },
    AwaitConfirm {
        hello: HostHello,
        transport: Box<Transport>,
        name: String,
        deadline: Instant,
    },
    Established {
        transport: Box<Transport>,
        origin: String,
    },
    Closed,
}

/// 一条连接的协议状态。
pub struct ServiceConnection {
    key: Arc<StaticKeypair>,
    state: State,
    pairing_timeout: Duration,
    gate: Arc<PairingGate>,
    holds_gate: bool,
}

impl Drop for ServiceConnection {
    fn drop(&mut self) {
        self.release_gate();
    }
}

impl ServiceConnection {
    /// 新连接。`key` 是 Vault Service 的静态密钥。
    #[must_use]
    pub fn new(key: Arc<StaticKeypair>) -> Self {
        Self {
            key,
            state: State::AwaitHostHello,
            pairing_timeout: PAIRING_TIMEOUT,
            gate: Arc::default(),
            holds_gate: false,
        }
    }

    /// 使用 Vault Service 共用的配对闸门。不设置时每条连接各用一个，只适合测试。
    #[must_use]
    pub fn with_pairing_gate(mut self, gate: Arc<PairingGate>) -> Self {
        self.gate = gate;
        self
    }

    /// 配对进行中时的截止时间。调用方应据此设置 socket 的读超时，到期即断开，释放连接与配对闸门。
    #[must_use]
    pub const fn pairing_deadline(&self) -> Option<Instant> {
        match &self.state {
            State::Pairing { deadline, .. } | State::AwaitConfirm { deadline, .. } => {
                Some(*deadline)
            }
            _ => None,
        }
    }

    fn release_gate(&mut self) {
        if self.holds_gate {
            self.holds_gate = false;
            self.gate.end();
        }
    }

    /// 修改配对确认时限（测试用）。
    #[must_use]
    pub fn with_pairing_timeout(mut self, timeout: Duration) -> Self {
        self.pairing_timeout = timeout;
        self
    }

    /// 会话已建立时，对方扩展的静态公钥。服务层据此登记连接，撤销配对时立即断开。
    #[must_use]
    pub fn peer_public(&self) -> Option<[u8; 32]> {
        match &self.state {
            State::Established { transport, .. } => Some(transport.remote_static()),
            _ => None,
        }
    }

    /// 会话是否已建立（可以处理请求）。
    #[must_use]
    pub const fn is_established(&self) -> bool {
        matches!(self.state, State::Established { .. })
    }

    /// 连接是否已关闭。
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        matches!(self.state, State::Closed)
    }

    /// 处理收到的一帧。任何协议错误都会让连接进入关闭状态。
    pub fn on_frame(
        &mut self,
        frame: &[u8],
        store: &dyn PairingStore,
        backend: &dyn VaultBackend,
    ) -> Vec<Output> {
        match self.step(frame, store, backend) {
            Ok(out) => out,
            Err(code) => self.fail(code),
        }
    }

    /// 用户对配对的决定。
    pub fn confirm_pairing(&mut self, accepted: bool, store: &mut dyn PairingStore) -> Vec<Output> {
        let State::AwaitConfirm {
            hello,
            mut transport,
            name,
            deadline,
        } = std::mem::replace(&mut self.state, State::Closed)
        else {
            return Vec::new();
        };
        // 超时由状态机自己执行，不依赖调用方（评审：规范与实现不一致）
        if !accepted || Instant::now() > deadline {
            return self.fail(ErrorCode::PairingRejected);
        }
        self.release_gate();
        let origin = hello.extension_origin.clone();
        store.save(PairingRecord {
            extension_public: transport.remote_static(),
            extension_origin: hello.extension_origin,
            browser: hello.browser,
            name,
            paired_at_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
                .unwrap_or(0),
        });
        match encrypt(
            &mut transport,
            &ServerMessage::Event {
                event: Event::Paired,
            },
        ) {
            Ok(frame) => {
                self.state = State::Established { transport, origin };
                vec![Output::Send(frame)]
            }
            Err(_) => self.fail(ErrorCode::BadRequest),
        }
    }

    /// 向扩展推送事件（如锁定）。会话未建立时忽略。
    pub fn push_event(&mut self, event: Event) -> Vec<Output> {
        let State::Established { transport, .. } = &mut self.state else {
            return Vec::new();
        };
        match encrypt(transport, &ServerMessage::Event { event }) {
            Ok(frame) => vec![Output::Send(frame)],
            Err(_) => self.fail(ErrorCode::BadRequest),
        }
    }

    fn fail(&mut self, code: ErrorCode) -> Vec<Output> {
        self.state = State::Closed;
        self.release_gate();
        let mut out = Vec::new();
        if let Ok(frame) = (ControlFrame::Error { code }).to_json() {
            out.push(Output::Send(frame));
        }
        out.push(Output::Close);
        out
    }

    fn step(
        &mut self,
        frame: &[u8],
        store: &dyn PairingStore,
        backend: &dyn VaultBackend,
    ) -> Result<Vec<Output>, ErrorCode> {
        let state = std::mem::replace(&mut self.state, State::Closed);
        match state {
            State::Closed => Ok(Vec::new()),
            State::AwaitHostHello => {
                let hello: HostHello =
                    serde_json::from_slice(frame).map_err(|_| ErrorCode::BadRequest)?;
                if hello.v != PROTOCOL_VERSION {
                    return Err(ErrorCode::UnsupportedVersion);
                }
                if hello.client != "native-host" || hello.extension_origin.is_empty() {
                    return Err(ErrorCode::BadRequest);
                }
                self.state = State::AwaitFirst { hello };
                Ok(Vec::new())
            }
            State::AwaitFirst { hello } => match parse(frame)? {
                ControlFrame::Pair { d } => {
                    // 时限从收到第 1 条消息的时刻起算（§4.2）
                    let received = Instant::now();
                    let deadline = received
                        .checked_add(self.pairing_timeout)
                        .ok_or(ErrorCode::BadRequest)?;
                    if !self.gate.begin(received) {
                        return Err(ErrorCode::PairingLimited);
                    }
                    self.holds_gate = true;
                    let mut hs = Handshake::pair_responder(&self.key, &hello.extension_origin)
                        .map_err(|_| ErrorCode::BadRequest)?;
                    let payload = hs
                        .read(&unb64(&d).map_err(|_| ErrorCode::BadRequest)?)
                        .map_err(|_| ErrorCode::BadRequest)?;
                    // XX 第一条消息的负载恰好是 32 字节的配对承诺（§4.2）
                    let commitment: [u8; 32] =
                        <[u8; 32]>::try_from(&payload[..]).map_err(|_| ErrorCode::BadRequest)?;
                    let reply = hs.write(&[]).map_err(|_| ErrorCode::BadRequest)?;
                    let browser = hello.browser.clone();
                    self.state = State::Pairing {
                        hello,
                        hs: Box::new(hs),
                        commitment,
                        deadline,
                    };
                    Ok(vec![
                        Output::PairingStarted { browser },
                        send_noise(&reply)?,
                    ])
                }
                ControlFrame::Session { d } => {
                    let mut hs = Handshake::session_responder(&self.key, &hello.extension_origin)
                        .map_err(|_| ErrorCode::BadRequest)?;
                    let payload = hs
                        .read(&unb64(&d).map_err(|_| ErrorCode::BadRequest)?)
                        .map_err(|_| ErrorCode::NotPaired)?;
                    // IK 第一条消息的负载必须为空（§4.3）
                    if !payload.is_empty() {
                        return Err(ErrorCode::BadRequest);
                    }
                    let remote = hs.remote_static().ok_or(ErrorCode::BadRequest)?;
                    // 公钥必须已配对，且来源与配对时一致（§4.3 第 2 步）
                    match store.find(&remote) {
                        Some(r) if r.extension_origin == hello.extension_origin => {}
                        _ => return Err(ErrorCode::NotPaired),
                    }
                    let reply = hs.write(&[]).map_err(|_| ErrorCode::BadRequest)?;
                    let transport = hs.into_transport().map_err(|_| ErrorCode::BadRequest)?;
                    self.state = State::Established {
                        transport: Box::new(transport),
                        origin: hello.extension_origin,
                    };
                    Ok(vec![send_noise(&reply)?])
                }
                _ => Err(ErrorCode::BadRequest),
            },
            State::Pairing {
                hello,
                mut hs,
                commitment,
                deadline,
            } => {
                let ControlFrame::Noise { d } = parse(frame)? else {
                    return Err(ErrorCode::BadRequest);
                };
                if Instant::now() > deadline {
                    return Err(ErrorCode::PairingRejected);
                }
                let payload = hs
                    .read(&unb64(&d).map_err(|_| ErrorCode::BadRequest)?)
                    .map_err(|_| ErrorCode::BadRequest)?;
                if !hs.is_finished() {
                    return Err(ErrorCode::BadRequest);
                }
                // 第 3 条负载 = nonce(32) ‖ 显示名的 UTF-8 字节。承诺按收到的原始字节核对，
                // 不存在第二种编码（§4.2，第二轮评审 G1）
                let remote = hs.remote_static().ok_or(ErrorCode::BadRequest)?;
                if pairing_commitment(&remote, &payload) != commitment {
                    return Err(ErrorCode::BadRequest);
                }
                let raw_name = payload
                    .get(PAIR_NONCE_LEN..)
                    .filter(|n| n.len() <= MAX_NAME_BYTES)
                    .ok_or(ErrorCode::BadRequest)?;
                let name = sanitize_display_name(
                    core::str::from_utf8(raw_name).map_err(|_| ErrorCode::BadRequest)?,
                );
                let sas = hs.sas().map_err(|_| ErrorCode::BadRequest)?;
                let transport = hs.into_transport().map_err(|_| ErrorCode::BadRequest)?;
                let browser = hello.browser.clone();
                self.state = State::AwaitConfirm {
                    hello,
                    transport: Box::new(transport),
                    name: name.clone(),
                    deadline,
                };
                Ok(vec![Output::ConfirmPairing { sas, name, browser }])
            }
            // 用户确认之前，扩展不得发送任何内容
            State::AwaitConfirm { .. } => Err(ErrorCode::BadRequest),
            State::Established {
                mut transport,
                origin,
            } => {
                // 每个请求都重新核对配对记录：撤销立即生效，不存在撤销与请求之间的竞态（评审 F1）
                match store.find(&transport.remote_static()) {
                    Some(r) if r.extension_origin == origin => {}
                    _ => return Err(ErrorCode::NotPaired),
                }
                let ControlFrame::Noise { d } = parse(frame)? else {
                    return Err(ErrorCode::BadRequest);
                };
                let plaintext = transport
                    .decrypt(&unb64(&d).map_err(|_| ErrorCode::BadRequest)?)
                    .map_err(|_| ErrorCode::BadRequest)?;
                let request: Request =
                    serde_json::from_slice(&plaintext).map_err(|_| ErrorCode::BadRequest)?;
                let reply = handle(&request, backend);
                let frame = encrypt(&mut transport, &reply).map_err(|_| ErrorCode::BadRequest)?;
                self.state = State::Established { transport, origin };
                Ok(vec![Output::Send(frame)])
            }
        }
    }
}

/// 处理一个请求，并执行最小披露规则（§5.2）。
fn handle(request: &Request, backend: &dyn VaultBackend) -> ServerMessage {
    let id = request.id;
    let err = |code| ServerMessage::Err {
        id,
        error: ErrorBody { code },
    };
    if backend.is_locked() && request.call != Call::Status {
        return err(ErrorCode::Locked);
    }
    match &request.call {
        Call::Status => ServerMessage::Ok {
            id,
            result: CallResult::Status {
                locked: backend.is_locked(),
            },
        },
        Call::Candidates { url } => ServerMessage::Ok {
            id,
            result: CallResult::Candidates {
                items: backend.candidates(url),
            },
        },
        Call::Fill { item_id, url } => match backend.item_matches(item_id, url) {
            None => err(ErrorCode::NotFound),
            Some(false) => err(ErrorCode::UrlMismatch),
            Some(true) => match backend.fill(item_id) {
                Some(data) => ServerMessage::Ok {
                    id,
                    result: CallResult::Fill(data),
                },
                None => err(ErrorCode::NotFound),
            },
        },
    }
}

fn parse(frame: &[u8]) -> Result<ControlFrame, ErrorCode> {
    ControlFrame::from_json(frame).map_err(|_| ErrorCode::BadRequest)
}

fn send_noise(message: &[u8]) -> Result<Output, ErrorCode> {
    ControlFrame::Noise { d: b64(message) }
        .to_json()
        .map(Output::Send)
        .map_err(|_| ErrorCode::BadRequest)
}

fn encrypt(transport: &mut Transport, message: &ServerMessage) -> Result<Vec<u8>, IpcError> {
    let json =
        zeroize::Zeroizing::new(serde_json::to_vec(message).map_err(|_| IpcError::BadMessage)?);
    let ct = transport.encrypt(&json)?;
    ControlFrame::Noise { d: b64(&ct) }.to_json()
}
