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
    Call, CallResult, ControlFrame, ErrorBody, ErrorCode, Event, HostHello, MAX_APP_MESSAGE,
    MAX_CANDIDATE_TEXT, MAX_CANDIDATES, MAX_NAME_BYTES, PROTOCOL_VERSION, Request, ServerMessage,
    b64, decode_canonical, sanitize_display_name, unb64,
};

/// 配对的时限（`spec/ipc.md` §4.2）：从收到第 1 条消息起算，覆盖握手与用户确认，超时视为拒绝。
pub const PAIRING_TIMEOUT: Duration = Duration::from_secs(60);
/// `fill` 首次授权的等待时间：到期按拒绝处理（§5.2 第 1 条）。
pub const FILL_AUTHORIZATION_TIMEOUT: Duration = Duration::from_secs(60);
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

/// `fill` 之前的授权检查结果（§5.2"按站点授权"）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FillGate {
    /// 已授权，且没有触发频率限制：这次使用已记下。
    Allowed,
    /// 这个配对还没有为这个条目在这个站点取用过凭据：需要用户在原生界面确认。
    NeedsAuthorization,
    /// 这个配对因频率限制被暂停（§5.2 第 3 条）。
    Paused,
}

/// 配对记录的存储。正式实现保存在加密数据库中；撤销配对即删除记录。
pub trait PairingStore {
    /// 配对记录是否已读入。记录存在加密数据库中，进程启动后、首次解锁前不可读，此时 IK 握手一律返回
    /// `locked`（§4.2 第 6 步）。
    fn is_loaded(&self) -> bool {
        true
    }
    /// 按扩展的静态公钥查找。
    fn find(&self, extension_public: &[u8; 32]) -> Option<PairingRecord>;
    /// 保存配对记录。只有保存成功，才会向扩展发送 `paired`（第三轮评审 §4.4）。
    ///
    /// # Errors
    /// 持久化失败时返回错误，配对按拒绝处理。
    fn save(&mut self, record: PairingRecord) -> std::io::Result<()>;
    /// 删除配对记录（撤销）。会话层在每个请求前重新核对记录，撤销对已建立的会话立即生效。
    ///
    /// # Errors
    /// 持久化失败时返回错误：调用方必须告知用户撤销可能在重启后失效。
    fn revoke(&mut self, extension_public: &[u8; 32]) -> std::io::Result<()>;
    /// `fill` 之前的授权检查（§5.2）：`(配对, 条目, 站点)` 是否已授权，以及频率限制。允许时记下这次使用。
    /// 默认要求用户确认（失败安全的方向）；正式实现见 `keevo-service`。
    fn fill_gate(
        &mut self,
        extension_public: &[u8; 32],
        item_id: &str,
        site: &str,
        now: Instant,
    ) -> FillGate {
        let _ = (extension_public, item_id, site, now);
        FillGate::NeedsAuthorization
    }
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

    fn save(&mut self, record: PairingRecord) -> std::io::Result<()> {
        self.records
            .retain(|r| r.extension_public != record.extension_public);
        self.records.push(record);
        Ok(())
    }

    fn revoke(&mut self, extension_public: &[u8; 32]) -> std::io::Result<()> {
        self.records
            .retain(|r| &r.extension_public != extension_public);
        Ok(())
    }

    /// 测试用：不做按站点授权。
    fn fill_gate(&mut self, _: &[u8; 32], _: &str, _: &str, _: Instant) -> FillGate {
        FillGate::Allowed
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
    /// 当前的解锁代次；锁定时为 `None`。每次解锁得到新值，配对确认时据此判断"仍是同一次解锁"（§4.2）。
    fn unlock_epoch(&self) -> Option<u64> {
        (!self.is_locked()).then_some(0)
    }
    /// 条目的标题与用户名，只用于原生授权界面（§5.2 第 1 条）。
    fn describe(&self, item_id: &str) -> Option<(String, String)> {
        let _ = item_id;
        None
    }
    /// 规范化后的站点 `scheme://host[:port]`（§5.2 第 1 条）。
    fn site(&self, url: &str) -> Option<String> {
        site_of(url)
    }
}

/// 把网址规范化为站点 `scheme://host[:port]`：方案与主机小写，去掉路径、查询、片段与用户信息。
/// 只接受 `https` 与 `http`。
#[must_use]
pub fn site_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "https" && scheme != "http" {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if host_port.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{}", host_port.to_ascii_lowercase()))
}

/// 一次等待用户授权的 `fill`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FillRequest {
    /// 发起请求的配对（扩展静态公钥）。
    pub extension_public: [u8; 32],
    /// 配对的显示名。
    pub pairing_name: String,
    /// 浏览器标识。
    pub browser: String,
    /// 条目 ID。
    pub item_id: String,
    /// 条目标题。
    pub title: String,
    /// 用户名（条目副标题）。
    pub username: String,
    /// 规范化后的站点。
    pub site: String,
}

/// 等待授权的请求在连接中的状态。
struct PendingFill {
    id: u32,
    item_id: String,
    url: String,
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
    /// 某个配对第一次为某个条目在某个站点取用凭据：请用户在原生界面确认（§5.2），60 秒内未确认按拒绝处理；
    /// 确认后先记下授权，再调用 [`ServiceConnection::resolve_fill`]。等待期间不得持有任何锁。
    AuthorizeFill(FillRequest),
    /// 这个配对因频率限制被暂停（§5.2 第 3 条）：在 Keevo.app 中提示，用户确认后恢复。
    FillPaused {
        /// 配对（扩展静态公钥）。
        extension_public: [u8; 32],
        /// 配对的显示名。
        pairing_name: String,
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
        epoch: u64,
    },
    AwaitConfirm {
        hello: HostHello,
        transport: Box<Transport>,
        name: String,
        deadline: Instant,
        epoch: u64,
    },
    Established {
        transport: Box<Transport>,
        origin: String,
        pending: Option<PendingFill>,
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
        store: &mut dyn PairingStore,
        backend: &dyn VaultBackend,
    ) -> Vec<Output> {
        match self.step(frame, store, backend) {
            Ok(out) => out,
            Err(code) => self.fail(code),
        }
    }

    /// 用户对配对的决定。`epoch_now` 是此刻的解锁代次（[`VaultBackend::unlock_epoch`]）：
    /// 已锁定，或已不是配对开始时的那一次解锁，都按拒绝处理（§4.2，第四轮评审 J5）。
    /// 调用方应在持有保险库锁的情况下读取代次并调用本方法，使确认与锁定之间有确定的先后。
    pub fn confirm_pairing(
        &mut self,
        accepted: bool,
        store: &mut dyn PairingStore,
        epoch_now: Option<u64>,
    ) -> Vec<Output> {
        let State::AwaitConfirm {
            hello,
            mut transport,
            name,
            deadline,
            epoch,
        } = std::mem::replace(&mut self.state, State::Closed)
        else {
            return Vec::new();
        };
        // 超时由状态机自己执行，不依赖调用方（评审：规范与实现不一致）
        if !accepted || Instant::now() > deadline {
            return self.fail(ErrorCode::PairingRejected);
        }
        if epoch_now != Some(epoch) {
            return self.fail(ErrorCode::Locked);
        }
        self.release_gate();
        let origin = hello.extension_origin.clone();
        let saved = store.save(PairingRecord {
            extension_public: transport.remote_static(),
            extension_origin: hello.extension_origin,
            browser: hello.browser,
            name,
            paired_at_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
                .unwrap_or(0),
        });
        if saved.is_err() {
            return self.fail(ErrorCode::PairingRejected);
        }
        match encrypt(
            &mut transport,
            &ServerMessage::Event {
                event: Event::Paired,
            },
        ) {
            Ok(frame) => {
                self.state = State::Established {
                    transport,
                    origin,
                    pending: None,
                };
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
        store: &mut dyn PairingStore,
        backend: &dyn VaultBackend,
    ) -> Result<Vec<Output>, ErrorCode> {
        let state = std::mem::replace(&mut self.state, State::Closed);
        match state {
            State::Closed => Ok(Vec::new()),
            State::AwaitHostHello => {
                let hello: HostHello =
                    decode_canonical(frame).map_err(|_| ErrorCode::BadRequest)?;
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
                    // 配对只在解锁时进行：确认需要原生界面，记录要写入加密数据库（§4.2 第 6 步）
                    let epoch = backend.unlock_epoch().ok_or(ErrorCode::Locked)?;
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
                        epoch,
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
                    // 首次解锁前配对记录还不可读（§4.3 第 2 步）
                    if !store.is_loaded() {
                        return Err(ErrorCode::Locked);
                    }
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
                        pending: None,
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
                epoch,
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
                    epoch,
                };
                Ok(vec![Output::ConfirmPairing { sas, name, browser }])
            }
            // 用户确认之前，扩展不得发送任何内容
            State::AwaitConfirm { .. } => Err(ErrorCode::BadRequest),
            State::Established {
                mut transport,
                origin,
                mut pending,
            } => {
                // 每个请求都重新核对配对记录：撤销立即生效，不存在撤销与请求之间的竞态（评审 F1）
                let record = match store.find(&transport.remote_static()) {
                    Some(r) if r.extension_origin == origin => r,
                    _ => return Err(ErrorCode::NotPaired),
                };
                let ControlFrame::Noise { d } = parse(frame)? else {
                    return Err(ErrorCode::BadRequest);
                };
                let plaintext = transport
                    .decrypt(&unb64(&d).map_err(|_| ErrorCode::BadRequest)?)
                    .map_err(|_| ErrorCode::BadRequest)?;
                let request: Request =
                    decode_canonical(&plaintext).map_err(|_| ErrorCode::BadRequest)?;
                let mut extra = Vec::new();
                let reply = match &request.call {
                    Call::Fill { item_id, url } if !backend.is_locked() => {
                        match gated_fill(request.id, item_id, url, &record, store, backend) {
                            Gated::Reply(reply) => reply,
                            Gated::Paused(reply) => {
                                extra.push(paused(&record));
                                reply
                            }
                            // 已有一个请求在等待授权时，新的 fill 直接拒绝
                            Gated::NeedsAuthorization(_) if pending.is_some() => {
                                ServerMessage::Err {
                                    id: request.id,
                                    error: ErrorBody {
                                        code: ErrorCode::NotAuthorized,
                                    },
                                }
                            }
                            Gated::NeedsAuthorization(req) => {
                                pending = Some(PendingFill {
                                    id: request.id,
                                    item_id: item_id.clone(),
                                    url: url.clone(),
                                });
                                self.state = State::Established {
                                    transport,
                                    origin,
                                    pending,
                                };
                                return Ok(vec![Output::AuthorizeFill(req)]);
                            }
                        }
                    }
                    _ => handle(&request, backend),
                };
                // 放不进一条 Noise 消息的响应改为 `response_too_large`（§2，第四轮评审 J4）
                let frame = match encrypt(&mut transport, &reply) {
                    Err(IpcError::TooLarge) => encrypt(
                        &mut transport,
                        &ServerMessage::Err {
                            id: request.id,
                            error: ErrorBody {
                                code: ErrorCode::ResponseTooLarge,
                            },
                        },
                    ),
                    other => other,
                }
                .map_err(|_| ErrorCode::BadRequest)?;
                self.state = State::Established {
                    transport,
                    origin,
                    pending,
                };
                let mut out = vec![Output::Send(frame)];
                out.append(&mut extra);
                Ok(out)
            }
        }
    }

    /// 用户对 [`Output::AuthorizeFill`] 的决定。`authorized` 为 `true` 时调用方必须已经记下授权
    /// （之后的 [`PairingStore::fill_gate`] 返回允许）。等待期间保险库可能已锁定、条目可能已变化，这里全部重新核对。
    pub fn resolve_fill(
        &mut self,
        authorized: bool,
        store: &mut dyn PairingStore,
        backend: &dyn VaultBackend,
    ) -> Vec<Output> {
        let State::Established {
            mut transport,
            origin,
            pending,
        } = std::mem::replace(&mut self.state, State::Closed)
        else {
            return Vec::new();
        };
        let Some(p) = pending else {
            self.state = State::Established {
                transport,
                origin,
                pending: None,
            };
            return Vec::new();
        };
        let record = match store.find(&transport.remote_static()) {
            Some(r) if r.extension_origin == origin => r,
            _ => return self.fail(ErrorCode::NotPaired),
        };
        let err = |code| ServerMessage::Err {
            id: p.id,
            error: ErrorBody { code },
        };
        let mut extra = Vec::new();
        let reply = if !authorized {
            err(ErrorCode::NotAuthorized)
        } else if backend.is_locked() {
            err(ErrorCode::Locked)
        } else {
            match gated_fill(p.id, &p.item_id, &p.url, &record, store, backend) {
                Gated::Reply(reply) => reply,
                Gated::Paused(reply) => {
                    extra.push(paused(&record));
                    reply
                }
                Gated::NeedsAuthorization(_) => err(ErrorCode::NotAuthorized),
            }
        };
        let frame = match encrypt(&mut transport, &reply) {
            Err(IpcError::TooLarge) => encrypt(&mut transport, &err(ErrorCode::ResponseTooLarge)),
            other => other,
        };
        let Ok(frame) = frame else {
            return self.fail(ErrorCode::BadRequest);
        };
        self.state = State::Established {
            transport,
            origin,
            pending: None,
        };
        let mut out = vec![Output::Send(frame)];
        out.append(&mut extra);
        out
    }
}

enum Gated {
    Reply(ServerMessage),
    Paused(ServerMessage),
    NeedsAuthorization(FillRequest),
}

fn paused(record: &PairingRecord) -> Output {
    Output::FillPaused {
        extension_public: record.extension_public,
        pairing_name: record.name.clone(),
        browser: record.browser.clone(),
    }
}

/// `fill` 的最小披露规则（§5.2）：网址再次校验，再按站点授权与频率限制，最后才取出秘密。
fn gated_fill(
    id: u32,
    item_id: &str,
    url: &str,
    record: &PairingRecord,
    store: &mut dyn PairingStore,
    backend: &dyn VaultBackend,
) -> Gated {
    let err = |code| ServerMessage::Err {
        id,
        error: ErrorBody { code },
    };
    match backend.item_matches(item_id, url) {
        None => return Gated::Reply(err(ErrorCode::NotFound)),
        Some(false) => return Gated::Reply(err(ErrorCode::UrlMismatch)),
        Some(true) => {}
    }
    let Some(site) = backend.site(url) else {
        return Gated::Reply(err(ErrorCode::UrlMismatch));
    };
    match store.fill_gate(&record.extension_public, item_id, &site, Instant::now()) {
        FillGate::Paused => Gated::Paused(err(ErrorCode::NotAuthorized)),
        FillGate::NeedsAuthorization => {
            let (title, username) = backend.describe(item_id).unwrap_or_default();
            Gated::NeedsAuthorization(FillRequest {
                extension_public: record.extension_public,
                pairing_name: record.name.clone(),
                browser: record.browser.clone(),
                item_id: item_id.to_owned(),
                title,
                username,
                site,
            })
        }
        FillGate::Allowed => Gated::Reply(match backend.fill(item_id) {
            Some(data) => ServerMessage::Ok {
                id,
                result: CallResult::Fill(data),
            },
            None => err(ErrorCode::NotFound),
        }),
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
                // 有界返回：最多 20 个，标题与副标题截短，只用于显示（§5.2）
                items: backend
                    .candidates(url)
                    .into_iter()
                    .take(MAX_CANDIDATES)
                    .map(|c| crate::message::Candidate {
                        title: c.title.chars().take(MAX_CANDIDATE_TEXT).collect(),
                        subtitle: c.subtitle.chars().take(MAX_CANDIDATE_TEXT).collect(),
                        ..c
                    })
                    .collect(),
            },
        },
        // fill 一律经由 gated_fill（按站点授权与频率限制）；走到这里说明调用方绕过了它，拒绝
        Call::Fill { .. } => err(ErrorCode::NotAuthorized),
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
    if json.len() > MAX_APP_MESSAGE {
        return Err(IpcError::TooLarge);
    }
    let ct = transport.encrypt(&json)?;
    ControlFrame::Noise { d: b64(&ct) }.to_json()
}
