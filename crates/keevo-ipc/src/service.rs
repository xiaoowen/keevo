//! Vault Service 一侧的协议状态机（`spec/ipc.md` §4–§5）。
//!
//! 一条连接对应一个 [`ServiceConnection`]。调用方把 native host 转来的每一帧交给
//! [`ServiceConnection::on_frame`]，再按返回的 [`Output`] 发帧、请求用户确认或断开连接。

use std::sync::Arc;

use keevo_crypto::{Handshake, StaticKeypair, Transport};
use serde::Deserialize;

use crate::error::IpcError;
use crate::message::{
    Call, CallResult, ControlFrame, ErrorBody, ErrorCode, Event, HostHello, PROTOCOL_VERSION,
    Request, ServerMessage, b64, unb64,
};

/// 配对名称的最大长度（字符）。
const MAX_NAME_CHARS: usize = 64;

/// 配对记录（§4.2 第 4 步）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingRecord {
    /// 扩展的静态公钥。
    pub extension_public: [u8; 32],
    /// 扩展来源。
    pub extension_origin: String,
    /// 浏览器标识。
    pub browser: String,
    /// 显示名。
    pub name: String,
}

/// 配对记录的存储。正式实现保存在加密数据库中；撤销配对即删除记录。
pub trait PairingStore {
    /// 按扩展的静态公钥查找。
    fn find(&self, extension_public: &[u8; 32]) -> Option<PairingRecord>;
    /// 保存配对记录。
    fn save(&mut self, record: PairingRecord);
}

/// 内存中的配对存储，用于测试与开发服务。
#[derive(Debug, Default)]
pub struct MemoryPairingStore {
    records: Vec<PairingRecord>,
}

impl MemoryPairingStore {
    /// 删除配对记录（撤销）。
    pub fn revoke(&mut self, extension_public: &[u8; 32]) {
        self.records
            .retain(|r| &r.extension_public != extension_public);
    }

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
        self.revoke(&record.extension_public);
        self.records.push(record);
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
    },
    AwaitConfirm {
        hello: HostHello,
        transport: Box<Transport>,
        name: String,
    },
    Established {
        transport: Box<Transport>,
    },
    Closed,
}

/// 一条连接的协议状态。
pub struct ServiceConnection {
    key: Arc<StaticKeypair>,
    state: State,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PairPayload {
    name: String,
}

impl ServiceConnection {
    /// 新连接。`key` 是 Vault Service 的静态密钥。
    #[must_use]
    pub const fn new(key: Arc<StaticKeypair>) -> Self {
        Self {
            key,
            state: State::AwaitHostHello,
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
        } = std::mem::replace(&mut self.state, State::Closed)
        else {
            return Vec::new();
        };
        if !accepted {
            return self.fail(ErrorCode::PairingRejected);
        }
        store.save(PairingRecord {
            extension_public: transport.remote_static(),
            extension_origin: hello.extension_origin,
            browser: hello.browser,
            name,
        });
        match encrypt(
            &mut transport,
            &ServerMessage::Event {
                event: Event::Paired,
            },
        ) {
            Ok(frame) => {
                self.state = State::Established { transport };
                vec![Output::Send(frame)]
            }
            Err(_) => self.fail(ErrorCode::BadRequest),
        }
    }

    /// 向扩展推送事件（如锁定）。会话未建立时忽略。
    pub fn push_event(&mut self, event: Event) -> Vec<Output> {
        let State::Established { transport } = &mut self.state else {
            return Vec::new();
        };
        match encrypt(transport, &ServerMessage::Event { event }) {
            Ok(frame) => vec![Output::Send(frame)],
            Err(_) => self.fail(ErrorCode::BadRequest),
        }
    }

    fn fail(&mut self, code: ErrorCode) -> Vec<Output> {
        self.state = State::Closed;
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
                    let mut hs = Handshake::pair_responder(&self.key, &hello.extension_origin)
                        .map_err(|_| ErrorCode::BadRequest)?;
                    let _ = hs
                        .read(&unb64(&d).map_err(|_| ErrorCode::BadRequest)?)
                        .map_err(|_| ErrorCode::BadRequest)?;
                    let reply = hs.write(&[]).map_err(|_| ErrorCode::BadRequest)?;
                    self.state = State::Pairing {
                        hello,
                        hs: Box::new(hs),
                    };
                    Ok(vec![send_noise(&reply)?])
                }
                ControlFrame::Session { d } => {
                    let mut hs = Handshake::session_responder(&self.key, &hello.extension_origin)
                        .map_err(|_| ErrorCode::BadRequest)?;
                    let _ = hs
                        .read(&unb64(&d).map_err(|_| ErrorCode::BadRequest)?)
                        .map_err(|_| ErrorCode::NotPaired)?;
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
                    };
                    Ok(vec![send_noise(&reply)?])
                }
                _ => Err(ErrorCode::BadRequest),
            },
            State::Pairing { hello, mut hs } => {
                let ControlFrame::Noise { d } = parse(frame)? else {
                    return Err(ErrorCode::BadRequest);
                };
                let payload = hs
                    .read(&unb64(&d).map_err(|_| ErrorCode::BadRequest)?)
                    .map_err(|_| ErrorCode::BadRequest)?;
                let PairPayload { name } =
                    serde_json::from_slice(&payload).map_err(|_| ErrorCode::BadRequest)?;
                if !hs.is_finished() {
                    return Err(ErrorCode::BadRequest);
                }
                let name: String = name
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(MAX_NAME_CHARS)
                    .collect();
                let sas = hs.sas().map_err(|_| ErrorCode::BadRequest)?;
                let transport = hs.into_transport().map_err(|_| ErrorCode::BadRequest)?;
                let browser = hello.browser.clone();
                self.state = State::AwaitConfirm {
                    hello,
                    transport: Box::new(transport),
                    name: name.clone(),
                };
                Ok(vec![Output::ConfirmPairing { sas, name, browser }])
            }
            // 用户确认之前，扩展不得发送任何内容
            State::AwaitConfirm { .. } => Err(ErrorCode::BadRequest),
            State::Established { mut transport } => {
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
                self.state = State::Established { transport };
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
