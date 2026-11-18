//! 扩展一侧的协议状态机（`spec/ipc.md` §4–§5）。
//!
//! 目前用于测试与开发工具；将来可编译为 WASM，供浏览器扩展复用同一套实现。

use keevo_crypto::{
    Handshake, PAIR_NONCE_LEN, StaticKeypair, Transport, pairing_commitment, pairing_nonce,
};

use crate::error::IpcError;
use crate::message::{
    Call, ControlFrame, ErrorCode, Event, PROTOCOL_VERSION, Request, ServerMessage, b64, unb64,
};

/// 客户端事件。
#[derive(Debug)]
pub enum ClientEvent {
    /// 配对握手完成：请把短认证串展示给用户，与 Keevo.app 中显示的比对。
    ShowSas([u8; 6]),
    /// 用户在 Keevo.app 中确认了配对。请保存 `service_public`，以后用它建立会话。
    Paired {
        /// Vault Service 的静态公钥。
        service_public: [u8; 32],
    },
    /// 会话已建立。
    Established,
    /// 收到响应或推送。
    Message(ServerMessage),
    /// 对方报告了错误，连接即将断开。
    Error(ErrorCode),
}

enum State {
    Idle,
    Pairing(Box<Handshake>, [u8; PAIR_NONCE_LEN]),
    AwaitPaired(Box<Transport>),
    Session(Box<Handshake>),
    Established(Box<Transport>),
    Closed,
}

/// 扩展一侧的连接。
pub struct ExtensionClient {
    key: StaticKeypair,
    origin: String,
    name: String,
    state: State,
    next_id: u32,
}

impl ExtensionClient {
    /// 新客户端。`key` 为扩展的静态密钥，`origin` 为扩展来源，`name` 为显示名。
    #[must_use]
    pub fn new(key: StaticKeypair, origin: &str, name: &str) -> Self {
        Self {
            key,
            origin: origin.to_owned(),
            name: name.to_owned(),
            state: State::Idle,
            next_id: 1,
        }
    }

    /// 扩展的静态公钥。
    #[must_use]
    pub const fn public_key(&self) -> [u8; 32] {
        self.key.public_key()
    }

    /// 导出扩展的静态私钥，只能用于写入扩展存储（`chrome.storage.local`），以便下次用 IK 重连。
    #[must_use]
    pub fn export_private_key(&self) -> zeroize::Zeroizing<[u8; 32]> {
        self.key.export_private()
    }

    /// 发给 native host 的第一帧。
    ///
    /// # Errors
    /// 序列化失败时返回 [`IpcError::BadMessage`]。
    pub fn hello() -> Result<Vec<u8>, IpcError> {
        ControlFrame::Hello {
            v: PROTOCOL_VERSION,
        }
        .to_json()
    }

    /// 开始配对（XX），返回要发送的帧。
    ///
    /// # Errors
    /// 不在初始状态时返回 [`IpcError::InvalidState`]。
    pub fn start_pairing(&mut self) -> Result<Vec<u8>, IpcError> {
        if !matches!(self.state, State::Idle) {
            return Err(IpcError::InvalidState);
        }
        let mut hs = Handshake::pair_initiator(&self.key, &self.origin)?;
        // 第 1 条消息承诺第 3 条消息的全部内容（spec/ipc.md §4.2）
        let nonce = pairing_nonce()?;
        let commitment = pairing_commitment(&self.key.public_key(), &nonce, &self.name);
        let msg = hs.write(&commitment)?;
        self.state = State::Pairing(Box::new(hs), nonce);
        ControlFrame::Pair { d: b64(&msg) }.to_json()
    }

    /// 用已保存的 Vault Service 公钥开始会话（IK），返回要发送的帧。
    ///
    /// # Errors
    /// 不在初始状态时返回 [`IpcError::InvalidState`]。
    pub fn start_session(&mut self, service_public: &[u8; 32]) -> Result<Vec<u8>, IpcError> {
        if !matches!(self.state, State::Idle) {
            return Err(IpcError::InvalidState);
        }
        let mut hs = Handshake::session_initiator(&self.key, service_public, &self.origin)?;
        let msg = hs.write(&[])?;
        self.state = State::Session(Box::new(hs));
        ControlFrame::Session { d: b64(&msg) }.to_json()
    }

    /// 发送请求，返回请求 ID 与要发送的帧。
    ///
    /// # Errors
    /// 会话未建立时返回 [`IpcError::InvalidState`]。
    pub fn request(&mut self, call: Call) -> Result<(u32, Vec<u8>), IpcError> {
        let State::Established(transport) = &mut self.state else {
            return Err(IpcError::InvalidState);
        };
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let json = zeroize::Zeroizing::new(
            serde_json::to_vec(&Request { id, call }).map_err(|_| IpcError::BadMessage)?,
        );
        let ct = transport.encrypt(&json)?;
        Ok((id, ControlFrame::Noise { d: b64(&ct) }.to_json()?))
    }

    /// 处理收到的一帧，返回要发送的帧与产生的事件。
    ///
    /// # Errors
    /// 帧格式错误、解密失败或状态不符时返回错误，连接应断开。
    pub fn on_frame(&mut self, frame: &[u8]) -> Result<(Vec<Vec<u8>>, Vec<ClientEvent>), IpcError> {
        let frame = ControlFrame::from_json(frame)?;
        if let ControlFrame::Error { code } = frame {
            self.state = State::Closed;
            return Ok((Vec::new(), vec![ClientEvent::Error(code)]));
        }
        let ControlFrame::Noise { d } = frame else {
            self.state = State::Closed;
            return Err(IpcError::BadMessage);
        };
        let data = unb64(&d)?;
        match std::mem::replace(&mut self.state, State::Closed) {
            State::Pairing(mut hs, nonce) => {
                // XX 第二条消息的负载必须为空（spec/ipc.md §4.2）
                if !hs.read(&data)?.is_empty() {
                    return Err(IpcError::BadMessage);
                }
                let payload = serde_json::to_vec(
                    &serde_json::json!({ "name": self.name, "nonce": b64(&nonce) }),
                )
                .map_err(|_| IpcError::BadMessage)?;
                let msg3 = hs.write(&payload)?;
                let sas = hs.sas()?;
                let transport = hs.into_transport()?;
                self.state = State::AwaitPaired(Box::new(transport));
                Ok((
                    vec![ControlFrame::Noise { d: b64(&msg3) }.to_json()?],
                    vec![ClientEvent::ShowSas(sas)],
                ))
            }
            State::AwaitPaired(mut transport) => {
                let msg = decode(&mut transport, &data)?;
                if msg
                    != (ServerMessage::Event {
                        event: Event::Paired,
                    })
                {
                    return Err(IpcError::BadMessage);
                }
                let service_public = transport.remote_static();
                self.state = State::Established(transport);
                Ok((Vec::new(), vec![ClientEvent::Paired { service_public }]))
            }
            State::Session(mut hs) => {
                // IK 第二条消息的负载必须为空（spec/ipc.md §4.3）
                if !hs.read(&data)?.is_empty() {
                    return Err(IpcError::BadMessage);
                }
                let transport = hs.into_transport()?;
                self.state = State::Established(Box::new(transport));
                Ok((Vec::new(), vec![ClientEvent::Established]))
            }
            State::Established(mut transport) => {
                let msg = decode(&mut transport, &data)?;
                self.state = State::Established(transport);
                Ok((Vec::new(), vec![ClientEvent::Message(msg)]))
            }
            State::Idle | State::Closed => Err(IpcError::InvalidState),
        }
    }
}

fn decode(transport: &mut Transport, data: &[u8]) -> Result<ServerMessage, IpcError> {
    let plaintext = transport.decrypt(data)?;
    serde_json::from_slice(&plaintext).map_err(|_| IpcError::BadMessage)
}
