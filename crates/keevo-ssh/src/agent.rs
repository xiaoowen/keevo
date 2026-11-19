//! SSH agent 消息（draft-miller-ssh-agent、OpenSSH `PROTOCOL.agent`，`spec/ssh-agent.md` §2）。
//!
//! 消息为 `uint32 长度` + `byte 类型` + 内容。本模块只解析与构造消息体（类型 + 内容），
//! 外加按长度读写整条消息的辅助函数；连接、授权与签名在 `keevo-service` 中。

use std::io::{self, Read, Write};

use crate::key::{PublicKey, fingerprint_blob};
use crate::wire::{Reader, WireError, Writer};

/// 单条消息的长度上限（`spec/ssh-agent.md` §2）。
pub const MAX_MESSAGE: usize = 256 * 1024;
/// 每个连接最多记录的 session-bind 次数（§5）。
pub const MAX_BINDS: usize = 16;

/// 消息类型。
pub mod msg {
    /// `SSH_AGENT_FAILURE`。
    pub const FAILURE: u8 = 5;
    /// `SSH_AGENT_SUCCESS`。
    pub const SUCCESS: u8 = 6;
    /// `SSH_AGENTC_REQUEST_IDENTITIES`。
    pub const REQUEST_IDENTITIES: u8 = 11;
    /// `SSH_AGENT_IDENTITIES_ANSWER`。
    pub const IDENTITIES_ANSWER: u8 = 12;
    /// `SSH_AGENTC_SIGN_REQUEST`。
    pub const SIGN_REQUEST: u8 = 13;
    /// `SSH_AGENT_SIGN_RESPONSE`。
    pub const SIGN_RESPONSE: u8 = 14;
    /// `SSH_AGENTC_EXTENSION`。
    pub const EXTENSION: u8 = 27;
    /// `SSH_AGENT_EXTENSION_FAILURE`。
    pub const EXTENSION_FAILURE: u8 = 28;
}

/// `session-bind@openssh.com` 扩展名。
pub const SESSION_BIND: &str = "session-bind@openssh.com";

/// 一个请求。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request<'a> {
    /// 列出公钥。
    Identities,
    /// 签名。
    Sign {
        /// 公钥 blob。
        key_blob: &'a [u8],
        /// 要签名的数据。
        data: &'a [u8],
        /// 标志（RSA 的哈希选择；Ed25519 忽略）。
        flags: u32,
    },
    /// `session-bind@openssh.com`。
    SessionBind(SessionBind),
    /// 其他扩展。
    Extension(String),
    /// 其他请求类型（添加、删除密钥、锁定等），一律拒绝。
    Other(u8),
}

/// 一次会话绑定（`spec/ssh-agent.md` §5）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionBind {
    /// 服务器的主机密钥 blob。
    pub host_key: Vec<u8>,
    /// SSH 会话标识。
    pub session_id: Vec<u8>,
    /// 主机密钥对会话标识的签名 blob。
    pub signature: Vec<u8>,
    /// 是否为转发的 agent 连接。
    pub forwarding: bool,
}

/// 会话绑定的验证结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindCheck {
    /// 主机密钥的签名有效。
    Verified,
    /// 主机密钥的算法不支持，无法验证：只用于显示。
    Unverified,
    /// 签名无效。
    Invalid,
}

impl SessionBind {
    /// 验证主机密钥对会话标识的签名（§5）。
    #[must_use]
    pub fn check(&self) -> BindCheck {
        match PublicKey::from_blob(&self.host_key) {
            Ok(key) => {
                if key.verify(&self.session_id, &self.signature) {
                    BindCheck::Verified
                } else {
                    BindCheck::Invalid
                }
            }
            Err(crate::KeyError::Unsupported(_)) => BindCheck::Unverified,
            Err(_) => BindCheck::Invalid,
        }
    }

    /// 主机密钥的 SHA-256 指纹。
    #[must_use]
    pub fn host_fingerprint(&self) -> String {
        fingerprint_blob(&self.host_key)
    }

    /// 主机密钥的算法名（无法解析时为空）。
    #[must_use]
    pub fn host_algorithm(&self) -> String {
        Reader::new(&self.host_key)
            .string()
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .unwrap_or_default()
    }
}

/// 解析消息体（类型 + 内容）。
///
/// # Errors
/// 消息为空、字段越界、规定的字段之后还有多余字节时返回错误。
pub fn parse_request(body: &[u8]) -> Result<Request<'_>, WireError> {
    let mut r = Reader::new(body);
    let kind = r.u8()?;
    match kind {
        msg::REQUEST_IDENTITIES => {
            r.finish()?;
            Ok(Request::Identities)
        }
        msg::SIGN_REQUEST => {
            let key_blob = r.string()?;
            let data = r.string()?;
            let flags = r.u32()?;
            r.finish()?;
            Ok(Request::Sign {
                key_blob,
                data,
                flags,
            })
        }
        msg::EXTENSION => {
            let name = r.string()?;
            if name == SESSION_BIND.as_bytes() {
                let host_key = r.string()?.to_vec();
                let session_id = r.string()?.to_vec();
                let signature = r.string()?.to_vec();
                let forwarding = r.bool()?;
                r.finish()?;
                Ok(Request::SessionBind(SessionBind {
                    host_key,
                    session_id,
                    signature,
                    forwarding,
                }))
            } else {
                // 其他扩展的内容不解析
                Ok(Request::Extension(
                    String::from_utf8_lossy(name).into_owned(),
                ))
            }
        }
        other => Ok(Request::Other(other)),
    }
}

/// `SSH_AGENT_IDENTITIES_ANSWER`：(公钥 blob, 注释) 列表。
#[must_use]
pub fn identities_answer(keys: &[(Vec<u8>, String)]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(msg::IDENTITIES_ANSWER)
        .u32(u32::try_from(keys.len()).unwrap_or(u32::MAX));
    for (blob, comment) in keys {
        w.string(blob).string(comment.as_bytes());
    }
    w.into_inner()
}

/// `SSH_AGENT_SIGN_RESPONSE`。
#[must_use]
pub fn sign_response(signature_blob: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(msg::SIGN_RESPONSE).string(signature_blob);
    w.into_inner()
}

/// 只有类型的回复：`SSH_AGENT_FAILURE`、`SSH_AGENT_SUCCESS`、`SSH_AGENT_EXTENSION_FAILURE`。
#[must_use]
pub fn simple(kind: u8) -> Vec<u8> {
    vec![kind]
}

/// 读取一条消息体。对方正常关闭（在消息边界上）时返回 `Ok(None)`。
///
/// # Errors
/// 长度为 0 或超过 [`MAX_MESSAGE`]、在消息中间断开、I/O 错误。
pub fn read_message<R: Read>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    let mut got = 0usize;
    while got < len.len() {
        let Some(buf) = len.get_mut(got..) else {
            break;
        };
        match r.read(buf) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => got = got.saturating_add(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let len = usize::try_from(u32::from_be_bytes(len)).unwrap_or(usize::MAX);
    if len == 0 || len > MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad agent message length",
        ));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(Some(body))
}

/// 写入一条消息（加上长度前缀）。
///
/// # Errors
/// I/O 错误；消息超过 [`MAX_MESSAGE`]。
pub fn write_message<W: Write>(w: &mut W, body: &[u8]) -> io::Result<()> {
    if body.len() > MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "agent message too long",
        ));
    }
    let len = u32::try_from(body.len()).map_err(|_| io::Error::other("too long"))?;
    let mut out = Vec::with_capacity(body.len().saturating_add(4));
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    w.write_all(&out)?;
    w.flush()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::PrivateKey;

    #[test]
    fn parses_requests() {
        assert_eq!(parse_request(&[11]).unwrap(), Request::Identities);
        assert!(parse_request(&[11, 0]).is_err());
        assert!(parse_request(&[]).is_err());

        let mut w = Writer::new();
        w.u8(msg::SIGN_REQUEST)
            .string(b"blob")
            .string(b"data")
            .u32(2);
        let body = w.into_inner();
        assert_eq!(
            parse_request(&body).unwrap(),
            Request::Sign {
                key_blob: b"blob",
                data: b"data",
                flags: 2
            }
        );
        // 多余字节
        let mut extra = body.clone();
        extra.push(0);
        assert!(parse_request(&extra).is_err());

        assert_eq!(parse_request(&[17, 1, 2]).unwrap(), Request::Other(17));
        let mut w = Writer::new();
        w.u8(msg::EXTENSION).string(b"query").raw(b"anything");
        assert_eq!(
            parse_request(&w.into_inner()).unwrap(),
            Request::Extension("query".into())
        );
    }

    #[test]
    fn session_bind_is_verified_with_ed25519_host_keys() {
        let host = PrivateKey::generate_ed25519("").unwrap();
        let sid = b"session identifier".to_vec();
        let bind = |signature: Vec<u8>, forwarding: bool| {
            let mut w = Writer::new();
            w.u8(msg::EXTENSION)
                .string(SESSION_BIND.as_bytes())
                .string(&host.public_key().blob())
                .string(&sid)
                .string(&signature)
                .bool(forwarding);
            w.into_inner()
        };
        let good = bind(host.sign(&sid), true);
        let Request::SessionBind(b) = parse_request(&good).unwrap() else {
            panic!("应为 session-bind")
        };
        assert!(b.forwarding);
        assert_eq!(b.check(), BindCheck::Verified);
        assert_eq!(b.host_fingerprint(), host.public_key().fingerprint());

        let other = PrivateKey::generate_ed25519("").unwrap();
        let Request::SessionBind(b) = parse_request(&bind(other.sign(&sid), false)).unwrap() else {
            panic!("应为 session-bind")
        };
        assert_eq!(b.check(), BindCheck::Invalid);

        // RSA 主机密钥：无法验证，只用于显示
        let mut rsa = Writer::new();
        rsa.string(b"ssh-rsa")
            .string(&[1, 0, 1])
            .string(&[0xc0; 64]);
        let b = SessionBind {
            host_key: rsa.into_inner(),
            session_id: sid,
            signature: vec![],
            forwarding: false,
        };
        assert_eq!(b.check(), BindCheck::Unverified);
        assert_eq!(b.host_algorithm(), "ssh-rsa");
    }

    #[test]
    fn frames_messages() {
        let mut buf = Vec::new();
        write_message(&mut buf, &identities_answer(&[(b"k".to_vec(), "c".into())])).unwrap();
        let mut r = buf.as_slice();
        let body = read_message(&mut r).unwrap().unwrap();
        assert_eq!(body[0], msg::IDENTITIES_ANSWER);
        assert_eq!(read_message(&mut r).unwrap(), None);
        // 长度为 0、过长、在中间断开
        assert!(read_message(&mut [0u8, 0, 0, 0].as_slice()).is_err());
        assert!(read_message(&mut [0u8, 0x10, 0, 1].as_slice()).is_err());
        assert!(read_message(&mut [0u8, 0, 0, 5, 1].as_slice()).is_err());
        assert!(read_message(&mut [0u8, 0].as_slice()).is_err());
    }
}
