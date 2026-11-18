use core::fmt;

use keevo_crypto::CryptoError;

use crate::message::ErrorCode;

/// IPC 错误。不携带任何秘密数据。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IpcError {
    /// 帧长度为 0 或超过上限（§2），连接必须断开。
    BadFrameLength(usize),
    /// 帧内容不符合协议。
    BadMessage,
    /// 对方报告的协议错误，或本方需要报告给对方的错误。
    Protocol(ErrorCode),
    /// 握手或传输加密失败。
    Crypto(CryptoError),
    /// 当前状态下不允许该操作。
    InvalidState,
    /// I/O 错误。
    Io(String),
    /// 应用消息超过一条 Noise 消息能承载的明文上限（§2）。
    TooLarge,
}

impl fmt::Display for IpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadFrameLength(n) => write!(f, "bad frame length {n}"),
            Self::BadMessage => f.write_str("bad message"),
            Self::Protocol(code) => write!(f, "protocol error: {}", code.as_str()),
            Self::Crypto(e) => write!(f, "crypto: {e}"),
            Self::InvalidState => f.write_str("invalid state"),
            Self::Io(e) => write!(f, "io: {e}"),
            Self::TooLarge => f.write_str("message too large"),
        }
    }
}

impl std::error::Error for IpcError {}

impl From<CryptoError> for IpcError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl From<std::io::Error> for IpcError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}
