//! 消息定义（`spec/ipc.md` §5）。

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::error::IpcError;

/// 协议版本。
pub const PROTOCOL_VERSION: u32 = 1;

/// 控制层帧：扩展 ↔ native host ↔ Vault Service 之间的明文 JSON（§5.1）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlFrame {
    /// 扩展 → host：协议版本。
    Hello {
        /// 版本。
        v: u32,
    },
    /// XX 配对的第一条握手消息。
    Pair {
        /// base64url（无填充）的 Noise 消息。
        d: String,
    },
    /// IK 会话的第一条握手消息。
    Session {
        /// base64url（无填充）的 Noise 消息。
        d: String,
    },
    /// 其余握手消息与传输消息。
    Noise {
        /// base64url（无填充）的 Noise 消息。
        d: String,
    },
    /// 错误，发送方随后断开。
    Error {
        /// 错误码。
        code: ErrorCode,
    },
}

impl ControlFrame {
    /// 编码为 JSON。
    ///
    /// # Errors
    /// 序列化失败时返回 [`IpcError::BadMessage`]。
    pub fn to_json(&self) -> Result<Vec<u8>, IpcError> {
        serde_json::to_vec(self).map_err(|_| IpcError::BadMessage)
    }

    /// 从 JSON 解码。
    ///
    /// # Errors
    /// 格式错误时返回 [`IpcError::BadMessage`]。
    pub fn from_json(bytes: &[u8]) -> Result<Self, IpcError> {
        serde_json::from_slice(bytes).map_err(|_| IpcError::BadMessage)
    }
}

/// base64url（无填充）编码。
#[must_use]
pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// base64url（无填充）解码。
///
/// # Errors
/// 格式错误时返回 [`IpcError::BadMessage`]。
pub fn unb64(s: &str) -> Result<Vec<u8>, IpcError> {
    URL_SAFE_NO_PAD.decode(s).map_err(|_| IpcError::BadMessage)
}

/// native host 发给 Vault Service 的首帧（§5.4）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostHello {
    /// 协议版本。
    pub v: u32,
    /// 客户端类型，目前只有 `native-host`。
    pub client: String,
    /// 扩展来源，如 `chrome-extension://<id>/`。
    pub extension_origin: String,
    /// 浏览器标识，如 `com.google.Chrome`。
    pub browser: String,
}

/// 错误码（§5.3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// 协议版本不支持。
    UnsupportedVersion,
    /// 扩展未配对。
    NotPaired,
    /// 用户拒绝配对或超时。
    PairingRejected,
    /// Vault Service 已锁定。
    Locked,
    /// 条目与网址不匹配。
    UrlMismatch,
    /// 条目不存在。
    NotFound,
    /// 消息格式错误。
    BadRequest,
    /// 无法连接 Vault Service。
    ServiceUnavailable,
}

impl ErrorCode {
    /// 错误码字符串。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedVersion => "unsupported_version",
            Self::NotPaired => "not_paired",
            Self::PairingRejected => "pairing_rejected",
            Self::Locked => "locked",
            Self::UrlMismatch => "url_mismatch",
            Self::NotFound => "not_found",
            Self::BadRequest => "bad_request",
            Self::ServiceUnavailable => "service_unavailable",
        }
    }
}

/// 会话内的请求（§5.2）。（serde 不支持 `flatten` 与 `deny_unknown_fields` 同时使用。）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// 请求 ID，由扩展分配，响应中原样返回。
    pub id: u32,
    /// 方法与参数。
    #[serde(flatten)]
    pub call: Call,
}

/// 请求的方法与参数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum Call {
    /// 查询锁定状态。
    Status,
    /// 查询与网址匹配的条目概要。
    Candidates {
        /// 当前帧的网址。
        url: String,
    },
    /// 取得填充所需的凭据。
    Fill {
        /// 条目 ID（十六进制）。
        item_id: String,
        /// 当前帧的网址，Vault Service 会再次校验是否与条目匹配。
        url: String,
    },
}

/// 候选条目：只含概要，不含任何秘密。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    /// 条目 ID（十六进制）。
    pub item_id: String,
    /// 标题。
    pub title: String,
    /// 副标题（通常是用户名）。
    pub subtitle: String,
}

/// 填充所需的凭据。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FillData {
    /// 用户名。
    pub username: String,
    /// 密码。
    pub password: String,
    /// 当前的一次性密码（如有）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<String>,
}

impl core::fmt::Debug for FillData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FillData(…)")
    }
}

impl Drop for FillData {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.username.zeroize();
        self.password.zeroize();
        if let Some(t) = self.totp.as_mut() {
            t.zeroize();
        }
    }
}

/// 请求的结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CallResult {
    /// `status` 的结果。
    Status {
        /// 是否已锁定。
        locked: bool,
    },
    /// `candidates` 的结果。
    Candidates {
        /// 匹配的条目。
        items: Vec<Candidate>,
    },
    /// `fill` 的结果。
    Fill(FillData),
}

/// 错误体。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorBody {
    /// 错误码。
    pub code: ErrorCode,
}

/// Vault Service 发往扩展的会话内消息。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServerMessage {
    /// 成功响应。
    Ok {
        /// 对应的请求 ID。
        id: u32,
        /// 结果。
        result: CallResult,
    },
    /// 错误响应。
    Err {
        /// 对应的请求 ID。
        id: u32,
        /// 错误。
        error: ErrorBody,
    },
    /// 推送事件。
    Event {
        /// 事件。
        event: Event,
    },
}

/// 推送事件。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    /// 用户确认了配对，此后可以发送请求。
    Paired,
    /// Vault Service 已锁定。
    Locked,
    /// Vault Service 已解锁。
    Unlocked,
}
