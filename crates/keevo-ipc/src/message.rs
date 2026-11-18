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
        decode_canonical(bytes)
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
    /// 已有配对正在进行，或配对尝试过于频繁（§4.2）。
    PairingLimited,
    /// 用户拒绝本次 `fill` 的站点授权、授权超时，或配对因频率限制被暂停（§5.2）。
    NotAuthorized,
    /// 响应放不进一条 Noise 消息（§2）。例如凭据过长，无法自动填充，应在 Keevo 中复制。
    ResponseTooLarge,
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
            Self::PairingLimited => "pairing_limited",
            Self::NotAuthorized => "not_authorized",
            Self::ResponseTooLarge => "response_too_large",
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

/// 配对显示名原始字节的上限。
pub const MAX_NAME_BYTES: usize = 256;
/// 清洗后的显示名最多保留的 Unicode 标量值个数。
pub const MAX_NAME_CHARS: usize = 64;

/// 清洗配对显示名（`spec/ipc.md` §4.2）：去掉控制字符（Cc）与格式字符（Cf，包括双向文字控制符和零宽字符），
/// 再保留前 [`MAX_NAME_CHARS`] 个 Unicode 标量值。扩展与 Vault Service 用同一个函数，两边显示的名称一致。
#[must_use]
pub fn sanitize_display_name(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_control() && !is_format_char(*c))
        .take(MAX_NAME_CHARS)
        .collect()
}

/// Unicode 一般类别 Cf（格式字符），按 Unicode 15.1。
fn is_format_char(c: char) -> bool {
    matches!(u32::from(c),
        0x00AD | 0x0600..=0x0605 | 0x061C | 0x06DD | 0x070F | 0x0890..=0x0891 | 0x08E2 | 0x180E
        | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x206F | 0xFEFF
        | 0xFFF9..=0xFFFB | 0x110BD | 0x110CD | 0x13430..=0x1343F | 0x1BCA0..=0x1BCA3
        | 0x1D173..=0x1D17A | 0xE0001 | 0xE0020..=0xE007F)
}

/// 一条 Noise 消息能承载的应用明文上限：65,535 字节的 Noise 消息减去 16 字节认证标签（§2）。
pub const MAX_APP_MESSAGE: usize = 65_519;
/// `candidates` 最多返回的条目数（§5.2）。
pub const MAX_CANDIDATES: usize = 20;
/// 候选的标题与副标题最多保留的 Unicode 标量值个数，只用于显示。
pub const MAX_CANDIDATE_TEXT: usize = 200;

/// 解码一条 JSON 消息，只接受其**规范编码**（§5）：解析后重新编码，必须与收到的字节完全相同。
/// 因此字段顺序、空白、转义、未知字段、可选字段的 `null` 都只有一种合法写法。
/// 重新编码的缓冲区会清零（消息里可能有密码）。
pub(crate) fn decode_canonical<T: Serialize + serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, IpcError> {
    let value: T = serde_json::from_slice(bytes).map_err(|_| IpcError::BadMessage)?;
    let mut again = zeroize::Zeroizing::new(Vec::with_capacity(bytes.len()));
    serde_json::to_writer(&mut *again, &value).map_err(|_| IpcError::BadMessage)?;
    if again.as_slice() != bytes {
        return Err(IpcError::BadMessage);
    }
    Ok(value)
}
