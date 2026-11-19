//! 与 Keevo.app 的连接（`spec/cli.md` §2–§3）与错误到退出码的映射（§7）。

use std::fmt;
use std::os::unix::net::UnixStream;

use keevo_ipc::cli::{
    CLI_CLIENT, CLI_PROTOCOL_VERSION, ClientHello, ErrorBody, Request, ServerHello, decode_response,
};
use keevo_ipc::frame::{read_socket_frame, write_socket_frame};

/// CLI 的错误，决定退出码。
#[derive(Debug)]
pub(crate) enum CliError {
    /// 用法错误（2）。
    Usage(String),
    /// 无法连接 Keevo（3）。
    Connect(String),
    /// 已锁定（4）。
    Locked(String),
    /// 未授权（5）。
    Denied(String),
    /// 引用无法解析（6）。
    Ref(String),
    /// 其他错误（1）。
    Other(String),
}

impl CliError {
    /// 退出码（`spec/cli.md` §7）。
    #[must_use]
    pub(crate) fn exit_code(&self) -> i32 {
        match self {
            Self::Other(_) => 1,
            Self::Usage(_) => 2,
            Self::Connect(_) => 3,
            Self::Locked(_) => 4,
            Self::Denied(_) => 5,
            Self::Ref(_) => 6,
        }
    }

    /// 由服务返回的错误码构造。
    #[must_use]
    pub(crate) fn from_code(code: &str, message: String) -> Self {
        match code {
            "locked" => Self::Locked(message),
            "denied" => Self::Denied(message),
            "not_found" | "ambiguous" | "bad_ref" | "unsupported_field" | "invalid_otp" => {
                Self::Ref(message)
            }
            "bad_request" | "invalid" => Self::Usage(message),
            _ => Self::Other(message),
        }
    }
}

impl From<ErrorBody> for CliError {
    fn from(e: ErrorBody) -> Self {
        let message = if e.message.is_empty() {
            e.error.clone()
        } else {
            e.message
        };
        Self::from_code(&e.error, message)
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(m)
            | Self::Connect(m)
            | Self::Locked(m)
            | Self::Denied(m)
            | Self::Ref(m)
            | Self::Other(m) => f.write_str(m),
        }
    }
}

/// 一个连接。
pub(crate) struct Client {
    stream: UnixStream,
    next: u32,
}

const NOT_RUNNING: &str = "无法连接 Keevo：请确认 Keevo 正在运行";

impl Client {
    /// 连接并握手。
    ///
    /// # Errors
    /// 连接失败、服务拒绝了这个 CLI（不是随当前 Keevo.app 一起构建的）时返回 [`CliError::Connect`]。
    pub(crate) fn connect() -> Result<Self, CliError> {
        let path = keevo_ipc::paths::cli_socket_path()
            .map_err(|e| CliError::Connect(format!("{NOT_RUNNING}（{e}）")))?;
        let mut stream =
            UnixStream::connect(&path).map_err(|_| CliError::Connect(NOT_RUNNING.into()))?;
        let hello = serde_json::to_vec(&ClientHello {
            v: CLI_PROTOCOL_VERSION,
            client: CLI_CLIENT.into(),
            version: env!("CARGO_PKG_VERSION").into(),
        })
        .map_err(|e| CliError::Other(e.to_string()))?;
        let rejected = || {
            CliError::Connect(
                "Keevo 拒绝了这个 keevo 命令：请使用 Keevo.app 自带的命令行工具（设置 → 开发者 → 命令行工具）"
                    .into(),
            )
        };
        write_socket_frame(&mut stream, &hello).map_err(|_| rejected())?;
        let reply: ServerHello = read_socket_frame(&mut stream)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .ok_or_else(rejected)?;
        if !reply.ok {
            return Err(CliError::Connect(format!(
                "Keevo 不支持这个版本的 keevo 命令（{}）：请更新",
                reply.error.unwrap_or_default()
            )));
        }
        Ok(Self { stream, next: 1 })
    }

    /// 发送请求并等待响应。
    ///
    /// # Errors
    /// 服务返回错误、连接断开或响应格式不对时返回错误。
    pub(crate) fn call<T: for<'de> serde::Deserialize<'de>>(
        &mut self,
        make: impl FnOnce(u32) -> Request,
    ) -> Result<T, CliError> {
        let id = self.next;
        self.next = self.next.wrapping_add(1);
        let body = serde_json::to_vec(&make(id)).map_err(|e| CliError::Other(e.to_string()))?;
        write_socket_frame(&mut self.stream, &body)
            .map_err(|_| CliError::Connect("与 Keevo 的连接已断开".into()))?;
        let reply = zeroize::Zeroizing::new(
            read_socket_frame(&mut self.stream)
                .map_err(|_| CliError::Connect("与 Keevo 的连接已断开".into()))?,
        );
        match decode_response::<T>(&reply, id) {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(e.into()),
            Err(e) => Err(CliError::Other(format!("无法理解 Keevo 的响应：{e}"))),
        }
    }
}
