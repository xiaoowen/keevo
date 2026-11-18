//! IPC socket 的位置（`spec/ipc.md` §2）。native host 与 Vault Service 必须算出同一个路径。

use std::path::PathBuf;

use crate::error::IpcError;

/// 开发构建可用的环境变量：覆盖 socket 路径（仅 debug 构建生效，release 构建忽略）。
pub const DEV_SOCKET_ENV: &str = "KEEVO_DEV_SOCKET";

/// socket 文件名。
pub const SOCKET_NAME: &str = "keevo.sock";

/// Vault Service 的 socket 路径。
///
/// - **debug 构建**：`KEEVO_DEV_SOCKET`，否则为 `~/Library/Application Support/Keevo-Dev/ipc/keevo.sock`。
/// - **release 构建**：`~/Library/Application Support/Keevo/ipc/keevo.sock`。Keevo 不绑定开发者团队，
///   不使用 App Group 容器（ADR-0003）。
///
/// # Errors
/// 无法确定主目录时返回错误。
pub fn socket_path() -> Result<PathBuf, IpcError> {
    if cfg!(debug_assertions) {
        if let Some(p) = std::env::var_os(DEV_SOCKET_ENV) {
            return Ok(PathBuf::from(p));
        }
        return Ok(home()?
            .join("Library/Application Support/Keevo-Dev/ipc")
            .join(SOCKET_NAME));
    }
    Ok(home()?
        .join("Library/Application Support/Keevo/ipc")
        .join(SOCKET_NAME))
}

fn home() -> Result<PathBuf, IpcError> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| IpcError::Io("HOME not set".into()))
}
