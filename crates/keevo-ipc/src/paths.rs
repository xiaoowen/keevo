//! IPC socket 的位置（`spec/ipc.md` §2）。native host 与 Vault Service 必须算出同一个路径。

use std::path::PathBuf;

use crate::error::IpcError;

/// 开发构建可用的环境变量：覆盖 socket 路径（仅 debug 构建生效，release 构建忽略）。
pub const DEV_SOCKET_ENV: &str = "KEEVO_DEV_SOCKET";
/// 开发构建可用的环境变量：覆盖 CLI 的 socket 路径（`spec/cli.md` §2）。
pub const DEV_CLI_SOCKET_ENV: &str = "KEEVO_DEV_CLI_SOCKET";
/// 开发构建可用的环境变量：覆盖 SSH Agent 的 socket 路径（`spec/ssh-agent.md` §1）。
pub const DEV_AGENT_SOCKET_ENV: &str = "KEEVO_DEV_AGENT_SOCKET";

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

/// 数据目录：debug 构建为 `Keevo-Dev`，release 构建为 `Keevo`。
fn data_dir() -> Result<PathBuf, IpcError> {
    let name = if cfg!(debug_assertions) {
        "Keevo-Dev"
    } else {
        "Keevo"
    };
    Ok(home()?.join("Library/Application Support").join(name))
}

fn dev_override(env: &str) -> Option<PathBuf> {
    if cfg!(debug_assertions) {
        std::env::var_os(env).map(PathBuf::from)
    } else {
        None
    }
}

/// 命令行工具的 socket 路径（`spec/cli.md` §2）：`<数据目录>/ipc/cli.sock`。
///
/// # Errors
/// 无法确定主目录时返回错误。
pub fn cli_socket_path() -> Result<PathBuf, IpcError> {
    if let Some(p) = dev_override(DEV_CLI_SOCKET_ENV) {
        return Ok(p);
    }
    Ok(data_dir()?.join("ipc/cli.sock"))
}

/// SSH Agent 的 socket 路径（`spec/ssh-agent.md` §1）：`<数据目录>/ssh/agent.sock`。
///
/// # Errors
/// 无法确定主目录时返回错误。
pub fn agent_socket_path() -> Result<PathBuf, IpcError> {
    if let Some(p) = dev_override(DEV_AGENT_SOCKET_ENV) {
        return Ok(p);
    }
    Ok(data_dir()?.join("ssh/agent.sock"))
}

/// SSH Agent 的便捷软链：`~/.keevo/agent.sock`（路径中没有空格，便于写进 `~/.ssh/config`）。
/// debug 构建为 `~/.keevo/agent-dev.sock`，不与正式版冲突。
///
/// # Errors
/// 无法确定主目录时返回错误。
pub fn agent_link_path() -> Result<PathBuf, IpcError> {
    let name = if cfg!(debug_assertions) {
        "agent-dev.sock"
    } else {
        "agent.sock"
    };
    Ok(home()?.join(".keevo").join(name))
}

fn home() -> Result<PathBuf, IpcError> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| IpcError::Io("HOME not set".into()))
}
