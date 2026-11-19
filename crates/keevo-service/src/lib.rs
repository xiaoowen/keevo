//! Vault Service 的本地 IPC 服务（`spec/ipc.md`）。
//!
//! 职责：
//! 1. 监听 Unix socket（目录权限 0700），对每个连接先校验对端代码签名（§3.1）；
//! 2. 为每个连接运行 [`keevo_ipc::service::ServiceConnection`] 状态机；
//! 3. 把状态机的后端接口接到 [`keevo_core::Vault`] 上，按网址匹配规则提供候选与填充数据。
//!
//! M0 由开发服务 `keevo-dev-service` 使用；M1 由 Keevo.app 经 FFI 启动。

mod backend;
mod pairing;
mod server;

pub use backend::CoreBackend;
pub use pairing::{
    AUTHORIZATION_KIND, Authorization, FILL_DISTINCT_LIMIT, FILL_WINDOW, LoadReport, PAIRING_KIND,
    PairingCache,
};
pub use server::{PairingPrompt, PeerPolicy, VaultService, bind};
