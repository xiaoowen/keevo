//! Keevo 本地通信协议（`spec/ipc.md`）。
//!
//! - [`frame`]：两段链路的分帧（§2）。
//! - [`message`]：控制层帧与会话内消息（§5）。
//! - [`service::ServiceConnection`]：Vault Service 一侧的协议状态机，包括配对、会话与最小披露。
//! - [`client::ExtensionClient`]：扩展一侧的协议状态机。用于测试，将来可编译为 WASM 供扩展使用。
//!
//! 状态机不做任何 I/O：调用方把收到的帧交给状态机，再把返回的帧发出去。
//! 因此同一套逻辑可以接到 socket、Native Messaging 或测试中的内存通道上。

pub mod client;
mod error;
pub mod frame;
pub mod message;
pub mod paths;
pub mod sas;
pub mod service;

pub use error::IpcError;

#[cfg(test)]
mod tests;
