//! SSH 密钥与 SSH agent 协议（`spec/ssh-agent.md`）。
//!
//! - [`wire`]：SSH 线上编码（RFC 4251 §5）。
//! - [`key`]：公钥、指纹、OpenSSH 私钥格式（Ed25519）。
//! - [`agent`]：agent 消息的解析与构造、`session-bind@openssh.com`。
//!
//! 签名与指纹的哈希由 `keevo-crypto` 完成，本 crate 不直接依赖密码学原语库。

pub mod agent;
pub mod key;
pub mod wire;

pub use key::{KeyError, PrivateKey, PublicKey};
