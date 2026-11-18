use std::collections::HashMap;
use std::fs;
use std::net::Shutdown;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;

use keevo_core::Vault;
use keevo_crypto::StaticKeypair;
use keevo_ipc::frame::{read_socket_frame, write_socket_frame};
use keevo_ipc::service::{Output, PairingStore, ServiceConnection};

use crate::backend::CoreBackend;

/// socket 对端的校验策略（`spec/ipc.md` §3.1）。
#[derive(Debug, Clone)]
pub enum PeerPolicy {
    /// 对端必须满足该代码签名要求。正式构建只允许这一种。
    CodeRequirement(String),
    /// 只依赖 socket 目录的 0700 权限（同一用户的任何进程都能连接）。仅供开发，构建为 release 时拒绝使用。
    DevSameUserOnly,
}

/// 请用户确认配对：展示短认证串，返回用户是否确认。实现应在 60 秒内未确认时返回 `false`。
pub trait PairingPrompt: Send + Sync {
    /// 展示并等待确认。
    fn confirm(&self, sas: [u8; 6], name: &str, browser: &str) -> bool;
}

/// 已建立会话的登记表：连接编号 → (扩展公钥, 用于主动断开的 socket 句柄)。
type Sessions = Arc<Mutex<HashMap<u64, ([u8; 32], UnixStream)>>>;

/// 本地 IPC 服务。
pub struct VaultService<S: PairingStore + Send + 'static> {
    vault: Arc<Mutex<Vault>>,
    key: Arc<StaticKeypair>,
    pairings: Arc<Mutex<S>>,
    prompt: Arc<dyn PairingPrompt>,
    policy: PeerPolicy,
    sessions: Sessions,
    next_conn: Arc<AtomicU64>,
}

impl<S: PairingStore + Send + 'static> Clone for VaultService<S> {
    fn clone(&self) -> Self {
        Self {
            vault: Arc::clone(&self.vault),
            key: Arc::clone(&self.key),
            pairings: Arc::clone(&self.pairings),
            prompt: Arc::clone(&self.prompt),
            policy: self.policy.clone(),
            sessions: Arc::clone(&self.sessions),
            next_conn: Arc::clone(&self.next_conn),
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl<S: PairingStore + Send + 'static> VaultService<S> {
    /// 创建服务。
    ///
    /// # Errors
    /// release 构建中使用 [`PeerPolicy::DevSameUserOnly`] 时返回错误。
    pub fn new(
        vault: Arc<Mutex<Vault>>,
        key: StaticKeypair,
        pairings: Arc<Mutex<S>>,
        prompt: Arc<dyn PairingPrompt>,
        policy: PeerPolicy,
    ) -> std::io::Result<Self> {
        if !cfg!(debug_assertions) && matches!(policy, PeerPolicy::DevSameUserOnly) {
            return Err(std::io::Error::other(
                "DevSameUserOnly is not allowed in release builds",
            ));
        }
        Ok(Self {
            vault,
            key: Arc::new(key),
            pairings,
            prompt,
            policy,
            sessions: Arc::default(),
            next_conn: Arc::default(),
        })
    }

    /// 撤销配对（`spec/ipc.md` §4.4）：删除配对记录，并立即断开该扩展的全部已建立会话。
    ///
    /// # Errors
    /// 配对记录持久化失败时返回错误；此时内存中的记录已删除、会话已断开，但重启后撤销可能失效。
    pub fn revoke(&self, extension_public: &[u8; 32]) -> std::io::Result<()> {
        let result = lock(&self.pairings).revoke(extension_public);
        for (pk, stream) in lock(&self.sessions).values() {
            if pk == extension_public {
                let _ = stream.shutdown(Shutdown::Both);
            }
        }
        result
    }

    /// 服务的静态公钥。
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.key.public_key()
    }

    /// 接受连接，直到监听器出错。每个连接一个线程。
    pub fn serve(&self, listener: &UnixListener) {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let svc = self.clone();
            thread::spawn(move || svc.handle(stream));
        }
    }

    /// 处理一个连接，直到对方断开或协议出错。
    pub fn handle(&self, mut stream: UnixStream) {
        if let PeerPolicy::CodeRequirement(req) = &self.policy
            && keevo_macos::verify_socket_peer(&stream, req) != Ok(true)
        {
            return;
        }
        let id = self.next_conn.fetch_add(1, Ordering::Relaxed);
        let mut conn = ServiceConnection::new(Arc::clone(&self.key));
        while let Ok(frame) = read_socket_frame(&mut stream) {
            let outputs = {
                let vault = lock(&self.vault);
                let pairings = lock(&self.pairings);
                conn.on_frame(&frame, &*pairings, &CoreBackend::new(&vault))
            };
            if !self.emit(&mut stream, &mut conn, outputs) {
                break;
            }
            self.register(id, &conn, &stream);
        }
        lock(&self.sessions).remove(&id);
    }

    /// 会话建立后登记连接，供撤销时主动断开。
    fn register(&self, id: u64, conn: &ServiceConnection, stream: &UnixStream) {
        let Some(pk) = conn.peer_public() else { return };
        let mut sessions = lock(&self.sessions);
        if sessions.contains_key(&id) {
            return;
        }
        // 登记前再核对一次：若握手与撤销同时发生，确保不会留下未被断开的会话
        if lock(&self.pairings).find(&pk).is_none() {
            let _ = stream.shutdown(Shutdown::Both);
            return;
        }
        if let Ok(handle) = stream.try_clone() {
            sessions.insert(id, (pk, handle));
        }
    }

    /// 发出状态机的输出。返回 `false` 表示连接应关闭。
    fn emit(
        &self,
        stream: &mut UnixStream,
        conn: &mut ServiceConnection,
        outputs: Vec<Output>,
    ) -> bool {
        for output in outputs {
            match output {
                Output::Send(frame) => {
                    if write_socket_frame(stream, &frame).is_err() {
                        return false;
                    }
                }
                Output::ConfirmPairing { sas, name, browser } => {
                    // 等待用户确认期间不持有任何锁
                    let accepted = self.prompt.confirm(sas, &name, &browser);
                    let more = conn.confirm_pairing(accepted, &mut *lock(&self.pairings));
                    if !self.emit(stream, conn, more) {
                        return false;
                    }
                }
                Output::Close => return false,
            }
        }
        true
    }
}

/// 绑定 socket：父目录权限设为 0700，并清除上次运行遗留的 socket 文件。
///
/// # Errors
/// 目录或 socket 无法创建时返回错误。
pub fn bind(path: &Path) -> std::io::Result<UnixListener> {
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("socket path has no parent"))?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    UnixListener::bind(path)
}
