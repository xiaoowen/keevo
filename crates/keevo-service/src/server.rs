use std::collections::HashMap;
use std::fs;
use std::io::Read;
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
use keevo_ipc::service::{
    FILL_AUTHORIZATION_TIMEOUT, FillRequest, Output, PairingGate, PairingRecord, PairingStore,
    SEARCH_AUTHORIZATION_TIMEOUT, SearchRequest, ServiceConnection, UPDATE_CONFIRMATION_TIMEOUT,
    VaultBackend, WriteOp, WriteRequest,
};

use crate::backend::CoreBackend;
use crate::pairing::{Authorization, Bound, Live, LoadReport, PairingCache, ReadOnly};

/// socket 对端的校验策略（`spec/ipc.md` §3.1）。
#[derive(Debug, Clone)]
pub enum PeerPolicy {
    /// 对端必须满足该代码签名要求。正式构建只允许这一种。
    CodeRequirement(String),
    /// 只依赖 socket 目录的 0700 权限（同一用户的任何进程都能连接）。仅供开发，构建为 release 时拒绝使用。
    DevSameUserOnly,
}

/// 请用户确认配对：展示短认证串，返回用户是否确认。实现必须在 `deadline` 到达时关闭界面并返回 `false`
/// （`spec/ipc.md` §4.2）；状态机也会拒绝迟到的确认，但只有界面按时返回，连接与配对闸门才会按时释放。
pub trait PairingPrompt: Send + Sync {
    /// 收到配对请求的第 1 条消息时调用：立即告诉用户"有浏览器正在请求配对"，让每次尝试都可见
    /// （`spec/ipc.md` §4.2）。
    fn started(&self, browser: &str) {
        let _ = browser;
    }
    /// 展示并等待确认。
    fn confirm(
        &self,
        sas: [u8; 6],
        name: &str,
        browser: &str,
        deadline: std::time::Instant,
    ) -> bool;
    /// 某个配对第一次为某个条目在某个站点取用凭据：在原生界面显示站点、条目与配对，请用户确认
    /// （`spec/ipc.md` §5.2）。必须在 `deadline` 到达时关闭界面并返回 `false`。默认拒绝。
    fn authorize_fill(&self, request: &FillRequest, deadline: std::time::Instant) -> bool {
        let _ = (request, deadline);
        false
    }
    /// 这个配对因频率限制被暂停（§5.2 第 3 条）：在 Keevo.app 中提示，用户确认后调用 [`VaultService::resume`]。
    fn fill_paused(&self, extension_public: &[u8; 32], name: &str, browser: &str) {
        let _ = (extension_public, name, browser);
    }
    /// 协议 v2：扩展请求更新已有登录的密码（`spec/ipc.md` §5.5）。在原生界面显示站点、条目与配对，请用户确认；
    /// `changed` 表示新密码与原来不同（只显示给用户，不告诉扩展）。必须在 `deadline` 到达时关闭界面并返回
    /// `false`。默认拒绝。
    fn confirm_update(
        &self,
        request: &WriteRequest,
        changed: bool,
        deadline: std::time::Instant,
    ) -> bool {
        let _ = (request, changed, deadline);
        false
    }
    /// 这个配对短时间内查询了太多不同的站点（`spec/ipc.md` §5.2）：在 Keevo.app 中提示，可能有人在冒用它枚举账户。
    fn queries_limited(&self, extension_public: &[u8; 32], name: &str, browser: &str) {
        let _ = (extension_public, name, browser);
    }
    /// 协议 v2：扩展保存了新的登录。在 Keevo.app 中提示，让每次写入都对用户可见（`spec/ipc.md` §5.5）。
    fn saved(&self, pairing_name: &str, browser: &str, title: &str) {
        let _ = (pairing_name, browser, title);
    }
    /// 协议 v3：这次解锁中第一次搜索全部条目（`spec/ipc.md` §5.6）。在原生界面显示配对与搜索词，请用户允许；
    /// 必须在 `deadline` 到达时关闭界面并返回 `false`。默认拒绝。
    fn authorize_search(&self, request: &SearchRequest, deadline: std::time::Instant) -> bool {
        let _ = (request, deadline);
        false
    }
    /// 协议 v3：扩展请求显示 Keevo 的主窗口；`item_id` 已核对存在（`spec/ipc.md` §5.6）。锁定时显示锁屏。
    fn open(&self, pairing_name: &str, browser: &str, item_id: Option<&str>) {
        let _ = (pairing_name, browser, item_id);
    }
    /// 协议 v3：扩展请求解锁（`spec/ipc.md` §5.6）。显示锁屏并说明是谁在等待；可以用 Touch ID 时直接请求验证。
    fn unlock_requested(&self, pairing_name: &str, browser: &str) {
        let _ = (pairing_name, browser);
    }
}

/// 已建立会话的登记表：连接编号 → (扩展公钥, 用于主动断开的 socket 句柄)。
type Sessions = Arc<Mutex<HashMap<u64, ([u8; 32], UnixStream)>>>;

/// 本地 IPC 服务。加锁顺序固定为"保险库 → 配对记录 → 会话登记表"，任何路径都不反向加锁。
pub struct VaultService {
    vault: Arc<Mutex<Vault>>,
    key: Arc<StaticKeypair>,
    pairings: Arc<Mutex<PairingCache>>,
    prompt: Arc<dyn PairingPrompt>,
    policy: PeerPolicy,
    sessions: Sessions,
    next_conn: Arc<AtomicU64>,
    gate: Arc<PairingGate>,
}

impl Clone for VaultService {
    fn clone(&self) -> Self {
        Self {
            vault: Arc::clone(&self.vault),
            key: Arc::clone(&self.key),
            pairings: Arc::clone(&self.pairings),
            prompt: Arc::clone(&self.prompt),
            policy: self.policy.clone(),
            sessions: Arc::clone(&self.sessions),
            next_conn: Arc::clone(&self.next_conn),
            gate: Arc::clone(&self.gate),
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl VaultService {
    /// 创建服务。配对记录在 [`VaultService::load_pairings`] 之前不可读（首次解锁前 IK 返回 `locked`）。
    ///
    /// # Errors
    /// release 构建中使用 [`PeerPolicy::DevSameUserOnly`] 时返回错误。
    pub fn new(
        vault: Arc<Mutex<Vault>>,
        key: StaticKeypair,
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
            pairings: Arc::default(),
            prompt,
            policy,
            sessions: Arc::default(),
            next_conn: Arc::default(),
            gate: Arc::default(),
        })
    }

    /// 撤销配对（`spec/ipc.md` §4.4）：删除配对记录，并立即断开该扩展的全部已建立会话。
    ///
    /// # Errors
    /// 配对记录持久化失败时返回错误；此时内存中的记录已删除、会话已断开，但重启后撤销可能失效。
    pub fn revoke(&self, extension_public: &[u8; 32]) -> std::io::Result<()> {
        let result = {
            let mut vault = lock(&self.vault);
            let mut cache = lock(&self.pairings);
            Bound {
                cache: &mut cache,
                vault: &mut vault,
            }
            .revoke(extension_public)
        };
        for (pk, stream) in lock(&self.sessions).values() {
            if pk == extension_public {
                let _ = stream.shutdown(Shutdown::Both);
            }
        }
        result
    }

    /// 解锁后调用：读入配对记录（先应用待提交的撤销）。
    ///
    /// # Errors
    /// 保险库已锁定或读取失败时返回错误。
    pub fn load_pairings(&self) -> std::io::Result<LoadReport> {
        let mut vault = lock(&self.vault);
        lock(&self.pairings).load(&mut vault)
    }

    /// 全部配对记录（"设置 → 浏览器"）。
    #[must_use]
    pub fn pairings(&self) -> Vec<PairingRecord> {
        lock(&self.pairings).records().to_vec()
    }

    /// 仍未写入数据库的撤销数（§4.4：大于 0 时提示"撤销可能在重启后失效"）。
    #[must_use]
    pub fn pending_revocations(&self) -> usize {
        lock(&self.pairings).pending_revocations()
    }

    /// 某个配对的全部站点授权（"设置 → 浏览器"）。
    #[must_use]
    pub fn authorizations(&self, extension_public: &[u8; 32]) -> Vec<Authorization> {
        lock(&self.pairings).authorizations(extension_public)
    }

    /// 撤销一项站点授权（§5.2 第 2 条）。之后这个配对再为该条目在该站点取用凭据，需要重新确认。
    ///
    /// # Errors
    /// 写入数据库失败时返回错误；此时内存中已撤销，但重启后可能恢复。
    pub fn revoke_authorization(
        &self,
        extension_public: &[u8; 32],
        item_id: &str,
        site: &str,
    ) -> std::io::Result<()> {
        let mut vault = lock(&self.vault);
        let mut cache = lock(&self.pairings);
        Bound {
            cache: &mut cache,
            vault: &mut vault,
        }
        .revoke_authorization(extension_public, item_id, site)
    }

    /// 这个配对是否因频率限制被暂停。
    #[must_use]
    pub fn is_paused(&self, extension_public: &[u8; 32]) -> bool {
        lock(&self.pairings).is_paused(extension_public)
    }

    /// 用户确认后恢复被暂停的配对（§5.2 第 3 条）。
    pub fn resume(&self, extension_public: &[u8; 32]) {
        lock(&self.pairings).resume(extension_public);
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
        let mut conn =
            ServiceConnection::new(Arc::clone(&self.key)).with_pairing_gate(Arc::clone(&self.gate));
        loop {
            // 配对进行中时，按绝对截止时间读取：到期即断开，释放连接与配对闸门（§4.2）
            let mut reader = DeadlineReader {
                stream: &stream,
                deadline: conn.pairing_deadline(),
            };
            let Ok(frame) = read_socket_frame(&mut reader) else {
                break;
            };
            let outputs = {
                let vault = lock(&self.vault);
                let mut pairings = lock(&self.pairings);
                conn.on_frame(&frame, &mut Live(&mut pairings), &CoreBackend::new(&vault))
            };
            // 会话一建立就登记，早于任何可能阻塞的发送（第二轮评审 G7）；
            // 配对确认发生在 emit 内，那里同样先登记再发送（第三轮评审 H6）
            if !self.register(id, &conn, &stream) || !self.emit(id, &mut stream, &mut conn, outputs)
            {
                break;
            }
        }
        lock(&self.sessions).remove(&id);
        let _ = stream.shutdown(Shutdown::Both);
    }

    /// 会话建立后登记连接，供撤销时主动断开。返回 `false` 表示连接必须关闭：
    /// 登记前发现配对已被撤销，或无法取得用于主动断开的句柄（第二轮评审 G7）。
    fn register(&self, id: u64, conn: &ServiceConnection, stream: &UnixStream) -> bool {
        let Some(pk) = conn.peer_public() else {
            return true;
        };
        let mut sessions = lock(&self.sessions);
        if sessions.contains_key(&id) {
            return true;
        }
        // 登记前再核对一次：若握手与撤销同时发生，确保不会留下未被断开的会话
        if ReadOnly(&lock(&self.pairings)).find(&pk).is_none() {
            return false;
        }
        match stream.try_clone() {
            Ok(handle) => {
                sessions.insert(id, (pk, handle));
                true
            }
            Err(_) => false,
        }
    }

    /// 发出状态机的输出。返回 `false` 表示连接应关闭。
    fn emit(
        &self,
        id: u64,
        stream: &mut UnixStream,
        conn: &mut ServiceConnection,
        outputs: Vec<Output>,
    ) -> bool {
        for output in outputs {
            match output {
                Output::Send(frame) => {
                    // 配对进行中时，写入同样服从绝对截止时间（§4.2，第四轮评审 §5.2）
                    let timeout = match conn.pairing_deadline() {
                        Some(d) => {
                            let left = d.saturating_duration_since(std::time::Instant::now());
                            if left.is_zero() {
                                return false;
                            }
                            Some(left)
                        }
                        None => None,
                    };
                    if stream.set_write_timeout(timeout).is_err()
                        || write_socket_frame(stream, &frame).is_err()
                    {
                        return false;
                    }
                }
                Output::PairingStarted { browser } => self.prompt.started(&browser),
                Output::ConfirmPairing { sas, name, browser } => {
                    // 等待用户确认期间不持有任何锁
                    let deadline = conn
                        .pairing_deadline()
                        .unwrap_or_else(std::time::Instant::now);
                    let accepted = self.prompt.confirm(sas, &name, &browser, deadline);
                    // 持有保险库锁读取解锁代次并提交：确认与锁定之间有确定的先后（第四轮评审 J5）
                    let more = {
                        let mut vault = lock(&self.vault);
                        let epoch = vault.unlock_epoch();
                        let mut cache = lock(&self.pairings);
                        conn.confirm_pairing(
                            accepted,
                            &mut Bound {
                                cache: &mut cache,
                                vault: &mut vault,
                            },
                            epoch,
                        )
                    };
                    // 确认后会话才建立：先登记，再发送 `paired`（第三轮评审 H6）
                    if !self.register(id, conn, stream) || !self.emit(id, stream, conn, more) {
                        return false;
                    }
                }
                Output::AuthorizeFill(request) => {
                    // 等待用户确认期间不持有任何锁（§5.2）
                    let now = std::time::Instant::now();
                    let deadline = now.checked_add(FILL_AUTHORIZATION_TIMEOUT).unwrap_or(now);
                    let accepted = self.prompt.authorize_fill(&request, deadline)
                        && std::time::Instant::now() <= deadline;
                    let more = {
                        let mut vault = lock(&self.vault);
                        let mut cache = lock(&self.pairings);
                        // 先写入授权，成功后才放行；写入失败（如等待期间已锁定）按拒绝处理
                        let granted = accepted
                            && Bound {
                                cache: &mut cache,
                                vault: &mut vault,
                            }
                            .authorize(&request.extension_public, &request.item_id, &request.site)
                            .is_ok();
                        conn.resolve_fill(granted, &mut Live(&mut cache), &CoreBackend::new(&vault))
                    };
                    if !self.emit(id, stream, conn, more) {
                        return false;
                    }
                }
                Output::FillPaused {
                    extension_public,
                    pairing_name,
                    browser,
                } => self
                    .prompt
                    .fill_paused(&extension_public, &pairing_name, &browser),
                Output::QueriesLimited {
                    extension_public,
                    pairing_name,
                    browser,
                } => self
                    .prompt
                    .queries_limited(&extension_public, &pairing_name, &browser),
                Output::Write(request) => {
                    let result = self.write(&request);
                    let more = {
                        let mut cache = lock(&self.pairings);
                        conn.resolve_write(result.clone(), &mut Live(&mut cache))
                    };
                    if let (Ok(_), WriteOp::Save { title, .. }) = (&result, &request.op) {
                        self.prompt
                            .saved(&request.pairing_name, &request.browser, title);
                    }
                    if !self.emit(id, stream, conn, more) {
                        return false;
                    }
                }
                Output::AuthorizeSearch(request) => {
                    // 等待用户允许期间不持有任何锁（§5.6）
                    let now = std::time::Instant::now();
                    let deadline = now.checked_add(SEARCH_AUTHORIZATION_TIMEOUT).unwrap_or(now);
                    let allowed = self.prompt.authorize_search(&request, deadline)
                        && std::time::Instant::now() <= deadline;
                    let more = {
                        let vault = lock(&self.vault);
                        let mut cache = lock(&self.pairings);
                        conn.resolve_search(
                            allowed,
                            &mut Live(&mut cache),
                            &CoreBackend::new(&vault),
                        )
                    };
                    if !self.emit(id, stream, conn, more) {
                        return false;
                    }
                }
                Output::Open {
                    pairing_name,
                    browser,
                    item_id,
                } => self
                    .prompt
                    .open(&pairing_name, &browser, item_id.as_deref()),
                Output::UnlockRequested {
                    pairing_name,
                    browser,
                } => self.prompt.unlock_requested(&pairing_name, &browser),
                Output::Close => return false,
            }
        }
        true
    }
}

impl VaultService {
    /// 执行协议 v2 的写操作（`spec/ipc.md` §5.5）。更新先请用户确认，等待期间不持有任何锁；
    /// 保存成功后为这个配对记下该条目在该站点的授权（凭据本来就是扩展提供的）。
    fn write(&self, request: &WriteRequest) -> Result<String, keevo_ipc::message::ErrorCode> {
        use keevo_ipc::message::ErrorCode;
        if request.needs_confirmation() {
            let changed = match &request.op {
                WriteOp::Update {
                    item_id, password, ..
                } => {
                    let vault = lock(&self.vault);
                    CoreBackend::new(&vault)
                        .fill(item_id)
                        .is_none_or(|d| d.password != password.expose())
                }
                WriteOp::Save { .. } => true,
            };
            let now = std::time::Instant::now();
            let deadline = now.checked_add(UPDATE_CONFIRMATION_TIMEOUT).unwrap_or(now);
            if !(self.prompt.confirm_update(request, changed, deadline)
                && std::time::Instant::now() <= deadline)
            {
                return Err(ErrorCode::NotAuthorized);
            }
        }
        let mut vault = lock(&self.vault);
        let item_id = crate::write::apply(&mut vault, request)?;
        if matches!(request.op, WriteOp::Save { .. }) {
            let mut cache = lock(&self.pairings);
            // 授权写入失败不影响保存本身：之后第一次填充时再请用户确认
            let _ = Bound {
                cache: &mut cache,
                vault: &mut vault,
            }
            .authorize(&request.extension_public, &item_id, &request.site);
        }
        Ok(item_id)
    }
}

/// 按绝对截止时间读取：每一次底层 `read` 之前都重新计算剩余时间（第三轮评审 H5）。
/// 只在读完整帧之前设一次相对超时不够：对端每隔一会儿送一个字节，就能让每次 `read` 都重新等待。
struct DeadlineReader<'a> {
    stream: &'a UnixStream,
    deadline: Option<std::time::Instant>,
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let timeout = match self.deadline {
            Some(d) => {
                let left = d.saturating_duration_since(std::time::Instant::now());
                if left.is_zero() {
                    return Err(std::io::ErrorKind::TimedOut.into());
                }
                Some(left)
            }
            None => None,
        };
        self.stream.set_read_timeout(timeout)?;
        (&*self.stream).read(buf)
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use std::io::Write;
    use std::time::{Duration, Instant};

    use keevo_crypto::KdfParams;
    use keevo_ipc::client::{ClientEvent, ExtensionClient};
    use keevo_ipc::frame::read_socket_frame;
    use keevo_ipc::message::HostHello;

    use super::*;

    struct Accept;
    impl PairingPrompt for Accept {
        fn confirm(&self, _: [u8; 6], _: &str, _: &str, _: Instant) -> bool {
            true
        }
        fn authorize_fill(&self, _: &FillRequest, _: Instant) -> bool {
            true
        }
    }

    fn service() -> (VaultService, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "keevo-svc-{}-{}",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let params = KdfParams::new(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1, [5; 16]).unwrap();
        let (vault, _) = Vault::create(&dir.join("v.sqlite"), "pw", params).unwrap();
        let svc = VaultService::new(
            Arc::new(Mutex::new(vault)),
            StaticKeypair::generate().unwrap(),
            Arc::new(Accept),
            PeerPolicy::DevSameUserOnly,
        )
        .unwrap();
        svc.load_pairings().unwrap();
        (svc, dir)
    }

    /// 第三轮评审 H5：对端每隔一会儿送一个字节，也不能把读取拖过截止时间。
    #[test]
    fn review3_h5_deadline_is_absolute_across_partial_reads() {
        let (a, mut b) = UnixStream::pair().unwrap();
        let writer = std::thread::spawn(move || {
            let _ = b.write_all(&8u32.to_be_bytes());
            for _ in 0..8 {
                std::thread::sleep(Duration::from_millis(30));
                if b.write_all(&[0]).is_err() {
                    break;
                }
            }
        });
        let start = Instant::now();
        let mut reader = DeadlineReader {
            stream: &a,
            deadline: Some(start + Duration::from_millis(100)),
        };
        assert!(read_socket_frame(&mut reader).is_err());
        assert!(
            start.elapsed() < Duration::from_millis(180),
            "{:?}",
            start.elapsed()
        );
        drop(a);
        writer.join().unwrap();
    }

    /// 第三轮评审 H6：XX 配对经用户确认建立会话后，先登记、再发送 `paired`。
    #[test]
    fn review3_h6_confirmed_pairing_registers_before_paired_is_sent() {
        let (svc, dir) = service();
        let (server_end, mut client_end) = UnixStream::pair().unwrap();
        let mut conn = ServiceConnection::new(Arc::clone(&svc.key));
        let origin = "chrome-extension://abcdefghijklmnopabcdefghijklmnop/";
        let hello = serde_json::to_vec(&HostHello {
            v: keevo_ipc::message::PROTOCOL_VERSION,
            client: "native-host".into(),
            extension_origin: origin.into(),
            browser: "dev".into(),
        })
        .unwrap();
        let mut client = ExtensionClient::new(StaticKeypair::generate().unwrap(), origin, "x");
        let step = |conn: &mut ServiceConnection, frame: &[u8]| {
            let vault = lock(&svc.vault);
            let mut pairings = lock(&svc.pairings);
            conn.on_frame(frame, &mut Live(&mut pairings), &CoreBackend::new(&vault))
        };
        assert!(step(&mut conn, &hello).is_empty());
        let out = step(&mut conn, &client.start_pairing().unwrap());
        let Some(Output::Send(msg2)) = out.into_iter().find(|o| matches!(o, Output::Send(_)))
        else {
            panic!("应收到第 2 条消息")
        };
        let (frames, _) = client.on_frame(&msg2).unwrap();
        let out = step(&mut conn, &frames[0]);
        assert!(
            out.iter()
                .any(|o| matches!(o, Output::ConfirmPairing { .. }))
        );

        let mut server_stream = server_end.try_clone().unwrap();
        assert!(svc.emit(7, &mut server_stream, &mut conn, out));
        assert!(
            lock(&svc.sessions).contains_key(&7),
            "发送 paired 时会话必须已登记"
        );
        let paired = read_socket_frame(&mut client_end).unwrap();
        let (_, events) = client.on_frame(&paired).unwrap();
        assert!(
            matches!(events[0], ClientEvent::Paired { .. }),
            "{events:?}"
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
