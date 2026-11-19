//! 开发者服务的共用部分（`spec/cli.md` §4.1、§5，`spec/ssh-agent.md` §4、§6）：原生确认界面的接口、
//! 等待解锁、按会话的授权记录。CLI 服务（[`crate::cli`]）与 SSH Agent（[`crate::agent`]）共用一个实例。

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use keevo_core::Vault;
use keevo_core::ssh_agent::AgentPolicy;
use keevo_crypto::Id128;

use crate::origin::{Origin, SessionKey};

/// 等待用户确认的时限。
pub const PROMPT_TIMEOUT: Duration = Duration::from_secs(60);
/// CLI 请求等待解锁的时限（`spec/cli.md` §4.1）。
pub const CLI_UNLOCK_WAIT: Duration = Duration::from_secs(60);
/// SSH 请求等待解锁的时限（`spec/ssh-agent.md` §6）。
pub const AGENT_UNLOCK_WAIT: Duration = Duration::from_secs(30);
/// 会话授权闲置多久失效。
pub const SESSION_IDLE: Duration = Duration::from_secs(10 * 60);
/// CLI 会话授权的最长有效期。
pub const SESSION_MAX: Duration = Duration::from_secs(12 * 60 * 60);
/// 被拒绝后，同一会话的请求在这段时间内直接拒绝（`spec/cli.md` §5 第 2 条）。
pub const DENIAL_COOLDOWN: Duration = Duration::from_secs(10);

/// 谁在等待解锁。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockReason {
    /// 命令行工具。
    Cli,
    /// SSH Agent。
    Ssh,
}

/// 一次 SSH 签名请求（显示在确认界面中）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshRequest {
    /// 来源。
    pub origin: Origin,
    /// 条目 ID。
    pub item_id: String,
    /// 条目标题。
    pub key_title: String,
    /// 公钥指纹。
    pub fingerprint: String,
    /// 目标主机的密钥指纹（有 session-bind 时）。
    pub host_fingerprint: Option<String>,
    /// 主机密钥的签名是否经过验证。
    pub host_verified: bool,
    /// 是否来自转发的 agent 连接。
    pub forwarded: bool,
    /// 这把密钥的策略。
    pub policy: AgentPolicy,
}

/// 由 Keevo.app 实现的原生界面。方法在服务的工作线程中调用，可以阻塞。
pub trait DeveloperPrompt: Send + Sync {
    /// 请 Keevo.app 显示解锁界面（说明谁在等待）。
    fn unlock_requested(&self, reason: UnlockReason) {
        let _ = reason;
    }
    /// 终端会话第一次请求时确认（`spec/cli.md` §5）。实现负责 Touch ID 或主密码验证；必须在 `deadline`
    /// 到达时关闭界面并返回 `false`。默认拒绝。
    fn authorize_cli(&self, origin: &Origin, deadline: Instant) -> bool {
        let _ = (origin, deadline);
        false
    }
    /// SSH 签名确认（`spec/ssh-agent.md` §4.3）。要求同上。默认拒绝。
    fn authorize_ssh(&self, request: &SshRequest, deadline: Instant) -> bool {
        let _ = (request, deadline);
        false
    }
    /// 一次签名完成（"最近使用"）。
    fn ssh_signed(&self, request: &SshRequest) {
        let _ = request;
    }
    /// CLI 执行了 `keevo lock`：保险库已锁定，Keevo.app 应切到锁屏。
    fn locked_by_cli(&self) {}
}

/// 一次授权。
#[derive(Debug, Clone)]
struct Grant {
    /// 授权时的解锁代次：锁定后再解锁即失效。
    epoch: Option<u64>,
    granted: Instant,
    last_used: Instant,
    origin: Origin,
}

impl Grant {
    fn valid(&self, epoch: Option<u64>, now: Instant, max: Duration) -> bool {
        self.epoch.is_some()
            && self.epoch == epoch
            && now.saturating_duration_since(self.last_used) <= SESSION_IDLE
            && now.saturating_duration_since(self.granted) <= max
    }
}

/// 已授权的 CLI 会话（"设置 → 开发者"）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliSession {
    /// 会话键。
    pub session: SessionKey,
    /// 授权时的来源。
    pub origin: Origin,
    /// 已授权多久。
    pub age: Duration,
    /// 闲置多久。
    pub idle: Duration,
}

#[derive(Default)]
struct Grants {
    cli: HashMap<SessionKey, Grant>,
    ssh: HashMap<(SessionKey, Id128), Grant>,
    denied: HashMap<SessionKey, Instant>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// CLI 与 SSH Agent 共用的状态。加锁顺序：确认界面 → 保险库 → 授权记录。
pub struct Developer {
    pub(crate) vault: Arc<Mutex<Vault>>,
    pub(crate) prompt: Arc<dyn DeveloperPrompt>,
    grants: Mutex<Grants>,
    /// 同一时间只显示一个确认界面（§5 最后一段）。
    prompting: Mutex<()>,
    /// 等待解锁的时限：CLI、SSH。
    unlock_waits: (Duration, Duration),
}

impl Developer {
    /// 创建。
    #[must_use]
    pub fn new(vault: Arc<Mutex<Vault>>, prompt: Arc<dyn DeveloperPrompt>) -> Arc<Self> {
        Self::with_unlock_waits(vault, prompt, CLI_UNLOCK_WAIT, AGENT_UNLOCK_WAIT)
    }

    /// 指定等待解锁的时限（测试用较短的时限）。
    #[must_use]
    pub fn with_unlock_waits(
        vault: Arc<Mutex<Vault>>,
        prompt: Arc<dyn DeveloperPrompt>,
        cli: Duration,
        agent: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            vault,
            prompt,
            grants: Mutex::default(),
            prompting: Mutex::new(()),
            unlock_waits: (cli, agent),
        })
    }

    pub(crate) fn vault(&self) -> MutexGuard<'_, Vault> {
        lock(&self.vault)
    }

    /// 已锁定时请 Keevo.app 显示解锁界面，按 `reason` 的时限等待。返回是否已解锁。
    pub(crate) fn wait_unlocked(&self, reason: UnlockReason) -> bool {
        let timeout = match reason {
            UnlockReason::Cli => self.unlock_waits.0,
            UnlockReason::Ssh => self.unlock_waits.1,
        };
        if self.vault().is_unlocked() {
            return true;
        }
        self.prompt.unlock_requested(reason);
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(200));
            if self.vault().is_unlocked() {
                return true;
            }
        }
        false
    }

    /// 当前的解锁代次；锁定时为 `None`。
    fn epoch(&self) -> Option<u64> {
        self.vault().unlock_epoch()
    }

    /// 这个终端会话当前的授权剩余时间；未授权时为 `None`。
    pub(crate) fn cli_expires_in(&self, session: &SessionKey) -> Option<Duration> {
        let epoch = self.epoch();
        let now = Instant::now();
        let grants = lock(&self.grants);
        let g = grants.cli.get(session)?;
        if !g.valid(epoch, now, SESSION_MAX) {
            return None;
        }
        let idle_left = SESSION_IDLE.saturating_sub(now.saturating_duration_since(g.last_used));
        let max_left = SESSION_MAX.saturating_sub(now.saturating_duration_since(g.granted));
        Some(idle_left.min(max_left))
    }

    /// 按终端会话授权 CLI（`spec/cli.md` §5）：有效的授权直接通过，否则请用户确认。
    pub(crate) fn authorize_cli(&self, origin: &Origin) -> bool {
        let arrival = Instant::now();
        if self.touch_cli(&origin.session) {
            return true;
        }
        if lock(&self.grants)
            .denied
            .get(&origin.session)
            .is_some_and(|t| arrival.saturating_duration_since(*t) < DENIAL_COOLDOWN)
        {
            return false;
        }
        let _one_at_a_time = lock(&self.prompting);
        // 排队期间同一会话的另一个请求可能已经得到授权
        if self.touch_cli(&origin.session) {
            return true;
        }
        let now = Instant::now();
        if now.saturating_duration_since(arrival) > PROMPT_TIMEOUT {
            return false;
        }
        let epoch = self.epoch();
        let deadline = now.checked_add(PROMPT_TIMEOUT).unwrap_or(now);
        let accepted = self.prompt.authorize_cli(origin, deadline) && Instant::now() <= deadline;
        // 确认期间锁定过：授权作废
        let still = accepted && self.vault().is_unlocked() && self.epoch() == epoch;
        let mut grants = lock(&self.grants);
        if still {
            let now = Instant::now();
            grants.cli.insert(
                origin.session,
                Grant {
                    epoch,
                    granted: now,
                    last_used: now,
                    origin: origin.clone(),
                },
            );
            grants.denied.remove(&origin.session);
        } else {
            grants.denied.insert(origin.session, Instant::now());
        }
        still
    }

    fn touch_cli(&self, session: &SessionKey) -> bool {
        let epoch = self.epoch();
        let now = Instant::now();
        let mut grants = lock(&self.grants);
        match grants.cli.get_mut(session) {
            Some(g) if g.valid(epoch, now, SESSION_MAX) => {
                g.last_used = now;
                true
            }
            Some(_) => {
                grants.cli.remove(session);
                false
            }
            None => false,
        }
    }

    /// SSH 签名授权（`spec/ssh-agent.md` §4）。
    pub(crate) fn authorize_ssh(&self, request: &SshRequest, item: Id128) -> bool {
        let arrival = Instant::now();
        let force_ask = request.forwarded;
        if !force_ask {
            match request.policy {
                AgentPolicy::Unlocked => return true,
                AgentPolicy::Session if self.touch_ssh(&request.origin.session, item) => {
                    return true;
                }
                _ => {}
            }
        }
        let _one_at_a_time = lock(&self.prompting);
        if !force_ask
            && request.policy == AgentPolicy::Session
            && self.touch_ssh(&request.origin.session, item)
        {
            return true;
        }
        let now = Instant::now();
        if now.saturating_duration_since(arrival) > PROMPT_TIMEOUT {
            return false;
        }
        let epoch = self.epoch();
        let deadline = now.checked_add(PROMPT_TIMEOUT).unwrap_or(now);
        let accepted = self.prompt.authorize_ssh(request, deadline) && Instant::now() <= deadline;
        let still = accepted && self.vault().is_unlocked() && self.epoch() == epoch;
        if still && !force_ask && request.policy == AgentPolicy::Session {
            let now = Instant::now();
            lock(&self.grants).ssh.insert(
                (request.origin.session, item),
                Grant {
                    epoch,
                    granted: now,
                    last_used: now,
                    origin: request.origin.clone(),
                },
            );
        }
        still
    }

    fn touch_ssh(&self, session: &SessionKey, item: Id128) -> bool {
        let epoch = self.epoch();
        let now = Instant::now();
        let mut grants = lock(&self.grants);
        match grants.ssh.get_mut(&(*session, item)) {
            // SSH 的会话授权只有闲置时限
            Some(g) if g.valid(epoch, now, Duration::MAX) => {
                g.last_used = now;
                true
            }
            Some(_) => {
                grants.ssh.remove(&(*session, item));
                false
            }
            None => false,
        }
    }

    /// 已授权的 CLI 会话（有效的）。
    #[must_use]
    pub fn cli_sessions(&self) -> Vec<CliSession> {
        let epoch = self.epoch();
        let now = Instant::now();
        let mut grants = lock(&self.grants);
        grants.cli.retain(|_, g| g.valid(epoch, now, SESSION_MAX));
        let mut out: Vec<CliSession> = grants
            .cli
            .iter()
            .map(|(k, g)| CliSession {
                session: *k,
                origin: g.origin.clone(),
                age: now.saturating_duration_since(g.granted),
                idle: now.saturating_duration_since(g.last_used),
            })
            .collect();
        out.sort_by_key(|s| s.age);
        out
    }

    /// 撤销一个 CLI 会话的授权。
    pub fn revoke_cli_session(&self, session: &SessionKey) {
        lock(&self.grants).cli.remove(session);
    }

    /// 撤销全部授权（锁定时由调用方触发；即使不调用，代次变化也会让旧授权失效）。
    pub fn revoke_all(&self) {
        let mut grants = lock(&self.grants);
        grants.cli.clear();
        grants.ssh.clear();
    }
}
