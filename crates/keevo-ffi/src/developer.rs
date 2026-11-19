//! 开发者能力的 FFI（`spec/cli.md`、`spec/ssh-agent.md`、`spec/secret-refs.md`）：命令行工具的服务、
//! SSH Agent、SSH 密钥的生成与导入、复制 `keevo://` 引用。

use std::sync::Arc;
use std::time::Instant;

use keevo_core::secret_ref::reference_for;
use keevo_core::ssh_agent::{AgentPolicy, policy_of};
use keevo_core::{Edit, FieldData, FieldKind, ItemType, NewField, RecordKey, RecordValue};
use keevo_service::agent::{LinkStatus, SshAgent, ensure_link, key_statuses};
use keevo_service::cli::CliService;
use keevo_service::developer::{
    Developer, DeveloperPrompt as ServicePrompt, SshRequest, UnlockReason,
};
use keevo_service::origin::{Origin, SessionKey};
use keevo_ssh::{KeyError, PrivateKey};
use zeroize::Zeroizing;

use crate::{KeevoError, KeevoVault, parse_id};

/// 请求的来源（显示在确认界面中）。
#[derive(Debug, Clone, uniffi::Record)]
pub struct RequestOrigin {
    /// 所在的应用，如 iTerm、Terminal、Visual Studio Code。
    pub app: Option<String>,
    /// 命令行。
    pub command: String,
    /// 父进程名，如 zsh、git。
    pub parent_name: String,
    /// 父进程不是 shell 时它的命令行，如 `git push`。
    pub parent_command: Option<String>,
    /// 是否在终端中（有控制终端）。
    pub in_terminal: bool,
}

impl From<&Origin> for RequestOrigin {
    fn from(o: &Origin) -> Self {
        Self {
            app: o.app.clone(),
            command: o.command.clone(),
            parent_name: o.parent_name.trim_start_matches('-').to_owned(),
            parent_command: o.parent_command.clone(),
            in_terminal: o.session.tty.is_some(),
        }
    }
}

/// 一次 SSH 签名请求。
#[derive(Debug, Clone, uniffi::Record)]
pub struct SshSignRequest {
    /// 来源。
    pub origin: RequestOrigin,
    /// 条目 ID。
    pub item_id: String,
    /// 条目标题。
    pub key_title: String,
    /// 公钥指纹。
    pub fingerprint: String,
    /// 目标主机的密钥指纹。
    pub host_fingerprint: Option<String>,
    /// 主机密钥的签名是否经过验证。
    pub host_verified: bool,
    /// 是否来自转发的 agent 连接。
    pub forwarded: bool,
    /// 策略：`ask`、`session`、`unlocked`。
    pub policy: String,
}

impl From<&SshRequest> for SshSignRequest {
    fn from(r: &SshRequest) -> Self {
        Self {
            origin: (&r.origin).into(),
            item_id: r.item_id.clone(),
            key_title: r.key_title.clone(),
            fingerprint: r.fingerprint.clone(),
            host_fingerprint: r.host_fingerprint.clone(),
            host_verified: r.host_verified,
            forwarded: r.forwarded,
            policy: r.policy.as_str().to_owned(),
        }
    }
}

/// 由 Swift 实现的原生确认界面。方法在服务的工作线程中调用，可以阻塞到用户回答或超时。
#[uniffi::export(with_foreign)]
pub trait DeveloperPrompt: Send + Sync {
    /// 请显示解锁界面。`reason` 为 `cli` 或 `ssh`。
    fn unlock_requested(&self, reason: String);
    /// 终端会话第一次请求（`spec/cli.md` §5）。实现负责 Touch ID 或主密码验证，`timeout_ms` 到期时关闭并返回 `false`。
    fn authorize_cli(&self, origin: RequestOrigin, timeout_ms: u64) -> bool;
    /// SSH 签名确认（`spec/ssh-agent.md` §4.3）。要求同上。
    fn authorize_ssh(&self, request: SshSignRequest, timeout_ms: u64) -> bool;
    /// 一次签名完成。
    fn ssh_signed(&self, request: SshSignRequest);
    /// `keevo lock`：保险库已锁定，切到锁屏。
    fn locked_by_cli(&self);
}

struct PromptAdapter(Arc<dyn DeveloperPrompt>);

fn timeout_ms(deadline: Instant) -> u64 {
    u64::try_from(
        deadline
            .saturating_duration_since(Instant::now())
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

impl ServicePrompt for PromptAdapter {
    fn unlock_requested(&self, reason: UnlockReason) {
        self.0.unlock_requested(
            match reason {
                UnlockReason::Cli => "cli",
                UnlockReason::Ssh => "ssh",
            }
            .into(),
        );
    }
    fn authorize_cli(&self, origin: &Origin, deadline: Instant) -> bool {
        self.0.authorize_cli(origin.into(), timeout_ms(deadline))
    }
    fn authorize_ssh(&self, request: &SshRequest, deadline: Instant) -> bool {
        self.0.authorize_ssh(request.into(), timeout_ms(deadline))
    }
    fn ssh_signed(&self, request: &SshRequest) {
        self.0.ssh_signed(request.into());
    }
    fn locked_by_cli(&self) {
        self.0.locked_by_cli();
    }
}

/// 运行中的开发者服务。
pub(crate) struct DeveloperServices {
    dev: Arc<Developer>,
    _cli: CliService,
    agent: Option<SshAgent>,
}

/// 一个已授权的终端会话。
#[derive(Debug, Clone, uniffi::Record)]
pub struct CliSessionInfo {
    /// 会话 ID（撤销时使用）。
    pub id: String,
    /// 授权时的来源。
    pub origin: RequestOrigin,
    /// 已授权的秒数。
    pub age_secs: u64,
    /// 闲置的秒数。
    pub idle_secs: u64,
}

/// SSH Agent 的状态。
#[derive(Debug, Clone, uniffi::Record)]
pub struct SshAgentInfo {
    /// 是否在运行。
    pub running: bool,
    /// socket 路径。
    pub socket_path: String,
    /// 便捷软链的路径。
    pub link_path: String,
    /// 软链无法创建或被占用时的说明。
    pub link_problem: Option<String>,
}

/// 一个 SSH 密钥条目在 Agent 中的状态。
#[derive(Debug, Clone, uniffi::Record)]
pub struct SshKeyInfo {
    /// 条目 ID。
    pub item_id: String,
    /// 条目标题。
    pub title: String,
    /// 策略：`ask`、`session`、`unlocked`；`None` 表示没有开启。
    pub policy: Option<String>,
    /// 公钥指纹。
    pub fingerprint: Option<String>,
    /// 公钥行。
    pub public_key: Option<String>,
    /// 私钥不可用的原因：`missing`、`multiple`、`not_openssh`、`pem`、`encrypted`、`unsupported`、`malformed`。
    pub problem: Option<String>,
}

fn session_id(k: &SessionKey) -> String {
    format!(
        "{}:{}:{}",
        k.tty.map_or_else(|| "-".into(), |t| t.to_string()),
        k.pid,
        k.start_us
    )
}

fn unavailable(e: impl std::fmt::Display) -> KeevoError {
    KeevoError::DeveloperServiceUnavailable {
        reason: e.to_string(),
    }
}

/// 构建时编译进主程序的 CLI cdhash（`spec/cli.md` §2）：逗号分隔，由 `scripts/package-macos.sh` 在签名 CLI
/// 之后设置。运行时不从磁盘读取。
const CLI_CDHASHES: Option<&str> = option_env!("KEEVO_CLI_CDHASHES");

fn cli_policy() -> Result<keevo_service::PeerPolicy, KeevoError> {
    let hashes: Vec<&str> = CLI_CDHASHES
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .collect();
    if hashes.is_empty() {
        if cfg!(debug_assertions) {
            return Ok(keevo_service::PeerPolicy::DevSameUserOnly);
        }
        return Err(unavailable(
            "CLI cdhash was not compiled in; build with scripts/package-macos.sh",
        ));
    }
    if hashes
        .iter()
        .any(|h| h.len() != 40 || !h.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(unavailable("malformed compiled-in cdhash"));
    }
    Ok(keevo_service::PeerPolicy::CodeRequirement(
        hashes
            .iter()
            .map(|h| format!("cdhash H\"{h}\""))
            .collect::<Vec<_>>()
            .join(" or "),
    ))
}

fn parse_policy(p: Option<&str>) -> Result<Option<AgentPolicy>, KeevoError> {
    match p {
        None => Ok(None),
        Some(s) => AgentPolicy::parse(s)
            .map(Some)
            .ok_or_else(|| crate::invalid("ssh agent policy")),
    }
}

fn key_error(e: KeyError) -> KeevoError {
    KeevoError::SshKey {
        code: e.code().to_owned(),
        detail: match e {
            KeyError::Unsupported(alg) => alg,
            _ => String::new(),
        },
    }
}

impl KeevoVault {
    fn with_developer<T>(&self, f: impl FnOnce(&mut DeveloperServices) -> T) -> Option<T> {
        let mut slot = self
            .developer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        slot.as_mut().map(f)
    }

    /// 把新的私钥写入 SSH 密钥条目：私钥、公钥、指纹、算法、注释（`docs/product.md` §5.3 的字段）；
    /// 没有开启 Agent 时设为"每次确认"。
    fn write_ssh_key(
        &self,
        item_id: keevo_core::Id128,
        key: &PrivateKey,
        private_text: &str,
    ) -> Result<(), KeevoError> {
        let mut vault = self.vault();
        let view = vault.item(item_id)?;
        if view.doc.item_type != ItemType::SshKey {
            return Err(crate::invalid("not an ssh key item"));
        }
        let public = key.public_key();
        let mut edits = Vec::new();
        let fields: Vec<(keevo_core::Id128, FieldKind, String)> = view
            .doc
            .records
            .iter()
            .filter_map(|(k, v)| match (k, &v.value) {
                (RecordKey::Field(id), Some(RecordValue::Field(f))) => {
                    Some((*id, f.kind, f.label.clone()))
                }
                _ => None,
            })
            .collect();
        let mut set = |kind: Option<FieldKind>, label: &str, value: &str, new_kind: FieldKind| {
            let existing = fields.iter().find(|(_, k, l)| match kind {
                Some(want) => *k == want,
                None => l == label && !matches!(k, FieldKind::KvList | FieldKind::RecoveryCodes),
            });
            match existing {
                Some((id, _, _)) => edits.push(Edit::SetFieldData {
                    field_id: *id,
                    data: FieldData::Text(value.into()),
                }),
                None => edits.push(Edit::AddField(NewField {
                    kind: new_kind,
                    label: label.into(),
                    purpose: None,
                    data: FieldData::Text(value.into()),
                })),
            }
        };
        set(
            Some(FieldKind::SshPrivateKey),
            "私钥",
            private_text,
            FieldKind::SshPrivateKey,
        );
        set(
            None,
            "公钥",
            &public.to_line(key.comment()),
            FieldKind::Multiline,
        );
        set(None, "指纹", &public.fingerprint(), FieldKind::Text);
        set(None, "算法", "Ed25519", FieldKind::Select);
        if !key.comment().is_empty() {
            set(None, "注释", key.comment(), FieldKind::Text);
        }
        if policy_of(&view.doc).is_none() {
            edits.push(Edit::SetSshAgent(Some(AgentPolicy::Ask)));
        }
        vault.update_item(item_id, edits)?;
        Ok(())
    }
}

#[uniffi::export]
impl KeevoVault {
    /// 启动命令行工具的服务（`spec/cli.md`）：监听 socket，按固定的 cdhash 校验 CLI。已启动时直接返回。
    ///
    /// # Errors
    /// 构建时没有编译进 CLI 的 cdhash（release 构建）、socket 无法创建时返回
    /// [`KeevoError::DeveloperServiceUnavailable`]。
    pub fn start_developer_services(
        &self,
        prompt: Arc<dyn DeveloperPrompt>,
    ) -> Result<(), KeevoError> {
        let mut slot = self
            .developer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.is_some() {
            return Ok(());
        }
        let dev = Developer::new(Arc::clone(&self.inner), Arc::new(PromptAdapter(prompt)));
        let cli = CliService::new(Arc::clone(&dev), cli_policy()?).map_err(unavailable)?;
        let path = keevo_ipc::paths::cli_socket_path().map_err(unavailable)?;
        let listener = keevo_service::bind(&path).map_err(unavailable)?;
        let serving = cli.clone();
        std::thread::Builder::new()
            .name("keevo-cli-service".into())
            .spawn(move || serving.serve(&listener))
            .map_err(unavailable)?;
        *slot = Some(DeveloperServices {
            dev,
            _cli: cli,
            agent: None,
        });
        Ok(())
    }

    /// 开启或关闭 SSH Agent（`spec/ssh-agent.md` §1）。开启时同时创建便捷软链 `~/.keevo/agent.sock`。
    ///
    /// # Errors
    /// 开发者服务没有启动、socket 无法创建时返回错误。
    pub fn set_ssh_agent_enabled(&self, enabled: bool) -> Result<SshAgentInfo, KeevoError> {
        let path = keevo_ipc::paths::agent_socket_path().map_err(unavailable)?;
        self.with_developer(|d| -> Result<(), KeevoError> {
            match (enabled, &d.agent) {
                (true, None) => {
                    let (agent, listener) =
                        SshAgent::bind(Arc::clone(&d.dev), &path).map_err(unavailable)?;
                    let serving = agent.clone();
                    std::thread::Builder::new()
                        .name("keevo-ssh-agent".into())
                        .spawn(move || serving.serve(&listener))
                        .map_err(unavailable)?;
                    d.agent = Some(agent);
                }
                (false, Some(agent)) => {
                    agent.stop();
                    d.agent = None;
                }
                _ => {}
            }
            Ok(())
        })
        .ok_or_else(|| unavailable("developer services not started"))??;
        Ok(self.ssh_agent_info())
    }

    /// SSH Agent 的状态；运行时顺带确保便捷软链存在。
    pub fn ssh_agent_info(&self) -> SshAgentInfo {
        let running = self.with_developer(|d| d.agent.is_some()).unwrap_or(false);
        let socket = keevo_ipc::paths::agent_socket_path().ok();
        let link = keevo_ipc::paths::agent_link_path().ok();
        let link_problem = match (&socket, &link, running) {
            (Some(s), Some(l), true) => match ensure_link(l, s) {
                LinkStatus::Ready => None,
                LinkStatus::Conflict(target) if target.is_empty() => {
                    Some(format!("{} 已存在，且不是软链", l.display()))
                }
                LinkStatus::Conflict(target) => Some(format!("{} 已指向 {target}", l.display())),
                LinkStatus::Failed(e) => Some(e),
            },
            _ => None,
        };
        SshAgentInfo {
            running,
            socket_path: socket.map(|p| p.display().to_string()).unwrap_or_default(),
            link_path: link.map(|p| p.display().to_string()).unwrap_or_default(),
            link_problem,
        }
    }

    /// 已授权的终端会话（"设置 → 开发者"）。
    pub fn cli_sessions(&self) -> Vec<CliSessionInfo> {
        self.with_developer(|d| {
            d.dev
                .cli_sessions()
                .into_iter()
                .map(|s| CliSessionInfo {
                    id: session_id(&s.session),
                    origin: (&s.origin).into(),
                    age_secs: s.age.as_secs(),
                    idle_secs: s.idle.as_secs(),
                })
                .collect()
        })
        .unwrap_or_default()
    }

    /// 撤销一个终端会话的授权。
    pub fn revoke_cli_session(&self, id: String) {
        self.with_developer(|d| {
            for s in d.dev.cli_sessions() {
                if session_id(&s.session) == id {
                    d.dev.revoke_cli_session(&s.session);
                }
            }
        });
    }

    /// 全部 SSH 密钥条目在 Agent 中的状态。
    ///
    /// # Errors
    /// 已锁定时返回 [`KeevoError::Locked`]。
    pub fn ssh_keys(&self) -> Result<Vec<SshKeyInfo>, KeevoError> {
        Ok(key_statuses(&self.vault())?
            .into_iter()
            .map(|s| SshKeyInfo {
                item_id: s.item_id,
                title: s.title,
                policy: s.policy.map(|p| p.as_str().to_owned()),
                fingerprint: s.fingerprint,
                public_key: s.public_key,
                problem: s.problem,
            })
            .collect())
    }

    /// 设置一把密钥在 Agent 中的策略：`ask`、`session`、`unlocked`；`None` 表示关闭。
    ///
    /// # Errors
    /// 策略不认识、条目不存在或已锁定。
    pub fn set_ssh_agent_policy(
        &self,
        item_id: String,
        policy: Option<String>,
    ) -> Result<(), KeevoError> {
        let id = parse_id(&item_id)?;
        let policy = parse_policy(policy.as_deref())?;
        self.vault()
            .update_item(id, vec![Edit::SetSshAgent(policy)])?;
        Ok(())
    }

    /// 为 SSH 密钥条目生成新的 Ed25519 密钥，写入私钥、公钥、指纹等字段。私钥不经过 FFI。返回指纹。
    ///
    /// # Errors
    /// 不是 SSH 密钥条目、已锁定。
    pub fn generate_ssh_key(&self, item_id: String) -> Result<String, KeevoError> {
        let id = parse_id(&item_id)?;
        let title = self
            .vault()
            .items()?
            .into_iter()
            .find(|i| i.id == id)
            .map(|i| i.overview.title)
            .ok_or(KeevoError::NotFound)?;
        let key = PrivateKey::generate_ed25519(&title).map_err(key_error)?;
        let text = key.to_openssh().map_err(key_error)?;
        self.write_ssh_key(id, &key, &text)?;
        Ok(key.public_key().fingerprint())
    }

    /// 导入 OpenSSH 私钥（未加密）到 SSH 密钥条目，写入私钥、公钥、指纹等字段。返回指纹。
    ///
    /// # Errors
    /// 私钥无法使用时返回 [`KeevoError::SshKey`]；不是 SSH 密钥条目、已锁定。
    pub fn import_ssh_private_key(
        &self,
        item_id: String,
        text: String,
    ) -> Result<String, KeevoError> {
        let id = parse_id(&item_id)?;
        let text = Zeroizing::new(text);
        let key = PrivateKey::parse(&text).map_err(key_error)?;
        // 以 Keevo 的格式重新编码：去掉多余的空白与旧的校验数
        let normalized = key.to_openssh().map_err(key_error)?;
        self.write_ssh_key(id, &key, &normalized)?;
        Ok(key.public_key().fingerprint())
    }

    /// 字段的 `keevo://` 引用（`spec/secret-refs.md` §5）。`kv_key` 为键值对中的一项。
    ///
    /// # Errors
    /// 已锁定、条目或字段不存在，或者这一项无法唯一引用。
    pub fn secret_reference(
        &self,
        item_id: String,
        field_id: String,
        kv_key: Option<String>,
    ) -> Result<String, KeevoError> {
        let item = parse_id(&item_id)?;
        let field = parse_id(&field_id)?;
        reference_for(&self.vault(), item, field, kv_key.as_deref()).map_err(|e| {
            KeevoError::InvalidInput {
                message: e.to_string(),
            }
        })
    }
}

/// SSH Agent 的便捷软链路径（`~/.keevo/agent.sock`），用于 `~/.ssh/config` 的 `IdentityAgent`。
#[uniffi::export]
pub fn ssh_agent_link_path() -> String {
    keevo_ipc::paths::agent_link_path()
        .map(|p| p.display().to_string())
        .unwrap_or_default()
}
