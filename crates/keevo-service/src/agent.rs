//! SSH Agent（`spec/ssh-agent.md`）：只提供保险库中开启了 Agent 的 Ed25519 密钥，按策略授权后代为签名。
//! 私钥只在签名时解码，用后清零；不接受外部密钥。

use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use keevo_core::ssh_agent::AgentPolicy;
use keevo_core::{FieldData, FieldKind, ItemType, RecordValue, Vault};
use keevo_crypto::Id128;
use keevo_ssh::agent::{
    BindCheck, MAX_BINDS, Request, SessionBind, identities_answer, msg, parse_request,
    read_message, sign_response, simple, write_message,
};
use keevo_ssh::{KeyError, PrivateKey};

use crate::developer::{Developer, SshRequest, UnlockReason};
use crate::origin::{NoTtyAnchor, Origin, SystemProcesses, origin_of};

/// 一把在 Agent 中可用的密钥。
struct AgentKey {
    item_id: Id128,
    title: String,
    policy: AgentPolicy,
    key: PrivateKey,
}

/// 一个 `ssh_key` 条目在 Agent 中的状态（"设置 → 开发者 → SSH Agent"）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentKeyStatus {
    /// 条目 ID。
    pub item_id: String,
    /// 条目标题。
    pub title: String,
    /// 策略；`None` 表示没有开启。
    pub policy: Option<AgentPolicy>,
    /// 公钥指纹（私钥可用时）。
    pub fingerprint: Option<String>,
    /// 公钥行（私钥可用时）。
    pub public_key: Option<String>,
    /// 私钥不可用的原因（错误码，见 [`KeyError::code`]）；`missing` 表示没有私钥、`multiple` 表示有多个私钥字段。
    pub problem: Option<String>,
}

/// 条目中唯一的 `ssh_private_key` 字段的文本。
fn private_key_text(doc: &keevo_core::ItemDoc) -> Result<String, &'static str> {
    let texts: Vec<&str> = doc
        .records
        .values()
        .filter_map(|v| match &v.value {
            Some(RecordValue::Field(f)) if f.kind == FieldKind::SshPrivateKey => match &f.data {
                FieldData::Text(t) => Some(t.expose()),
                _ => None,
            },
            _ => None,
        })
        .filter(|t| !t.trim().is_empty())
        .collect();
    match texts.as_slice() {
        [one] => Ok((*one).to_owned()),
        [] => Err("missing"),
        _ => Err("multiple"),
    }
}

/// 全部 `ssh_key` 条目在 Agent 中的状态，按标题排序。
///
/// # Errors
/// 已锁定或读取失败。
pub fn key_statuses(vault: &Vault) -> keevo_core::Result<Vec<AgentKeyStatus>> {
    let policies = vault.ssh_agent_policies()?;
    let mut out = Vec::new();
    for item in vault.items()? {
        if item.overview.item_type != ItemType::SshKey || item.overview.trashed_at.is_some() {
            continue;
        }
        let view = vault.item(item.id)?;
        let mut status = AgentKeyStatus {
            item_id: item.id.to_hex(),
            title: item.overview.title.clone(),
            policy: policies.get(&item.id).copied(),
            fingerprint: None,
            public_key: None,
            problem: None,
        };
        match private_key_text(&view.doc) {
            Ok(text) => {
                let text = zeroize::Zeroizing::new(text);
                match PrivateKey::parse(&text) {
                    Ok(key) => {
                        let public = key.public_key();
                        status.fingerprint = Some(public.fingerprint());
                        status.public_key = Some(public.to_line(key.comment()));
                    }
                    Err(e) => status.problem = Some(e.code().to_owned()),
                }
            }
            Err(p) => status.problem = Some(p.to_owned()),
        }
        out.push(status);
    }
    out.sort_by_key(|k| k.title.to_lowercase());
    Ok(out)
}

/// 在 Agent 中可用的密钥（§3），按标题排序。
fn agent_keys(vault: &Vault) -> Vec<AgentKey> {
    let (Ok(items), Ok(policies)) = (vault.items(), vault.ssh_agent_policies()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in items {
        if item.overview.item_type != ItemType::SshKey || item.overview.trashed_at.is_some() {
            continue;
        }
        let Ok(view) = vault.item(item.id) else {
            continue;
        };
        let Some(policy) = policies.get(&item.id).copied() else {
            continue;
        };
        let Ok(text) = private_key_text(&view.doc) else {
            continue;
        };
        let text = zeroize::Zeroizing::new(text);
        let key = match PrivateKey::parse(&text) {
            Ok(k) => k,
            Err(KeyError::Unsupported(_) | _) => continue,
        };
        out.push(AgentKey {
            item_id: item.id,
            title: item.overview.title,
            policy,
            key,
        });
    }
    out.sort_by_key(|k| k.title.to_lowercase());
    out
}

/// SSH Agent 服务。
#[derive(Clone)]
pub struct SshAgent {
    dev: Arc<Developer>,
    stopped: Arc<AtomicBool>,
    path: PathBuf,
}

impl SshAgent {
    /// 在 `path` 监听（目录权限 0700，清除遗留的 socket 文件），返回服务与监听器。
    ///
    /// # Errors
    /// socket 无法创建时返回错误。
    pub fn bind(dev: Arc<Developer>, path: &Path) -> std::io::Result<(Self, UnixListener)> {
        let listener = crate::server::bind(path)?;
        Ok((
            Self {
                dev,
                stopped: Arc::default(),
                path: path.to_owned(),
            },
            listener,
        ))
    }

    /// 接受连接，每个连接一个线程，直到 [`SshAgent::stop`]。
    pub fn serve(&self, listener: &UnixListener) {
        for stream in listener.incoming() {
            if self.stopped.load(Ordering::Relaxed) {
                break;
            }
            let Ok(stream) = stream else { continue };
            let agent = self.clone();
            std::thread::spawn(move || agent.handle(stream));
        }
    }

    /// 停止：不再接受连接，删除 socket 文件。
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Relaxed);
        // 唤醒阻塞在 accept 上的线程
        let _ = UnixStream::connect(&self.path);
        let _ = std::fs::remove_file(&self.path);
    }

    /// 处理一个连接。
    pub fn handle(&self, mut stream: UnixStream) {
        let origin = keevo_macos::process::socket_peer_pid(&stream)
            .ok()
            .and_then(|pid| origin_of(&SystemProcesses, pid, NoTtyAnchor::App));
        let mut binds: Vec<SessionBind> = Vec::new();
        let mut forwarded = false;
        loop {
            if self.stopped.load(Ordering::Relaxed) {
                break;
            }
            let body = match read_message(&mut stream) {
                Ok(Some(b)) => b,
                Ok(None) | Err(_) => break,
            };
            let reply = match parse_request(&body) {
                Ok(Request::Identities) => self.identities(),
                Ok(Request::Sign { key_blob, data, .. }) => match &origin {
                    Some(origin) => self.sign(origin, key_blob, data, binds.last(), forwarded),
                    // 来源进程无法识别（已退出）：拒绝
                    None => simple(msg::FAILURE),
                },
                Ok(Request::SessionBind(bind)) => match bind.check() {
                    BindCheck::Invalid => simple(msg::FAILURE),
                    BindCheck::Verified | BindCheck::Unverified => {
                        if binds.len() >= MAX_BINDS {
                            break;
                        }
                        forwarded |= bind.forwarding;
                        binds.push(bind);
                        simple(msg::SUCCESS)
                    }
                },
                Ok(Request::Extension(_)) => simple(msg::EXTENSION_FAILURE),
                Ok(Request::Other(_)) | Err(_) => simple(msg::FAILURE),
            };
            if write_message(&mut stream, &reply).is_err() {
                break;
            }
        }
    }

    fn identities(&self) -> Vec<u8> {
        if !self.dev.wait_unlocked(UnlockReason::Ssh) {
            return identities_answer(&[]);
        }
        let keys = agent_keys(&self.dev.vault());
        let list: Vec<(Vec<u8>, String)> = keys
            .iter()
            .map(|k| (k.key.public_key().blob(), k.title.clone()))
            .collect();
        identities_answer(&list)
    }

    fn sign(
        &self,
        origin: &Origin,
        key_blob: &[u8],
        data: &[u8],
        bind: Option<&SessionBind>,
        forwarded: bool,
    ) -> Vec<u8> {
        if !self.dev.wait_unlocked(UnlockReason::Ssh) {
            return simple(msg::FAILURE);
        }
        // 先找到密钥与策略，再在不持有保险库锁的情况下请求确认
        let (item_id, request) = {
            let vault = self.dev.vault();
            let keys = agent_keys(&vault);
            let Some(k) = keys.iter().find(|k| k.key.public_key().blob() == key_blob) else {
                return simple(msg::FAILURE);
            };
            let public = k.key.public_key();
            (
                k.item_id,
                SshRequest {
                    origin: origin.clone(),
                    item_id: k.item_id.to_hex(),
                    key_title: k.title.clone(),
                    fingerprint: public.fingerprint(),
                    host_fingerprint: bind.map(SessionBind::host_fingerprint),
                    host_verified: bind.is_some_and(|b| b.check() == BindCheck::Verified),
                    forwarded,
                    policy: k.policy,
                },
            )
        };
        if !self.dev.authorize_ssh(&request, item_id) {
            return simple(msg::FAILURE);
        }
        // 授权之后重新读取：确认期间密钥可能被删除或关闭
        let signature = {
            let vault = self.dev.vault();
            agent_keys(&vault)
                .into_iter()
                .find(|k| k.item_id == item_id && k.key.public_key().blob() == key_blob)
                .map(|k| k.key.sign(data))
        };
        match signature {
            Some(sig) => {
                self.dev.prompt.ssh_signed(&request);
                sign_response(&sig)
            }
            None => simple(msg::FAILURE),
        }
    }
}

/// 便捷软链（`spec/ssh-agent.md` §1）的状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkStatus {
    /// 已创建，或已经指向 Agent。
    Ready,
    /// 已存在且指向别处，或是普通文件：不改动。附现有的目标（普通文件时为空）。
    Conflict(String),
    /// 创建失败。
    Failed(String),
}

/// 确保 `link` 是指向 `target` 的软链。已存在且指向别处、或是普通文件时不改动。
#[must_use]
pub fn ensure_link(link: &Path, target: &Path) -> LinkStatus {
    match std::fs::read_link(link) {
        Ok(existing) if existing == target => return LinkStatus::Ready,
        Ok(existing) => return LinkStatus::Conflict(existing.display().to_string()),
        Err(_) if link.symlink_metadata().is_ok() => return LinkStatus::Conflict(String::new()),
        Err(_) => {}
    }
    if let Some(dir) = link.parent() {
        use std::os::unix::fs::DirBuilderExt;
        if let Err(e) = std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
        {
            return LinkStatus::Failed(e.to_string());
        }
    }
    match std::os::unix::fs::symlink(target, link) {
        Ok(()) => LinkStatus::Ready,
        Err(e) => LinkStatus::Failed(e.to_string()),
    }
}
