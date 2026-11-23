//! 命令行工具的服务（`spec/cli.md`）：监听 `cli.sock`，校验对端 cdhash，按终端会话授权，回答请求。

use std::collections::HashMap;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use keevo_core::search::{Query, SearchIndex};
use keevo_core::secret_ref::{self, RefError, SecretRef};
use keevo_core::templates::{Preset, template};
use keevo_core::{Edit, FieldData, FieldKind, ItemType, NewField, RecordKey, RecordValue, Vault};
use keevo_crypto::Id128;
use keevo_ipc::cli::{
    CLI_CLIENT, CLI_PROTOCOL_VERSION, ClientHello, CreateResult, FieldArg, FieldInfo, ItemResult,
    ItemSummary, ItemsResult, MAX_REFS, Request, ResolveResult, ResolvedValue, ServerHello, SetArg,
    StatusResult, TotpResult, encode_err, encode_ok,
};
use keevo_ipc::frame::{read_socket_frame, write_socket_frame};
use zeroize::{Zeroize, Zeroizing};

use crate::developer::{Developer, UnlockReason};
use crate::origin::{NoTtyAnchor, Origin, SystemProcesses, origin_of};
use crate::server::PeerPolicy;

/// 握手必须在这段时间内完成。
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// 连接闲置多久后断开。
const IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// CLI 服务。
#[derive(Clone)]
pub struct CliService {
    dev: Arc<Developer>,
    policy: PeerPolicy,
    stopped: Arc<AtomicBool>,
}

/// 一次请求的失败。
struct Failure {
    code: &'static str,
    message: String,
}

impl Failure {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl From<RefError> for Failure {
    fn from(e: RefError) -> Self {
        Self::new(e.code(), e.to_string())
    }
}

impl From<keevo_core::CoreError> for Failure {
    fn from(e: keevo_core::CoreError) -> Self {
        match e {
            keevo_core::CoreError::Locked => Self::new("locked", "Keevo 已锁定"),
            keevo_core::CoreError::NotFound => Self::new("not_found", "找不到条目"),
            other => Self::new("failed", other.to_string()),
        }
    }
}

type Reply = Result<Zeroizing<Vec<u8>>, Failure>;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn ok<T: serde::Serialize>(id: u32, result: &T) -> Reply {
    encode_ok(id, result)
        .map(Zeroizing::new)
        .map_err(|e| Failure::new("failed", e.to_string()))
}

impl CliService {
    /// 创建。release 构建拒绝 [`PeerPolicy::DevSameUserOnly`]。
    ///
    /// # Errors
    /// release 构建中使用 [`PeerPolicy::DevSameUserOnly`] 时返回错误。
    pub fn new(dev: Arc<Developer>, policy: PeerPolicy) -> std::io::Result<Self> {
        if !cfg!(debug_assertions) && matches!(policy, PeerPolicy::DevSameUserOnly) {
            return Err(std::io::Error::other(
                "DevSameUserOnly is not allowed in release builds",
            ));
        }
        Ok(Self {
            dev,
            policy,
            stopped: Arc::default(),
        })
    }

    /// 接受连接，每个连接一个线程。
    pub fn serve(&self, listener: &UnixListener) {
        for stream in listener.incoming() {
            if self.stopped.load(Ordering::Relaxed) {
                break;
            }
            let Ok(stream) = stream else { continue };
            let svc = self.clone();
            std::thread::spawn(move || svc.handle(stream));
        }
    }

    /// 处理一个连接。
    pub fn handle(&self, mut stream: UnixStream) {
        if let PeerPolicy::CodeRequirement(req) = &self.policy
            && keevo_macos::verify_socket_peer(&stream, req) != Ok(true)
        {
            return;
        }
        let Ok(pid) = keevo_macos::process::socket_peer_pid(&stream) else {
            return;
        };
        let Some(origin) = origin_of(&SystemProcesses, pid, NoTtyAnchor::Parent) else {
            return;
        };
        if !self.hello(&mut stream) {
            return;
        }
        let _ = stream.set_read_timeout(Some(IDLE_TIMEOUT));
        while let Ok(frame) = read_socket_frame(&mut stream) {
            let request: Request = match serde_json::from_slice(&frame) {
                Ok(r) => r,
                Err(e) => {
                    let id = serde_json::from_slice::<serde_json::Value>(&frame)
                        .ok()
                        .and_then(|v| v.get("id").and_then(serde_json::Value::as_u64))
                        .and_then(|i| u32::try_from(i).ok())
                        .unwrap_or(0);
                    if let Ok(bytes) = encode_err(id, "bad_request", &e.to_string()) {
                        let _ = write_socket_frame(&mut stream, &bytes);
                    }
                    break;
                }
            };
            let id = request.id();
            let reply = self.dispatch(&request, &origin);
            let bytes = match reply {
                Ok(bytes) => bytes,
                Err(f) => match encode_err(id, f.code, &f.message) {
                    Ok(b) => Zeroizing::new(b),
                    Err(_) => break,
                },
            };
            if write_socket_frame(&mut stream, &bytes).is_err() {
                break;
            }
        }
    }

    fn hello(&self, stream: &mut UnixStream) -> bool {
        let _ = stream.set_read_timeout(Some(HELLO_TIMEOUT));
        let Ok(frame) = read_socket_frame(stream) else {
            return false;
        };
        let accepted = serde_json::from_slice::<ClientHello>(&frame)
            .is_ok_and(|h| h.v == CLI_PROTOCOL_VERSION && h.client == CLI_CLIENT);
        let reply = ServerHello {
            v: CLI_PROTOCOL_VERSION,
            ok: accepted,
            version: accepted.then(|| env!("CARGO_PKG_VERSION").to_owned()),
            error: (!accepted).then(|| "unsupported_version".to_owned()),
        };
        let Ok(bytes) = serde_json::to_vec(&reply) else {
            return false;
        };
        write_socket_frame(stream, &bytes).is_ok() && accepted
    }

    fn dispatch(&self, request: &Request, origin: &Origin) -> Reply {
        let id = request.id();
        match request {
            Request::Status { .. } => {
                let locked = !self.dev.vault().is_unlocked();
                let expires = self.dev.cli_expires_in(&origin.session);
                return ok(
                    id,
                    &StatusResult {
                        locked,
                        authorized: expires.is_some(),
                        expires_in: expires.map(|d| d.as_secs()),
                    },
                );
            }
            Request::Lock { .. } => {
                self.dev.vault().lock();
                self.dev.revoke_all();
                self.dev.prompt.locked_by_cli();
                return ok(id, &());
            }
            _ => {}
        }
        if !self.dev.wait_unlocked(UnlockReason::Cli) {
            return Err(Failure::new(
                "locked",
                "Keevo 已锁定：请在 Keevo 中解锁后重试",
            ));
        }
        if !self.dev.authorize_cli(origin) {
            return Err(Failure::new(
                "denied",
                "没有得到授权：在 Keevo 中被拒绝或超时",
            ));
        }
        let mut vault = self.dev.vault();
        match request {
            Request::Resolve { refs, .. } => resolve(id, &mut vault, refs),
            Request::Items {
                vault: v, query, ..
            } => items(id, &vault, v.as_deref(), query.as_deref()),
            Request::Item { item, reveal, .. } => item_detail(id, &vault, item, *reveal),
            Request::Totp { item, .. } => totp(id, &vault, item),
            Request::Create {
                vault: v,
                item_type,
                title,
                fields,
                ..
            } => create(id, &mut vault, v, item_type, title, fields),
            Request::Edit {
                item, title, set, ..
            } => edit(id, &mut vault, item, title.as_deref(), set),
            Request::Status { .. } | Request::Lock { .. } => Err(Failure::new("failed", "")),
        }
    }

    /// 停止接受新连接（已建立的连接继续，直到对方断开）。
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Relaxed);
    }
}

fn resolve(id: u32, vault: &mut Vault, refs: &[String]) -> Reply {
    if refs.is_empty() || refs.len() > MAX_REFS {
        return Err(Failure::new("bad_request", "refs 应有 1–256 个"));
    }
    let now = now_ms();
    let mut used = Vec::new();
    let mut values: Vec<ResolvedValue> = refs
        .iter()
        .map(
            |r| match SecretRef::parse(r).and_then(|r| r.resolve_item(vault, now)) {
                Ok((item, v)) => {
                    used.push(item);
                    ResolvedValue {
                        value: Some(v.to_string()),
                        error: None,
                        message: None,
                    }
                }
                Err(e) => ResolvedValue {
                    value: None,
                    error: Some(e.code().to_owned()),
                    message: Some(e.to_string()),
                },
            },
        )
        .collect();
    // 取用了的条目各记一次使用（列表排序）；同一次请求中引用同一条目的多个字段只算一次
    used.sort_unstable();
    used.dedup();
    crate::backend::record_uses(vault, &used);
    let reply = ok(
        id,
        &ResolveResult {
            values: values.clone(),
        },
    );
    for v in &mut values {
        if let Some(s) = v.value.as_mut() {
            s.zeroize();
        }
    }
    reply
}

fn type_name(t: ItemType) -> String {
    serde_json::to_value(t)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn kind_name(k: FieldKind) -> String {
    serde_json::to_value(k)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn vault_names(vault: &Vault) -> Result<HashMap<Id128, String>, Failure> {
    Ok(vault
        .vaults()?
        .into_iter()
        .map(|v| (v.id, v.name))
        .collect())
}

fn items(id: u32, vault: &Vault, only: Option<&str>, query: Option<&str>) -> Reply {
    let names = vault_names(vault)?;
    let only = only.map(|v| secret_ref::find_vault(vault, v)).transpose()?;
    let all: Vec<_> = vault
        .items()?
        .into_iter()
        .filter(|i| i.overview.trashed_at.is_none() && only.is_none_or(|v| i.vault_id == v))
        .collect();
    let ordered: Vec<&keevo_core::ItemSummary> =
        match query.map(str::trim).filter(|q| !q.is_empty()) {
            Some(q) => {
                let index = SearchIndex::new(&all, &names);
                index
                    .search(&Query::parse(q))
                    .into_iter()
                    .filter_map(|h| all.iter().find(|i| i.id == h.id))
                    .collect()
            }
            None => {
                let mut v: Vec<_> = all.iter().collect();
                v.sort_by(|a, b| {
                    a.overview
                        .title
                        .to_lowercase()
                        .cmp(&b.overview.title.to_lowercase())
                });
                v
            }
        };
    let items = ordered
        .into_iter()
        .map(|i| ItemSummary {
            id: i.id.to_hex(),
            vault: names.get(&i.vault_id).cloned().unwrap_or_default(),
            title: i.overview.title.clone(),
            item_type: type_name(i.overview.item_type),
            subtitle: i.overview.subtitle.clone(),
            tags: i.overview.tags.clone(),
            favorite: i.overview.favorite,
        })
        .collect();
    ok(id, &ItemsResult { items })
}

/// 条目中的字段：默认分区在前，然后按分区的顺序；分区内按（排序键，ID）排列。
fn ordered_fields(
    doc: &keevo_core::ItemDoc,
) -> Vec<(Id128, Option<String>, keevo_core::FieldValue)> {
    let mut sections: Vec<(String, Id128, String)> = doc
        .records
        .iter()
        .filter_map(|(k, v)| match (k, &v.value) {
            (RecordKey::Section(id), Some(RecordValue::Section(s))) => {
                Some((s.order.clone(), *id, s.label.clone()))
            }
            _ => None,
        })
        .collect();
    sections.sort();
    let rank = |s: Option<Id128>| {
        s.and_then(|s| sections.iter().position(|(_, id, _)| *id == s))
            .map_or(0, |i| i.saturating_add(1))
    };
    let mut fields: Vec<_> = doc
        .records
        .iter()
        .filter_map(|(k, v)| match (k, &v.value) {
            (RecordKey::Field(id), Some(RecordValue::Field(f))) => Some((
                (rank(f.section), f.order.clone(), *id),
                (
                    *id,
                    f.section.and_then(|s| {
                        sections
                            .iter()
                            .find(|(_, id, _)| *id == s)
                            .map(|(_, _, l)| l.clone())
                    }),
                    f.clone(),
                ),
            )),
            _ => None,
        })
        .collect();
    fields.sort_by(|a, b| a.0.cmp(&b.0));
    fields.into_iter().map(|(_, f)| f).collect()
}

fn item_detail(id: u32, vault: &Vault, spec: &str, reveal: bool) -> Reply {
    let item_id = secret_ref::find_item(vault, spec)?;
    let view = vault.item(item_id)?;
    let names = vault_names(vault)?;
    let overview = view.doc.overview();
    let mut fields: Vec<FieldInfo> = ordered_fields(&view.doc)
        .into_iter()
        .map(|(fid, section, f)| {
            let concealed = f.kind.is_concealed();
            let value = match &f.data {
                FieldData::Text(t) => (reveal || !concealed).then(|| t.expose().to_owned()),
                // 附件只显示文件名与大小；内容不经过命令行
                FieldData::Attachment(a) => Some(format!("{}（{} 字节）", a.name, a.size)),
                FieldData::Kv(entries) => Some(
                    entries
                        .iter()
                        .map(|e| {
                            if e.concealed && !reveal {
                                format!("{}=••••••", e.key)
                            } else {
                                format!("{}={}", e.key, e.value.expose())
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                FieldData::Codes(codes) => reveal.then(|| {
                    codes
                        .iter()
                        .map(|c| {
                            if c.used {
                                format!("{}（已使用）", c.code.expose())
                            } else {
                                c.code.expose().to_owned()
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                }),
            };
            FieldInfo {
                id: fid.to_hex(),
                section,
                label: f.label.clone(),
                kind: kind_name(f.kind),
                concealed,
                value,
            }
        })
        .collect();
    let reply = ok(
        id,
        &ItemResult {
            id: item_id.to_hex(),
            vault: names.get(&view.vault_id).cloned().unwrap_or_default(),
            title: overview.title,
            item_type: type_name(view.doc.item_type),
            tags: overview.tags,
            fields: fields.clone(),
        },
    );
    for f in &mut fields {
        if let Some(v) = f.value.as_mut() {
            v.zeroize();
        }
    }
    reply
}

fn totp(id: u32, vault: &Vault, spec: &str) -> Reply {
    let item_id = secret_ref::find_item(vault, spec)?;
    let view = vault.item(item_id)?;
    let totps: Vec<Id128> = ordered_fields(&view.doc)
        .into_iter()
        .filter(|(_, _, f)| f.kind == FieldKind::Totp)
        .map(|(fid, _, _)| fid)
        .collect();
    let field = match totps.as_slice() {
        [one] => *one,
        [] => return Err(Failure::new("not_found", "这个条目没有一次性密码")),
        _ => {
            return Err(Failure::new(
                "ambiguous",
                "这个条目有多个一次性密码字段，请用 keevo read 指定字段",
            ));
        }
    };
    let code = vault
        .otp_code(item_id, field, now_ms())
        .map_err(|_| Failure::new("invalid_otp", "一次性密码的配置不正确"))?;
    let mut result = TotpResult {
        code: code.code.to_string(),
        remaining: u32::try_from(code.remaining_ms.div_ceil(1000)).unwrap_or(u32::MAX),
    };
    let reply = ok(id, &result);
    result.code.zeroize();
    reply
}

fn parse_type(name: &str) -> Result<ItemType, Failure> {
    serde_json::from_value(serde_json::Value::String(name.to_owned())).map_err(|_| {
        Failure::new(
            "invalid",
            format!("不认识的条目类型「{name}」：可以是 login、secure_note、ssh_key、api_credential、database、environment、email_account、two_factor"),
        )
    })
}

fn is_text_kind(k: FieldKind) -> bool {
    !matches!(k, FieldKind::KvList | FieldKind::RecoveryCodes)
}

fn create(
    id: u32,
    vault: &mut Vault,
    vault_name: &str,
    item_type: &str,
    title: &str,
    fields: &[FieldArg],
) -> Reply {
    let vault_id = secret_ref::find_vault(vault, vault_name)?;
    let item_type = parse_type(item_type)?;
    if title.trim().is_empty() {
        return Err(Failure::new("invalid", "标题不能为空"));
    }
    let mut tpl = template(item_type, Preset::Default);
    for arg in fields {
        let section = match &arg.section {
            Some(name) => Some(
                tpl.sections
                    .iter()
                    .position(|s| s == name)
                    .ok_or_else(|| Failure::new("invalid", format!("模板中没有分区「{name}」")))?,
            ),
            None => None,
        };
        let existing = tpl.fields.iter_mut().find(|(s, f)| {
            f.label == arg.label && (section.is_none() || *s == section) && is_text_kind(f.kind)
        });
        match existing {
            Some((_, f)) => f.data = FieldData::Text(arg.value.as_str().into()),
            None => tpl.fields.push((
                section,
                NewField {
                    kind: FieldKind::Text,
                    label: arg.label.clone(),
                    purpose: None,
                    data: FieldData::Text(arg.value.as_str().into()),
                },
            )),
        }
    }
    let item_id = vault.create_item_from_template(vault_id, title, tpl)?;
    ok(
        id,
        &CreateResult {
            id: item_id.to_hex(),
        },
    )
}

fn edit(id: u32, vault: &mut Vault, spec: &str, title: Option<&str>, set: &[SetArg]) -> Reply {
    let item_id = secret_ref::find_item(vault, spec)?;
    let view = vault.item(item_id)?;
    let fields = ordered_fields(&view.doc);
    let mut edits = Vec::new();
    if let Some(t) = title {
        if t.trim().is_empty() {
            return Err(Failure::new("invalid", "标题不能为空"));
        }
        edits.push(Edit::SetTitle(t.to_owned()));
    }
    for arg in set {
        let matches: Vec<_> = fields
            .iter()
            .filter(|(fid, _, f)| fid.to_hex() == arg.field || f.label == arg.field)
            .collect();
        let (fid, _, f) = match matches.as_slice() {
            [one] => *one,
            [] => {
                return Err(Failure::new(
                    "not_found",
                    format!("找不到字段「{}」", arg.field),
                ));
            }
            _ => {
                return Err(Failure::new(
                    "ambiguous",
                    format!("有多个字段叫「{}」，请改用字段 ID", arg.field),
                ));
            }
        };
        if !is_text_kind(f.kind) {
            return Err(Failure::new(
                "invalid",
                format!("「{}」不是文本字段，请在 Keevo 中编辑", f.label),
            ));
        }
        edits.push(Edit::SetFieldData {
            field_id: *fid,
            data: FieldData::Text(arg.value.as_str().into()),
        });
    }
    if !edits.is_empty() {
        vault.update_item(item_id, edits)?;
    }
    ok(id, &())
}
