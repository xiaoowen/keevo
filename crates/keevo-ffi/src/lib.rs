//! 通过 UniFFI 把 `keevo-core` 导出给 Swift。
//!
//! M0 只导出空壳应用需要的最小接口：创建、打开、解锁、锁定，以及登录条目的读写。
//!
//! **已知限制（M1 处理）**：
//! - 秘密值（主密码、账户密钥、字段值）目前以普通 `String` 跨越 FFI 边界。
//!   M1 改为 `SecretValue` 句柄：Swift 只在显示或复制的瞬间取出明文（`docs/architecture.md` §4.2）。

use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use keevo_core::{
    AccountSecretKey, CoreError, Edit, FieldData, FieldKind, Id128, ItemType, KdfParams, NewField,
    Purpose, RecordKey, RecordValue, Vault,
};

uniffi::setup_scaffolding!();

/// 暴露给 Swift 的错误。不携带任何秘密数据。
#[derive(Debug, uniffi::Error)]
pub enum KeevoError {
    /// 保险库已锁定。
    Locked,
    /// 主密码或账户密钥错误。
    WrongCredentials,
    /// 账户密钥格式错误（附带原因码，如 `checksum_mismatch`）。
    InvalidSecretKey {
        /// 原因码。
        code: String,
    },
    /// 还没有账户。
    NoAccount,
    /// 已经有账户。
    AccountExists,
    /// 对象不存在。
    NotFound,
    /// 数据被篡改或损坏。
    Tampered,
    /// 输入不合法。
    InvalidInput {
        /// 说明。
        message: String,
    },
    /// 其他内部错误。
    Internal {
        /// 说明（不含秘密）。
        message: String,
    },
}

impl fmt::Display for KeevoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Locked => f.write_str("locked"),
            Self::WrongCredentials => f.write_str("wrong credentials"),
            Self::InvalidSecretKey { code } => write!(f, "invalid secret key: {code}"),
            Self::NoAccount => f.write_str("no account"),
            Self::AccountExists => f.write_str("account exists"),
            Self::NotFound => f.write_str("not found"),
            Self::Tampered => f.write_str("tampered"),
            Self::InvalidInput { message } => write!(f, "invalid input: {message}"),
            Self::Internal { message } => write!(f, "internal: {message}"),
        }
    }
}

impl std::error::Error for KeevoError {}

impl From<CoreError> for KeevoError {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::Locked => Self::Locked,
            CoreError::WrongCredentials => Self::WrongCredentials,
            CoreError::NoAccount => Self::NoAccount,
            CoreError::AccountExists => Self::AccountExists,
            CoreError::NotFound => Self::NotFound,
            CoreError::Tampered => Self::Tampered,
            other => Self::Internal {
                message: other.to_string(),
            },
        }
    }
}

/// 新建账户的结果。
#[derive(uniffi::Record)]
pub struct NewAccount {
    /// 已解锁的保险库。
    pub vault: Arc<KeevoVault>,
    /// 账户密钥的显示形式。调用方必须引导用户保存到应急包，并存入钥匙串。
    pub secret_key: String,
}

/// 保险库。
#[derive(uniffi::Record)]
pub struct VaultEntry {
    /// ID（十六进制）。
    pub id: String,
    /// 名称。
    pub name: String,
}

/// 条目列表项。
#[derive(uniffi::Record)]
pub struct ItemEntry {
    /// ID（十六进制）。
    pub id: String,
    /// 所属保险库 ID。
    pub vault_id: String,
    /// 条目类型，如 `login`。
    pub item_type: String,
    /// 标题。
    pub title: String,
    /// 副标题。
    pub subtitle: String,
    /// 网址。
    pub urls: Vec<String>,
    /// 是否收藏。
    pub favorite: bool,
    /// 是否在回收站。
    pub trashed: bool,
    /// 是否有未解决的并发冲突。
    pub has_conflicts: bool,
}

/// 条目字段。
#[derive(uniffi::Record)]
pub struct FieldEntry {
    /// ID（十六进制）。
    pub id: String,
    /// 显示名。
    pub label: String,
    /// 字段类型，如 `concealed`。
    pub kind: String,
    /// 是否默认隐藏。
    pub concealed: bool,
    /// 值。结构化字段（键值对、恢复码）每项一行。
    pub value: String,
}

/// 新建登录条目的输入。
#[derive(uniffi::Record)]
pub struct LoginInput {
    /// 标题。
    pub title: String,
    /// 用户名。
    pub username: String,
    /// 密码。
    pub password: String,
    /// 网址（可为空）。
    pub url: String,
}

/// 新建账户：在 `path` 创建数据库、账户与默认保险库。
///
/// # Errors
/// 已有账户等情况返回对应错误。
#[uniffi::export]
pub fn create_account(path: String, password: String) -> Result<NewAccount, KeevoError> {
    let params = KdfParams::generate_default().map_err(CoreError::from)?;
    let (vault, secret_key) = Vault::create(Path::new(&path), &password, params)?;
    Ok(NewAccount {
        vault: Arc::new(KeevoVault {
            inner: Mutex::new(vault),
        }),
        secret_key: secret_key.to_display_string().as_str().to_owned(),
    })
}

/// 打开已有的数据库（锁定状态）。
///
/// # Errors
/// 没有账户时返回 [`KeevoError::NoAccount`]。
#[uniffi::export]
pub fn open_vault(path: String) -> Result<Arc<KeevoVault>, KeevoError> {
    Ok(Arc::new(KeevoVault {
        inner: Mutex::new(Vault::open(Path::new(&path))?),
    }))
}

/// 一个本地保险库及其解锁状态。线程安全。
#[derive(uniffi::Object)]
pub struct KeevoVault {
    inner: Mutex<Vault>,
}

impl KeevoVault {
    fn vault(&self) -> MutexGuard<'_, Vault> {
        // 某次调用中途 panic 不应导致再也无法锁定，因此在中毒时继续使用内部数据
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[uniffi::export]
impl KeevoVault {
    /// 是否已解锁。
    pub fn is_unlocked(&self) -> bool {
        self.vault().is_unlocked()
    }

    /// 解锁。耗时约 1 秒（Argon2id），请在后台线程调用。
    ///
    /// # Errors
    /// 账户密钥格式错误返回 [`KeevoError::InvalidSecretKey`]；凭据错误返回
    /// [`KeevoError::WrongCredentials`]。
    pub fn unlock(&self, password: String, secret_key: String) -> Result<(), KeevoError> {
        let sk =
            AccountSecretKey::parse(&secret_key).map_err(|e| KeevoError::InvalidSecretKey {
                code: e.code().to_owned(),
            })?;
        Ok(self.vault().unlock(&password, &sk)?)
    }

    /// 锁定：清除内存中的全部密钥。
    pub fn lock(&self) {
        self.vault().lock();
    }

    /// 全部保险库。
    ///
    /// # Errors
    /// 已锁定时返回 [`KeevoError::Locked`]。
    pub fn vaults(&self) -> Result<Vec<VaultEntry>, KeevoError> {
        Ok(self
            .vault()
            .vaults()?
            .into_iter()
            .map(|v| VaultEntry {
                id: v.id.to_hex(),
                name: v.name,
            })
            .collect())
    }

    /// 全部条目（含回收站中的条目）。
    ///
    /// # Errors
    /// 已锁定时返回 [`KeevoError::Locked`]。
    pub fn items(&self) -> Result<Vec<ItemEntry>, KeevoError> {
        Ok(self
            .vault()
            .items()?
            .into_iter()
            .map(|i| ItemEntry {
                id: i.id.to_hex(),
                vault_id: i.vault_id.to_hex(),
                item_type: item_type_name(i.overview.item_type).to_owned(),
                title: i.overview.title,
                subtitle: i.overview.subtitle,
                urls: i.overview.urls,
                favorite: i.overview.favorite,
                trashed: i.overview.trashed_at.is_some(),
                has_conflicts: i.has_conflicts,
            })
            .collect())
    }

    /// 新建登录条目，返回条目 ID。
    ///
    /// # Errors
    /// 已锁定、保险库不存在或输入不合法时返回对应错误。
    pub fn create_login(&self, vault_id: String, input: LoginInput) -> Result<String, KeevoError> {
        let vault_id = parse_id(&vault_id)?;
        let mut fields = vec![
            NewField {
                kind: FieldKind::Text,
                label: "用户名".into(),
                purpose: Some(Purpose::Username),
                data: FieldData::Text(input.username.as_str().into()),
            },
            NewField {
                kind: FieldKind::Concealed,
                label: "密码".into(),
                purpose: Some(Purpose::Password),
                data: FieldData::Text(input.password.as_str().into()),
            },
        ];
        if !input.url.is_empty() {
            fields.push(NewField {
                kind: FieldKind::Url,
                label: "网站".into(),
                purpose: None,
                data: FieldData::Text(input.url.as_str().into()),
            });
        }
        let id = self
            .vault()
            .create_item(vault_id, ItemType::Login, &input.title, fields)?;
        Ok(id.to_hex())
    }

    /// 条目的全部字段，按排序键排列。
    ///
    /// # Errors
    /// 已锁定或条目不存在时返回对应错误。
    pub fn fields(&self, item_id: String) -> Result<Vec<FieldEntry>, KeevoError> {
        let view = self.vault().item(parse_id(&item_id)?)?;
        let mut fields: Vec<(String, FieldEntry)> = view
            .doc
            .records
            .iter()
            .filter_map(|(k, v)| match (k, &v.value) {
                (RecordKey::Field(id), Some(RecordValue::Field(f))) => Some((
                    f.order.clone(),
                    FieldEntry {
                        id: id.to_hex(),
                        label: f.label.clone(),
                        kind: field_kind_name(f.kind).to_owned(),
                        concealed: f.kind.is_concealed(),
                        value: field_text(&f.data),
                    },
                )),
                _ => None,
            })
            .collect();
        fields.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.id.cmp(&b.1.id)));
        Ok(fields.into_iter().map(|(_, f)| f).collect())
    }

    /// 修改条目标题。
    ///
    /// # Errors
    /// 已锁定或条目不存在时返回对应错误。
    pub fn rename_item(&self, item_id: String, title: String) -> Result<(), KeevoError> {
        Ok(self
            .vault()
            .update_item(parse_id(&item_id)?, vec![Edit::SetTitle(title)])?)
    }

    /// 移入回收站。
    ///
    /// # Errors
    /// 已锁定或条目不存在时返回对应错误。
    pub fn trash_item(&self, item_id: String) -> Result<(), KeevoError> {
        Ok(self.vault().trash_item(parse_id(&item_id)?)?)
    }
}

fn parse_id(hex: &str) -> Result<Id128, KeevoError> {
    let bytes = hex.as_bytes();
    if bytes.len() != 32 {
        return Err(KeevoError::InvalidInput {
            message: "id must be 32 hex characters".into(),
        });
    }
    let mut out = [0u8; 16];
    for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        let s = std::str::from_utf8(pair).map_err(|_| KeevoError::InvalidInput {
            message: "id".into(),
        })?;
        *slot = u8::from_str_radix(s, 16).map_err(|_| KeevoError::InvalidInput {
            message: "id".into(),
        })?;
    }
    Ok(Id128::from_bytes(out))
}

fn field_text(data: &FieldData) -> String {
    match data {
        FieldData::Text(s) => s.expose().to_owned(),
        FieldData::Kv(entries) => entries
            .iter()
            .map(|e| format!("{}={}", e.key, e.value.expose()))
            .collect::<Vec<_>>()
            .join("\n"),
        FieldData::Codes(codes) => codes
            .iter()
            .map(|c| {
                format!(
                    "{}{}",
                    c.code.expose(),
                    if c.used { "（已用）" } else { "" }
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
    }
}

const fn item_type_name(t: ItemType) -> &'static str {
    match t {
        ItemType::Login => "login",
        ItemType::EmailAccount => "email_account",
        ItemType::SecureNote => "secure_note",
        ItemType::SshKey => "ssh_key",
        ItemType::ApiCredential => "api_credential",
        ItemType::Database => "database",
        ItemType::Environment => "environment",
        ItemType::TwoFactor => "two_factor",
    }
}

const fn field_kind_name(k: FieldKind) -> &'static str {
    match k {
        FieldKind::Text => "text",
        FieldKind::Multiline => "multiline",
        FieldKind::Concealed => "concealed",
        FieldKind::Email => "email",
        FieldKind::Url => "url",
        FieldKind::Phone => "phone",
        FieldKind::Date => "date",
        FieldKind::MonthYear => "month_year",
        FieldKind::Select => "select",
        FieldKind::Totp => "totp",
        FieldKind::SshPrivateKey => "ssh_private_key",
        FieldKind::Reference => "reference",
        FieldKind::RecoveryCodes => "recovery_codes",
        FieldKind::KvList => "kv_list",
        FieldKind::File => "file",
    }
}
