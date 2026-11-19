//! 通过 UniFFI 把 `keevo-core` 导出给 Swift。
//!
//! M1.1 导出条目的完整增删改查：详情、编辑、回收站、永久删除、历史与恢复、冲突处理、精简与重建，
//! 以及 KDF 参数确认；本机密钥包裹（免输账户密钥、Touch ID，`spec/crypto.md` §8.7）。
//!
//! Secure Enclave 的操作由 Swift 实现 [`SecureEnclaveProvider`] 提供。被包裹的材料（AUK、账户密钥、
//! 设备 ID）不经过 Swift，跨越边界的只有每次包裹各不相同的协商结果。
//!
//! **秘密值**（`docs/architecture.md` §4.2）：
//! - Rust 交给 Swift 的秘密（字段值、冲突版本的值、新账户的账户密钥）都是 [`SecretValue`] 句柄。
//!   明文留在 Rust 的清零缓冲区里，Swift 只在显示或复制的那一刻调用 `expose()` 取出，用完即弃。
//! - Swift 交给 Rust 的输入（主密码、编辑后的字段值）仍是 `String`：它们来自 SwiftUI 的文本框，
//!   在 Swift 一侧本来就以 `String` 存在，Swift 的字符串也无法清零。Rust 收到后立即放进清零缓冲区。

use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use zeroize::Zeroizing;

use keevo_core::local::{EnclaveError, EnclaveKey, EphemeralAgreement, LocalKeys, SecureEnclave};
use keevo_core::search::{Query, SearchIndex};
use keevo_core::{LocalPurpose, PasswordReason, Store};

use keevo_core::{
    AccountSecretKey, CodeEntry, CoreError, Edit, FieldData, FieldKind, Id128, ItemDoc, ItemType,
    KdfParams, KvEntry, NewField, Purpose, RecordKey, RecordValue, RecordVersion, Vault,
};

uniffi::setup_scaffolding!();

/// 暴露给 Swift 的错误。不携带任何秘密数据。
#[derive(Debug, uniffi::Error)]
pub enum KeevoError {
    /// 保险库已锁定。
    Locked,
    /// 主密码或账户密钥错误。
    WrongCredentials,
    /// KDF 参数异常地高，需要用户确认后才会解锁。
    KdfNeedsConfirmation,
    /// 条目合并后过大，需要先精简才能保存。
    ItemTooLarge,
    /// 条目超出上限，只能导出或重建为新条目。
    ItemNeedsRebuild,
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
    /// 用户取消了 Touch ID 或认证超时。什么都没有改变，不要提示错误。
    Cancelled,
    /// Secure Enclave 暂时不可用（如屏幕锁定）。什么都没有改变，稍后重试；
    /// 一直如此时可以让用户选择 [`open_vault_reenrolling`]。
    EnclaveUnavailable,
    /// 本机没有可用的账户密钥，需要用户从应急包输入，然后调用 [`KeevoVault::unlock`]。
    SecretKeyRequired,
    /// 此时不能用 Touch ID（原因见 [`KeevoVault::password_reason`]），改用主密码。
    TouchIdUnavailable,
    /// Touch ID 未能识别指纹。连续 3 次后必须输入主密码。
    AuthenticationFailed,
    /// 一次性密码的配置不合法（不是 `otpauth://totp/` URI 或 Base32 密钥，或参数超出范围）。
    InvalidOtp,
    /// 浏览器扩展的本地服务无法启动。
    BrowserServiceUnavailable {
        /// 原因（不含秘密）。
        reason: String,
    },
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
            Self::KdfNeedsConfirmation => f.write_str("kdf needs confirmation"),
            Self::ItemTooLarge => f.write_str("item too large"),
            Self::ItemNeedsRebuild => f.write_str("item needs rebuild"),
            Self::InvalidSecretKey { code } => write!(f, "invalid secret key: {code}"),
            Self::NoAccount => f.write_str("no account"),
            Self::AccountExists => f.write_str("account exists"),
            Self::NotFound => f.write_str("not found"),
            Self::Tampered => f.write_str("tampered"),
            Self::Cancelled => f.write_str("cancelled"),
            Self::EnclaveUnavailable => f.write_str("secure enclave unavailable"),
            Self::SecretKeyRequired => f.write_str("secret key required"),
            Self::TouchIdUnavailable => f.write_str("touch id unavailable"),
            Self::AuthenticationFailed => f.write_str("touch id authentication failed"),
            Self::InvalidOtp => f.write_str("invalid one-time password"),
            Self::BrowserServiceUnavailable { reason } => {
                write!(f, "browser service unavailable: {reason}")
            }
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
            CoreError::KdfNeedsConfirmation => Self::KdfNeedsConfirmation,
            CoreError::ItemTooLarge => Self::ItemTooLarge,
            CoreError::ItemNeedsRebuild => Self::ItemNeedsRebuild,
            CoreError::NoAccount => Self::NoAccount,
            CoreError::AccountExists => Self::AccountExists,
            CoreError::NotFound => Self::NotFound,
            CoreError::Tampered => Self::Tampered,
            CoreError::Cancelled => Self::Cancelled,
            CoreError::EnclaveUnavailable => Self::EnclaveUnavailable,
            CoreError::SecretKeyRequired => Self::SecretKeyRequired,
            CoreError::TouchIdUnavailable => Self::TouchIdUnavailable,
            CoreError::AuthenticationFailed => Self::AuthenticationFailed,
            CoreError::InvalidOtp => Self::InvalidOtp,
            CoreError::OutOfRange => Self::InvalidInput {
                message: "out of range".into(),
            },
            other => Self::Internal {
                message: other.to_string(),
            },
        }
    }
}

/// Swift 报告的 Secure Enclave 错误（`spec/crypto.md` §8.7"失败与恢复"）。
#[derive(Debug, uniffi::Error)]
pub enum EnclaveFailure {
    /// 用户取消或认证超时。
    Cancelled,
    /// 暂时不可用，或无法确定原因。
    Unavailable,
    /// 能确定材料本身已失效：blob 无法解析、密钥因指纹变化而失效。
    Unusable,
    /// 用户在场验证未通过（指纹不匹配）。
    Failed,
}

impl fmt::Display for EnclaveFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Cancelled => "cancelled",
            Self::Unavailable => "unavailable",
            Self::Unusable => "unusable",
            Self::Failed => "failed",
        })
    }
}

impl std::error::Error for EnclaveFailure {}

impl From<uniffi::UnexpectedUniFFICallbackError> for EnclaveFailure {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        // 无法确定原因：按暂时不可用处理，什么都不改变
        Self::Unavailable
    }
}

/// 新建的 Secure Enclave 密钥。
#[derive(uniffi::Record)]
pub struct EnclaveKeyData {
    /// 密钥 blob（`dataRepresentation`）。
    pub blob: Vec<u8>,
    /// 公钥（`x963Representation`，65 字节）。
    pub public_key: Vec<u8>,
}

/// 临时密钥的协商结果。
#[derive(uniffi::Record)]
pub struct EphemeralAgreementData {
    /// 临时公钥（`x963Representation`，65 字节）。
    pub ephemeral_public: Vec<u8>,
    /// 协商结果（`SharedSecret` 的原始 32 字节）。
    pub shared: Vec<u8>,
}

/// 由 Swift（CryptoKit）实现的 Secure Enclave 操作（`spec/crypto.md` §8.7"分工"）。
/// `purpose` 是用途字节：0x01 AUK（访问控制要求 `biometryCurrentSet`）、0x02 账户密钥、
/// 0x03 服务静态私钥、0x04 设备标记。
#[uniffi::export(with_foreign)]
pub trait SecureEnclaveProvider: Send + Sync {
    /// 按用途创建 Secure Enclave P-256 密钥。
    ///
    /// # Errors
    /// 见 [`EnclaveFailure`]。
    fn create_key(&self, purpose: u8) -> Result<EnclaveKeyData, EnclaveFailure>;

    /// 生成临时 P-256 密钥并与 `public_key` 协商（软件运算）。
    ///
    /// # Errors
    /// 公钥无效时返回 [`EnclaveFailure::Unusable`]。
    fn agree_ephemeral(
        &self,
        public_key: Vec<u8>,
    ) -> Result<EphemeralAgreementData, EnclaveFailure>;

    /// 用 blob 恢复 Secure Enclave 私钥，与临时公钥协商。用途 0x01 在此弹出 Touch ID。
    ///
    /// # Errors
    /// 见 [`EnclaveFailure`]。
    fn agree(
        &self,
        purpose: u8,
        key_blob: Vec<u8>,
        ephemeral_public: Vec<u8>,
    ) -> Result<Vec<u8>, EnclaveFailure>;
}

/// 把 Swift 的实现接到核心层的 [`SecureEnclave`] 上。协商结果一到 Rust 就放进会清零的缓冲区。
struct EnclaveAdapter(Arc<dyn SecureEnclaveProvider>);

const fn enclave_error(e: &EnclaveFailure) -> EnclaveError {
    match e {
        EnclaveFailure::Cancelled => EnclaveError::Cancelled,
        EnclaveFailure::Unavailable => EnclaveError::Unavailable,
        EnclaveFailure::Unusable => EnclaveError::Unusable,
        EnclaveFailure::Failed => EnclaveError::Failed,
    }
}

impl SecureEnclave for EnclaveAdapter {
    fn create_key(&self, purpose: LocalPurpose) -> Result<EnclaveKey, EnclaveError> {
        let key = self
            .0
            .create_key(purpose.byte())
            .map_err(|e| enclave_error(&e))?;
        Ok(EnclaveKey {
            blob: key.blob,
            public_key: key.public_key,
        })
    }

    fn agree_ephemeral(&self, public_key: &[u8]) -> Result<EphemeralAgreement, EnclaveError> {
        let a = self
            .0
            .agree_ephemeral(public_key.to_vec())
            .map_err(|e| enclave_error(&e))?;
        Ok(EphemeralAgreement {
            ephemeral_public: a.ephemeral_public,
            shared: zeroize::Zeroizing::new(a.shared),
        })
    }

    fn agree(
        &self,
        purpose: LocalPurpose,
        blob: &[u8],
        ephemeral_public: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, EnclaveError> {
        self.0
            .agree(purpose.byte(), blob.to_vec(), ephemeral_public.to_vec())
            .map(zeroize::Zeroizing::new)
            .map_err(|e| enclave_error(&e))
    }
}

/// 这台 Mac 的本机环境：本机密钥目录、Secure Enclave，以及本次开机的标识。
#[derive(uniffi::Record)]
pub struct LocalEnvironment {
    /// 本机密钥目录（`spec/crypto.md` §8.7）。
    pub local_dir: String,
    /// 本次开机的标识（`kern.bootsessionuuid`）。用于"重启后的首次解锁必须输入主密码"；
    /// 取不到时传空字符串，Touch ID 就会一直要求先输入主密码。
    pub boot_session: String,
    /// Secure Enclave 的实现。
    pub enclave: Arc<dyn SecureEnclaveProvider>,
}

fn local_keys(env: LocalEnvironment) -> Result<LocalKeys, KeevoError> {
    Ok(LocalKeys::load(
        Path::new(&env.local_dir),
        Arc::new(EnclaveAdapter(env.enclave)),
    )?
    .with_boot_session(&env.boot_session))
}

/// 为什么此时不能用 Touch ID、必须输入主密码。解锁界面据此说明原因（`docs/ux.md` §3.2）。
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordReasonKind {
    /// 没有启用 Touch ID。
    NotEnabled,
    /// Touch ID 已失效（例如指纹有变化）；用主密码解锁后自动恢复。
    Invalidated,
    /// Mac 重启后的首次解锁。
    Restarted,
    /// 距上次输入主密码超过了设定的天数。
    IntervalElapsed,
    /// Touch ID 连续失败次数过多。
    TooManyFailures,
}

const fn reason_kind(r: PasswordReason) -> PasswordReasonKind {
    match r {
        PasswordReason::NotEnabled => PasswordReasonKind::NotEnabled,
        PasswordReason::Invalidated => PasswordReasonKind::Invalidated,
        PasswordReason::Restarted => PasswordReasonKind::Restarted,
        PasswordReason::IntervalElapsed => PasswordReasonKind::IntervalElapsed,
        PasswordReason::TooManyFailures => PasswordReasonKind::TooManyFailures,
    }
}

/// 跨越 FFI 的秘密值句柄（`docs/architecture.md` §4.2）。明文留在 Rust 的清零缓冲区里，
/// Swift 只在显示或复制的那一刻调用 [`SecretValue::expose`]。
///
/// 句柄由发出它的保险库登记；保险库锁定时全部清零，之后 `expose()` 只返回空字符串。
#[derive(uniffi::Object)]
pub struct SecretValue(Mutex<Option<Zeroizing<String>>>);

impl SecretValue {
    /// 不登记到任何保险库的句柄（例如生成器的结果），锁定时不清零，随 Swift 释放而清零。
    fn detached(value: Zeroizing<String>) -> Arc<Self> {
        Arc::new(Self(Mutex::new(Some(value))))
    }

    fn with<T>(&self, f: impl FnOnce(&str) -> T) -> T {
        let guard = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(guard.as_ref().map_or("", |s| s.as_str()))
    }
}

/// 一个保险库发出的全部句柄，锁定时清零（`docs/architecture.md` §4.2"锁定时使所有句柄失效"）。
#[derive(Default)]
struct SecretRegistry(Mutex<Vec<std::sync::Weak<SecretValue>>>);

impl SecretRegistry {
    fn issue(&self, value: Zeroizing<String>) -> Arc<SecretValue> {
        let secret = Arc::new(SecretValue(Mutex::new(Some(value))));
        let mut list = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        list.retain(|w| w.strong_count() > 0);
        list.push(Arc::downgrade(&secret));
        secret
    }

    fn wipe(&self) {
        let mut list = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for secret in list.drain(..).filter_map(|w| w.upgrade()) {
            // 替换为 None 时，旧的 Zeroizing<String> 被丢弃并清零
            *secret
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        }
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue(…)")
    }
}

#[uniffi::export]
impl SecretValue {
    /// 取出明文。只在显示或复制的那一刻调用，用完即弃。保险库锁定之后返回空字符串。
    pub fn expose(&self) -> String {
        self.with(str::to_owned)
    }

    /// 是否为空（锁定之后总是为空）。不需要取出明文。
    pub fn is_empty(&self) -> bool {
        self.with(str::is_empty)
    }

    /// 是否与 `other` 相同。编辑器据此判断有没有改动，不需要取出明文。
    pub fn equals(&self, other: String) -> bool {
        let other = Zeroizing::new(other);
        self.with(|s| s == other.as_str())
    }
}

/// 一次性密码的配置（不含密钥），用于添加时预览与校验。
#[derive(uniffi::Record)]
pub struct OtpInfo {
    /// 发行方。
    pub issuer: Option<String>,
    /// 账户名。
    pub account: Option<String>,
    /// 哈希：`SHA1`、`SHA256`、`SHA512`。
    pub algorithm: String,
    /// 位数。
    pub digits: u32,
    /// 周期（秒）。
    pub period: u32,
}

/// 某一时刻的验证码。
#[derive(uniffi::Record)]
pub struct OtpCodeEntry {
    /// 验证码。
    pub code: Arc<SecretValue>,
    /// 周期（秒）。
    pub period: u32,
    /// 距失效还有多少毫秒。
    pub remaining_ms: u64,
}

/// 解析 `otpauth://totp/…` URI 或 Base32 密钥，返回不含密钥的配置。用于添加一次性密码前校验输入。
///
/// # Errors
/// 不合法时返回 [`KeevoError::InvalidOtp`]。
#[uniffi::export]
pub fn parse_otp(text: String) -> Result<OtpInfo, KeevoError> {
    let text = Zeroizing::new(text);
    let c = keevo_core::otp::OtpConfig::parse(&text)?;
    Ok(OtpInfo {
        issuer: c.issuer.clone(),
        account: c.account.clone(),
        algorithm: match c.algorithm {
            keevo_core::OtpAlgorithm::Sha1 => "SHA1",
            keevo_core::OtpAlgorithm::Sha256 => "SHA256",
            keevo_core::OtpAlgorithm::Sha512 => "SHA512",
        }
        .to_owned(),
        digits: c.digits,
        period: c.period,
    })
}

/// 密码生成方式（`keevo-core::generator`）。
#[derive(uniffi::Enum)]
pub enum GeneratorRecipe {
    /// 随机字符，长度 8–128，每个选中的类别至少出现一次。
    Password {
        /// 长度。
        length: u32,
        /// 小写字母。
        lowercase: bool,
        /// 大写字母。
        uppercase: bool,
        /// 数字。
        digits: bool,
        /// 符号。
        symbols: bool,
        /// 排除容易看错的字符。
        avoid_ambiguous: bool,
    },
    /// 口令短语，3–20 个单词（EFF 大词表）。
    Passphrase {
        /// 单词数。
        words: u32,
        /// 分隔符（最多 3 个字符）。
        separator: String,
        /// 首字母大写。
        capitalize: bool,
        /// 加一位随机数字。
        include_number: bool,
    },
    /// 纯数字，4–32 位。
    Pin {
        /// 位数。
        length: u32,
    },
}

/// 生成结果。
#[derive(uniffi::Record)]
pub struct GeneratedPassword {
    /// 生成的值。
    pub value: Arc<SecretValue>,
    /// 熵（比特），按实际的取值空间计算。
    pub entropy_bits: f64,
}

/// 生成密码。
///
/// # Errors
/// 参数超出范围或没有选中任何字符类别时返回 [`KeevoError::InvalidInput`]。
#[uniffi::export]
pub fn generate_password(recipe: GeneratorRecipe) -> Result<GeneratedPassword, KeevoError> {
    use keevo_core::generator::{Recipe, generate};
    let recipe = match recipe {
        GeneratorRecipe::Password {
            length,
            lowercase,
            uppercase,
            digits,
            symbols,
            avoid_ambiguous,
        } => Recipe::Password {
            length,
            lowercase,
            uppercase,
            digits,
            symbols,
            avoid_ambiguous,
        },
        GeneratorRecipe::Passphrase {
            words,
            separator,
            capitalize,
            include_number,
        } => Recipe::Passphrase {
            words,
            separator,
            capitalize,
            include_number,
        },
        GeneratorRecipe::Pin { length } => Recipe::Pin { length },
    };
    let g = generate(&recipe)?;
    Ok(GeneratedPassword {
        value: SecretValue::detached(g.value),
        entropy_bits: g.entropy_bits,
    })
}

/// 生成一个新的随机 ID（十六进制），用于在同一批编辑中新建分区并引用它。
///
/// # Errors
/// 随机数不可用时返回 [`KeevoError::Internal`]。
#[uniffi::export]
pub fn new_id() -> Result<String, KeevoError> {
    Ok(Id128::random().map_err(CoreError::from)?.to_hex())
}

/// 新建账户的结果。
#[derive(uniffi::Record)]
pub struct NewAccount {
    /// 已解锁的保险库。
    pub vault: Arc<KeevoVault>,
    /// 账户密钥的显示形式（`K1-…`）。调用方必须引导用户保存到应急包；本机的副本已由 Secure Enclave 包裹。
    pub secret_key: Arc<SecretValue>,
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
    /// 标签。
    pub tags: Vec<String>,
    /// 是否在回收站。
    pub trashed: bool,
    /// 最后修改时间（Unix 毫秒，取各记录时间戳的最大值）。
    pub updated_ms: u64,
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
    /// 值。结构化字段（键值对、恢复码）每项一行。只在显示或复制时取出明文。
    pub value: Arc<SecretValue>,
    /// 自动填充用途，如 `password`；没有时为 `None`。
    pub purpose: Option<String>,
    /// 所在分区；`None` 为默认分区（包括分区已被删除的情形）。
    pub section_id: Option<String>,
    /// 键值对（`kv_list` 字段），其他字段为空。
    pub kv: Vec<KvItem>,
    /// 恢复码（`recovery_codes` 字段），其他字段为空。
    pub codes: Vec<CodeItem>,
}

/// 键值对中的一项。
#[derive(uniffi::Record)]
pub struct KvItem {
    /// 键（如环境变量名）。
    pub key: String,
    /// 值。
    pub value: Arc<SecretValue>,
    /// 值是否默认隐藏。
    pub concealed: bool,
}

/// 一个恢复码。
#[derive(uniffi::Record)]
pub struct CodeItem {
    /// 恢复码。
    pub code: Arc<SecretValue>,
    /// 是否已使用。
    pub used: bool,
}

/// 键值对的输入。
#[derive(uniffi::Record)]
pub struct KvInput {
    /// 键。
    pub key: String,
    /// 值。
    pub value: String,
    /// 值是否默认隐藏。
    pub concealed: bool,
}

/// 恢复码的输入。
#[derive(uniffi::Record)]
pub struct CodeInput {
    /// 恢复码。
    pub code: String,
    /// 是否已使用。
    pub used: bool,
}

/// 分区。
#[derive(uniffi::Record)]
pub struct SectionEntry {
    /// ID（十六进制）。
    pub id: String,
    /// 名称。
    pub label: String,
}

/// 条目详情（合并全部头修订之后的视图）。
#[derive(uniffi::Record)]
pub struct ItemDetail {
    /// ID（十六进制）。
    pub id: String,
    /// 所属保险库 ID。
    pub vault_id: String,
    /// 条目类型，如 `login`。
    pub item_type: String,
    /// 标题。
    pub title: String,
    /// 是否收藏。
    pub favorite: bool,
    /// 标签，按名称排序。
    pub tags: Vec<String>,
    /// 是否在回收站。
    pub trashed: bool,
    /// 分区，按排序键排列（不含默认分区）。
    pub sections: Vec<SectionEntry>,
    /// 字段：默认分区在前，然后按分区的顺序，分区内按排序键排列。
    pub fields: Vec<FieldEntry>,
    /// 待处理的冲突。保存前必须先展示（`spec/revisions.md` §5.4）。
    pub conflicts: Vec<ConflictEntry>,
    /// 另一台设备删除了它，但这里有并发的修改，已撤销删除。保存即确认恢复。
    pub resurrected: bool,
    /// 合并时发现的出处不一致的记录数（`spec/revisions.md` §5.6），保存前必须提示。
    pub integrity_issues: u32,
    /// 头修订数；大于 1 表示有尚未收敛的并发修改。
    pub head_count: u32,
    /// 最后修改时间（Unix 毫秒）。
    pub updated_ms: u64,
    /// 历史修订数（含已清理内容的修订）。
    pub revision_count: u32,
}

/// 一个记录键上的冲突。
#[derive(uniffi::Record)]
pub struct ConflictEntry {
    /// 记录键（如 `attr:title`、`field:<id>`），处理冲突时原样传回。
    pub key: String,
    /// 记录的种类：`title`、`favorite`、`tag`、`section`、`field`，其他属性为 `attr`。界面据此本地化显示。
    pub kind: String,
    /// 用户起的名字：字段名、分区名或标签名；标题、收藏等属性为 `None`。
    pub label: Option<String>,
    /// 当前胜出的版本。
    pub current: ConflictVersion,
    /// 其余并发版本。
    pub others: Vec<ConflictVersion>,
}

/// 冲突中的一个版本。
#[derive(uniffi::Record)]
pub struct ConflictVersion {
    /// 写入这个版本的修订 ID。
    pub rev_id: String,
    /// 值的文本；`None` 表示这个版本删除了该记录。布尔值为 `true` / `false`，标签为空字符串。
    pub value: Option<Arc<SecretValue>>,
    /// 是否默认隐藏（密码等）。
    pub concealed: bool,
}

/// 对条目的一次编辑。
#[derive(uniffi::Enum)]
pub enum ItemEdit {
    /// 修改标题。
    SetTitle {
        /// 新标题。
        title: String,
    },
    /// 收藏或取消收藏。
    SetFavorite {
        /// 是否收藏。
        favorite: bool,
    },
    /// 添加标签。
    AddTag {
        /// 标签名。
        tag: String,
    },
    /// 移除标签。
    RemoveTag {
        /// 标签名。
        tag: String,
    },
    /// 在默认分区的末尾新增字段。键值对与恢复码字段以空列表创建，`value` 被忽略。
    AddField {
        /// 字段类型，如 `text`、`concealed`、`kv_list`。
        kind: String,
        /// 显示名。
        label: String,
        /// 自动填充用途，如 `username`。
        purpose: Option<String>,
        /// 值。
        value: String,
    },
    /// 在某个分区的末尾新增字段（`section_id` 为 `None` 时为默认分区）。
    /// 键值对字段取 `kv`、恢复码字段取 `codes` 作为初始内容，其他字段取 `value`。
    AddFieldToSection {
        /// 分区 ID；可以是同一批编辑中 `AddSection` 新建的分区。
        section_id: Option<String>,
        /// 字段类型。
        kind: String,
        /// 显示名。
        label: String,
        /// 自动填充用途。
        purpose: Option<String>,
        /// 值（文本类字段）。
        value: String,
        /// 初始键值对（`kv_list`）。
        kv: Vec<KvInput>,
        /// 初始恢复码（`recovery_codes`）。
        codes: Vec<CodeInput>,
    },
    /// 修改字段的显示名。
    SetFieldLabel {
        /// 字段 ID。
        field_id: String,
        /// 新名称。
        label: String,
    },
    /// 修改字段的自动填充用途。
    SetFieldPurpose {
        /// 字段 ID。
        field_id: String,
        /// 新用途；`None` 表示不参与识别。
        purpose: Option<String>,
    },
    /// 替换键值对字段的全部内容。
    SetFieldKv {
        /// 字段 ID。
        field_id: String,
        /// 新的键值对。
        entries: Vec<KvInput>,
    },
    /// 替换恢复码字段的全部内容（也用于标记某个恢复码已使用）。
    SetFieldCodes {
        /// 字段 ID。
        field_id: String,
        /// 新的恢复码。
        codes: Vec<CodeInput>,
    },
    /// 移动字段：放进 `section_id`，排在 `before_field_id` 之前；为 `None` 时排在末尾。
    MoveField {
        /// 字段 ID。
        field_id: String,
        /// 目标分区；`None` 为默认分区。
        section_id: Option<String>,
        /// 排在这个字段之前；它必须在目标分区中。
        before_field_id: Option<String>,
    },
    /// 在末尾新增分区。ID 由调用方用 [`new_id`] 生成，同一批编辑中可以接着把字段放进去。
    AddSection {
        /// 分区 ID。
        section_id: String,
        /// 名称。
        label: String,
    },
    /// 分区改名。
    RenameSection {
        /// 分区 ID。
        section_id: String,
        /// 新名称。
        label: String,
    },
    /// 删除分区：其中的字段移到默认分区末尾。
    RemoveSection {
        /// 分区 ID。
        section_id: String,
    },
    /// 修改文本类字段的值。
    SetFieldValue {
        /// 字段 ID。
        field_id: String,
        /// 新值。
        value: String,
    },
    /// 删除字段。
    RemoveField {
        /// 字段 ID。
        field_id: String,
    },
}

/// 历史中的一个修订，从新到旧。
#[derive(uniffi::Record)]
pub struct HistoryItem {
    /// 修订 ID。
    pub rev_id: String,
    /// 这一修订时的标题；墓碑或已清理时为 `None`。
    pub title: Option<String>,
    /// 这一修订时的最近修改时间（Unix 毫秒）；墓碑或已清理时为 `None`。
    pub updated_ms: Option<u64>,
    /// 是否为永久删除留下的墓碑。
    pub deleted: bool,
    /// 内容是否已被清理，只剩元数据。
    pub pruned: bool,
    /// 是否合并了多个分支（写时收敛）。
    pub merge: bool,
}

/// 账户的 KDF 参数，用于向用户确认异常的解锁参数（`spec/crypto.md` §5.3）。
#[derive(uniffi::Record, Clone, Copy, PartialEq, Eq)]
pub struct KdfInfo {
    /// 内存（KiB）。
    pub memory_kib: u32,
    /// 迭代次数。
    pub iterations: u32,
    /// 并行度。
    pub parallelism: u32,
}

/// 精简时保留的版本。
#[derive(uniffi::Record)]
pub struct KeepVersion {
    /// 记录键。
    pub key: String,
    /// 保留哪一个修订写入的版本。
    pub rev_id: String,
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

/// 新建账户：在 `path` 创建数据库、账户与默认保险库，并把设备标记与账户密钥包裹到
/// 本机密钥目录（`spec/crypto.md` §8.7）。之后日常只需主密码。
///
/// # Errors
/// 已有账户等情况返回对应错误；Secure Enclave 不可用时返回 [`KeevoError::EnclaveUnavailable`]。
#[uniffi::export]
pub fn create_account(
    path: String,
    password: String,
    local: LocalEnvironment,
) -> Result<NewAccount, KeevoError> {
    let params = KdfParams::generate_default().map_err(CoreError::from)?;
    let local = local_keys(local)?;
    let store = Store::open(Path::new(&path)).map_err(CoreError::from)?;
    let (vault, secret_key) = Vault::create_with_local(store, &password, params, local)?;
    let vault = Arc::new(KeevoVault::new(vault));
    let secret_key = vault.secrets.issue(secret_key.to_display_string());
    Ok(NewAccount { vault, secret_key })
}

/// 打开已有的数据库（锁定状态），接入这台 Mac 的本机环境。
///
/// # Errors
/// 没有账户时返回 [`KeevoError::NoAccount`]；Secure Enclave 暂时不可用时返回
/// [`KeevoError::EnclaveUnavailable`]，此时什么都没有改变。
#[uniffi::export]
pub fn open_vault(path: String, local: LocalEnvironment) -> Result<Arc<KeevoVault>, KeevoError> {
    let local = local_keys(local)?;
    let store = Store::open(Path::new(&path)).map_err(CoreError::from)?;
    Ok(Arc::new(KeevoVault::new(Vault::open_with_local(
        store, local,
    )?)))
}

/// 重新登记本机并打开：生成新的设备 ID，丢弃本机的全部包裹，之后需要输入账户密钥。
/// 只在 [`open_vault`] 一直返回 [`KeevoError::EnclaveUnavailable`]、用户确认之后调用。
///
/// # Errors
/// 同 [`open_vault`]。
#[uniffi::export]
pub fn open_vault_reenrolling(
    path: String,
    local: LocalEnvironment,
) -> Result<Arc<KeevoVault>, KeevoError> {
    let local = local_keys(local)?;
    let store = Store::open(Path::new(&path)).map_err(CoreError::from)?;
    Ok(Arc::new(KeevoVault::new(Vault::open_reenrolling_local(
        store, local,
    )?)))
}

/// 一个本地保险库及其解锁状态。线程安全。
#[derive(uniffi::Object)]
pub struct KeevoVault {
    /// 与 Vault Service 共享：浏览器扩展的请求与应用的操作使用同一个保险库与同一把锁。
    inner: Arc<Mutex<Vault>>,
    /// 浏览器扩展的本地服务（`spec/ipc.md`），由 [`KeevoVault::start_browser_service`] 启动。
    service: Mutex<Option<keevo_service::VaultService>>,
    secrets: SecretRegistry,
    /// 搜索索引（解密后的概要），锁定时丢弃。
    search_index: Mutex<Option<SearchIndex>>,
}

impl KeevoVault {
    fn new(vault: Vault) -> Self {
        Self {
            inner: Arc::new(Mutex::new(vault)),
            service: Mutex::new(None),
            secrets: SecretRegistry::default(),
            search_index: Mutex::new(None),
        }
    }

    fn index(&self) -> MutexGuard<'_, Option<SearchIndex>> {
        self.search_index
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

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
        self.vault().unlock(&password, &sk)?;
        self.after_unlock();
        Ok(())
    }

    /// 只用主密码解锁：账户密钥取自本机包裹。耗时约 1 秒（Argon2id），请在后台线程调用。
    ///
    /// # Errors
    /// 本机没有可用的账户密钥时返回 [`KeevoError::SecretKeyRequired`]，此时询问账户密钥并调用
    /// [`KeevoVault::unlock`]；主密码错误返回 [`KeevoError::WrongCredentials`]。
    pub fn unlock_with_password(&self, password: String) -> Result<(), KeevoError> {
        self.vault().unlock_with_password(&password)?;
        self.after_unlock();
        Ok(())
    }

    /// 用 Touch ID 解锁。会弹出系统的 Touch ID 提示，请在后台线程调用。
    ///
    /// # Errors
    /// 用户取消返回 [`KeevoError::Cancelled`]；未启用或已失效返回 [`KeevoError::TouchIdUnavailable`]。
    pub fn unlock_with_touch_id(&self) -> Result<(), KeevoError> {
        self.vault().unlock_with_touch_id()?;
        self.after_unlock();
        Ok(())
    }

    /// 启用 Touch ID：用户再输入一次主密码。耗时约 1 秒，请在后台线程调用。
    ///
    /// # Errors
    /// 已锁定返回 [`KeevoError::Locked`]；主密码错误返回 [`KeevoError::WrongCredentials`]。
    pub fn enable_touch_id(&self, password: String) -> Result<(), KeevoError> {
        Ok(self.vault().enable_touch_id(&password)?)
    }

    /// 关闭 Touch ID：先重新验证（`docs/ux.md` §5）。`password` 为 `None` 时用 Touch ID 验证，会弹出提示，
    /// 请在后台线程调用。
    ///
    /// # Errors
    /// 验证失败返回对应错误（主密码错误、取消、未能识别等），此时不关闭。
    pub fn disable_touch_id(&self, password: Option<String>) -> Result<(), KeevoError> {
        let proof = password.as_deref().map_or(
            keevo_core::Reverify::TouchId,
            keevo_core::Reverify::Password,
        );
        Ok(self.vault().disable_touch_id(proof)?)
    }

    /// Touch ID 是否已启用且未失效。
    pub fn touch_id_enabled(&self) -> bool {
        self.vault().touch_id_enabled()
    }

    /// 此时能否用 Touch ID 解锁；不能时返回原因。
    ///
    /// # Errors
    /// SQLite 错误。
    pub fn password_reason(&self) -> Result<Option<PasswordReasonKind>, KeevoError> {
        Ok(self.vault().password_reason()?.map(reason_kind))
    }

    /// 必须重新输入主密码的间隔天数（默认 14）。
    ///
    /// # Errors
    /// SQLite 错误。
    pub fn password_interval_days(&self) -> Result<u8, KeevoError> {
        Ok(self.vault().password_interval_days()?)
    }

    /// 设定必须重新输入主密码的间隔天数（1–30）。
    ///
    /// # Errors
    /// 超出范围返回 [`KeevoError::InvalidInput`]。
    pub fn set_password_interval_days(&self, days: u8) -> Result<(), KeevoError> {
        Ok(self.vault().set_password_interval_days(days)?)
    }

    /// 本机是否有可用的账户密钥；没有时解锁界面要询问账户密钥。
    pub fn has_local_secret_key(&self) -> bool {
        self.vault().has_local_secret_key()
    }

    /// 锁定：清除内存中的全部密钥，并清零这个保险库发出的全部秘密值句柄。
    pub fn lock(&self) {
        self.vault().lock();
        self.secrets.wipe();
        *self.index() = None;
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
        let items = {
            let vault = self.vault();
            let items = vault.items()?;
            let names = vault
                .vaults()?
                .into_iter()
                .map(|v| (v.id, v.name))
                .collect();
            // 顺便建立搜索索引：之后每次按键只做比较（docs/product.md §6.1"搜索每次按键 < 16 ms"）
            *self.index() = Some(SearchIndex::new(&items, &names));
            items
        };
        Ok(items
            .into_iter()
            .map(|i| ItemEntry {
                id: i.id.to_hex(),
                vault_id: i.vault_id.to_hex(),
                item_type: item_type_name(i.overview.item_type).to_owned(),
                title: i.overview.title,
                subtitle: i.overview.subtitle,
                urls: i.overview.urls,
                favorite: i.overview.favorite,
                tags: i.overview.tags,
                trashed: i.overview.trashed_at.is_some(),
                updated_ms: i.overview.updated.millis(),
                has_conflicts: i.has_conflicts,
            })
            .collect())
    }

    /// 搜索条目（含回收站中的条目），返回按相关度排序的条目 ID。语法见 `keevo-core::search`：
    /// 普通词、`"短语"`、`type:`、`tag:`、`vault:`、`url:`、`is:fav`、`is:conflict`，前加 `-` 表示排除。
    ///
    /// 使用最近一次 [`KeevoVault::items`] 建立的索引；还没有索引时先建立。
    ///
    /// # Errors
    /// 已锁定时返回 [`KeevoError::Locked`]。
    pub fn search(&self, query: String) -> Result<Vec<String>, KeevoError> {
        if !self.vault().is_unlocked() {
            return Err(KeevoError::Locked);
        }
        if self.index().is_none() {
            self.items()?;
        }
        let query = Query::parse(&query);
        Ok(self
            .index()
            .as_ref()
            .map(|ix| ix.search(&query).iter().map(|h| h.id.to_hex()).collect())
            .unwrap_or_default())
    }

    /// 按类型模板新建条目（默认分区与字段为空值），返回条目 ID。之后由编辑器填写。
    /// `preset` 只对 `api_credential` 有意义：`api_key`（默认）或 `access_token`。
    ///
    /// # Errors
    /// 类型或预设不认识时返回 [`KeevoError::InvalidInput`]。
    pub fn create_item(
        &self,
        vault_id: String,
        item_type: String,
        preset: Option<String>,
        title: String,
    ) -> Result<String, KeevoError> {
        use keevo_core::templates::{Preset, template};
        let item_type = item_type_from(&item_type).ok_or_else(|| invalid("item type"))?;
        let preset = match preset.as_deref() {
            None | Some("api_key") => Preset::Default,
            Some("access_token") => Preset::AccessToken,
            Some(_) => return Err(invalid("preset")),
        };
        let id = self.vault().create_item_from_template(
            parse_id(&vault_id)?,
            &title,
            template(item_type, preset),
        )?;
        Ok(id.to_hex())
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
        Ok(doc_fields(&view.doc, &self.secrets))
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

    /// 条目详情：合并全部头修订之后的视图，含冲突与需要提示的状态。
    ///
    /// # Errors
    /// 已锁定或条目不存在（含已永久删除）时返回对应错误。
    pub fn item(&self, item_id: String) -> Result<ItemDetail, KeevoError> {
        let id = parse_id(&item_id)?;
        let (view, revisions) = {
            let vault = self.vault();
            (vault.item(id)?, vault.revision_count(id)?)
        };
        let overview = view.doc.overview();
        let conflicts = view
            .conflicts
            .iter()
            .map(|c| conflict_entry(&view.doc, &c.key, &self.secrets))
            .collect();
        Ok(ItemDetail {
            id: view.id.to_hex(),
            vault_id: view.vault_id.to_hex(),
            item_type: item_type_name(view.doc.item_type).to_owned(),
            title: overview.title,
            favorite: overview.favorite,
            tags: overview.tags,
            trashed: overview.trashed_at.is_some(),
            sections: doc_sections(&view.doc),
            fields: doc_fields(&view.doc, &self.secrets),
            conflicts,
            resurrected: view.resurrected,
            integrity_issues: u32::try_from(view.integrity_issues.len()).unwrap_or(u32::MAX),
            head_count: u32::try_from(view.head_count).unwrap_or(u32::MAX),
            updated_ms: overview.updated.millis(),
            revision_count: u32::try_from(revisions).unwrap_or(u32::MAX),
        })
    }

    /// 在一次写入中应用多个编辑（写时收敛，`spec/revisions.md` §5.4）。
    ///
    /// # Errors
    /// 输入不合法返回 [`KeevoError::InvalidInput`]；条目过大返回 [`KeevoError::ItemTooLarge`]；
    /// 超出上限返回 [`KeevoError::ItemNeedsRebuild`]。
    pub fn update_item(&self, item_id: String, edits: Vec<ItemEdit>) -> Result<(), KeevoError> {
        let edits = edits
            .into_iter()
            .map(core_edit)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(self.vault().update_item(parse_id(&item_id)?, edits)?)
    }

    /// 从回收站恢复。
    ///
    /// # Errors
    /// 已锁定或条目不存在时返回对应错误。
    pub fn restore_item(&self, item_id: String) -> Result<(), KeevoError> {
        Ok(self.vault().restore_item(parse_id(&item_id)?)?)
    }

    /// 永久删除。不可撤销；条目的内容随后进入正常的历史清理。
    ///
    /// # Errors
    /// 已锁定或条目不存在时返回对应错误。
    pub fn purge_item(&self, item_id: String) -> Result<(), KeevoError> {
        Ok(self.vault().purge_item(parse_id(&item_id)?)?)
    }

    /// 一次性密码字段此刻的验证码。界面按 `remaining_ms` 在到期时重新获取。
    ///
    /// # Errors
    /// 字段不存在返回 [`KeevoError::NotFound`]；不是一次性密码字段或配置不合法返回 [`KeevoError::InvalidOtp`]。
    pub fn otp_code(&self, item_id: String, field_id: String) -> Result<OtpCodeEntry, KeevoError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        let code = self
            .vault()
            .otp_code(parse_id(&item_id)?, parse_id(&field_id)?, now)?;
        Ok(OtpCodeEntry {
            code: self.secrets.issue(code.code),
            period: code.period,
            remaining_ms: code.remaining_ms,
        })
    }

    /// 条目的历史，从新到旧。
    ///
    /// # Errors
    /// 已锁定或数据被篡改时返回对应错误。
    pub fn history(&self, item_id: String) -> Result<Vec<HistoryItem>, KeevoError> {
        Ok(self
            .vault()
            .history(parse_id(&item_id)?)?
            .into_iter()
            .map(|h| HistoryItem {
                rev_id: h.rev_id.to_hex(),
                title: h.overview.as_ref().map(|o| o.title.clone()),
                updated_ms: h.overview.as_ref().map(|o| o.updated.millis()),
                deleted: h.deleted,
                pruned: h.pruned,
                merge: h.parents.len() > 1,
            })
            .collect())
    }

    /// 某个历史修订的字段，按排序键排列。
    ///
    /// # Errors
    /// 修订不存在、是墓碑或已清理时返回 [`KeevoError::NotFound`]。
    pub fn revision_fields(
        &self,
        item_id: String,
        rev_id: String,
    ) -> Result<Vec<FieldEntry>, KeevoError> {
        let doc = self
            .vault()
            .revision_doc(parse_id(&item_id)?, parse_id(&rev_id)?)?;
        Ok(doc_fields(&doc, &self.secrets))
    }

    /// 恢复到此版本：把历史修订的值作为一次新的编辑写入。
    ///
    /// # Errors
    /// 修订不存在、是墓碑或已清理时返回 [`KeevoError::NotFound`]。
    pub fn restore_version(&self, item_id: String, rev_id: String) -> Result<(), KeevoError> {
        Ok(self
            .vault()
            .restore_version(parse_id(&item_id)?, parse_id(&rev_id)?)?)
    }

    /// 处理冲突：保留写于 `rev_id` 的版本。
    ///
    /// # Errors
    /// 记录键或版本不存在时返回对应错误。
    pub fn resolve_conflict(
        &self,
        item_id: String,
        key: String,
        rev_id: String,
    ) -> Result<(), KeevoError> {
        let key = parse_key(&key)?;
        Ok(self
            .vault()
            .resolve_conflict(parse_id(&item_id)?, &key, parse_id(&rev_id)?)?)
    }

    /// 精简（`spec/revisions.md` §7.1）：在一次写入中处理冲突并删除字段，用于 [`KeevoError::ItemTooLarge`]。
    ///
    /// # Errors
    /// 精简后仍然过大时返回 [`KeevoError::ItemTooLarge`]。
    pub fn compact_item(
        &self,
        item_id: String,
        keep: Vec<KeepVersion>,
        remove: Vec<String>,
    ) -> Result<(), KeevoError> {
        let keep = keep
            .iter()
            .map(|k| Ok((parse_key(&k.key)?, parse_id(&k.rev_id)?)))
            .collect::<Result<Vec<_>, KeevoError>>()?;
        let remove = remove
            .iter()
            .map(|k| parse_key(k))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(self
            .vault()
            .compact_item(parse_id(&item_id)?, &keep, &remove)?)
    }

    /// 重建（`spec/revisions.md` §7.1）：用于 [`KeevoError::ItemNeedsRebuild`]，返回新条目的 ID。
    ///
    /// # Errors
    /// 复制后仍超出上限时返回错误，需要在 `drop` 中选出更多不保留的键。
    pub fn rebuild_item(&self, item_id: String, drop: Vec<String>) -> Result<String, KeevoError> {
        let drop = drop
            .iter()
            .map(|k| parse_key(k))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(self
            .vault()
            .rebuild_item(parse_id(&item_id)?, &drop)?
            .to_hex())
    }

    /// 账户的 KDF 参数。[`KeevoError::KdfNeedsConfirmation`] 时把它们展示给用户确认。
    ///
    /// # Errors
    /// 没有账户或参数格式错误时返回对应错误。
    pub fn kdf_params(&self) -> Result<KdfInfo, KeevoError> {
        Ok(kdf_info(&self.vault().kdf_params()?))
    }

    /// 用户确认了 `confirmed` 这组 KDF 参数后解锁；`secret_key` 为 `None` 时取自本机包裹。参数已不是这一组时返回
    /// [`KeevoError::KdfNeedsConfirmation`]，不执行派生（`spec/crypto.md` §5.3）。
    ///
    /// # Errors
    /// 同 [`KeevoVault::unlock`]。
    pub fn unlock_confirming_kdf(
        &self,
        password: String,
        secret_key: Option<String>,
        confirmed: KdfInfo,
    ) -> Result<(), KeevoError> {
        let sk = secret_key
            .map(|s| {
                AccountSecretKey::parse(&s).map_err(|e| KeevoError::InvalidSecretKey {
                    code: e.code().to_owned(),
                })
            })
            .transpose()?;
        let mut vault = self.vault();
        let params = vault.kdf_params()?;
        if kdf_info(&params) != confirmed {
            return Err(KeevoError::KdfNeedsConfirmation);
        }
        match sk {
            Some(sk) => vault.unlock_confirmed_expensive_kdf(&password, &sk, &params)?,
            None => vault.unlock_with_password_confirmed(&password, &params)?,
        }
        drop(vault);
        self.after_unlock();
        Ok(())
    }

    /// 启动浏览器扩展的本地服务（`spec/ipc.md`）：监听 socket，按固定的 cdhash 校验 native host（§3.1）。
    /// 服务与应用共用同一个保险库；锁定时只回答 `status`。已启动时直接返回。
    ///
    /// # Errors
    /// 构建时没有编译进 native host 的 cdhash（release 构建）、Secure Enclave 暂时不可用、socket 无法创建时
    /// 返回 [`KeevoError::BrowserServiceUnavailable`] 等。
    pub fn start_browser_service(
        &self,
        prompt: Arc<dyn BrowserPrompt>,
    ) -> Result<BrowserServiceInfo, KeevoError> {
        let path =
            keevo_ipc::paths::socket_path().map_err(|e| KeevoError::BrowserServiceUnavailable {
                reason: e.to_string(),
            })?;
        self.start_service_at(prompt, &path)
    }

    /// 重新验证用户（`docs/ux.md` §5）：解除浏览器配对等敏感操作之前调用。`password` 为 `None` 时用 Touch ID，
    /// 会弹出提示，请在后台线程调用。
    ///
    /// # Errors
    /// 主密码错误、用户取消、Touch ID 未能识别等，返回对应错误。
    pub fn reverify(&self, password: Option<String>) -> Result<(), KeevoError> {
        let proof = password.as_deref().map_or(
            keevo_core::Reverify::TouchId,
            keevo_core::Reverify::Password,
        );
        Ok(self.vault().reverify(proof)?)
    }

    /// 已配对的浏览器扩展（"设置 → 浏览器"）。服务未启动或首次解锁前为空。
    pub fn browser_pairings(&self) -> Vec<BrowserPairing> {
        self.with_service(|svc| {
            svc.pairings()
                .into_iter()
                .map(|r| BrowserPairing {
                    id: hex(&r.extension_public),
                    name: r.name,
                    browser: r.browser,
                    paused: svc.is_paused(&r.extension_public),
                    extension_origin: r.extension_origin,
                    paired_at_ms: r.paired_at_ms,
                })
                .collect()
        })
        .unwrap_or_default()
    }

    /// 解除配对：删除记录并立即断开该扩展的会话（`spec/ipc.md` §4.4）。返回 `false` 表示写入数据库失败：
    /// 撤销已在内存中生效，但必须提示用户"撤销可能在重启后失效"。
    ///
    /// # Errors
    /// 服务未启动或 ID 不合法时返回错误。
    pub fn revoke_browser_pairing(&self, id: String) -> Result<bool, KeevoError> {
        let pk = pairing_key(&id)?;
        self.with_service(|svc| svc.revoke(&pk).is_ok())
            .ok_or_else(service_not_started)
    }

    /// 某个配对的站点授权（"设置 → 浏览器"，`spec/ipc.md` §5.2 第 2 条），附条目标题。
    ///
    /// # Errors
    /// 服务未启动、ID 不合法或已锁定时返回错误。
    pub fn browser_authorizations(
        &self,
        pairing_id: String,
    ) -> Result<Vec<BrowserAuthorization>, KeevoError> {
        let pk = pairing_key(&pairing_id)?;
        let list = self
            .with_service(|svc| svc.authorizations(&pk))
            .ok_or_else(service_not_started)?;
        let titles: std::collections::HashMap<String, String> = self
            .vault()
            .items()?
            .into_iter()
            .map(|i| (i.id.to_hex(), i.overview.title))
            .collect();
        Ok(list
            .into_iter()
            .map(|a| BrowserAuthorization {
                title: titles.get(&a.item_id).cloned(),
                item_id: a.item_id,
                site: a.site,
                granted_at_ms: a.granted_at_ms,
            })
            .collect())
    }

    /// 撤销一项站点授权。返回 `false` 表示写入数据库失败：内存中已撤销，但重启后可能恢复。
    ///
    /// # Errors
    /// 服务未启动或 ID 不合法时返回错误。
    pub fn revoke_browser_authorization(
        &self,
        pairing_id: String,
        item_id: String,
        site: String,
    ) -> Result<bool, KeevoError> {
        let pk = pairing_key(&pairing_id)?;
        self.with_service(|svc| svc.revoke_authorization(&pk, &item_id, &site).is_ok())
            .ok_or_else(service_not_started)
    }

    /// 恢复因频率限制被暂停的配对（`spec/ipc.md` §5.2 第 3 条）。
    ///
    /// # Errors
    /// 服务未启动或 ID 不合法时返回错误。
    pub fn resume_browser_pairing(&self, pairing_id: String) -> Result<(), KeevoError> {
        let pk = pairing_key(&pairing_id)?;
        self.with_service(|svc| svc.resume(&pk))
            .ok_or_else(service_not_started)
    }
}

fn pairing_key(id: &str) -> Result<[u8; 32], KeevoError> {
    unhex(id)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| invalid("pairing id"))
}

fn service_not_started() -> KeevoError {
    KeevoError::BrowserServiceUnavailable {
        reason: "not started".into(),
    }
}

impl KeevoVault {
    fn start_service_at(
        &self,
        prompt: Arc<dyn BrowserPrompt>,
        path: &Path,
    ) -> Result<BrowserServiceInfo, KeevoError> {
        let mut slot = self
            .service
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.is_some() {
            return Ok(BrowserServiceInfo {
                new_identity: false,
            });
        }
        let unavailable = |e: std::io::Error| KeevoError::BrowserServiceUnavailable {
            reason: e.to_string(),
        };
        let policy = peer_policy()?;
        let (key, new_identity) = self.vault().service_static_key()?;
        let svc = keevo_service::VaultService::new(
            Arc::clone(&self.inner),
            key,
            Arc::new(PromptAdapter(prompt)),
            policy,
        )
        .map_err(unavailable)?;
        let listener = keevo_service::bind(path).map_err(unavailable)?;
        if self.vault().is_unlocked() {
            let _ = svc.load_pairings();
        }
        let serving = svc.clone();
        std::thread::Builder::new()
            .name("keevo-browser-service".into())
            .spawn(move || serving.serve(&listener))
            .map_err(unavailable)?;
        *slot = Some(svc);
        Ok(BrowserServiceInfo { new_identity })
    }

    fn with_service<T>(&self, f: impl FnOnce(&keevo_service::VaultService) -> T) -> Option<T> {
        let slot = self
            .service
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        slot.as_ref().map(f)
    }

    /// 解锁之后：服务读入配对记录（先应用待提交的撤销，`spec/ipc.md` §4.2）。
    fn after_unlock(&self) {
        self.with_service(|svc| {
            let _ = svc.load_pairings();
        });
    }
}

/// Chrome native messaging host 的名称，与扩展 `background.ts` 中的 `NATIVE_HOST` 一致。
pub const BROWSER_HOST_NAME: &str = "io.github.xiaoowen.keevo";

/// native messaging host 的名称（写入浏览器的 host 清单）。
#[uniffi::export]
pub fn browser_host_name() -> String {
    BROWSER_HOST_NAME.to_owned()
}

/// Keevo 扩展的 ID：构建时由扩展清单中的公钥计算（`scripts/build-macos.sh`），写入 host 清单的
/// `allowed_origins`（`spec/ipc.md` §3.2）。没有编译进来时为 `None`。
#[uniffi::export]
pub fn browser_extension_id() -> Option<String> {
    option_env!("KEEVO_EXTENSION_ID").map(str::to_owned)
}

/// 构建时编译进主程序的 native host cdhash（`spec/ipc.md` §3.1）：逗号分隔的十六进制，由
/// `scripts/package-macos.sh` 在签名 host 之后设置。运行时不从磁盘读取。
const HOST_CDHASHES: Option<&str> = option_env!("KEEVO_HOST_CDHASHES");

fn peer_policy() -> Result<keevo_service::PeerPolicy, KeevoError> {
    let hashes: Vec<&str> = HOST_CDHASHES
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .collect();
    if hashes.is_empty() {
        if cfg!(debug_assertions) {
            return Ok(keevo_service::PeerPolicy::DevSameUserOnly);
        }
        return Err(KeevoError::BrowserServiceUnavailable {
            reason: "native host cdhash was not compiled in; build with scripts/package-macos.sh"
                .into(),
        });
    }
    if hashes
        .iter()
        .any(|h| h.len() != 40 || !h.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(KeevoError::BrowserServiceUnavailable {
            reason: "malformed compiled-in cdhash".into(),
        });
    }
    let requirement = hashes
        .iter()
        .map(|h| format!("cdhash H\"{h}\""))
        .collect::<Vec<_>>()
        .join(" or ");
    Ok(keevo_service::PeerPolicy::CodeRequirement(requirement))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

/// 由 Swift 实现的原生确认界面（`spec/ipc.md` §4.2、§5.2：只出现在 Keevo.app 中，扩展与网页无法伪造）。
/// 这些方法在服务的工作线程中调用，可以阻塞，直到用户回答或超时。
#[uniffi::export(with_foreign)]
pub trait BrowserPrompt: Send + Sync {
    /// 收到配对请求的第 1 条消息：立即告诉用户"有浏览器正在请求配对"，每次尝试都可见。
    fn pairing_started(&self, browser: String);
    /// 请用户确认两边的短认证串（6 个词，`spec/sas-wordlist-v1.tsv`）一致。必须在 `timeout_ms` 毫秒内返回，
    /// 超时按拒绝处理。
    fn confirm_pairing(
        &self,
        words: Vec<SasWord>,
        name: String,
        browser: String,
        timeout_ms: u64,
    ) -> bool;
    /// 某个配对第一次为某个条目在某个站点取用凭据（`spec/ipc.md` §5.2）：显示站点、条目与配对，请用户确认。
    /// 必须在 `timeout_ms` 毫秒内返回，超时按拒绝处理。
    fn authorize_fill(&self, request: BrowserFillRequest, timeout_ms: u64) -> bool;
    /// 这个配对因频率限制被暂停（§5.2 第 3 条）：提示用户，用户确认后调用
    /// [`KeevoVault::resume_browser_pairing`]。
    fn fill_paused(&self, pairing_id: String, name: String, browser: String);
    /// 协议 v2：扩展请求更新已有登录的密码（§5.5）。显示站点、条目与配对，请用户确认；`changed` 为 `false`
    /// 表示新密码与保存的相同（只告诉用户）。必须在 `timeout_ms` 毫秒内返回，超时按拒绝处理。
    fn confirm_update(&self, request: BrowserUpdateRequest, changed: bool, timeout_ms: u64)
    -> bool;
    /// 协议 v2：扩展保存了新的登录（§5.5）。提示用户，不需要确认。
    fn login_saved(&self, pairing_name: String, browser: String, title: String);
    /// 这个配对短时间内查询了太多不同的网站（§5.2）：提示用户，可能有人在冒用它枚举账户。
    fn queries_limited(&self, pairing_id: String, name: String, browser: String);
}

/// 一次等待确认的密码更新（`spec/ipc.md` §5.5）。不含密码本身。
#[derive(uniffi::Record)]
pub struct BrowserUpdateRequest {
    /// 发起请求的配对。
    pub pairing_id: String,
    /// 配对的显示名。
    pub pairing_name: String,
    /// 浏览器标识。
    pub browser: String,
    /// 条目 ID。
    pub item_id: String,
    /// 条目标题。
    pub title: String,
    /// 条目的用户名。
    pub username: String,
    /// 规范化后的站点。
    pub site: String,
}

/// 短认证串的一个词：同一个字节的中文词与英文词互为翻译，两端都同时显示（`spec/ipc.md` §4.2）。
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct SasWord {
    /// 中文词。
    pub zh: String,
    /// 英文词。
    pub en: String,
}

/// 一次等待授权的 `fill`（`spec/ipc.md` §5.2）。
#[derive(uniffi::Record)]
pub struct BrowserFillRequest {
    /// 发起请求的配对。
    pub pairing_id: String,
    /// 配对的显示名。
    pub pairing_name: String,
    /// 浏览器标识。
    pub browser: String,
    /// 条目 ID。
    pub item_id: String,
    /// 条目标题。
    pub title: String,
    /// 用户名（条目副标题）。
    pub username: String,
    /// 规范化后的站点 `scheme://host[:port]`。
    pub site: String,
}

/// 一项站点授权：某个配对可以为某个条目在某个站点取用凭据。
#[derive(uniffi::Record)]
pub struct BrowserAuthorization {
    /// 条目 ID。
    pub item_id: String,
    /// 条目标题；条目已不存在时为 `None`。
    pub title: Option<String>,
    /// 规范化后的站点。
    pub site: String,
    /// 授权时间（Unix 毫秒）。
    pub granted_at_ms: u64,
}

struct PromptAdapter(Arc<dyn BrowserPrompt>);

impl keevo_service::PairingPrompt for PromptAdapter {
    fn started(&self, browser: &str) {
        self.0.pairing_started(browser.to_owned());
    }

    fn confirm(
        &self,
        sas: [u8; 6],
        name: &str,
        browser: &str,
        deadline: std::time::Instant,
    ) -> bool {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return false;
        }
        let ms = u64::try_from(left.as_millis()).unwrap_or(u64::MAX);
        let words = keevo_ipc::sas::sas_words(&sas)
            .iter()
            .map(|w| SasWord {
                zh: w.zh.to_owned(),
                en: w.en.to_owned(),
            })
            .collect();
        self.0
            .confirm_pairing(words, name.to_owned(), browser.to_owned(), ms)
            && std::time::Instant::now() <= deadline
    }

    fn authorize_fill(
        &self,
        r: &keevo_ipc::service::FillRequest,
        deadline: std::time::Instant,
    ) -> bool {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return false;
        }
        let ms = u64::try_from(left.as_millis()).unwrap_or(u64::MAX);
        let request = BrowserFillRequest {
            pairing_id: hex(&r.extension_public),
            pairing_name: r.pairing_name.clone(),
            browser: r.browser.clone(),
            item_id: r.item_id.clone(),
            title: r.title.clone(),
            username: r.username.clone(),
            site: r.site.clone(),
        };
        self.0.authorize_fill(request, ms) && std::time::Instant::now() <= deadline
    }

    fn fill_paused(&self, extension_public: &[u8; 32], name: &str, browser: &str) {
        self.0
            .fill_paused(hex(extension_public), name.to_owned(), browser.to_owned());
    }

    fn confirm_update(
        &self,
        r: &keevo_ipc::service::WriteRequest,
        changed: bool,
        deadline: std::time::Instant,
    ) -> bool {
        let keevo_ipc::service::WriteOp::Update {
            item_id,
            title,
            username,
            ..
        } = &r.op
        else {
            return false;
        };
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return false;
        }
        let ms = u64::try_from(left.as_millis()).unwrap_or(u64::MAX);
        let request = BrowserUpdateRequest {
            pairing_id: hex(&r.extension_public),
            pairing_name: r.pairing_name.clone(),
            browser: r.browser.clone(),
            item_id: item_id.clone(),
            title: title.clone(),
            username: username.clone(),
            site: r.site.clone(),
        };
        self.0.confirm_update(request, changed, ms) && std::time::Instant::now() <= deadline
    }

    fn saved(&self, pairing_name: &str, browser: &str, title: &str) {
        self.0.login_saved(
            pairing_name.to_owned(),
            browser.to_owned(),
            title.to_owned(),
        );
    }

    fn queries_limited(&self, extension_public: &[u8; 32], name: &str, browser: &str) {
        self.0
            .queries_limited(hex(extension_public), name.to_owned(), browser.to_owned());
    }
}

/// 启动结果。
#[derive(uniffi::Record)]
pub struct BrowserServiceInfo {
    /// 这次启动生成了新的服务身份（第一次启动，或本机密钥包裹已失效）。已配对的扩展需要重新配对。
    pub new_identity: bool,
}

/// 一个已配对的浏览器扩展。
#[derive(uniffi::Record)]
pub struct BrowserPairing {
    /// ID（扩展静态公钥的十六进制），撤销时传回。
    pub id: String,
    /// 显示名（已清洗）。
    pub name: String,
    /// 浏览器标识，如 `com.google.Chrome`。
    pub browser: String,
    /// 扩展来源。
    pub extension_origin: String,
    /// 配对时间（Unix 毫秒）。
    pub paired_at_ms: u64,
    /// 因频率限制被暂停（`spec/ipc.md` §5.2 第 3 条）。
    pub paused: bool,
}

const fn kdf_info(p: &KdfParams) -> KdfInfo {
    KdfInfo {
        memory_kib: p.memory_kib(),
        iterations: p.iterations(),
        parallelism: p.parallelism(),
    }
}

fn parse_key(s: &str) -> Result<RecordKey, KeevoError> {
    s.parse().map_err(|_| invalid("record key"))
}

fn invalid(what: &str) -> KeevoError {
    KeevoError::InvalidInput {
        message: what.into(),
    }
}

fn new_field(
    kind: &str,
    label: String,
    purpose: Option<String>,
    value: &str,
) -> Result<NewField, KeevoError> {
    let kind = field_kind_from(kind).ok_or_else(|| invalid("field kind"))?;
    let purpose = purpose
        .map(|p| purpose_from(&p).ok_or_else(|| invalid("purpose")))
        .transpose()?;
    let data = match kind {
        FieldKind::KvList => FieldData::Kv(Vec::new()),
        FieldKind::RecoveryCodes => FieldData::Codes(Vec::new()),
        _ => FieldData::Text(value.into()),
    };
    Ok(NewField {
        kind,
        label,
        purpose,
        data,
    })
}

fn kv_entries(entries: Vec<KvInput>) -> Vec<KvEntry> {
    entries
        .into_iter()
        .map(|e| KvEntry {
            key: e.key,
            value: Zeroizing::new(e.value).as_str().into(),
            concealed: e.concealed,
        })
        .collect()
}

fn code_entries(codes: Vec<CodeInput>) -> Vec<CodeEntry> {
    codes
        .into_iter()
        .map(|c| CodeEntry {
            code: Zeroizing::new(c.code).as_str().into(),
            used: c.used,
        })
        .collect()
}

fn core_edit(edit: ItemEdit) -> Result<Edit, KeevoError> {
    Ok(match edit {
        ItemEdit::SetTitle { title } => Edit::SetTitle(title),
        ItemEdit::SetFavorite { favorite } => Edit::SetFavorite(favorite),
        ItemEdit::AddTag { tag } => Edit::AddTag(tag),
        ItemEdit::RemoveTag { tag } => Edit::RemoveTag(tag),
        ItemEdit::AddField {
            kind,
            label,
            purpose,
            value,
        } => Edit::AddField(new_field(&kind, label, purpose, &Zeroizing::new(value))?),
        ItemEdit::AddFieldToSection {
            section_id,
            kind,
            label,
            purpose,
            value,
            kv,
            codes,
        } => {
            let mut field = new_field(&kind, label, purpose, &Zeroizing::new(value))?;
            match &mut field.data {
                FieldData::Kv(entries) => *entries = kv_entries(kv),
                FieldData::Codes(list) => *list = code_entries(codes),
                FieldData::Text(_) => {}
            }
            Edit::AddFieldToSection {
                section: section_id.as_deref().map(parse_id).transpose()?,
                field,
            }
        }
        ItemEdit::SetFieldValue { field_id, value } => Edit::SetFieldData {
            field_id: parse_id(&field_id)?,
            data: FieldData::Text(Zeroizing::new(value).as_str().into()),
        },
        ItemEdit::SetFieldLabel { field_id, label } => Edit::SetFieldLabel {
            field_id: parse_id(&field_id)?,
            label,
        },
        ItemEdit::SetFieldPurpose { field_id, purpose } => Edit::SetFieldPurpose {
            field_id: parse_id(&field_id)?,
            purpose: purpose
                .map(|p| purpose_from(&p).ok_or_else(|| invalid("purpose")))
                .transpose()?,
        },
        ItemEdit::SetFieldKv { field_id, entries } => Edit::SetFieldData {
            field_id: parse_id(&field_id)?,
            data: FieldData::Kv(kv_entries(entries)),
        },
        ItemEdit::SetFieldCodes { field_id, codes } => Edit::SetFieldData {
            field_id: parse_id(&field_id)?,
            data: FieldData::Codes(code_entries(codes)),
        },
        ItemEdit::RemoveField { field_id } => Edit::RemoveField(parse_id(&field_id)?),
        ItemEdit::MoveField {
            field_id,
            section_id,
            before_field_id,
        } => Edit::MoveField {
            field_id: parse_id(&field_id)?,
            section: section_id.as_deref().map(parse_id).transpose()?,
            before: before_field_id.as_deref().map(parse_id).transpose()?,
        },
        ItemEdit::AddSection { section_id, label } => Edit::AddSection {
            section_id: parse_id(&section_id)?,
            label,
        },
        ItemEdit::RenameSection { section_id, label } => Edit::RenameSection {
            section_id: parse_id(&section_id)?,
            label,
        },
        ItemEdit::RemoveSection { section_id } => Edit::RemoveSection(parse_id(&section_id)?),
    })
}

/// 文档中的字段，按排序键排列。
/// 分区，按（排序键，ID）排列。
fn ordered_sections(doc: &ItemDoc) -> Vec<(Id128, String)> {
    let mut out: Vec<(String, Id128, String)> = doc
        .records
        .iter()
        .filter_map(|(k, v)| match (k, &v.value) {
            (RecordKey::Section(id), Some(RecordValue::Section(s))) => {
                Some((s.order.clone(), *id, s.label.clone()))
            }
            _ => None,
        })
        .collect();
    out.sort();
    out.into_iter().map(|(_, id, label)| (id, label)).collect()
}

fn doc_sections(doc: &ItemDoc) -> Vec<SectionEntry> {
    ordered_sections(doc)
        .into_iter()
        .map(|(id, label)| SectionEntry {
            id: id.to_hex(),
            label,
        })
        .collect()
}

/// 文档中的字段：默认分区在前，然后按分区的顺序，分区内按（排序键，ID）排列。
fn doc_fields(doc: &ItemDoc, secrets: &SecretRegistry) -> Vec<FieldEntry> {
    let sections = ordered_sections(doc);
    let rank = |s: Option<Id128>| -> (usize, Option<Id128>) {
        match s.and_then(|s| sections.iter().position(|(id, _)| *id == s)) {
            Some(i) => (i.saturating_add(1), s),
            None => (0, None),
        }
    };
    let mut fields: Vec<((usize, String, Id128), FieldEntry)> = doc
        .records
        .iter()
        .filter_map(|(k, v)| match (k, &v.value) {
            (RecordKey::Field(id), Some(RecordValue::Field(f))) => {
                let (r, section) = rank(f.section);
                let (kv, codes) = match &f.data {
                    FieldData::Kv(entries) => (
                        entries
                            .iter()
                            .map(|e| KvItem {
                                key: e.key.clone(),
                                value: secrets.issue(Zeroizing::new(e.value.expose().to_owned())),
                                concealed: e.concealed,
                            })
                            .collect(),
                        Vec::new(),
                    ),
                    FieldData::Codes(list) => (
                        Vec::new(),
                        list.iter()
                            .map(|c| CodeItem {
                                code: secrets.issue(Zeroizing::new(c.code.expose().to_owned())),
                                used: c.used,
                            })
                            .collect(),
                    ),
                    FieldData::Text(_) => (Vec::new(), Vec::new()),
                };
                Some((
                    (r, f.order.clone(), *id),
                    FieldEntry {
                        id: id.to_hex(),
                        label: f.label.clone(),
                        kind: field_kind_name(f.kind).to_owned(),
                        concealed: f.kind.is_concealed(),
                        value: secrets.issue(field_text(&f.data)),
                        purpose: f.purpose.map(|p| purpose_name(p).to_owned()),
                        section_id: section.map(|s| s.to_hex()),
                        kv,
                        codes,
                    },
                ))
            }
            _ => None,
        })
        .collect();
    fields.sort_by(|a, b| a.0.cmp(&b.0));
    fields.into_iter().map(|(_, f)| f).collect()
}

/// 冲突的显示：记录键的名称，以及每个版本的值。
fn conflict_entry(doc: &ItemDoc, key: &RecordKey, secrets: &SecretRegistry) -> ConflictEntry {
    let versions = doc.versions(key);
    let named = || {
        versions.iter().find_map(|v| match &v.value {
            Some(RecordValue::Field(f)) => Some(f.label.clone()),
            Some(RecordValue::Section(s)) => Some(s.label.clone()),
            _ => None,
        })
    };
    let (kind, label) = match key {
        RecordKey::Attr(n) if n == "title" || n == "favorite" => (n.as_str(), None),
        RecordKey::Attr(_) => ("attr", None),
        RecordKey::Tag(t) => ("tag", Some(t.clone())),
        RecordKey::Section(_) => ("section", named()),
        RecordKey::Field(_) => ("field", named()),
    };
    let version = |v: &RecordVersion| ConflictVersion {
        rev_id: v.rev.to_hex(),
        value: v.value.as_ref().map(|v| secrets.issue(value_text(v))),
        concealed: matches!(&v.value, Some(RecordValue::Field(f)) if f.kind.is_concealed()),
    };
    let mut iter = versions.into_iter();
    let current = iter.next().map_or(
        ConflictVersion {
            rev_id: String::new(),
            value: None,
            concealed: false,
        },
        version,
    );
    ConflictEntry {
        key: key.to_string(),
        kind: kind.to_owned(),
        label,
        current,
        others: iter.map(version).collect(),
    }
}

fn value_text(v: &RecordValue) -> Zeroizing<String> {
    match v {
        RecordValue::Text(s) => Zeroizing::new(s.expose().to_owned()),
        RecordValue::Bool(b) => Zeroizing::new(b.to_string()),
        RecordValue::Int(i) => Zeroizing::new(i.to_string()),
        RecordValue::Tag => Zeroizing::new(String::new()),
        RecordValue::Section(s) => Zeroizing::new(s.label.clone()),
        RecordValue::Field(f) => field_text(&f.data),
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

/// 字段值的文本：结构化字段每项一行。直接写入清零缓冲区，不经过不清零的中间字符串。
fn field_text(data: &FieldData) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::new());
    match data {
        FieldData::Text(s) => out.push_str(s.expose()),
        FieldData::Kv(entries) => {
            for (i, e) in entries.iter().enumerate() {
                if i > 0 {
                    out.push('\n');
                }
                out.push_str(&e.key);
                out.push('=');
                out.push_str(e.value.expose());
            }
        }
        FieldData::Codes(codes) => {
            for (i, c) in codes.iter().enumerate() {
                if i > 0 {
                    out.push('\n');
                }
                out.push_str(c.code.expose());
                if c.used {
                    out.push_str("（已用）");
                }
            }
        }
    }
    out
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
    }
}

const ALL_FIELD_KINDS: [FieldKind; 14] = [
    FieldKind::Text,
    FieldKind::Multiline,
    FieldKind::Concealed,
    FieldKind::Email,
    FieldKind::Url,
    FieldKind::Phone,
    FieldKind::Date,
    FieldKind::MonthYear,
    FieldKind::Select,
    FieldKind::Totp,
    FieldKind::SshPrivateKey,
    FieldKind::Reference,
    FieldKind::RecoveryCodes,
    FieldKind::KvList,
];

fn field_kind_from(name: &str) -> Option<FieldKind> {
    ALL_FIELD_KINDS
        .into_iter()
        .find(|k| field_kind_name(*k) == name)
}

const fn purpose_name(p: Purpose) -> &'static str {
    match p {
        Purpose::Username => "username",
        Purpose::Password => "password",
        Purpose::Otp => "otp",
        Purpose::Notes => "notes",
    }
}

fn purpose_from(name: &str) -> Option<Purpose> {
    [
        Purpose::Username,
        Purpose::Password,
        Purpose::Otp,
        Purpose::Notes,
    ]
    .into_iter()
    .find(|p| purpose_name(*p) == name)
}

#[cfg(test)]
mod tests;

const ALL_ITEM_TYPES: [ItemType; 8] = [
    ItemType::Login,
    ItemType::EmailAccount,
    ItemType::SecureNote,
    ItemType::SshKey,
    ItemType::ApiCredential,
    ItemType::Database,
    ItemType::Environment,
    ItemType::TwoFactor,
];

fn item_type_from(name: &str) -> Option<ItemType> {
    ALL_ITEM_TYPES
        .into_iter()
        .find(|t| item_type_name(*t) == name)
}
