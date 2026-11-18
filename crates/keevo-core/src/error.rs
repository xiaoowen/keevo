use core::fmt;

use keevo_crypto::CryptoError;
use keevo_format::FormatError;
use keevo_store::StoreError;

/// `keevo-core` 的结果类型。
pub type Result<T> = core::result::Result<T, CoreError>;

/// 核心错误。不携带任何秘密数据。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoreError {
    /// 保险库已锁定。
    Locked,
    /// 主密码或账户密钥错误。为避免泄露信息，两者不作区分。
    WrongCredentials,
    /// KDF 参数超出本机自动执行预算（`spec/crypto.md` §5.3）。参数可能被篡改，用于耗尽资源；
    /// 需要用户确认 [`crate::Vault::kdf_params`] 后，改用 [`crate::Vault::unlock_confirmed_expensive_kdf`]。
    KdfNeedsConfirmation,
    /// 条目合并后超过单个信封的上限，无法保存（`spec/revisions.md` §7.1）。读取与导出不受影响；
    /// 需要先用 [`crate::Vault::compact_item`] 精简。
    ItemTooLarge,
    /// 条目超出了精简也无法回到的上限（头超过 4096 个，或记录键超过 4096 个，`spec/revisions.md` §7.1）。
    /// 条目只读；可以导出，或用 [`crate::Vault::rebuild_item`] 重建为新条目。
    ItemNeedsRebuild,
    /// 数据库中还没有账户。
    NoAccount,
    /// 数据库中已经有账户。
    AccountExists,
    /// 对象不存在或已被删除。
    NotFound,
    /// 数据被篡改或损坏：认证失败，或内容与上下文不符。
    Tampered,
    /// 用户取消了 Touch ID，或认证超时。什么都没有改变（`spec/crypto.md` §8.7）。
    Cancelled,
    /// Secure Enclave 暂时不可用（如屏幕锁定）。什么都没有改变，稍后重试。
    EnclaveUnavailable,
    /// 本机没有可用的账户密钥，需要用户从应急包输入。
    SecretKeyRequired,
    /// Touch ID 未启用、已失效，或此时必须输入主密码（[`crate::Vault::password_reason`]）。
    TouchIdUnavailable,
    /// Touch ID 验证未通过（指纹不匹配）。连续 3 次后必须输入主密码。
    AuthenticationFailed,
    /// 设置值超出允许的范围。
    OutOfRange,
    /// 要新建的对象已经存在（例如分区 ID 重复）。
    AlreadyExists,
    /// 一次性密码的配置不合法（不是 `otpauth://totp/` URI 或 Base32 密钥，或参数超出范围）。
    InvalidOtp,
    /// 本机密钥文件读写失败。
    Io(std::io::ErrorKind),
    /// 密码学错误。
    Crypto(CryptoError),
    /// 数据格式错误。
    Format(FormatError),
    /// 存储错误。
    Store(StoreError),
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Locked => f.write_str("vault is locked"),
            Self::WrongCredentials => f.write_str("wrong master password or secret key"),
            Self::KdfNeedsConfirmation => f.write_str("kdf parameters exceed the automatic budget"),
            Self::ItemTooLarge => f.write_str("item is too large to save"),
            Self::ItemNeedsRebuild => f.write_str("item must be rebuilt"),
            Self::NoAccount => f.write_str("no account"),
            Self::AccountExists => f.write_str("account already exists"),
            Self::NotFound => f.write_str("not found"),
            Self::Tampered => f.write_str("data was tampered with or corrupted"),
            Self::Cancelled => f.write_str("cancelled by the user"),
            Self::EnclaveUnavailable => f.write_str("secure enclave is temporarily unavailable"),
            Self::SecretKeyRequired => f.write_str("secret key is required"),
            Self::TouchIdUnavailable => f.write_str("touch id is not available"),
            Self::AuthenticationFailed => f.write_str("touch id authentication failed"),
            Self::OutOfRange => f.write_str("value out of range"),
            Self::InvalidOtp => f.write_str("invalid one-time password configuration"),
            Self::AlreadyExists => f.write_str("already exists"),
            Self::Io(kind) => write!(f, "io: {kind}"),
            Self::Crypto(e) => write!(f, "crypto: {e}"),
            Self::Format(e) => write!(f, "format: {e}"),
            Self::Store(e) => write!(f, "store: {e}"),
        }
    }
}

impl std::error::Error for CoreError {}

impl From<CryptoError> for CoreError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::DecryptionFailed | CryptoError::KeyIdMismatch => Self::Tampered,
            other => Self::Crypto(other),
        }
    }
}

impl From<FormatError> for CoreError {
    fn from(e: FormatError) -> Self {
        match e {
            FormatError::ItemTooLarge => Self::ItemTooLarge,
            other => Self::Format(other),
        }
    }
}

impl From<StoreError> for CoreError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::AccountExists => Self::AccountExists,
            other => Self::Store(other),
        }
    }
}
