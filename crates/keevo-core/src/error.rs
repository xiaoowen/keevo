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
    /// 数据库中还没有账户。
    NoAccount,
    /// 数据库中已经有账户。
    AccountExists,
    /// 对象不存在或已被删除。
    NotFound,
    /// 数据被篡改或损坏：认证失败，或内容与上下文不符。
    Tampered,
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
            Self::NoAccount => f.write_str("no account"),
            Self::AccountExists => f.write_str("account already exists"),
            Self::NotFound => f.write_str("not found"),
            Self::Tampered => f.write_str("data was tampered with or corrupted"),
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
        Self::Format(e)
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
