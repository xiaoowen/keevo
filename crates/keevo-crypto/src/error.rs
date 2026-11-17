use core::fmt;

/// `keevo-crypto` 的结果类型。
pub type Result<T> = core::result::Result<T, CryptoError>;

/// 本 crate 的所有错误。错误中不携带任何密钥、口令或明文。
///
/// [`CryptoError::code`] 返回 `spec/crypto.md` 中定义的错误码，供测试向量与 FFI 使用。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    /// 数据格式不正确：长度、版本字节、填充等不符合规范。
    Malformed,
    /// 信封版本不受支持。
    UnsupportedVersion,
    /// 算法标识不受支持。
    UnsupportedAlgorithm,
    /// 信封头部的密钥 ID 与提供的密钥不一致。上层应与 [`CryptoError::DecryptionFailed`] 同等对待。
    KeyIdMismatch,
    /// 认证失败：密钥错误，或数据、上下文被篡改。
    DecryptionFailed,
    /// 明文超过单个信封的上限。
    TooLarge,
    /// 加解密时提供的上下文与操作不匹配（例如用非 `WrappedKey` 的上下文包裹密钥）。
    InvalidContext,
    /// KDF 参数低于客户端硬编码的下限。
    KdfBelowMinimum,
    /// KDF 参数高于客户端硬编码的上限。
    KdfAboveMaximum,
    /// 主密码为空。
    EmptyPassword,
    /// 主密码规范化后超过长度上限。
    PasswordTooLong,
    /// 账户密钥解析失败。
    SecretKey(SecretKeyError),
    /// 操作系统随机数生成器不可用。
    Random,
    /// KDF 内部错误。参数校验通过后不应出现。
    Kdf,
}

/// 账户密钥（Secret Key）的解析错误，对应 `spec/crypto.md` §4.3。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecretKeyError {
    /// 前缀不是 `K1`。
    WrongPrefix,
    /// 去掉分隔符后的长度既不是 30 也不是 28。
    WrongLength,
    /// 含有 Crockford Base32 字母表之外的字符。
    InvalidCharacter,
    /// 首字符的值大于 7，不是规范编码。
    NonCanonical,
    /// 校验位不一致，通常是输入有误。
    ChecksumMismatch,
}

impl CryptoError {
    /// `spec/crypto.md` 中定义的错误码。
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::UnsupportedVersion => "unsupported_version",
            Self::UnsupportedAlgorithm => "unsupported_algorithm",
            Self::KeyIdMismatch => "key_id_mismatch",
            Self::DecryptionFailed => "decryption_failed",
            Self::TooLarge => "too_large",
            Self::InvalidContext => "invalid_context",
            Self::KdfBelowMinimum => "below_minimum",
            Self::KdfAboveMaximum => "above_maximum",
            Self::EmptyPassword => "empty_password",
            Self::PasswordTooLong => "password_too_long",
            Self::SecretKey(e) => e.code(),
            Self::Random => "random_unavailable",
            Self::Kdf => "kdf_internal",
        }
    }
}

impl SecretKeyError {
    /// `spec/crypto.md` §4.3 中定义的错误码。
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::WrongPrefix => "wrong_prefix",
            Self::WrongLength => "wrong_length",
            Self::InvalidCharacter => "invalid_character",
            Self::NonCanonical => "non_canonical",
            Self::ChecksumMismatch => "checksum_mismatch",
        }
    }
}

impl From<SecretKeyError> for CryptoError {
    fn from(e: SecretKeyError) -> Self {
        Self::SecretKey(e)
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl fmt::Display for SecretKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for CryptoError {}
impl std::error::Error for SecretKeyError {}
