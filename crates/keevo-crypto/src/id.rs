use core::fmt;

use crate::error::Result;
use crate::random;

fn hex(bytes: &[u8]) -> String {
    use fmt::Write;
    bytes.iter().fold(
        String::with_capacity(bytes.len().saturating_mul(2)),
        |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        },
    )
}

/// 16 字节随机标识符（`spec/crypto.md` §2），用于账户、保险库、条目、修订等。不是秘密。
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Id128([u8; 16]);

impl Id128 {
    /// 全零 ID，表示 AAD 中"不适用"的字段。
    pub const ZERO: Self = Self([0u8; 16]);

    /// 生成随机 ID。
    ///
    /// # Errors
    /// 操作系统随机数生成器不可用时返回 [`crate::CryptoError::Random`]。
    pub fn random() -> Result<Self> {
        random::array().map(Self)
    }

    /// 由字节构造。
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// 字节表示。
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// 小写十六进制表示。
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex(&self.0)
    }
}

impl fmt::Debug for Id128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id128({})", self.to_hex())
    }
}

/// 密钥 ID（`kid`）。用于在解密前确认使用了正确的密钥。不是秘密。
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId([u8; 16]);

impl KeyId {
    pub(crate) fn random() -> Result<Self> {
        random::array().map(Self)
    }

    /// 由字节构造。
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// 字节表示。
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId({})", hex(&self.0))
    }
}
