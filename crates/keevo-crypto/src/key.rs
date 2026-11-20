use zeroize::Zeroizing;

use crate::envelope::{self, AadContext, Part};
use crate::error::{CryptoError, Result};
use crate::id::KeyId;
use crate::random;

/// 被包裹密钥的明文长度：`child_kid (16) ‖ child_key (32)`（`spec/crypto.md` §9.2）。
const WRAPPED_KEY_PLAINTEXT_LEN: usize = 48;

/// 256 位对称密钥及其 ID。
///
/// - 释放时清零。
/// - 刻意不实现 `Debug`、`Display`、`Clone` 和序列化，避免密钥被打印、记录或意外复制。
/// - 密钥只能通过 [`SymmetricKey::generate`]、[`SymmetricKey::unwrap_key`]、
///   [`crate::derive_account_unlock_key`] 或 [`crate::AccountKeyset::open`] 获得，
///   不能从任意字节构造。
pub struct SymmetricKey {
    id: KeyId,
    bytes: Zeroizing<[u8; 32]>,
}

impl SymmetricKey {
    /// 生成随机密钥与随机 ID。
    ///
    /// # Errors
    /// 操作系统随机数生成器不可用时返回 [`CryptoError::Random`]。
    pub fn generate() -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        random::fill(bytes.as_mut())?;
        Ok(Self {
            id: KeyId::random()?,
            bytes,
        })
    }

    pub(crate) fn from_parts(id: KeyId, bytes: Zeroizing<[u8; 32]>) -> Self {
        Self { id, bytes }
    }

    /// 测试专用：由已知字节构造。
    #[cfg(test)]
    pub(crate) fn from_raw(id: [u8; 16], bytes: [u8; 32]) -> Self {
        Self {
            id: KeyId::from_bytes(id),
            bytes: Zeroizing::new(bytes),
        }
    }

    /// 测试专用（`test-util` 特性）：由已知字节构造，供其他 crate 的跨实现测试向量使用。正式构建中不存在。
    #[cfg(feature = "test-util")]
    #[must_use]
    pub fn from_raw_for_tests(id: [u8; 16], bytes: [u8; 32]) -> Self {
        Self {
            id: KeyId::from_bytes(id),
            bytes: Zeroizing::new(bytes),
        }
    }

    /// 密钥 ID。
    #[must_use]
    pub const fn id(&self) -> KeyId {
        self.id
    }

    pub(crate) fn expose(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// 用本密钥包裹 `child`，返回信封。
    ///
    /// # Errors
    /// `ctx.part` 不是 [`Part::WrappedKey`] 时返回 [`CryptoError::InvalidContext`]。
    pub fn wrap_key(&self, ctx: &AadContext, child: &Self) -> Result<Vec<u8>> {
        if ctx.part != Part::WrappedKey {
            return Err(CryptoError::InvalidContext);
        }
        let mut plaintext = Zeroizing::new([0u8; WRAPPED_KEY_PLAINTEXT_LEN]);
        let (kid, key) = plaintext.split_at_mut(16);
        kid.copy_from_slice(child.id.as_bytes());
        key.copy_from_slice(child.expose());
        envelope::seal(self, ctx, plaintext.as_ref())
    }

    /// 解开由 [`SymmetricKey::wrap_key`] 生成的信封。
    ///
    /// # Errors
    /// 上下文不是 [`Part::WrappedKey`] 时返回 [`CryptoError::InvalidContext`]；
    /// 认证失败、密钥不匹配或格式错误时返回对应错误。
    pub fn unwrap_key(&self, ctx: &AadContext, wrapped: &[u8]) -> Result<Self> {
        if ctx.part != Part::WrappedKey {
            return Err(CryptoError::InvalidContext);
        }
        let plaintext = envelope::open(self, ctx, wrapped)?;
        let (kid, key) = plaintext
            .split_first_chunk::<16>()
            .filter(|(_, key)| key.len() == 32)
            .ok_or(CryptoError::Malformed)?;
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(key);
        Ok(Self {
            id: KeyId::from_bytes(*kid),
            bytes,
        })
    }
}
