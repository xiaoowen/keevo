//! 加密信封 v1（`spec/crypto.md` §8）。

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::SecretBytes;
use crate::error::{CryptoError, Result};
use crate::id::{Id128, KeyId};
use crate::key::SymmetricKey;
use crate::padding;
use crate::random;

const VERSION: u8 = 0x01;
const ALG_XCHACHA20_POLY1305: u8 = 0x01;
const AAD_LABEL: &[u8; 12] = b"keevo/v1/aad";
const NONCE_LEN: usize = 24;
pub(crate) const TAG_LEN: usize = 16;

/// 信封头部长度：`version (1) ‖ alg (1) ‖ kid (16) ‖ nonce (24)`。
pub const HEADER_LEN: usize = 42;
/// AAD 长度。
pub const AAD_LEN: usize = 132;
/// 最短的合法信封：头部 + 最小填充桶 256 + tag。
pub const MIN_ENVELOPE_LEN: usize = HEADER_LEN + 256 + TAG_LEN;
/// 单个信封的明文上限：16 MiB。更大的数据使用附件分块加密。
pub const MAX_PLAINTEXT_LEN: usize = 16 * 1024 * 1024;
/// 最长的合法信封：头部 + padded_len(4 + MAX_PLAINTEXT_LEN) + tag。超过即为格式错误，
/// 在复制与认证之前拒绝，防止未认证输入触发大块内存分配（评审 F3）。
pub const MAX_ENVELOPE_LEN: usize = HEADER_LEN + 17_301_504 + TAG_LEN;

/// 被加密对象的类型（`spec/crypto.md` §9.1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum ObjectType {
    /// 账户密钥集。
    AccountKeyset = 0x01,
    /// 保险库元数据与保险库密钥。
    Vault = 0x02,
    /// 条目。
    Item = 0x03,
    /// 附件。
    Attachment = 0x04,
    /// 同步日志段（M2）。
    SyncSegment = 0x05,
    /// 同步快照（M2）。
    SyncSnapshot = 0x06,
    /// 加密的设备名（M2）。
    DeviceName = 0x07,
}

/// 对象中的部分（`spec/crypto.md` §9.2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum Part {
    /// 单一部分的对象。
    Content = 0x01,
    /// 被包裹的子密钥。
    WrappedKey = 0x02,
    /// 条目概要。
    Overview = 0x03,
    /// 条目详情。
    Details = 0x04,
    /// 附件分块，`part_index` 为块序号。
    Chunk = 0x05,
}

impl ObjectType {
    #[expect(
        clippy::as_conversions,
        reason = "repr(u8) 无字段枚举到 u8 的转换是无损的"
    )]
    const fn code(self) -> u8 {
        self as u8
    }
}

impl Part {
    #[expect(
        clippy::as_conversions,
        reason = "repr(u8) 无字段枚举到 u8 的转换是无损的"
    )]
    const fn code(self) -> u8 {
        self as u8
    }
}

/// 加解密上下文，构成 AAD 的主体（`spec/crypto.md` §8.2）。
///
/// 解密时必须提供与加密时完全相同的上下文，否则认证失败。不适用的字段填 [`Id128::ZERO`]
/// 与全零 `binding`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AadContext {
    /// 对象类型。
    pub object_type: ObjectType,
    /// 对象中的部分。
    pub part: Part,
    /// 部分序号（附件块序号），其他情况为 0。
    pub part_index: u32,
    /// 账户 ID。
    pub account_id: Id128,
    /// 保险库 ID。
    pub vault_id: Id128,
    /// 对象 ID。
    pub object_id: Id128,
    /// 修订 ID。
    pub rev_id: Id128,
    /// 类型专属的绑定值。
    pub binding: [u8; 32],
}

impl AadContext {
    /// 构造 AAD 字节（§8.2），定长 132 字节。
    pub(crate) fn aad_bytes(&self, kid: &KeyId) -> Vec<u8> {
        let mut out = Vec::with_capacity(AAD_LEN);
        out.extend_from_slice(AAD_LABEL);
        out.push(VERSION);
        out.push(ALG_XCHACHA20_POLY1305);
        out.extend_from_slice(kid.as_bytes());
        out.push(self.object_type.code());
        out.push(self.part.code());
        out.extend_from_slice(&self.part_index.to_be_bytes());
        out.extend_from_slice(self.account_id.as_bytes());
        out.extend_from_slice(self.vault_id.as_bytes());
        out.extend_from_slice(self.object_id.as_bytes());
        out.extend_from_slice(self.rev_id.as_bytes());
        out.extend_from_slice(&self.binding);
        debug_assert_eq!(out.len(), AAD_LEN);
        out
    }
}

/// 用 `key` 加密 `plaintext`，nonce 随机生成。
///
/// # Errors
/// 明文超过 [`MAX_PLAINTEXT_LEN`] 时返回 [`CryptoError::TooLarge`]；随机数不可用时返回
/// [`CryptoError::Random`]。
pub fn seal(key: &SymmetricKey, ctx: &AadContext, plaintext: &[u8]) -> Result<Vec<u8>> {
    seal_with_nonce(key, ctx, plaintext, random::array()?)
}

/// 指定 nonce 加密。只供本 crate 内部与测试向量使用，不得公开。
pub(crate) fn seal_with_nonce(
    key: &SymmetricKey,
    ctx: &AadContext,
    plaintext: &[u8],
    nonce: [u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    let kid = key.id();
    let aad = ctx.aad_bytes(&kid);
    let mut buf = padding::pad(plaintext)?;
    cipher(key)?
        .encrypt_in_place(&XNonce::from(nonce), &aad, &mut *buf)
        .map_err(|_| CryptoError::TooLarge)?;

    let mut out = Vec::with_capacity(HEADER_LEN.saturating_add(buf.len()));
    out.push(VERSION);
    out.push(ALG_XCHACHA20_POLY1305);
    out.extend_from_slice(kid.as_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&buf);
    Ok(out)
}

/// 解密并认证信封，返回明文。
///
/// # Errors
/// 按 §8.5 的顺序返回 `Malformed`、`UnsupportedVersion`、`UnsupportedAlgorithm`、
/// `KeyIdMismatch`、`DecryptionFailed`，解填充失败时返回 `Malformed`。
pub fn open(key: &SymmetricKey, ctx: &AadContext, envelope: &[u8]) -> Result<SecretBytes> {
    let header = Header::parse(envelope)?;
    if header.kid != key.id() {
        return Err(CryptoError::KeyIdMismatch);
    }
    let aad = ctx.aad_bytes(&header.kid);
    let mut buf = Zeroizing::new(header.body.to_vec());
    cipher(key)?
        .decrypt_in_place(&XNonce::from(header.nonce), &aad, &mut *buf)
        .map_err(|_| CryptoError::DecryptionFailed)?;
    padding::unpad(buf)
}

/// 读取信封头部中的密钥 ID，用于在解密前找到对应的密钥。
///
/// # Errors
/// 信封格式或版本不受支持时返回对应错误。
pub fn envelope_key_id(envelope: &[u8]) -> Result<KeyId> {
    Header::parse(envelope).map(|h| h.kid)
}

struct Header<'a> {
    kid: KeyId,
    nonce: [u8; NONCE_LEN],
    body: &'a [u8],
}

impl<'a> Header<'a> {
    fn parse(envelope: &'a [u8]) -> Result<Self> {
        if envelope.len() < MIN_ENVELOPE_LEN || envelope.len() > MAX_ENVELOPE_LEN {
            return Err(CryptoError::Malformed);
        }
        let (&[version, alg], rest) = envelope
            .split_first_chunk::<2>()
            .ok_or(CryptoError::Malformed)?;
        if version != VERSION {
            return Err(CryptoError::UnsupportedVersion);
        }
        if alg != ALG_XCHACHA20_POLY1305 {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        let (kid, rest) = rest
            .split_first_chunk::<16>()
            .ok_or(CryptoError::Malformed)?;
        let (nonce, body) = rest
            .split_first_chunk::<NONCE_LEN>()
            .ok_or(CryptoError::Malformed)?;
        Ok(Self {
            kid: KeyId::from_bytes(*kid),
            nonce: *nonce,
            body,
        })
    }
}

fn cipher(key: &SymmetricKey) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(key.expose()).map_err(|_| CryptoError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> AadContext {
        AadContext {
            object_type: ObjectType::Item,
            part: Part::Details,
            part_index: 0,
            account_id: Id128::from_bytes([1; 16]),
            vault_id: Id128::from_bytes([2; 16]),
            object_id: Id128::from_bytes([3; 16]),
            rev_id: Id128::from_bytes([4; 16]),
            binding: [0; 32],
        }
    }

    #[test]
    fn roundtrip() {
        let key = SymmetricKey::generate().unwrap();
        for msg in [&b""[..], b"hello", &[7u8; 5000]] {
            let env = seal(&key, &ctx(), msg).unwrap();
            assert_eq!(open(&key, &ctx(), &env).unwrap().as_slice(), msg);
        }
    }

    #[test]
    fn nonces_are_fresh() {
        let key = SymmetricKey::generate().unwrap();
        let a = seal(&key, &ctx(), b"same").unwrap();
        let b = seal(&key, &ctx(), b"same").unwrap();
        assert_ne!(a[18..42], b[18..42]);
        assert_ne!(a, b);
    }

    #[test]
    fn any_context_change_fails_authentication() {
        let key = SymmetricKey::generate().unwrap();
        let env = seal(&key, &ctx(), b"secret").unwrap();
        let variants: Vec<AadContext> = vec![
            AadContext {
                object_type: ObjectType::Vault,
                ..ctx()
            },
            AadContext {
                part: Part::Overview,
                ..ctx()
            },
            AadContext {
                part_index: 1,
                ..ctx()
            },
            AadContext {
                account_id: Id128::from_bytes([9; 16]),
                ..ctx()
            },
            AadContext {
                vault_id: Id128::from_bytes([9; 16]),
                ..ctx()
            },
            AadContext {
                object_id: Id128::from_bytes([9; 16]),
                ..ctx()
            },
            AadContext {
                rev_id: Id128::from_bytes([9; 16]),
                ..ctx()
            },
            AadContext {
                binding: [9; 32],
                ..ctx()
            },
        ];
        for v in variants {
            assert_eq!(
                open(&key, &v, &env).err(),
                Some(CryptoError::DecryptionFailed),
                "{v:?}"
            );
        }
    }

    #[test]
    fn every_byte_is_authenticated() {
        let key = SymmetricKey::generate().unwrap();
        let env = seal(&key, &ctx(), b"secret").unwrap();
        for i in 0..env.len() {
            let mut t = env.clone();
            t[i] ^= 0x01;
            let err = open(&key, &ctx(), &t).err().unwrap();
            let expected = match i {
                0 => CryptoError::UnsupportedVersion,
                1 => CryptoError::UnsupportedAlgorithm,
                2..18 => CryptoError::KeyIdMismatch,
                _ => CryptoError::DecryptionFailed,
            };
            assert_eq!(err, expected, "byte {i}");
        }
    }

    #[test]
    fn truncated_or_extended_envelopes_are_rejected() {
        let key = SymmetricKey::generate().unwrap();
        let env = seal(&key, &ctx(), b"secret").unwrap();
        assert_eq!(
            open(&key, &ctx(), &env[..env.len() - 1]).err(),
            Some(CryptoError::Malformed)
        );
        let mut longer = env.clone();
        longer.push(0);
        assert_eq!(
            open(&key, &ctx(), &longer).err(),
            Some(CryptoError::DecryptionFailed)
        );
        assert_eq!(open(&key, &ctx(), &[]).err(), Some(CryptoError::Malformed));
    }

    #[test]
    fn wrong_key_is_rejected() {
        let key = SymmetricKey::generate().unwrap();
        let env = seal(&key, &ctx(), b"secret").unwrap();
        let other = SymmetricKey::generate().unwrap();
        assert_eq!(
            open(&other, &ctx(), &env).err(),
            Some(CryptoError::KeyIdMismatch)
        );
        // 相同 kid、不同密钥字节：必须在认证阶段失败
        let same_id = SymmetricKey::from_raw(*key.id().as_bytes(), [0x42; 32]);
        assert_eq!(
            open(&same_id, &ctx(), &env).err(),
            Some(CryptoError::DecryptionFailed)
        );
    }

    #[test]
    fn key_wrapping_roundtrip_and_context_check() {
        let parent = SymmetricKey::generate().unwrap();
        let child = SymmetricKey::generate().unwrap();
        let wctx = AadContext {
            part: Part::WrappedKey,
            ..ctx()
        };
        let wrapped = parent.wrap_key(&wctx, &child).unwrap();
        let back = parent.unwrap_key(&wctx, &wrapped).unwrap();
        assert_eq!(back.id(), child.id());
        assert_eq!(back.expose(), child.expose());

        assert_eq!(
            parent.wrap_key(&ctx(), &child).err(),
            Some(CryptoError::InvalidContext)
        );
        assert_eq!(
            parent.unwrap_key(&ctx(), &wrapped).err(),
            Some(CryptoError::InvalidContext)
        );
    }
}

#[cfg(test)]
mod review_tests {
    use super::*;

    #[test]
    fn max_envelope_len_matches_padding_rule() {
        let padded = crate::padding::padded_len(4 + MAX_PLAINTEXT_LEN).unwrap();
        assert_eq!(MAX_ENVELOPE_LEN, HEADER_LEN + padded + TAG_LEN);
    }

    /// 评审 F3：超过最大合法长度的信封在复制与认证之前就被拒绝。
    #[test]
    fn review_f3_oversized_envelope_is_rejected_before_copying() {
        let key = SymmetricKey::generate().unwrap();
        let ctx = AadContext {
            object_type: ObjectType::Item,
            part: Part::Details,
            part_index: 0,
            account_id: Id128::ZERO,
            vault_id: Id128::ZERO,
            object_id: Id128::ZERO,
            rev_id: Id128::ZERO,
            binding: [0; 32],
        };
        let mut env = seal(&key, &ctx, b"x").unwrap();
        env.resize(MAX_ENVELOPE_LEN + 1, 0);
        assert_eq!(open(&key, &ctx, &env).err(), Some(CryptoError::Malformed));
    }
}
