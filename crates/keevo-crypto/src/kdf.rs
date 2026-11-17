use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::random;

const ALG_ARGON2ID: u8 = 0x01;

/// Argon2id 参数（`spec/crypto.md` §5）。不是秘密，以明文与密钥集一同存放。
///
/// 构造时总会校验硬编码的上下限，因此一个 `KdfParams` 值必然是合法的。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    m_kib: u32,
    t: u32,
    p: u32,
    salt: [u8; 16],
}

impl KdfParams {
    /// 编码后的长度。
    pub const ENCODED_LEN: usize = 29;
    /// 默认内存：256 MiB。
    pub const DEFAULT_M_KIB: u32 = 262_144;
    /// 默认迭代次数。
    pub const DEFAULT_T: u32 = 3;
    /// 默认并行度。
    pub const DEFAULT_P: u32 = 4;
    /// 内存下限：64 MiB。
    pub const MIN_M_KIB: u32 = 65_536;
    /// 内存上限：4 GiB。
    pub const MAX_M_KIB: u32 = 4_194_304;
    /// 迭代次数下限。
    pub const MIN_T: u32 = 3;
    /// 迭代次数上限。
    pub const MAX_T: u32 = 32;
    /// 并行度下限。
    pub const MIN_P: u32 = 1;
    /// 并行度上限。
    pub const MAX_P: u32 = 16;

    /// 构造并校验参数。
    ///
    /// # Errors
    /// 低于下限返回 [`CryptoError::KdfBelowMinimum`]，高于上限返回 [`CryptoError::KdfAboveMaximum`]。
    pub const fn new(m_kib: u32, t: u32, p: u32, salt: [u8; 16]) -> Result<Self> {
        if m_kib < Self::MIN_M_KIB || t < Self::MIN_T || p < Self::MIN_P {
            return Err(CryptoError::KdfBelowMinimum);
        }
        if m_kib > Self::MAX_M_KIB || t > Self::MAX_T || p > Self::MAX_P {
            return Err(CryptoError::KdfAboveMaximum);
        }
        Ok(Self { m_kib, t, p, salt })
    }

    /// 默认参数加一个新的随机 salt。创建账户和修改主密码时使用。
    ///
    /// # Errors
    /// 操作系统随机数生成器不可用时返回 [`CryptoError::Random`]。
    pub fn generate_default() -> Result<Self> {
        Self::new(
            Self::DEFAULT_M_KIB,
            Self::DEFAULT_T,
            Self::DEFAULT_P,
            random::array()?,
        )
    }

    /// 按 §5.1 解码。
    ///
    /// # Errors
    /// 长度错误返回 [`CryptoError::Malformed`]，算法未知返回 [`CryptoError::UnsupportedAlgorithm`]，
    /// 越界返回对应错误。
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let bytes: &[u8; Self::ENCODED_LEN] =
            bytes.try_into().map_err(|_| CryptoError::Malformed)?;
        let (&[alg], rest) = bytes
            .split_first_chunk::<1>()
            .ok_or(CryptoError::Malformed)?;
        if alg != ALG_ARGON2ID {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        let (m, rest) = rest
            .split_first_chunk::<4>()
            .ok_or(CryptoError::Malformed)?;
        let (t, rest) = rest
            .split_first_chunk::<4>()
            .ok_or(CryptoError::Malformed)?;
        let (p, salt) = rest
            .split_first_chunk::<4>()
            .ok_or(CryptoError::Malformed)?;
        let salt: [u8; 16] = salt.try_into().map_err(|_| CryptoError::Malformed)?;
        Self::new(
            u32::from_be_bytes(*m),
            u32::from_be_bytes(*t),
            u32::from_be_bytes(*p),
            salt,
        )
    }

    /// 按 §5.1 编码。
    #[must_use]
    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0u8; Self::ENCODED_LEN];
        let mut v = Vec::with_capacity(Self::ENCODED_LEN);
        v.push(ALG_ARGON2ID);
        v.extend_from_slice(&self.m_kib.to_be_bytes());
        v.extend_from_slice(&self.t.to_be_bytes());
        v.extend_from_slice(&self.p.to_be_bytes());
        v.extend_from_slice(&self.salt);
        out.copy_from_slice(&v);
        out
    }

    /// 内存（KiB）。
    #[must_use]
    pub const fn memory_kib(&self) -> u32 {
        self.m_kib
    }

    /// 迭代次数。
    #[must_use]
    pub const fn iterations(&self) -> u32 {
        self.t
    }

    /// 并行度。
    #[must_use]
    pub const fn parallelism(&self) -> u32 {
        self.p
    }

    /// salt。
    #[must_use]
    pub const fn salt(&self) -> &[u8; 16] {
        &self.salt
    }

    /// 计算 Argon2id，输出 32 字节（§6 中的 `K_p`）。不使用 secret 与 associated data。
    pub(crate) fn argon2id(&self, password: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let params =
            Params::new(self.m_kib, self.t, self.p, Some(32)).map_err(|_| CryptoError::Kdf)?;
        let mut out = Zeroizing::new([0u8; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(password, &self.salt, out.as_mut())
            .map_err(|_| CryptoError::Kdf)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let p = KdfParams::generate_default().unwrap();
        assert_eq!(KdfParams::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn bounds_are_enforced() {
        let salt = [7u8; 16];
        assert_eq!(
            KdfParams::new(65_535, 3, 4, salt),
            Err(CryptoError::KdfBelowMinimum)
        );
        assert_eq!(
            KdfParams::new(65_536, 2, 4, salt),
            Err(CryptoError::KdfBelowMinimum)
        );
        assert_eq!(
            KdfParams::new(65_536, 3, 0, salt),
            Err(CryptoError::KdfBelowMinimum)
        );
        assert_eq!(
            KdfParams::new(4_194_305, 3, 4, salt),
            Err(CryptoError::KdfAboveMaximum)
        );
        assert_eq!(
            KdfParams::new(65_536, 33, 4, salt),
            Err(CryptoError::KdfAboveMaximum)
        );
        assert_eq!(
            KdfParams::new(65_536, 3, 17, salt),
            Err(CryptoError::KdfAboveMaximum)
        );
        assert!(KdfParams::new(65_536, 3, 1, salt).is_ok());
    }
}
