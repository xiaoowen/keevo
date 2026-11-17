//! 账户密钥集（`spec/crypto.md` §7）。

use zeroize::Zeroizing;

use crate::envelope::{self, AadContext, ObjectType, Part};
use crate::error::{CryptoError, Result};
use crate::hkdf::sha256;
use crate::id::{Id128, KeyId};
use crate::kdf::KdfParams;
use crate::key::SymmetricKey;

const KEYSET_VERSION: u8 = 0x01;
const PLAINTEXT_LEN: usize = 145;
const BINDING_LABEL: &[u8] = b"keevo/v1/keyset-binding";

/// 账户密钥集：账户对称密钥（ASK）、账户同步密钥（SyK）与账户签名密钥种子。
///
/// 由 AUK 封装后与 KDF 参数一同存放。释放时清零。
pub struct AccountKeyset {
    ask: SymmetricKey,
    syk: SymmetricKey,
    sign: SymmetricKey,
}

impl AccountKeyset {
    /// 生成新的密钥集。
    ///
    /// # Errors
    /// 操作系统随机数生成器不可用时返回 [`CryptoError::Random`]。
    pub fn generate() -> Result<Self> {
        Ok(Self {
            ask: SymmetricKey::generate()?,
            syk: SymmetricKey::generate()?,
            sign: SymmetricKey::generate()?,
        })
    }

    /// 账户对称密钥 ASK：包裹各保险库密钥。
    #[must_use]
    pub const fn account_key(&self) -> &SymmetricKey {
        &self.ask
    }

    /// 账户同步密钥 SyK：M2 同步文件的外层加密。
    #[must_use]
    pub const fn sync_key(&self) -> &SymmetricKey {
        &self.syk
    }

    /// 用 AUK 封装密钥集（§7.3）。
    ///
    /// # Errors
    /// `epoch` 为 0 时返回 [`CryptoError::InvalidContext`]；其他错误见 [`envelope::seal`]。
    pub fn seal(
        &self,
        auk: &SymmetricKey,
        account_id: &Id128,
        epoch: u64,
        params: &KdfParams,
    ) -> Result<Vec<u8>> {
        let ctx = context(account_id, epoch, params)?;
        envelope::seal(auk, &ctx, self.encode().as_ref())
    }

    #[cfg(test)]
    pub(crate) fn seal_with_nonce(
        &self,
        auk: &SymmetricKey,
        account_id: &Id128,
        epoch: u64,
        params: &KdfParams,
        nonce: [u8; 24],
    ) -> Result<Vec<u8>> {
        let ctx = context(account_id, epoch, params)?;
        envelope::seal_with_nonce(auk, &ctx, self.encode().as_ref(), nonce)
    }

    /// 用 AUK 解开密钥集。主密码或账户密钥错误时返回 [`CryptoError::KeyIdMismatch`]；
    /// 上层应把它与 [`CryptoError::DecryptionFailed`] 一样视为"无法解锁"。
    ///
    /// # Errors
    /// 见 [`envelope::open`]；明文格式错误时返回 [`CryptoError::Malformed`]。
    pub fn open(
        auk: &SymmetricKey,
        account_id: &Id128,
        epoch: u64,
        params: &KdfParams,
        sealed: &[u8],
    ) -> Result<Self> {
        let ctx = context(account_id, epoch, params)?;
        let plaintext = envelope::open(auk, &ctx, sealed)?;
        Self::decode(&plaintext)
    }

    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(PLAINTEXT_LEN));
        out.push(KEYSET_VERSION);
        for key in [&self.ask, &self.syk, &self.sign] {
            out.extend_from_slice(key.id().as_bytes());
            out.extend_from_slice(key.expose());
        }
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PLAINTEXT_LEN {
            return Err(CryptoError::Malformed);
        }
        let (&[version], mut rest) = bytes
            .split_first_chunk::<1>()
            .ok_or(CryptoError::Malformed)?;
        if version != KEYSET_VERSION {
            return Err(CryptoError::Malformed);
        }
        let mut next = || -> Result<SymmetricKey> {
            let (kid, after) = rest
                .split_first_chunk::<16>()
                .ok_or(CryptoError::Malformed)?;
            let (key, after) = after
                .split_first_chunk::<32>()
                .ok_or(CryptoError::Malformed)?;
            rest = after;
            let mut bytes = Zeroizing::new([0u8; 32]);
            bytes.copy_from_slice(key);
            Ok(SymmetricKey::from_parts(KeyId::from_bytes(*kid), bytes))
        };
        Ok(Self {
            ask: next()?,
            syk: next()?,
            sign: next()?,
        })
    }

    #[cfg(test)]
    pub(crate) fn from_keys(ask: SymmetricKey, syk: SymmetricKey, sign: SymmetricKey) -> Self {
        Self { ask, syk, sign }
    }

    #[cfg(test)]
    pub(crate) const fn signing_seed(&self) -> &SymmetricKey {
        &self.sign
    }
}

/// 绑定值（§7.2）：把 `epoch` 与 KDF 参数纳入 AAD，防止参数被篡改或旧版本被回放。
pub(crate) fn binding(epoch: u64, params: &KdfParams) -> [u8; 32] {
    sha256(&[BINDING_LABEL, &epoch.to_be_bytes(), &params.encode()])
}

fn context(account_id: &Id128, epoch: u64, params: &KdfParams) -> Result<AadContext> {
    if epoch == 0 {
        return Err(CryptoError::InvalidContext);
    }
    Ok(AadContext {
        object_type: ObjectType::AccountKeyset,
        part: Part::Content,
        part_index: 0,
        account_id: *account_id,
        vault_id: Id128::ZERO,
        object_id: *account_id,
        rev_id: Id128::ZERO,
        binding: binding(epoch, params),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(salt: u8) -> KdfParams {
        KdfParams::new(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1, [salt; 16]).unwrap()
    }

    #[test]
    fn seal_open_roundtrip() {
        let auk = SymmetricKey::generate().unwrap();
        let id = Id128::random().unwrap();
        let ks = AccountKeyset::generate().unwrap();
        let sealed = ks.seal(&auk, &id, 1, &params(1)).unwrap();
        let back = AccountKeyset::open(&auk, &id, 1, &params(1), &sealed).unwrap();
        assert_eq!(back.account_key().expose(), ks.account_key().expose());
        assert_eq!(back.sync_key().id(), ks.sync_key().id());
        assert_eq!(back.signing_seed().expose(), ks.signing_seed().expose());
    }

    #[test]
    fn tampered_kdf_params_or_epoch_fail() {
        let auk = SymmetricKey::generate().unwrap();
        let id = Id128::random().unwrap();
        let sealed = AccountKeyset::generate()
            .unwrap()
            .seal(&auk, &id, 3, &params(1))
            .unwrap();
        // 被篡改的 KDF 参数（这里用不同的 salt 模拟）
        assert_eq!(
            AccountKeyset::open(&auk, &id, 3, &params(2), &sealed).err(),
            Some(CryptoError::DecryptionFailed)
        );
        // 旧 epoch 被当作新 epoch 回放
        assert_eq!(
            AccountKeyset::open(&auk, &id, 2, &params(1), &sealed).err(),
            Some(CryptoError::DecryptionFailed)
        );
        assert_eq!(
            AccountKeyset::open(&auk, &id, 0, &params(1), &sealed).err(),
            Some(CryptoError::InvalidContext)
        );
    }
}
