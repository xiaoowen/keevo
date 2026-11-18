//! 本机密钥包裹 v1（`spec/crypto.md` §8.7）。
//!
//! Secure Enclave 的密钥协商由平台层完成，本模块只接收协商结果 `shared` 与临时公钥。
//! 被包裹的材料只以本 crate 的类型（[`SymmetricKey`]、[`AccountSecretKey`]、[`Id128`]）进出，
//! 原始字节不离开本 crate。

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::envelope::TAG_LEN;
use crate::error::{CryptoError, Result};
use crate::hkdf::hkdf_sha256;
use crate::id::Id128;
use crate::key::SymmetricKey;
use crate::random;
use crate::secret_key::AccountSecretKey;
use crate::two_skd::auk_kid;

const VERSION: u8 = 0x01;
const LABEL: &[u8] = b"keevo/v1/local-wrap";
const NONCE_LEN: usize = 24;
/// 临时公钥（X9.63 未压缩）的长度。
pub const EPH_PUB_LEN: usize = 65;
/// 协商结果的长度。
pub const SHARED_LEN: usize = 32;
const HEADER_LEN: usize = 2 + EPH_PUB_LEN;
/// 包裹的最大长度：头部、nonce、最长的明文（32）与 tag。
pub const MAX_LOCAL_WRAP_LEN: usize = HEADER_LEN + NONCE_LEN + 32 + TAG_LEN;
const SHORT_WRAP_LEN: usize = HEADER_LEN + NONCE_LEN + 16 + TAG_LEN;
const AAD_LEN: usize = LABEL.len() + HEADER_LEN + 32;
const INFO_LEN: usize = LABEL.len() + 1;

/// 包裹的用途（§8.7 用途表）。每个用途使用各自的 Secure Enclave 密钥。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
pub enum LocalPurpose {
    /// AUK，用于 Touch ID 解锁。
    Auk,
    /// 账户密钥。
    SecretKey,
    /// Vault Service 的 Noise 静态私钥。
    ServiceStatic,
    /// 设备标记（`device_id`）。
    DeviceMarker,
}

impl LocalPurpose {
    /// 全部用途。
    pub const ALL: [Self; 4] = [
        Self::Auk,
        Self::SecretKey,
        Self::ServiceStatic,
        Self::DeviceMarker,
    ];

    /// 线上取值。
    #[must_use]
    pub const fn byte(self) -> u8 {
        match self {
            Self::Auk => 0x01,
            Self::SecretKey => 0x02,
            Self::ServiceStatic => 0x03,
            Self::DeviceMarker => 0x04,
        }
    }

    /// 由线上取值解析。
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Auk),
            0x02 => Some(Self::SecretKey),
            0x03 => Some(Self::ServiceStatic),
            0x04 => Some(Self::DeviceMarker),
            _ => None,
        }
    }

    /// 是否要求用户在场（Touch ID）。
    #[must_use]
    pub const fn requires_presence(self) -> bool {
        matches!(self, Self::Auk)
    }

    const fn plaintext_len(self) -> usize {
        match self {
            Self::Auk | Self::ServiceStatic => 32,
            Self::SecretKey | Self::DeviceMarker => 16,
        }
    }

    const fn wrapped_len(self) -> usize {
        match self {
            Self::Auk | Self::ServiceStatic => MAX_LOCAL_WRAP_LEN,
            Self::SecretKey | Self::DeviceMarker => SHORT_WRAP_LEN,
        }
    }
}

/// 包裹时由平台层给出的协商结果：临时公钥，以及它与 Secure Enclave 公钥协商得到的 `shared`。
pub struct LocalAgreement {
    eph_pub: [u8; EPH_PUB_LEN],
    shared: Zeroizing<[u8; SHARED_LEN]>,
}

impl LocalAgreement {
    /// 检查长度与前缀后构造。点是否在曲线上由平台层在协商时检查。
    ///
    /// # Errors
    /// 长度不符或临时公钥不以 `0x04` 开头时返回 [`CryptoError::Malformed`]。
    pub fn new(eph_pub: &[u8], shared: &[u8]) -> Result<Self> {
        Ok(Self {
            eph_pub: eph_pub_from(eph_pub)?,
            shared: shared_from(shared)?,
        })
    }
}

/// 包裹的头部，用于在解包前把临时公钥交给平台层协商。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LocalWrapHeader {
    /// 用途。
    pub purpose: LocalPurpose,
    /// 临时公钥。
    pub eph_pub: [u8; EPH_PUB_LEN],
}

impl LocalWrapHeader {
    /// 解析包裹的头部，并检查总长度与用途对应的明文长度一致。
    ///
    /// # Errors
    /// 长度、前缀或用途不符返回 [`CryptoError::Malformed`]；版本不符返回 [`CryptoError::UnsupportedVersion`]。
    pub fn parse(wrapped: &[u8]) -> Result<Self> {
        if wrapped.len() > MAX_LOCAL_WRAP_LEN {
            return Err(CryptoError::Malformed);
        }
        let (&[version, purpose], rest) = wrapped
            .split_first_chunk::<2>()
            .ok_or(CryptoError::Malformed)?;
        if version != VERSION {
            return Err(CryptoError::UnsupportedVersion);
        }
        let purpose = LocalPurpose::from_byte(purpose).ok_or(CryptoError::Malformed)?;
        if wrapped.len() != purpose.wrapped_len() {
            return Err(CryptoError::Malformed);
        }
        let eph_pub = eph_pub_from(rest.get(..EPH_PUB_LEN).ok_or(CryptoError::Malformed)?)?;
        Ok(Self { purpose, eph_pub })
    }
}

/// 包裹 AUK（用途 0x01）。
///
/// # Errors
/// 随机数错误时返回 [`CryptoError::Random`]。
pub fn wrap_auk(
    auk: &SymmetricKey,
    account_id: &Id128,
    device_id: &Id128,
    agreement: &LocalAgreement,
) -> Result<Vec<u8>> {
    seal(
        LocalPurpose::Auk,
        auk.expose(),
        account_id,
        Some(device_id),
        agreement,
    )
}

/// 解开 AUK。kid 由 AUK 重新派生。
///
/// # Errors
/// 格式错误返回 [`CryptoError::Malformed`]；认证失败返回 [`CryptoError::DecryptionFailed`]。
pub fn unwrap_auk(
    wrapped: &[u8],
    account_id: &Id128,
    device_id: &Id128,
    shared: &[u8],
) -> Result<SymmetricKey> {
    let plain = open(
        LocalPurpose::Auk,
        wrapped,
        account_id,
        Some(device_id),
        shared,
    )?;
    let mut auk = Zeroizing::new([0u8; 32]);
    auk.copy_from_slice(&plain);
    let kid = auk_kid(&auk, account_id)?;
    Ok(SymmetricKey::from_parts(kid, auk))
}

/// 包裹账户密钥（用途 0x02），明文是 128 位原始值。
///
/// # Errors
/// 随机数错误时返回 [`CryptoError::Random`]。
pub fn wrap_secret_key(
    secret_key: &AccountSecretKey,
    account_id: &Id128,
    device_id: &Id128,
    agreement: &LocalAgreement,
) -> Result<Vec<u8>> {
    seal(
        LocalPurpose::SecretKey,
        secret_key.expose(),
        account_id,
        Some(device_id),
        agreement,
    )
}

/// 解开账户密钥。
///
/// # Errors
/// 同 [`unwrap_auk`]。
pub fn unwrap_secret_key(
    wrapped: &[u8],
    account_id: &Id128,
    device_id: &Id128,
    shared: &[u8],
) -> Result<AccountSecretKey> {
    let plain = open(
        LocalPurpose::SecretKey,
        wrapped,
        account_id,
        Some(device_id),
        shared,
    )?;
    let mut bytes = Zeroizing::new([0u8; 16]);
    bytes.copy_from_slice(&plain);
    Ok(AccountSecretKey::from_secret(bytes))
}

/// 包裹设备标记（用途 0x04）。明文就是 `device_id`，`aad` 中 `device_id` 的位置为零。
///
/// # Errors
/// 随机数错误时返回 [`CryptoError::Random`]。
pub fn wrap_device_marker(
    device_id: &Id128,
    account_id: &Id128,
    agreement: &LocalAgreement,
) -> Result<Vec<u8>> {
    seal(
        LocalPurpose::DeviceMarker,
        device_id.as_bytes(),
        account_id,
        None,
        agreement,
    )
}

/// 解开设备标记，得到 `device_id`。
///
/// # Errors
/// 同 [`unwrap_auk`]。
pub fn unwrap_device_marker(wrapped: &[u8], account_id: &Id128, shared: &[u8]) -> Result<Id128> {
    let plain = open(
        LocalPurpose::DeviceMarker,
        wrapped,
        account_id,
        None,
        shared,
    )?;
    let bytes: [u8; 16] = plain
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Malformed)?;
    Ok(Id128::from_bytes(bytes))
}

fn header_bytes(purpose: LocalPurpose, eph_pub: &[u8; EPH_PUB_LEN]) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[0] = VERSION;
    out[1] = purpose.byte();
    out[2..].copy_from_slice(eph_pub);
    out
}

fn aad(header: &[u8; HEADER_LEN], account_id: &Id128, device_id: Option<&Id128>) -> Vec<u8> {
    let mut out = Vec::with_capacity(AAD_LEN);
    out.extend_from_slice(LABEL);
    out.extend_from_slice(header);
    out.extend_from_slice(account_id.as_bytes());
    out.extend_from_slice(device_id.map_or(&[0u8; 16], |d| d.as_bytes()));
    out
}

fn cipher(
    purpose: LocalPurpose,
    shared: &[u8; SHARED_LEN],
    account_id: &Id128,
) -> Result<XChaCha20Poly1305> {
    let mut info = Vec::with_capacity(INFO_LEN);
    info.extend_from_slice(LABEL);
    info.push(purpose.byte());
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf_sha256(shared, account_id.as_bytes(), &info, key.as_mut())?;
    XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| CryptoError::Malformed)
}

fn seal(
    purpose: LocalPurpose,
    plaintext: &[u8],
    account_id: &Id128,
    device_id: Option<&Id128>,
    agreement: &LocalAgreement,
) -> Result<Vec<u8>> {
    if plaintext.len() != purpose.plaintext_len() {
        return Err(CryptoError::Malformed);
    }
    let header = header_bytes(purpose, &agreement.eph_pub);
    let nonce: [u8; NONCE_LEN] = random::array()?;
    let mut buf = Zeroizing::new(plaintext.to_vec());
    cipher(purpose, &agreement.shared, account_id)?
        .encrypt_in_place(
            &XNonce::from(nonce),
            &aad(&header, account_id, device_id),
            &mut *buf,
        )
        .map_err(|_| CryptoError::TooLarge)?;
    let mut out = Vec::with_capacity(MAX_LOCAL_WRAP_LEN);
    out.extend_from_slice(&header);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&buf);
    Ok(out)
}

fn open(
    purpose: LocalPurpose,
    wrapped: &[u8],
    account_id: &Id128,
    device_id: Option<&Id128>,
    shared: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let parsed = LocalWrapHeader::parse(wrapped)?;
    if parsed.purpose != purpose {
        return Err(CryptoError::Malformed);
    }
    let shared = shared_from(shared)?;
    let header = header_bytes(purpose, &parsed.eph_pub);
    let rest = wrapped.get(HEADER_LEN..).ok_or(CryptoError::Malformed)?;
    let (nonce, body) = rest
        .split_first_chunk::<NONCE_LEN>()
        .ok_or(CryptoError::Malformed)?;
    let mut buf = Zeroizing::new(body.to_vec());
    cipher(purpose, &shared, account_id)?
        .decrypt_in_place(
            &XNonce::from(*nonce),
            &aad(&header, account_id, device_id),
            &mut *buf,
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;
    Ok(buf)
}

fn eph_pub_from(bytes: &[u8]) -> Result<[u8; EPH_PUB_LEN]> {
    let out: [u8; EPH_PUB_LEN] = bytes.try_into().map_err(|_| CryptoError::Malformed)?;
    if out[0] != 0x04 {
        return Err(CryptoError::Malformed);
    }
    Ok(out)
}

fn shared_from(bytes: &[u8]) -> Result<Zeroizing<[u8; SHARED_LEN]>> {
    let mut out = Zeroizing::new([0u8; SHARED_LEN]);
    if bytes.len() != SHARED_LEN {
        return Err(CryptoError::Malformed);
    }
    out.copy_from_slice(bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: Id128 = Id128::from_bytes([1; 16]);
    const DEVICE: Id128 = Id128::from_bytes([2; 16]);

    fn agreement(seed: u8) -> LocalAgreement {
        let mut eph = [seed; EPH_PUB_LEN];
        eph[0] = 0x04;
        LocalAgreement::new(&eph, &[seed.wrapping_add(1); SHARED_LEN]).unwrap()
    }

    fn shared(seed: u8) -> [u8; SHARED_LEN] {
        [seed.wrapping_add(1); SHARED_LEN]
    }

    #[test]
    fn round_trips_and_lengths() {
        let auk = SymmetricKey::from_raw([0; 16], [7; 32]);
        let sk = AccountSecretKey::from_bytes([9; 16]);
        let a = agreement(3);

        let w = wrap_auk(&auk, &ACCOUNT, &DEVICE, &a).unwrap();
        assert_eq!(w.len(), MAX_LOCAL_WRAP_LEN);
        let back = unwrap_auk(&w, &ACCOUNT, &DEVICE, &shared(3)).unwrap();
        assert_eq!(back.expose(), auk.expose());
        assert_eq!(
            back.id(),
            auk_kid(auk.expose(), &ACCOUNT).unwrap(),
            "kid 由 AUK 重新派生"
        );

        let w = wrap_secret_key(&sk, &ACCOUNT, &DEVICE, &a).unwrap();
        assert_eq!(w.len(), 123);
        assert_eq!(
            unwrap_secret_key(&w, &ACCOUNT, &DEVICE, &shared(3))
                .unwrap()
                .expose(),
            sk.expose()
        );

        let w = wrap_device_marker(&DEVICE, &ACCOUNT, &a).unwrap();
        assert_eq!(
            unwrap_device_marker(&w, &ACCOUNT, &shared(3)).unwrap(),
            DEVICE
        );
        let header = LocalWrapHeader::parse(&w).unwrap();
        assert_eq!(header.purpose, LocalPurpose::DeviceMarker);
        assert_eq!(header.eph_pub, a.eph_pub);
    }

    #[test]
    fn each_nonce_is_fresh() {
        let sk = AccountSecretKey::from_bytes([9; 16]);
        let a = agreement(3);
        let w1 = wrap_secret_key(&sk, &ACCOUNT, &DEVICE, &a).unwrap();
        let w2 = wrap_secret_key(&sk, &ACCOUNT, &DEVICE, &a).unwrap();
        assert_ne!(w1, w2);
    }

    /// 改动任何一个字节、换账户或设备、换协商结果、换用途，都无法解开。
    #[test]
    fn bindings_are_enforced() {
        let sk = AccountSecretKey::from_bytes([9; 16]);
        let w = wrap_secret_key(&sk, &ACCOUNT, &DEVICE, &agreement(3)).unwrap();
        for i in 0..w.len() {
            let mut t = w.clone();
            t[i] ^= 0x01;
            assert!(
                unwrap_secret_key(&t, &ACCOUNT, &DEVICE, &shared(3)).is_err(),
                "第 {i} 字节被改动"
            );
        }
        let other = Id128::from_bytes([5; 16]);
        assert_eq!(
            unwrap_secret_key(&w, &other, &DEVICE, &shared(3)).err(),
            Some(CryptoError::DecryptionFailed)
        );
        assert_eq!(
            unwrap_secret_key(&w, &ACCOUNT, &other, &shared(3)).err(),
            Some(CryptoError::DecryptionFailed),
            "绑定 device_id"
        );
        assert_eq!(
            unwrap_secret_key(&w, &ACCOUNT, &DEVICE, &shared(4)).err(),
            Some(CryptoError::DecryptionFailed)
        );
        assert_eq!(
            unwrap_device_marker(&w, &ACCOUNT, &shared(3)).err(),
            Some(CryptoError::Malformed),
            "用途不符"
        );
        assert_eq!(
            unwrap_secret_key(&w, &ACCOUNT, &DEVICE, &[0; 31]).err(),
            Some(CryptoError::Malformed)
        );
    }

    #[test]
    fn malformed_inputs_are_rejected_before_decrypting() {
        let sk = AccountSecretKey::from_bytes([9; 16]);
        let w = wrap_secret_key(&sk, &ACCOUNT, &DEVICE, &agreement(3)).unwrap();
        let mut v2 = w.clone();
        v2[0] = 0x02;
        assert_eq!(
            LocalWrapHeader::parse(&v2).err(),
            Some(CryptoError::UnsupportedVersion)
        );
        let mut p = w.clone();
        p[1] = 0x05;
        assert_eq!(
            LocalWrapHeader::parse(&p).err(),
            Some(CryptoError::Malformed)
        );
        let mut compressed = w.clone();
        compressed[2] = 0x02;
        assert_eq!(
            LocalWrapHeader::parse(&compressed).err(),
            Some(CryptoError::Malformed)
        );
        assert_eq!(
            LocalWrapHeader::parse(&w[..w.len() - 1]).err(),
            Some(CryptoError::Malformed)
        );
        let mut long = w.clone();
        long.push(0);
        assert_eq!(
            LocalWrapHeader::parse(&long).err(),
            Some(CryptoError::Malformed),
            "长度按用途固定"
        );
        assert_eq!(
            LocalWrapHeader::parse(&[0x01; 200]).err(),
            Some(CryptoError::Malformed)
        );
        assert!(LocalWrapHeader::parse(&[]).is_err());
        let mut eph = [0u8; EPH_PUB_LEN];
        eph[0] = 0x02;
        assert!(LocalAgreement::new(&eph, &[0; SHARED_LEN]).is_err());
        assert!(LocalAgreement::new(&eph[..64], &[0; SHARED_LEN]).is_err());
    }

    /// 设备标记的 aad 中 device_id 为零：任何 device_id 下都能解开（解开之前还不知道它）。
    #[test]
    fn device_marker_aad_uses_zero_device_id() {
        let a = agreement(3);
        let w = wrap_device_marker(&DEVICE, &ACCOUNT, &a).unwrap();
        let header = header_bytes(LocalPurpose::DeviceMarker, &a.eph_pub);
        assert_eq!(
            &aad(&header, &ACCOUNT, None)[LABEL.len() + HEADER_LEN + 16..],
            &[0u8; 16]
        );
        assert_eq!(
            unwrap_device_marker(&w, &ACCOUNT, &shared(3)).unwrap(),
            DEVICE
        );
    }
}
