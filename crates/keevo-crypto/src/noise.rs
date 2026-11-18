//! Noise 握手与传输加密（`spec/ipc.md` §4）。
//!
//! - 首次配对：`Noise_XX_25519_ChaChaPoly_SHA256`，完成后双方比对短认证串（SAS）。
//! - 已配对的会话：`Noise_IK_25519_ChaChaPoly_SHA256`。
//!
//! 扩展是发起方，Vault Service 是响应方。扩展来源写入 prologue，一个扩展的配对无法挪给另一个扩展使用。

use curve25519_dalek::MontgomeryPoint;
use zeroize::Zeroizing;

use crate::SecretBytes;
use crate::error::{CryptoError, Result};
use crate::hkdf::{hkdf_sha256, sha256};
use crate::random;

const PATTERN_XX: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const PATTERN_IK: &str = "Noise_IK_25519_ChaChaPoly_SHA256";
/// Noise 单条消息的上限（Noise 规范）。
pub const MAX_NOISE_MESSAGE: usize = 65_535;
const TAG_LEN: usize = 16;
const SAS_INFO: &[u8] = b"keevo/v1/ipc-sas";
const PAIR_COMMIT_TAG: &[u8] = b"keevo/v1/ipc-pair-commit";
/// 配对承诺随机数的长度。
pub const PAIR_NONCE_LEN: usize = 32;

/// 配对承诺（`spec/ipc.md` §4.2）：扩展在 XX 第 1 条消息中发送，承诺它的静态公钥与第 3 条消息负载的
/// **原始字节**（`nonce ‖ 显示名`）。
///
/// 承诺必须覆盖实际发送的字节，而不是解析后的字段：握手哈希覆盖的是密文字节，若同一语义允许多种编码，
/// 发起方仍能在看到对方贡献之后挑选编码来改变 SAS（第二轮评审 G1）。
#[must_use]
pub fn pairing_commitment(static_public: &[u8; 32], third_payload: &[u8]) -> [u8; 32] {
    sha256(&[PAIR_COMMIT_TAG, static_public, third_payload])
}

/// 生成配对承诺用的随机数。
///
/// # Errors
/// 系统随机数不可用时返回 [`CryptoError::Random`]。
pub fn pairing_nonce() -> Result<[u8; PAIR_NONCE_LEN]> {
    let mut n = [0u8; PAIR_NONCE_LEN];
    random::fill(&mut n)?;
    Ok(n)
}

/// 握手用途，写入 prologue。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HandshakePurpose {
    /// 首次配对（XX）。
    Pair,
    /// 已配对后的会话（IK）。
    Session,
}

impl HandshakePurpose {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::Pair => b"pair",
            Self::Session => b"session",
        }
    }
}

/// Noise 静态密钥对（X25519）。私钥释放时清零；不实现 `Debug`、`Clone` 与序列化。
pub struct StaticKeypair {
    private: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl StaticKeypair {
    /// 生成新的静态密钥对。
    ///
    /// # Errors
    /// 操作系统随机数生成器不可用时返回 [`CryptoError::Random`]。
    pub fn generate() -> Result<Self> {
        let mut private = Zeroizing::new([0u8; 32]);
        random::fill(private.as_mut())?;
        Ok(Self::from_private(private))
    }

    /// 从持久化的私钥恢复（Vault Service 的私钥由 Secure Enclave 包裹后存成文件，见 ADR-0003；
    /// 扩展的私钥存于 `chrome.storage.local`）。
    #[must_use]
    pub fn from_private(private: Zeroizing<[u8; 32]>) -> Self {
        let public = MontgomeryPoint::mul_base_clamped(*private).to_bytes();
        Self { private, public }
    }

    /// 导出私钥，只能用于写入安全存储。
    #[must_use]
    pub fn export_private(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.private)
    }

    /// 公钥。
    #[must_use]
    pub const fn public_key(&self) -> [u8; 32] {
        self.public
    }
}

fn prologue(purpose: HandshakePurpose, extension_origin: &str) -> Vec<u8> {
    let mut p = Vec::with_capacity(32usize.saturating_add(extension_origin.len()));
    p.extend_from_slice(b"keevo/v1/ipc\0");
    p.extend_from_slice(purpose.label());
    p.push(0);
    p.extend_from_slice(extension_origin.as_bytes());
    p
}

fn builder_error(_: snow::Error) -> CryptoError {
    CryptoError::Malformed
}

/// 进行中的 Noise 握手。
pub struct Handshake {
    state: snow::HandshakeState,
}

impl Handshake {
    /// 扩展发起配对（XX）。
    ///
    /// # Errors
    /// 参数无效时返回 [`CryptoError::Malformed`]。
    pub fn pair_initiator(local: &StaticKeypair, extension_origin: &str) -> Result<Self> {
        Self::build(
            PATTERN_XX,
            local,
            None,
            HandshakePurpose::Pair,
            extension_origin,
            true,
        )
    }

    /// Vault Service 响应配对（XX）。
    ///
    /// # Errors
    /// 参数无效时返回 [`CryptoError::Malformed`]。
    pub fn pair_responder(local: &StaticKeypair, extension_origin: &str) -> Result<Self> {
        Self::build(
            PATTERN_XX,
            local,
            None,
            HandshakePurpose::Pair,
            extension_origin,
            false,
        )
    }

    /// 扩展用已保存的 Vault Service 公钥发起会话（IK）。
    ///
    /// # Errors
    /// 参数无效时返回 [`CryptoError::Malformed`]。
    pub fn session_initiator(
        local: &StaticKeypair,
        responder_public: &[u8; 32],
        extension_origin: &str,
    ) -> Result<Self> {
        Self::build(
            PATTERN_IK,
            local,
            Some(responder_public),
            HandshakePurpose::Session,
            extension_origin,
            true,
        )
    }

    /// Vault Service 响应会话（IK）。读完第一条消息后，用 [`Handshake::remote_static`]
    /// 核对扩展是否已配对。
    ///
    /// # Errors
    /// 参数无效时返回 [`CryptoError::Malformed`]。
    pub fn session_responder(local: &StaticKeypair, extension_origin: &str) -> Result<Self> {
        Self::build(
            PATTERN_IK,
            local,
            None,
            HandshakePurpose::Session,
            extension_origin,
            false,
        )
    }

    fn build(
        pattern: &str,
        local: &StaticKeypair,
        remote: Option<&[u8; 32]>,
        purpose: HandshakePurpose,
        extension_origin: &str,
        initiator: bool,
    ) -> Result<Self> {
        let params = pattern.parse().map_err(builder_error)?;
        let prologue = prologue(purpose, extension_origin);
        let mut builder = snow::Builder::new(params)
            .local_private_key(local.private.as_ref())
            .map_err(builder_error)?
            .prologue(&prologue)
            .map_err(builder_error)?;
        if let Some(remote) = remote {
            builder = builder.remote_public_key(remote).map_err(builder_error)?;
        }
        let state = if initiator {
            builder.build_initiator()
        } else {
            builder.build_responder()
        }
        .map_err(builder_error)?;
        Ok(Self { state })
    }

    /// 写出下一条握手消息。
    ///
    /// # Errors
    /// 负载过长返回 [`CryptoError::TooLarge`]；不该由本方发送时返回 [`CryptoError::InvalidContext`]。
    pub fn write(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        if !self.state.is_my_turn() || self.state.is_handshake_finished() {
            return Err(CryptoError::InvalidContext);
        }
        let mut buf = vec![0u8; MAX_NOISE_MESSAGE];
        let n = self
            .state
            .write_message(payload, &mut buf)
            .map_err(|_| CryptoError::TooLarge)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// 读入对方的握手消息，返回其负载。
    ///
    /// # Errors
    /// 认证失败（包括 prologue 或密钥不匹配）返回 [`CryptoError::DecryptionFailed`]。
    pub fn read(&mut self, message: &[u8]) -> Result<SecretBytes> {
        if self.state.is_my_turn() || self.state.is_handshake_finished() {
            return Err(CryptoError::InvalidContext);
        }
        if message.len() > MAX_NOISE_MESSAGE {
            return Err(CryptoError::TooLarge);
        }
        let mut buf = Zeroizing::new(vec![0u8; message.len()]);
        let n = self
            .state
            .read_message(message, &mut buf)
            .map_err(|_| CryptoError::DecryptionFailed)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// 握手是否完成。
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// 对方的静态公钥（读到对应消息之后才可用）。
    #[must_use]
    pub fn remote_static(&self) -> Option<[u8; 32]> {
        self.state
            .get_remote_static()
            .and_then(|k| k.try_into().ok())
    }

    /// 短认证串（§4.2），握手完成后才可用。
    ///
    /// # Errors
    /// 握手未完成时返回 [`CryptoError::InvalidContext`]。
    pub fn sas(&self) -> Result<[u8; 6]> {
        if !self.is_finished() {
            return Err(CryptoError::InvalidContext);
        }
        let mut out = [0u8; 6];
        hkdf_sha256(self.state.get_handshake_hash(), &[], SAS_INFO, &mut out)?;
        Ok(out)
    }

    /// 进入传输模式。
    ///
    /// # Errors
    /// 握手未完成时返回 [`CryptoError::InvalidContext`]。
    pub fn into_transport(self) -> Result<Transport> {
        let remote = self.remote_static().ok_or(CryptoError::InvalidContext)?;
        let state = self
            .state
            .into_transport_mode()
            .map_err(|_| CryptoError::InvalidContext)?;
        Ok(Transport { state, remote })
    }
}

/// 握手完成后的双向加密通道。每个方向的 nonce 严格递增，重放或乱序都会解密失败。
pub struct Transport {
    state: snow::TransportState,
    remote: [u8; 32],
}

impl Transport {
    /// 对方的静态公钥。
    #[must_use]
    pub const fn remote_static(&self) -> [u8; 32] {
        self.remote
    }

    /// 加密一条消息。
    ///
    /// # Errors
    /// 负载超过单条 Noise 消息的上限时返回 [`CryptoError::TooLarge`]。
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let len = plaintext
            .len()
            .checked_add(TAG_LEN)
            .ok_or(CryptoError::TooLarge)?;
        if len > MAX_NOISE_MESSAGE {
            return Err(CryptoError::TooLarge);
        }
        let mut buf = vec![0u8; len];
        let n = self
            .state
            .write_message(plaintext, &mut buf)
            .map_err(|_| CryptoError::TooLarge)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// 解密一条消息。
    ///
    /// # Errors
    /// 认证失败、重放或乱序时返回 [`CryptoError::DecryptionFailed`]。
    pub fn decrypt(&mut self, message: &[u8]) -> Result<SecretBytes> {
        if message.len() > MAX_NOISE_MESSAGE {
            return Err(CryptoError::TooLarge);
        }
        let mut buf = Zeroizing::new(vec![0u8; message.len()]);
        let n = self
            .state
            .read_message(message, &mut buf)
            .map_err(|_| CryptoError::DecryptionFailed)?;
        buf.truncate(n);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORIGIN: &str = "chrome-extension://abcdefghijklmnopabcdefghijklmnop/";

    fn pair(ext: &StaticKeypair, svc: &StaticKeypair) -> (Handshake, Handshake) {
        let mut i = Handshake::pair_initiator(ext, ORIGIN).unwrap();
        let mut r = Handshake::pair_responder(svc, ORIGIN).unwrap();
        r.read(&i.write(&[]).unwrap()).unwrap();
        i.read(&r.write(&[]).unwrap()).unwrap();
        let name = r.read(&i.write(br#"{"name":"Chrome"}"#).unwrap()).unwrap();
        assert_eq!(name.as_slice(), br#"{"name":"Chrome"}"#);
        (i, r)
    }

    #[test]
    fn xx_pairing_yields_matching_sas_and_static_keys() {
        let ext = StaticKeypair::generate().unwrap();
        let svc = StaticKeypair::generate().unwrap();
        let (i, r) = pair(&ext, &svc);
        assert!(i.is_finished() && r.is_finished());
        assert_eq!(i.sas().unwrap(), r.sas().unwrap());
        assert_eq!(i.remote_static(), Some(svc.public_key()));
        assert_eq!(r.remote_static(), Some(ext.public_key()));

        let mut ti = i.into_transport().unwrap();
        let mut tr = r.into_transport().unwrap();
        let c = ti.encrypt(b"ping").unwrap();
        assert_eq!(tr.decrypt(&c).unwrap().as_slice(), b"ping");
        let c = tr.encrypt(b"pong").unwrap();
        assert_eq!(ti.decrypt(&c).unwrap().as_slice(), b"pong");
    }

    #[test]
    fn different_extension_origin_breaks_the_handshake() {
        let ext = StaticKeypair::generate().unwrap();
        let svc = StaticKeypair::generate().unwrap();
        let mut i = Handshake::pair_initiator(&ext, ORIGIN).unwrap();
        let mut r = Handshake::pair_responder(&svc, "chrome-extension://evil/").unwrap();
        r.read(&i.write(&[]).unwrap()).unwrap();
        // 第二条消息开始带认证，prologue 不同必然失败
        assert_eq!(
            i.read(&r.write(&[]).unwrap()).err(),
            Some(CryptoError::DecryptionFailed)
        );
    }

    #[test]
    fn ik_session_with_paired_keys() {
        let ext = StaticKeypair::generate().unwrap();
        let svc = StaticKeypair::generate().unwrap();
        let mut i = Handshake::session_initiator(&ext, &svc.public_key(), ORIGIN).unwrap();
        let mut r = Handshake::session_responder(&svc, ORIGIN).unwrap();
        r.read(&i.write(&[]).unwrap()).unwrap();
        // 响应方读完第一条消息即可核对扩展是否已配对
        assert_eq!(r.remote_static(), Some(ext.public_key()));
        i.read(&r.write(&[]).unwrap()).unwrap();
        assert!(i.is_finished() && r.is_finished());
        let mut ti = i.into_transport().unwrap();
        let mut tr = r.into_transport().unwrap();
        assert_eq!(
            tr.decrypt(&ti.encrypt(b"x").unwrap()).unwrap().as_slice(),
            b"x"
        );
    }

    #[test]
    fn ik_with_wrong_service_key_fails() {
        let ext = StaticKeypair::generate().unwrap();
        let svc = StaticKeypair::generate().unwrap();
        let impostor = StaticKeypair::generate().unwrap();
        let mut i = Handshake::session_initiator(&ext, &impostor.public_key(), ORIGIN).unwrap();
        let mut r = Handshake::session_responder(&svc, ORIGIN).unwrap();
        assert_eq!(
            r.read(&i.write(&[]).unwrap()).err(),
            Some(CryptoError::DecryptionFailed)
        );
    }

    #[test]
    fn replay_reorder_and_tamper_are_rejected() {
        let (i, r) = pair(
            &StaticKeypair::generate().unwrap(),
            &StaticKeypair::generate().unwrap(),
        );
        let mut ti = i.into_transport().unwrap();
        let mut tr = r.into_transport().unwrap();
        let m1 = ti.encrypt(b"one").unwrap();
        let m2 = ti.encrypt(b"two").unwrap();
        // 乱序：先收到第二条
        assert_eq!(tr.decrypt(&m2).err(), Some(CryptoError::DecryptionFailed));
        let mut tampered = m1.clone();
        tampered[0] ^= 1;
        assert_eq!(
            tr.decrypt(&tampered).err(),
            Some(CryptoError::DecryptionFailed)
        );
    }

    #[test]
    fn replayed_message_is_rejected() {
        let (i, r) = pair(
            &StaticKeypair::generate().unwrap(),
            &StaticKeypair::generate().unwrap(),
        );
        let mut ti = i.into_transport().unwrap();
        let mut tr = r.into_transport().unwrap();
        let m = ti.encrypt(b"once").unwrap();
        assert!(tr.decrypt(&m).is_ok());
        assert_eq!(tr.decrypt(&m).err(), Some(CryptoError::DecryptionFailed));
    }

    #[test]
    fn private_key_roundtrip_and_misuse_checks() {
        let kp = StaticKeypair::generate().unwrap();
        let restored = StaticKeypair::from_private(kp.export_private());
        assert_eq!(restored.public_key(), kp.public_key());

        let mut i = Handshake::pair_initiator(&kp, ORIGIN).unwrap();
        assert_eq!(
            i.read(&[0u8; 32]).err(),
            Some(CryptoError::InvalidContext),
            "还没轮到读"
        );
        assert_eq!(i.sas().err(), Some(CryptoError::InvalidContext));
        let _ = i.write(&[]).unwrap();
        assert_eq!(
            i.write(&[]).err(),
            Some(CryptoError::InvalidContext),
            "还没轮到写"
        );
    }
}
