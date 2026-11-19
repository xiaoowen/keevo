//! Ed25519 签名（RFC 8032 §5.1），供 SSH Agent 使用（`spec/ssh-agent.md` §3）。
//!
//! 群运算来自 curve25519-dalek（Noise 的 X25519 已经依赖它），这里只按 RFC 8032 组合：
//! 私钥种子经 SHA-512 展开为钳位后的标量与前缀，签名 `R = rB`、`S = r + H(R‖A‖M)·a`。
//! 签名是确定性的，不需要随机数。由 RFC 8032 §7.1 的已知答案与 OpenSSH 的互通测试验证。

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::{Scalar, clamp_integer};
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, Zeroizing};

use crate::error::Result;
use crate::random;

/// 私钥种子的长度。
pub const ED25519_SEED_LEN: usize = 32;
/// 公钥的长度。
pub const ED25519_PUBLIC_LEN: usize = 32;
/// 签名的长度。
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// Ed25519 私钥。释放时清零；不实现 `Clone`、`Debug`。
pub struct Ed25519SigningKey {
    seed: Zeroizing<[u8; ED25519_SEED_LEN]>,
    scalar: Scalar,
    prefix: Zeroizing<[u8; 32]>,
    public: [u8; ED25519_PUBLIC_LEN],
}

impl Drop for Ed25519SigningKey {
    fn drop(&mut self) {
        self.scalar.zeroize();
    }
}

fn sha512(parts: &[&[u8]]) -> Zeroizing<[u8; 64]> {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(&h.finalize());
    out
}

impl Ed25519SigningKey {
    /// 生成新的私钥（种子取自操作系统 CSPRNG）。
    ///
    /// # Errors
    /// 随机数生成器不可用时返回 [`CryptoError::Random`]。
    pub fn generate() -> Result<Self> {
        let mut seed = Zeroizing::new([0u8; ED25519_SEED_LEN]);
        random::fill(seed.as_mut())?;
        Ok(Self::from_seed(seed))
    }

    /// 由 32 字节种子恢复（RFC 8032 的"私钥"）。
    #[must_use]
    pub fn from_seed(seed: Zeroizing<[u8; ED25519_SEED_LEN]>) -> Self {
        let h = sha512(&[seed.as_ref()]);
        let mut lower = Zeroizing::new([0u8; 32]);
        lower.copy_from_slice(h.get(..32).unwrap_or(&[0; 32]));
        let mut prefix = Zeroizing::new([0u8; 32]);
        prefix.copy_from_slice(h.get(32..).unwrap_or(&[0; 32]));
        let scalar = Scalar::from_bytes_mod_order(clamp_integer(*lower));
        let public = EdwardsPoint::mul_base(&scalar).compress().to_bytes();
        Self {
            seed,
            scalar,
            prefix,
            public,
        }
    }

    /// 公钥。
    #[must_use]
    pub fn public_key(&self) -> [u8; ED25519_PUBLIC_LEN] {
        self.public
    }

    /// 种子（写入 OpenSSH 私钥格式时使用）。
    #[must_use]
    pub fn seed(&self) -> Zeroizing<[u8; ED25519_SEED_LEN]> {
        self.seed.clone()
    }

    /// 签名 `message`。
    #[must_use]
    // 标量与点的运算都在群中取模（curve25519-dalek 的运算符），不会溢出
    #[allow(clippy::arithmetic_side_effects)]
    pub fn sign(&self, message: &[u8]) -> [u8; ED25519_SIGNATURE_LEN] {
        let mut r = Scalar::from_bytes_mod_order_wide(&sha512(&[self.prefix.as_ref(), message]));
        let big_r = EdwardsPoint::mul_base(&r).compress().to_bytes();
        let k = Scalar::from_bytes_mod_order_wide(&sha512(&[&big_r, &self.public, message]));
        let mut s = r + k * self.scalar;
        let mut sig = [0u8; ED25519_SIGNATURE_LEN];
        sig[..32].copy_from_slice(&big_r);
        sig[32..].copy_from_slice(&s.to_bytes());
        r.zeroize();
        s.zeroize();
        sig
    }
}

/// 验证 Ed25519 签名（RFC 8032 §5.1.7，不乘余因子的严格形式）：`S` 必须是规范编码，
/// 公钥必须能解码为曲线上的点，且 `[S]B − [k]A` 的编码与 `R` 逐字节相同。
#[must_use]
// 点取负是群运算，不会溢出
#[allow(clippy::arithmetic_side_effects)]
pub fn ed25519_verify(
    public: &[u8; ED25519_PUBLIC_LEN],
    message: &[u8],
    signature: &[u8; ED25519_SIGNATURE_LEN],
) -> bool {
    let Some(a) = CompressedEdwardsY(*public).decompress() else {
        return false;
    };
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);
    let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)) else {
        return false;
    };
    let k = Scalar::from_bytes_mod_order_wide(&sha512(&[&r_bytes, public, message]));
    let check = EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &(-a), &s);
    check.compress().to_bytes() == r_bytes
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]
mod tests {
    use super::*;

    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        let v = hex::decode(s).unwrap();
        v.try_into().unwrap()
    }

    /// RFC 8032 §7.1 的 TEST 1–3：由种子得到公钥，签名逐字节相同，并能通过验证。
    #[test]
    fn rfc8032_known_answers() {
        let cases: [(&str, &str, &str, &str); 3] = [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            (
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
        ];
        for (seed, public, message, signature) in cases {
            let key = Ed25519SigningKey::from_seed(Zeroizing::new(unhex(seed)));
            assert_eq!(hex::encode(key.public_key()), public);
            let msg = hex::decode(message).unwrap();
            let sig = key.sign(&msg);
            assert_eq!(hex::encode(sig), signature);
            assert!(ed25519_verify(&key.public_key(), &msg, &sig));
        }
    }

    #[test]
    fn verification_rejects_tampering() {
        let key = Ed25519SigningKey::generate().unwrap();
        let sig = key.sign(b"keevo");
        assert!(ed25519_verify(&key.public_key(), b"keevo", &sig));
        assert!(!ed25519_verify(&key.public_key(), b"keevo!", &sig));
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(!ed25519_verify(&key.public_key(), b"keevo", &bad));
        // S 不是规范编码（加上群的阶 l）
        let mut non_canonical = sig;
        let l: [u8; 32] = unhex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
        let mut carry = 0u16;
        for i in 0..32 {
            let v = u16::from(non_canonical[32 + i]) + u16::from(l[i]) + carry;
            non_canonical[32 + i] = (v & 0xff) as u8;
            carry = v >> 8;
        }
        assert!(!ed25519_verify(&key.public_key(), b"keevo", &non_canonical));
        let other = Ed25519SigningKey::generate().unwrap();
        assert!(!ed25519_verify(&other.public_key(), b"keevo", &sig));
    }

    #[test]
    fn seed_round_trips() {
        let key = Ed25519SigningKey::generate().unwrap();
        let again = Ed25519SigningKey::from_seed(key.seed());
        assert_eq!(key.public_key(), again.public_key());
        assert_eq!(key.sign(b"x"), again.sign(b"x"));
    }
}
