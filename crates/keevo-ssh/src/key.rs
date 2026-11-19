//! SSH 密钥：公钥的线上编码（blob）、公钥行与指纹、OpenSSH 私钥格式（`openssh-key-v1`）。
//!
//! 格式依据 OpenSSH 的 `PROTOCOL.key`、RFC 8709（Ed25519）与 RFC 8410（PKCS#8 中的 Ed25519）。
//! 只支持 Ed25519（`spec/ssh-agent.md` §3），其他算法解析为 [`KeyError::Unsupported`]，由界面说明原因。
//!
//! 导入时接受：未加密或以 `aes*-ctr` + bcrypt 口令保护的 OpenSSH 私钥；未加密的 PKCS#8 PEM（Ed25519）。
//! 写出时只写未加密的 OpenSSH 格式（私钥由保险库加密保存）。

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use keevo_crypto::{
    CryptoError, ED25519_PUBLIC_LEN, ED25519_SEED_LEN, ED25519_SIGNATURE_LEN, Ed25519SigningKey,
    OPENSSH_CIPHER_BLOCK, OPENSSH_CIPHERS, ed25519_verify, openssh_decrypt, random_below, sha256,
};
use zeroize::Zeroizing;

use crate::wire::{Reader, WireError, Writer};

/// Ed25519 的算法名。
pub const ED25519: &str = "ssh-ed25519";

const BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const END: &str = "-----END OPENSSH PRIVATE KEY-----";
const MAGIC: &[u8] = b"openssh-key-v1\0";
/// 未加密时私钥段按 8 字节对齐（OpenSSH 的 `none` 密码的块大小）。
const BLOCK: usize = 8;
/// 私钥文本的长度上限：远大于任何真实的私钥，防止巨大的输入。
pub const MAX_PRIVATE_KEY_TEXT: usize = 64 * 1024;

/// 密钥解析错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// 不是 OpenSSH 私钥格式。
    NotOpenSsh,
    /// 加密的 PEM（旧式 `Proc-Type: 4,ENCRYPTED` 或 `ENCRYPTED PRIVATE KEY`）：需要先用 `ssh-keygen -p`
    /// 转换为 OpenSSH 格式（可以保留口令）。
    Pem,
    /// 私钥有口令保护，需要提供口令。
    Encrypted,
    /// 口令不对。
    WrongPassphrase,
    /// 不支持的加密方式（例如 `aes256-gcm@openssh.com`）：需要先用 `ssh-keygen -p -Z aes256-ctr` 转换。
    UnsupportedCipher(String),
    /// 不支持的算法。
    Unsupported(String),
    /// 结构错误。
    Malformed,
}

impl KeyError {
    /// 稳定的错误码（供界面翻译）。
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotOpenSsh => "not_openssh",
            Self::Pem => "pem",
            Self::Encrypted => "encrypted",
            Self::WrongPassphrase => "wrong_passphrase",
            Self::UnsupportedCipher(_) => "cipher",
            Self::Unsupported(_) => "unsupported",
            Self::Malformed => "malformed",
        }
    }
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(alg) => write!(f, "unsupported key type: {alg}"),
            Self::UnsupportedCipher(c) => write!(f, "unsupported cipher: {c}"),
            other => f.write_str(other.code()),
        }
    }
}

impl std::error::Error for KeyError {}

impl From<WireError> for KeyError {
    fn from(_: WireError) -> Self {
        Self::Malformed
    }
}

/// 公钥。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// Ed25519。
    Ed25519([u8; ED25519_PUBLIC_LEN]),
}

impl PublicKey {
    /// 由线上编码（blob）解析。
    ///
    /// # Errors
    /// 算法不支持返回 [`KeyError::Unsupported`]；结构错误返回 [`KeyError::Malformed`]。
    pub fn from_blob(blob: &[u8]) -> Result<Self, KeyError> {
        let mut r = Reader::new(blob);
        let alg = r.string()?;
        if alg != ED25519.as_bytes() {
            return Err(KeyError::Unsupported(
                String::from_utf8_lossy(alg).into_owned(),
            ));
        }
        let key: [u8; ED25519_PUBLIC_LEN] =
            r.string()?.try_into().map_err(|_| KeyError::Malformed)?;
        r.finish()?;
        Ok(Self::Ed25519(key))
    }

    /// 算法名。
    #[must_use]
    pub fn algorithm(&self) -> &'static str {
        match self {
            Self::Ed25519(_) => ED25519,
        }
    }

    /// 线上编码（blob）。
    #[must_use]
    pub fn blob(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Self::Ed25519(k) => w.string(ED25519.as_bytes()).string(k),
        };
        w.into_inner()
    }

    /// SHA-256 指纹，与 `ssh-keygen -l` 相同：`SHA256:` + 不带填充的 Base64。
    #[must_use]
    pub fn fingerprint(&self) -> String {
        fingerprint_blob(&self.blob())
    }

    /// `authorized_keys` 格式的公钥行：`ssh-ed25519 AAAA… 注释`。
    #[must_use]
    pub fn to_line(&self, comment: &str) -> String {
        let mut line = format!("{} {}", self.algorithm(), STANDARD.encode(self.blob()));
        let comment = comment.trim();
        if !comment.is_empty() {
            line.push(' ');
            // 公钥行中不能有换行
            line.push_str(&comment.replace(['\n', '\r'], " "));
        }
        line
    }

    /// 解析公钥行（`算法 Base64 [注释]`）。
    ///
    /// # Errors
    /// 格式错误或算法不支持时返回错误。
    pub fn parse_line(line: &str) -> Result<(Self, String), KeyError> {
        let mut parts = line.trim().splitn(3, char::is_whitespace);
        let alg = parts.next().ok_or(KeyError::Malformed)?;
        let b64 = parts.next().ok_or(KeyError::Malformed)?;
        let comment = parts.next().unwrap_or("").trim().to_owned();
        let blob = STANDARD.decode(b64).map_err(|_| KeyError::Malformed)?;
        let key = Self::from_blob(&blob)?;
        if key.algorithm() != alg {
            return Err(KeyError::Malformed);
        }
        Ok((key, comment))
    }

    /// 验证签名 blob（`string 算法` + `string 签名`）是否为本公钥对 `data` 的签名。
    #[must_use]
    pub fn verify(&self, data: &[u8], signature_blob: &[u8]) -> bool {
        let mut r = Reader::new(signature_blob);
        let (Ok(alg), Ok(sig)) = (r.string(), r.string()) else {
            return false;
        };
        if r.finish().is_err() {
            return false;
        }
        match self {
            Self::Ed25519(k) => {
                let Ok(sig) = <[u8; ED25519_SIGNATURE_LEN]>::try_from(sig) else {
                    return false;
                };
                alg == ED25519.as_bytes() && ed25519_verify(k, data, &sig)
            }
        }
    }
}

/// 任意公钥 blob 的 SHA-256 指纹（包括不支持的算法，例如 session-bind 中的 RSA 主机密钥）。
#[must_use]
pub fn fingerprint_blob(blob: &[u8]) -> String {
    format!("SHA256:{}", STANDARD_NO_PAD.encode(sha256(blob)))
}

/// 私钥。不实现 `Clone`、`Debug`；释放时清零。
pub struct PrivateKey {
    key: Ed25519SigningKey,
    comment: String,
}

impl PrivateKey {
    /// 生成新的 Ed25519 私钥。
    ///
    /// # Errors
    /// 随机数生成器不可用时返回 [`KeyError::Malformed`]（不会在正常系统上发生）。
    pub fn generate_ed25519(comment: &str) -> Result<Self, KeyError> {
        Ok(Self {
            key: Ed25519SigningKey::generate().map_err(|_| KeyError::Malformed)?,
            comment: comment.to_owned(),
        })
    }

    /// 公钥。
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey::Ed25519(self.key.public_key())
    }

    /// 私钥中记录的注释。
    #[must_use]
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// 签名，返回签名 blob（`string 算法` + `string 签名`，RFC 8709 §6）。
    #[must_use]
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let sig = self.key.sign(data);
        let mut w = Writer::new();
        w.string(ED25519.as_bytes()).string(&sig);
        w.into_inner()
    }

    /// 解析私钥文本（未加密）。有口令保护时返回 [`KeyError::Encrypted`]。
    ///
    /// # Errors
    /// 见 [`PrivateKey::parse_with_passphrase`]。
    pub fn parse(text: &str) -> Result<Self, KeyError> {
        Self::parse_with_passphrase(text, None)
    }

    /// 解析私钥文本：OpenSSH 格式（可以有口令保护），或未加密的 PKCS#8 PEM（Ed25519）。
    ///
    /// # Errors
    /// - 不是私钥：[`KeyError::NotOpenSsh`]；加密的 PEM：[`KeyError::Pem`]；
    /// - 算法不支持：[`KeyError::Unsupported`]（不需要口令就能判断）；加密方式不支持：[`KeyError::UnsupportedCipher`]；
    /// - 需要口令而没有给出：[`KeyError::Encrypted`]；口令不对：[`KeyError::WrongPassphrase`]；
    /// - 结构错误、公私钥不一致：[`KeyError::Malformed`]。
    pub fn parse_with_passphrase(text: &str, passphrase: Option<&str>) -> Result<Self, KeyError> {
        if text.len() > MAX_PRIVATE_KEY_TEXT {
            return Err(KeyError::Malformed);
        }
        let text = text.trim();
        if text.starts_with("-----BEGIN ") && !text.starts_with(BEGIN) {
            return parse_pem(text);
        }
        let bytes = pem_body(text, BEGIN, END)?;
        let rest = bytes.strip_prefix(MAGIC).ok_or(KeyError::NotOpenSsh)?;
        let mut r = Reader::new(rest);
        let cipher = r.string()?;
        let kdf = r.string()?;
        let kdf_options = r.string()?;
        let encrypted = match (cipher, kdf) {
            (b"none", b"none") => false,
            (_, b"bcrypt") if cipher != b"none" => true,
            _ => return Err(KeyError::Malformed),
        };
        if r.u32()? != 1 {
            // 一个文件中有多把密钥：ssh-keygen 不会这样写
            return Err(KeyError::Malformed);
        }
        let public_blob = r.string()?;
        let private = r.string()?;
        // 先判断算法（公钥在加密范围之外）：不支持的算法不必先要口令，也给出名称而不是笼统的结构错误
        let public = PublicKey::from_blob(public_blob)?;
        if !encrypted {
            r.finish()?;
            return parse_private(private, &public, BLOCK, false);
        }
        let cipher = String::from_utf8_lossy(cipher).into_owned();
        if !OPENSSH_CIPHERS.contains(&cipher.as_str()) {
            // 带认证的加密方式在私钥段之后还有认证标签，这里不再往下解析
            return Err(KeyError::UnsupportedCipher(cipher));
        }
        r.finish()?;
        let passphrase = passphrase
            .filter(|p| !p.is_empty())
            .ok_or(KeyError::Encrypted)?;
        let mut o = Reader::new(kdf_options);
        let salt = o.string()?;
        let rounds = o.u32()?;
        o.finish()?;
        let mut plain = Zeroizing::new(private.to_vec());
        openssh_decrypt(&cipher, passphrase.as_bytes(), salt, rounds, &mut plain).map_err(|e| {
            match e {
                CryptoError::EmptyPassword => KeyError::Encrypted,
                _ => KeyError::Malformed,
            }
        })?;
        parse_private(&plain, &public, OPENSSH_CIPHER_BLOCK, true)
    }

    /// 设置注释（例如 PKCS#8 没有注释时，用条目标题）。
    pub fn set_comment(&mut self, comment: &str) {
        comment.clone_into(&mut self.comment);
    }

    /// 编码为 OpenSSH 私钥文本（未加密），与 `ssh-keygen -t ed25519 -N ''` 的输出格式相同。
    ///
    /// # Errors
    /// 随机数生成器不可用时返回 [`KeyError::Malformed`]（不会在正常系统上发生）。
    pub fn to_openssh(&self) -> Result<Zeroizing<String>, KeyError> {
        let public = self.public_key();
        let pk = self.key.public_key();
        let check = random_below(u32::MAX).map_err(|_| KeyError::Malformed)?;
        let mut secret = Zeroizing::new(Vec::with_capacity(ED25519_SEED_LEN * 2));
        secret.extend_from_slice(self.key.seed().as_ref());
        secret.extend_from_slice(&pk);

        let mut p = Writer::new();
        p.u32(check)
            .u32(check)
            .string(ED25519.as_bytes())
            .string(&pk)
            .string(&secret)
            .string(self.comment.as_bytes());
        let mut pad = 1u8;
        while !p.len().is_multiple_of(BLOCK) {
            p.u8(pad);
            pad = pad.wrapping_add(1);
        }
        let private = Zeroizing::new(p.into_inner());

        let mut w = Writer::new();
        w.raw(MAGIC)
            .string(b"none")
            .string(b"none")
            .string(b"")
            .u32(1)
            .string(&public.blob())
            .string(&private);
        let bytes = Zeroizing::new(w.into_inner());
        let b64 = Zeroizing::new(STANDARD.encode(bytes.as_slice()));
        let mut out = Zeroizing::new(String::with_capacity(b64.len().saturating_add(80)));
        out.push_str(BEGIN);
        out.push('\n');
        // OpenSSH 每行 70 个字符
        for chunk in b64.as_bytes().chunks(70) {
            out.push_str(std::str::from_utf8(chunk).map_err(|_| KeyError::Malformed)?);
            out.push('\n');
        }
        out.push_str(END);
        out.push('\n');
        Ok(out)
    }
}

/// 取出 PEM 包装中的 Base64 内容并解码。
fn pem_body(text: &str, begin: &str, end: &str) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    let body = text
        .strip_prefix(begin)
        .and_then(|t| t.strip_suffix(end))
        .ok_or(KeyError::NotOpenSsh)?;
    let b64: Zeroizing<String> =
        Zeroizing::new(body.chars().filter(|c| !c.is_whitespace()).collect());
    Ok(Zeroizing::new(
        STANDARD
            .decode(b64.as_bytes())
            .map_err(|_| KeyError::Malformed)?,
    ))
}

/// 私钥段（未加密或已解密）：两个校验数、算法、公钥、私钥、注释、填充。`encrypted` 时校验数不一致说明口令不对。
fn parse_private(
    private: &[u8],
    public: &PublicKey,
    block: usize,
    encrypted: bool,
) -> Result<PrivateKey, KeyError> {
    let mut p = Reader::new(private);
    let check1 = p.u32()?;
    let check2 = p.u32()?;
    if check1 != check2 {
        return Err(if encrypted {
            KeyError::WrongPassphrase
        } else {
            KeyError::Malformed
        });
    }
    let alg = p.string()?;
    if alg != ED25519.as_bytes() {
        return Err(KeyError::Unsupported(
            String::from_utf8_lossy(alg).into_owned(),
        ));
    }
    let pk: [u8; ED25519_PUBLIC_LEN] = p.string()?.try_into().map_err(|_| KeyError::Malformed)?;
    let sk = p.string()?;
    let comment = String::from_utf8_lossy(p.string()?).into_owned();
    // 填充：1, 2, 3, …，补齐到块大小
    let padding = p.remaining();
    if padding.len() >= block
        || padding
            .iter()
            .zip(1u8..)
            .any(|(&byte, expected)| byte != expected)
    {
        return Err(KeyError::Malformed);
    }
    // Ed25519 私钥字段是 种子 ‖ 公钥（64 字节）
    let (seed, embedded_pk) = sk
        .split_at_checked(ED25519_SEED_LEN)
        .ok_or(KeyError::Malformed)?;
    if embedded_pk != pk || &PublicKey::Ed25519(pk) != public {
        return Err(KeyError::Malformed);
    }
    from_seed(seed, &pk, comment)
}

/// 由种子恢复私钥，并核对与公钥一致：否则是伪造或损坏的文件。
fn from_seed(
    seed: &[u8],
    expected_public: &[u8; 32],
    comment: String,
) -> Result<PrivateKey, KeyError> {
    let mut seed_arr = Zeroizing::new([0u8; ED25519_SEED_LEN]);
    seed_arr.copy_from_slice(seed.get(..ED25519_SEED_LEN).ok_or(KeyError::Malformed)?);
    let key = Ed25519SigningKey::from_seed(seed_arr);
    if &key.public_key() != expected_public {
        return Err(KeyError::Malformed);
    }
    Ok(PrivateKey { key, comment })
}

/// RFC 8410 的 PKCS#8 v1（`OneAsymmetricKey` 版本 0）中 Ed25519 私钥的固定前缀，之后是 32 字节种子。
const PKCS8_ED25519_V1: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
/// 版本 1（带公钥）的前缀；种子之后是 `[1] BIT STRING` 形式的公钥。
const PKCS8_ED25519_V2: [u8; 16] = [
    0x30, 0x51, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
const PKCS8_V2_PUBLIC: [u8; 3] = [0x81, 0x21, 0x00];
/// 算法标识（DER 编码的 OID），用于说明不支持的算法。
const OID_RSA: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
];
const OID_EC: [u8; 9] = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

/// PEM 格式的私钥：只接受未加密的 PKCS#8（Ed25519）；其他说明原因。
fn parse_pem(text: &str) -> Result<PrivateKey, KeyError> {
    let label = text
        .strip_prefix("-----BEGIN ")
        .and_then(|t| t.split_once("-----"))
        .map_or("", |(label, _)| label);
    let legacy_encrypted = text.contains("Proc-Type: 4,ENCRYPTED");
    match label {
        "PRIVATE KEY" => {}
        "ENCRYPTED PRIVATE KEY" => return Err(KeyError::Pem),
        "RSA PRIVATE KEY" | "EC PRIVATE KEY" | "DSA PRIVATE KEY" if legacy_encrypted => {
            return Err(KeyError::Pem);
        }
        "RSA PRIVATE KEY" => return Err(KeyError::Unsupported("ssh-rsa".into())),
        "EC PRIVATE KEY" => return Err(KeyError::Unsupported("ecdsa".into())),
        "DSA PRIVATE KEY" => return Err(KeyError::Unsupported("ssh-dss".into())),
        _ => return Err(KeyError::NotOpenSsh),
    }
    let der = pem_body(
        text,
        "-----BEGIN PRIVATE KEY-----",
        "-----END PRIVATE KEY-----",
    )?;
    let contains = |needle: &[u8]| der.windows(needle.len()).any(|w| w == needle);
    if der.len() == 48 && der.starts_with(&PKCS8_ED25519_V1) {
        // v1 不带公钥，没有可核对的
        let mut seed = Zeroizing::new([0u8; ED25519_SEED_LEN]);
        seed.copy_from_slice(der.get(16..48).ok_or(KeyError::Malformed)?);
        return Ok(PrivateKey {
            key: Ed25519SigningKey::from_seed(seed),
            comment: String::new(),
        });
    }
    if der.len() == 83 && der.starts_with(&PKCS8_ED25519_V2) {
        let seed = der.get(16..48).ok_or(KeyError::Malformed)?;
        if der.get(48..51) != Some(&PKCS8_V2_PUBLIC[..]) {
            return Err(KeyError::Malformed);
        }
        let pk: [u8; 32] = der
            .get(51..83)
            .and_then(|b| b.try_into().ok())
            .ok_or(KeyError::Malformed)?;
        return from_seed(seed, &pk, String::new());
    }
    if contains(&OID_RSA) {
        return Err(KeyError::Unsupported("ssh-rsa".into()));
    }
    if contains(&OID_EC) {
        return Err(KeyError::Unsupported("ecdsa".into()));
    }
    Err(KeyError::Malformed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// 由 `ssh-keygen -q -t ed25519 -N '' -C test@keevo` 生成（仅用于测试，不对应任何真实账户）。
    const SSH_KEYGEN_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCEINkisk/PQal8sdhMm95ScnaOrT06e7/sQx8InucktwAAAJDcsvP33LLz
9wAAAAtzc2gtZWQyNTUxOQAAACCEINkisk/PQal8sdhMm95ScnaOrT06e7/sQx8Inucktw
AAAEBjyq8TKb7fOKhypCbR67h4HweHfOoFSjYrXbKFS5kj3YQg2SKyT89BqXyx2Eyb3lJy
do6tPTp7v+xDHwie5yS3AAAACnRlc3RAa2Vldm8BAgM=
-----END OPENSSH PRIVATE KEY-----
";
    /// 同一把密钥的 `.pub` 文件与 `ssh-keygen -lf` 的指纹。
    const SSH_KEYGEN_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIQg2SKyT89BqXyx2Eyb3lJydo6tPTp7v+xDHwie5yS3 test@keevo";
    const SSH_KEYGEN_FINGERPRINT: &str = "SHA256:7c8GBuOAt2qcDj3Pik3RNArB+fLS3hcl/jaWXEu0Xq0";

    #[test]
    fn generated_keys_round_trip() {
        let key = PrivateKey::generate_ed25519("me@mac").unwrap();
        let text = key.to_openssh().unwrap();
        let again = PrivateKey::parse(&text).unwrap();
        assert_eq!(again.public_key(), key.public_key());
        assert_eq!(again.comment(), "me@mac");
        let sig = again.sign(b"data");
        assert!(key.public_key().verify(b"data", &sig));
        assert!(!key.public_key().verify(b"other", &sig));
        let line = key.public_key().to_line("me@mac");
        let (parsed, comment) = PublicKey::parse_line(&line).unwrap();
        assert_eq!(parsed, key.public_key());
        assert_eq!(comment, "me@mac");
        assert!(key.public_key().fingerprint().starts_with("SHA256:"));
    }

    #[test]
    fn parses_ssh_keygen_output() {
        let key = PrivateKey::parse(SSH_KEYGEN_KEY).unwrap();
        assert_eq!(key.comment(), "test@keevo");
        assert_eq!(key.public_key().to_line("test@keevo"), SSH_KEYGEN_PUB);
        assert_eq!(key.public_key().fingerprint(), SSH_KEYGEN_FINGERPRINT);
        let sig = key.sign(b"x");
        assert!(key.public_key().verify(b"x", &sig));
        // 重新编码后除了随机的校验数，其余与 ssh-keygen 的输出相同：能被再次解析为同一把密钥
        let again = PrivateKey::parse(&key.to_openssh().unwrap()).unwrap();
        assert_eq!(again.public_key(), key.public_key());
    }

    #[test]
    fn rejects_other_formats() {
        assert_eq!(
            PrivateKey::parse(
                "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----"
            )
            .err(),
            Some(KeyError::Unsupported("ssh-rsa".into()))
        );
        assert_eq!(
            PrivateKey::parse("ssh-ed25519 AAAA").err(),
            Some(KeyError::NotOpenSsh)
        );
        let mut text = PrivateKey::generate_ed25519("")
            .unwrap()
            .to_openssh()
            .unwrap()
            .to_string();
        text = text.replace(
            "BEGIN OPENSSH PRIVATE KEY-----\n",
            "BEGIN OPENSSH PRIVATE KEY-----\nAAAA",
        );
        assert!(PrivateKey::parse(&text).is_err());
    }

    const PASSPHRASE: &str = "correct horse";

    /// 由 ssh-keygen 生成的有口令保护的私钥（`testdata/README.md`）：三种 AES-CTR 都能用口令解开，
    /// 得到与 `.pub` 相同的公钥；没有口令、口令不对时分别说明。
    #[test]
    fn decrypts_passphrase_protected_keys() {
        for (text, pub_line, comment) in [
            (
                include_str!("testdata/ed25519-aes256-ctr"),
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO9fhNi5eNgkx390VfLRbowBEnQAcpHN6we/lRG6ehH6",
                "enc256@keevo",
            ),
            (
                include_str!("testdata/ed25519-aes128-ctr"),
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDTFHOeW7xJ893wKuwXvVlQ4ZstbkIshbCNLT62d0tbq",
                "enc128@keevo",
            ),
            (
                include_str!("testdata/ed25519-aes192-ctr"),
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOzFfdQEalUvbU5EjfPO4uIjik2IPV96g4jMihuKfrM3",
                "enc192@keevo",
            ),
        ] {
            assert_eq!(PrivateKey::parse(text).err(), Some(KeyError::Encrypted));
            assert_eq!(
                PrivateKey::parse_with_passphrase(text, Some("")).err(),
                Some(KeyError::Encrypted)
            );
            assert_eq!(
                PrivateKey::parse_with_passphrase(text, Some("wrong horse")).err(),
                Some(KeyError::WrongPassphrase)
            );
            let key = PrivateKey::parse_with_passphrase(text, Some(PASSPHRASE)).unwrap();
            assert_eq!(key.comment(), comment);
            assert_eq!(key.public_key().to_line(""), pub_line);
            let sig = key.sign(b"x");
            assert!(key.public_key().verify(b"x", &sig));
            // 重新编码为未加密的格式（保险库中保存的形式）后可以直接解析
            let plain = key.to_openssh().unwrap();
            assert!(plain.contains(BEGIN));
            assert_eq!(
                PrivateKey::parse(&plain).unwrap().public_key(),
                key.public_key()
            );
        }
    }

    /// 不支持的加密方式与算法：不需要口令就能说明；加密的 PEM 说明转换方法。
    #[test]
    fn explains_unsupported_ciphers_and_formats() {
        assert_eq!(
            PrivateKey::parse(include_str!("testdata/ed25519-aes256-gcm")).err(),
            Some(KeyError::UnsupportedCipher("aes256-gcm@openssh.com".into()))
        );
        for passphrase in [None, Some(PASSPHRASE)] {
            assert_eq!(
                PrivateKey::parse_with_passphrase(
                    include_str!("testdata/rsa-aes256-ctr"),
                    passphrase
                )
                .err(),
                Some(KeyError::Unsupported("ssh-rsa".into()))
            );
        }
        assert_eq!(
            PrivateKey::parse(include_str!("testdata/rsa-legacy-encrypted.pem")).err(),
            Some(KeyError::Pem)
        );
        assert_eq!(
            PrivateKey::parse(include_str!("testdata/ec.pem")).err(),
            Some(KeyError::Unsupported("ecdsa".into()))
        );
        assert_eq!(
            PrivateKey::parse(
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----"
            )
            .err(),
            Some(KeyError::Pem)
        );
    }

    /// openssl 生成的 PKCS#8 PEM（RFC 8410）：v1 只有种子；v2 带公钥，必须一致。
    #[test]
    fn parses_pkcs8_ed25519() {
        let key = PrivateKey::parse(include_str!("testdata/ed25519-pkcs8.pem")).unwrap();
        assert_eq!(
            key.public_key().to_line(""),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO/U5n7j7xECrWn4b042vu0pSaJ3cVe6gFLYOjqbAPf5"
        );
        assert_eq!(key.comment(), "");
        // 由同一个种子构造 v2（带公钥）
        let v1 = include_str!("testdata/ed25519-pkcs8.pem");
        let body: String = v1.lines().filter(|l| !l.starts_with("-----")).collect();
        let der = STANDARD.decode(body).unwrap();
        let pem = |der: &[u8]| {
            format!(
                "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
                STANDARD.encode(der)
            )
        };
        let PublicKey::Ed25519(pk) = key.public_key();
        let mut v2 = PKCS8_ED25519_V2.to_vec();
        v2.extend_from_slice(&der[16..48]);
        v2.extend_from_slice(&PKCS8_V2_PUBLIC);
        v2.extend_from_slice(&pk);
        assert_eq!(
            PrivateKey::parse(&pem(&v2)).unwrap().public_key(),
            key.public_key()
        );
        let mut forged = v2.clone();
        forged[82] ^= 1;
        assert_eq!(
            PrivateKey::parse(&pem(&forged)).err(),
            Some(KeyError::Malformed)
        );
        assert_eq!(
            PrivateKey::parse(&pem(&der[..47])).err(),
            Some(KeyError::Malformed)
        );
    }

    #[test]
    fn rejects_mismatched_public_key() {
        let a = PrivateKey::generate_ed25519("").unwrap();
        let b = PrivateKey::generate_ed25519("").unwrap();
        // 用 b 的公钥替换外层的公钥 blob
        let text = a.to_openssh().unwrap();
        let body: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
        let mut bytes = STANDARD.decode(body).unwrap();
        let pa = a.public_key().blob();
        let pb = b.public_key().blob();
        let pos = bytes.windows(pa.len()).position(|w| w == pa).unwrap();
        bytes[pos..pos + pb.len()].copy_from_slice(&pb);
        let forged = format!("{BEGIN}\n{}\n{END}\n", STANDARD.encode(&bytes));
        assert_eq!(PrivateKey::parse(&forged).err(), Some(KeyError::Malformed));
    }
}
