use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{CryptoError, Result};

/// HKDF-SHA-256（RFC 5869）。`out` 的长度即 L。
pub(crate) fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, out)
        .map_err(|_| CryptoError::Malformed)
}

/// SHA-256。仅用于非秘密值（校验位、绑定值）。
pub(crate) fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}
