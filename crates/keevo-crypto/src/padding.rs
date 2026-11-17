//! 长度填充（`spec/crypto.md` §8.3）：`len (4) ‖ M ‖ 0…`，总长度为 max(256, Padmé(4 + len))。

use zeroize::Zeroizing;

use crate::envelope::{MAX_PLAINTEXT_LEN, TAG_LEN};
use crate::error::{CryptoError, Result};

const MIN_PADDED_LEN: usize = 256;
const LEN_PREFIX: usize = 4;

/// 给定 `n = 4 + len(M)`，返回填充后的总长度。
pub(crate) fn padded_len(n: usize) -> Result<usize> {
    if n <= MIN_PADDED_LEN {
        return Ok(MIN_PADDED_LEN);
    }
    // n > 256，因此 e ≥ 8、s ≥ 4、e − s ≥ 4，以下运算都不会下溢
    let e = n.ilog2();
    let s = e.ilog2().checked_add(1).ok_or(CryptoError::TooLarge)?;
    let mask = (1usize << e.checked_sub(s).ok_or(CryptoError::TooLarge)?)
        .checked_sub(1)
        .ok_or(CryptoError::TooLarge)?;
    Ok(n.checked_add(mask).ok_or(CryptoError::TooLarge)? & !mask)
}

/// 填充明文。返回的缓冲区预留了 AEAD tag 的容量，原地加密时不会重新分配（以免在已释放内存中留下明文副本）。
pub(crate) fn pad(plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if plaintext.len() > MAX_PLAINTEXT_LEN {
        return Err(CryptoError::TooLarge);
    }
    let len = u32::try_from(plaintext.len()).map_err(|_| CryptoError::TooLarge)?;
    let n = LEN_PREFIX
        .checked_add(plaintext.len())
        .ok_or(CryptoError::TooLarge)?;
    let total = padded_len(n)?;
    let capacity = total.checked_add(TAG_LEN).ok_or(CryptoError::TooLarge)?;

    let mut buf = Zeroizing::new(Vec::with_capacity(capacity));
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(plaintext);
    buf.resize(total, 0);
    Ok(buf)
}

/// 严格解填充：长度前缀、总长度与填充字节都必须完全符合规范，否则返回 [`CryptoError::Malformed`]。
/// 原地操作，不产生额外副本。
pub(crate) fn unpad(mut buf: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>> {
    let (prefix, rest) = buf
        .split_first_chunk::<LEN_PREFIX>()
        .ok_or(CryptoError::Malformed)?;
    let len = usize::try_from(u32::from_be_bytes(*prefix)).map_err(|_| CryptoError::Malformed)?;
    if len > MAX_PLAINTEXT_LEN || len > rest.len() {
        return Err(CryptoError::Malformed);
    }
    let n = LEN_PREFIX.checked_add(len).ok_or(CryptoError::Malformed)?;
    if padded_len(n)? != buf.len() {
        return Err(CryptoError::Malformed);
    }
    let (_, padding) = rest.split_at(len);
    if padding.iter().fold(0u8, |acc, &b| acc | b) != 0 {
        return Err(CryptoError::Malformed);
    }
    buf.drain(..LEN_PREFIX);
    buf.truncate(len);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_various_lengths() {
        for len in [0usize, 1, 251, 252, 253, 1000, 70_000] {
            let data: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect();
            let padded = pad(&data).unwrap();
            assert_eq!(padded.len(), padded_len(4 + len).unwrap());
            assert!(padded.capacity() >= padded.len() + TAG_LEN);
            assert_eq!(unpad(padded).unwrap().as_slice(), data.as_slice());
        }
    }

    #[test]
    fn padme_overhead_is_bounded() {
        for n in (257..2_000_000).step_by(997) {
            let p = padded_len(n).unwrap();
            assert!(p >= n);
            // Padmé 的开销不超过约 12%
            assert!((p - n) * 100 <= n * 12, "n = {n}, padded = {p}");
        }
    }

    #[test]
    fn unpad_rejects_non_canonical_inputs() {
        let good = pad(b"secret").unwrap();

        let mut nonzero_padding = good.clone();
        *nonzero_padding.last_mut().unwrap() = 1;
        assert_eq!(unpad(nonzero_padding).err(), Some(CryptoError::Malformed));

        let mut length_too_big = good.clone();
        length_too_big[..4].copy_from_slice(&300u32.to_be_bytes());
        assert_eq!(unpad(length_too_big).err(), Some(CryptoError::Malformed));

        let mut extra_bucket = good.clone();
        extra_bucket.resize(512, 0);
        assert_eq!(unpad(extra_bucket).err(), Some(CryptoError::Malformed));

        assert_eq!(
            unpad(Zeroizing::new(vec![0, 0])).err(),
            Some(CryptoError::Malformed)
        );
    }

    #[test]
    fn oversized_plaintext_is_rejected() {
        let big = vec![0u8; MAX_PLAINTEXT_LEN + 1];
        assert_eq!(pad(&big).err(), Some(CryptoError::TooLarge));
    }
}
