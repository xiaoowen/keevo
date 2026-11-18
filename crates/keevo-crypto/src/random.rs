use crate::error::{CryptoError, Result};

/// 用操作系统 CSPRNG 填满缓冲区。
pub(crate) fn fill(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| CryptoError::Random)
}

/// 生成 N 字节随机数组。仅用于非秘密值（ID、nonce、salt）；秘密值请直接填入 `Zeroizing` 缓冲区。
pub(crate) fn array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}

/// `[0, bound)` 中均匀分布的随机整数，用于密码生成器（`keevo-core::generator`）。
///
/// 拒绝采样：落在 `2^32` 除以 `bound` 的余数区间里的值丢弃，避免取模偏差。
///
/// # Errors
/// `bound` 为 0 时返回 [`CryptoError::Malformed`]；随机数生成器不可用时返回 [`CryptoError::Random`]。
pub fn random_below(bound: u32) -> Result<u32> {
    if bound == 0 {
        return Err(CryptoError::Malformed);
    }
    // 2^32 mod bound：小于它的值所在的那一轮不完整
    let threshold = bound
        .wrapping_neg()
        .checked_rem(bound)
        .ok_or(CryptoError::Malformed)?;
    loop {
        let r = u32::from_le_bytes(array()?);
        if r >= threshold {
            return r.checked_rem(bound).ok_or(CryptoError::Malformed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_below_is_in_range_and_covers_all_values() {
        assert!(random_below(0).is_err());
        assert_eq!(random_below(1).unwrap(), 0);
        let mut seen = [0u32; 7];
        for _ in 0..7000 {
            let v = random_below(7).unwrap();
            seen[usize::try_from(v).unwrap()] += 1;
        }
        // 每个值期望 1000 次；偏离 30% 以上的概率可以忽略
        assert!(seen.iter().all(|&n| (700..=1300).contains(&n)), "{seen:?}");
        let big = random_below(u32::MAX).unwrap();
        assert!(big < u32::MAX);
    }
}
