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
