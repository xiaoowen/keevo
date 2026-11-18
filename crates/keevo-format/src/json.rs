use std::io;

use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use crate::error::{FormatError, Result};

struct Counter(usize);

impl io::Write for Counter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 = self.0.saturating_add(buf.len());
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// 序列化为 JSON。先计算长度再一次性分配，避免扩容时在已释放内存中留下明文副本。
///
/// # Errors
/// 序列化失败时返回 [`FormatError::Malformed`]。
pub fn to_json<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>> {
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value)
        .map_err(|e| FormatError::Malformed(e.to_string()))?;
    let mut out = Zeroizing::new(Vec::with_capacity(counter.0));
    serde_json::to_writer(&mut *out, value).map_err(|e| FormatError::Malformed(e.to_string()))?;
    Ok(out)
}

/// 从 JSON 反序列化。错误信息只包含行列位置，不含内容。
///
/// # Errors
/// 结构不符合预期时返回 [`FormatError::Malformed`]。
pub fn from_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes)
        .map_err(|e| FormatError::Malformed(format!("line {} column {}", e.line(), e.column())))
}

/// 解码，并要求输入恰好是其规范编码（`spec/vault-format.md` §1）：解析后重新编码，必须与输入逐字节相同。
/// 因此字段顺序、空白、转义、数字写法、可选字段的 `null`、结构体写成数组等，都只有一种合法写法。
///
/// # Errors
/// 结构错误或不是规范编码时返回 [`FormatError::Malformed`]。
pub fn from_canonical_json<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
    let value: T = from_json(bytes)?;
    if to_json(&value)?.as_slice() != bytes {
        return Err(FormatError::Malformed("not canonical".into()));
    }
    Ok(value)
}
