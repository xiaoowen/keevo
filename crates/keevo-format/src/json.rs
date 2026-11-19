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

/// 错误先后的第 0 步（`spec/vault-format.md` §1.1）：文档是 JSON 对象，且 `v` 是能用 64 位有符号整数
/// 表示的整数但不是 `expected` 时，返回 [`FormatError::UnsupportedVersion`]，先于结构检查。
/// 新版本的文档可能带有本版本不认识的字段，否则会被误报为 `malformed`。
///
/// 只读取 `v`：其余成员按 [`serde::de::IgnoredAny`] 跳过，不构造任何值。其他情况（不是对象、没有 `v`、
/// `v` 不是整数、重复的 `v`）交给之后的结构检查。
pub(crate) fn check_version(bytes: &[u8], expected: u32) -> Result<()> {
    check_version_in(bytes, &[expected])
}

/// 同 [`check_version`]，但接受若干个版本（条目详情：v1 与 v2）。
pub(crate) fn check_version_in(bytes: &[u8], known: &[u32]) -> Result<()> {
    #[derive(serde::Deserialize)]
    struct Probe {
        v: Option<i64>,
    }
    if let Ok(Probe { v: Some(v) }) = serde_json::from_slice::<Probe>(bytes)
        && !known.iter().any(|k| i64::from(*k) == v)
    {
        return Err(FormatError::UnsupportedVersion(
            u32::try_from(v).unwrap_or(u32::MAX),
        ));
    }
    Ok(())
}
