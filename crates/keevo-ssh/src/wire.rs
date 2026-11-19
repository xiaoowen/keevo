//! SSH 线上编码（RFC 4251 §5）：`byte`、`boolean`、`uint32`、`string`。

use std::fmt;

/// 解码错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// 数据在某个字段中间结束。
    Truncated,
    /// 规定的字段之后还有多余的字节。
    TrailingBytes,
    /// 长度超出范围。
    TooLong,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated",
            Self::TrailingBytes => "trailing bytes",
            Self::TooLong => "too long",
        })
    }
}

impl std::error::Error for WireError {}

/// 按顺序读取字段。
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    /// 从 `buf` 开始读取。
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let (head, rest) = self.buf.split_at_checked(n).ok_or(WireError::Truncated)?;
        self.buf = rest;
        Ok(head)
    }

    /// `byte`。
    ///
    /// # Errors
    /// 数据不足时返回 [`WireError::Truncated`]。
    pub fn u8(&mut self) -> Result<u8, WireError> {
        self.take(1)?.first().copied().ok_or(WireError::Truncated)
    }

    /// `boolean`：0 为假，其他值为真（RFC 4251 §5）。
    ///
    /// # Errors
    /// 数据不足时返回 [`WireError::Truncated`]。
    pub fn bool(&mut self) -> Result<bool, WireError> {
        Ok(self.u8()? != 0)
    }

    /// `uint32`（大端）。
    ///
    /// # Errors
    /// 数据不足时返回 [`WireError::Truncated`]。
    pub fn u32(&mut self) -> Result<u32, WireError> {
        let b: [u8; 4] = self.take(4)?.try_into().map_err(|_| WireError::Truncated)?;
        Ok(u32::from_be_bytes(b))
    }

    /// `string`：`uint32` 长度 + 字节。
    ///
    /// # Errors
    /// 数据不足时返回 [`WireError::Truncated`]。
    pub fn string(&mut self) -> Result<&'a [u8], WireError> {
        let len = usize::try_from(self.u32()?).map_err(|_| WireError::TooLong)?;
        self.take(len)
    }

    /// 剩余的字节。
    #[must_use]
    pub fn remaining(&self) -> &'a [u8] {
        self.buf
    }

    /// 要求已经读完。
    ///
    /// # Errors
    /// 还有多余字节时返回 [`WireError::TrailingBytes`]。
    pub fn finish(&self) -> Result<(), WireError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(WireError::TrailingBytes)
        }
    }
}

/// 按顺序写入字段。
#[derive(Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// 空的缓冲区。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `byte`。
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    /// `boolean`。
    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.u8(u8::from(v))
    }

    /// `uint32`（大端）。
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// `string`。长度超过 `u32` 的部分不会出现：调用方只写入有界的数据。
    pub fn string(&mut self, v: &[u8]) -> &mut Self {
        let len = u32::try_from(v.len()).unwrap_or(u32::MAX);
        self.u32(len);
        self.buf.extend_from_slice(v);
        self
    }

    /// 原样追加字节。
    pub fn raw(&mut self, v: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(v);
        self
    }

    /// 已写入的长度。
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// 取出缓冲区。
    #[must_use]
    pub fn into_inner(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut w = Writer::new();
        w.u8(7).bool(true).u32(0xdead_beef).string(b"ssh-ed25519");
        let bytes = w.into_inner();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.u8().unwrap(), 7);
        assert!(r.bool().unwrap());
        assert_eq!(r.u32().unwrap(), 0xdead_beef);
        assert_eq!(r.string().unwrap(), b"ssh-ed25519");
        r.finish().unwrap();
    }

    #[test]
    fn rejects_truncated_and_trailing() {
        assert_eq!(Reader::new(&[0, 0, 0]).u32(), Err(WireError::Truncated));
        assert_eq!(
            Reader::new(&[0, 0, 0, 5, 1]).string(),
            Err(WireError::Truncated)
        );
        assert_eq!(
            Reader::new(&[0xff, 0xff, 0xff, 0xff]).string(),
            Err(WireError::Truncated)
        );
        let mut r = Reader::new(&[1, 2]);
        r.u8().unwrap();
        assert_eq!(r.finish(), Err(WireError::TrailingBytes));
    }
}
