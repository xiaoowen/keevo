//! `keevo run` 的输出遮蔽（`spec/cli.md` §7）：把子进程输出中出现的已解析值替换为 [`MASK`]。
//!
//! 按字节流处理：输出末尾可能是某个值的开头时先留着，等下一块数据（或超时）再决定。
//! 遮蔽只是防止意外露出，不是安全边界。

use zeroize::Zeroizing;

/// 替换文本。
pub(crate) const MASK: &[u8] = b"<concealed by keevo>";
/// 少于这个长度的值不遮蔽（避免把常见的短字符串都替换掉）。
pub(crate) const MIN_MASKED_LEN: usize = 4;

/// 流式遮蔽器。
pub(crate) struct Masker {
    /// 要遮蔽的值，按长度从长到短（同一位置优先匹配更长的值）。
    secrets: Vec<Zeroizing<Vec<u8>>>,
    /// 留着待定的字节。
    pending: Zeroizing<Vec<u8>>,
}

impl Masker {
    /// 由已解析的值创建；短于 [`MIN_MASKED_LEN`] 的值与重复的值被忽略。
    #[must_use]
    pub(crate) fn new<'a>(values: impl IntoIterator<Item = &'a str>) -> Self {
        let mut secrets: Vec<Zeroizing<Vec<u8>>> = values
            .into_iter()
            .filter(|v| v.len() >= MIN_MASKED_LEN)
            .map(|v| Zeroizing::new(v.as_bytes().to_vec()))
            .collect();
        secrets.sort_by(|a, b| {
            b.len()
                .cmp(&a.len())
                .then_with(|| a.as_slice().cmp(b.as_slice()))
        });
        secrets.dedup_by(|a, b| a.as_slice() == b.as_slice());
        Self {
            secrets,
            pending: Zeroizing::new(Vec::new()),
        }
    }

    /// 是否没有需要遮蔽的值。
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    /// 送入一块输出，返回可以立即写出的部分。
    pub(crate) fn push(&mut self, data: &[u8]) -> Vec<u8> {
        let mut buf = Zeroizing::new(std::mem::take(&mut *self.pending));
        buf.extend_from_slice(data);
        let mut out = Vec::with_capacity(buf.len());
        let mut i = 0usize;
        while let Some(rest) = buf.get(i..) {
            if rest.is_empty() {
                break;
            }
            if let Some(s) = self.secrets.iter().find(|s| rest.starts_with(s)) {
                out.extend_from_slice(MASK);
                i = i.saturating_add(s.len());
                continue;
            }
            // 剩下的字节可能是某个值的开头：留到下一块
            if self
                .secrets
                .iter()
                .any(|s| rest.len() < s.len() && s.starts_with(rest))
            {
                self.pending.extend_from_slice(rest);
                break;
            }
            if let Some(&b) = rest.first() {
                out.push(b);
            }
            i = i.saturating_add(1);
        }
        out
    }

    /// 输出结束（或等待超时）：写出留着的字节。
    pub(crate) fn flush(&mut self) -> Vec<u8> {
        std::mem::take(&mut *self.pending)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn all(m: &mut Masker, chunks: &[&[u8]]) -> String {
        let mut out = Vec::new();
        for c in chunks {
            out.extend(m.push(c));
        }
        out.extend(m.flush());
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn masks_values_within_and_across_chunks() {
        let mut m = Masker::new(["s3cret-token", "abc"]);
        assert_eq!(
            all(&mut m, &[b"key=s3cret-token\n"]),
            "key=<concealed by keevo>\n"
        );
        // 跨两块
        assert_eq!(
            all(&mut m, &[b"key=s3cr", b"et-token!"]),
            "key=<concealed by keevo>!"
        );
        // 太短的值不遮蔽
        assert_eq!(all(&mut m, &[b"abc"]), "abc");
        // 开头相同但不是这个值
        assert_eq!(all(&mut m, &[b"s3cr", b"ew"]), "s3crew");
        // 结尾是值的开头：flush 时原样写出
        assert_eq!(all(&mut m, &[b"x s3c"]), "x s3c");
    }

    #[test]
    fn prefers_longer_values_and_handles_utf8() {
        let mut m = Masker::new(["密码密码", "密码密码密码"]);
        assert_eq!(
            all(&mut m, &["[密码密码密码]".as_bytes()]),
            "[<concealed by keevo>]"
        );
        let mut m = Masker::new(["aaaa"]);
        assert_eq!(
            all(&mut m, &[b"aaaaaaaaa"]),
            "<concealed by keevo><concealed by keevo>a"
        );
        assert!(Masker::new(["ab"]).is_empty());
    }
}
