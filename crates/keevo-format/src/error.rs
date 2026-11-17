use core::fmt;

/// `keevo-format` 的结果类型。
pub type Result<T> = core::result::Result<T, FormatError>;

/// 数据格式错误。不携带任何明文内容。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FormatError {
    /// JSON 结构不符合 `spec/vault-format.md`。附带的是位置信息，不含内容。
    Malformed(String),
    /// 格式版本不受支持。
    UnsupportedVersion(u32),
    /// 记录值的类型与记录键不匹配。
    ValueKindMismatch,
    /// 多个头修订的条目类型不一致。
    ItemTypeMismatch,
    /// 没有可合并的头修订。
    NoHeads,
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(at) => write!(f, "malformed: {at}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported format version {v}"),
            Self::ValueKindMismatch => f.write_str("record value kind does not match key"),
            Self::ItemTypeMismatch => f.write_str("heads disagree on item type"),
            Self::NoHeads => f.write_str("no heads to merge"),
        }
    }
}

impl std::error::Error for FormatError {}
