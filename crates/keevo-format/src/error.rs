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
    /// 同一修订 ID 出现了不同的元数据（父修订或来源设备）。只可能来自损坏的数据或恶意设备。
    RevisionConflict,
    /// 记录键上没有指定的版本。
    NoSuchVersion,
    /// 修订的父修订不在修订图中（父修订必须先于子修订加入，因此也排除了环）。
    MissingParent,
    /// 单个记录值编码后超过 256 KiB（`spec/vault-format.md` §2），或整数超出 ±(2⁵³−1)。
    ValueTooLarge,
    /// 条目详情编码后超过单个信封的明文上限（`spec/revisions.md` §7.1）。读取不受影响；
    /// 需要先精简（处理冲突、删除字段）才能保存。
    ItemTooLarge,
    /// HLC 已达到上限，无法再生成更大的时间戳。
    ClockExhausted,
    /// 保留键（`attr:purged`）不能由客户端直接写入，或以规范不允许的形态出现。
    ReservedKey,
    /// 条目的记录键超过 [`crate::MAX_KEYS`] 个。
    TooManyKeys,
    /// 修订的父修订超过 [`crate::MAX_GRAPH_PARENTS`] 个。
    TooManyParents,
    /// 记录键的名称不合法（`spec/vault-format.md` §2）。
    InvalidKey,
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(at) => write!(f, "malformed: {at}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported format version {v}"),
            Self::ValueKindMismatch => f.write_str("record value kind does not match key"),
            Self::ItemTypeMismatch => f.write_str("heads disagree on item type"),
            Self::NoHeads => f.write_str("no heads to merge"),
            Self::RevisionConflict => f.write_str("conflicting metadata for the same revision"),
            Self::NoSuchVersion => f.write_str("no such record version"),
            Self::MissingParent => f.write_str("parent revision is not in the graph"),
            Self::ValueTooLarge => f.write_str("record value is too large"),
            Self::ItemTooLarge => f.write_str("item exceeds the envelope size limit"),
            Self::ClockExhausted => f.write_str("hlc exhausted"),
            Self::ReservedKey => f.write_str("reserved record key"),
            Self::TooManyKeys => f.write_str("too many record keys"),
            Self::TooManyParents => f.write_str("too many parent revisions"),
            Self::InvalidKey => f.write_str("invalid record key"),
        }
    }
}

impl FormatError {
    /// 规范中的错误码（`spec/vault-format.md`、`spec/revisions.md`），测试向量与诊断信息使用。
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Malformed(_) => "malformed",
            Self::UnsupportedVersion(_) => "unsupported_version",
            Self::ValueKindMismatch => "value_kind_mismatch",
            Self::ItemTypeMismatch => "item_type_mismatch",
            Self::NoHeads => "no_heads",
            Self::RevisionConflict => "revision_conflict",
            Self::NoSuchVersion => "no_such_version",
            Self::MissingParent => "missing_parent",
            Self::ValueTooLarge => "value_too_large",
            Self::ItemTooLarge => "item_too_large",
            Self::ClockExhausted => "clock_exhausted",
            Self::ReservedKey => "reserved_key",
            Self::TooManyKeys => "too_many_keys",
            Self::TooManyParents => "too_many_parents",
            Self::InvalidKey => "invalid_key",
        }
    }
}

impl std::error::Error for FormatError {}
