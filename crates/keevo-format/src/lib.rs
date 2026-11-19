//! Keevo 的数据模型。
//!
//! 实现 `spec/revisions.md`（修订图、记录、HLC、因果合并）与 `spec/vault-format.md`
//! （条目明文结构）。本 crate 只做纯数据处理，不涉及加密与存储。
//!
//! - [`ItemDoc`]：一个修订的完整明文，即记录映射。
//! - [`RevisionGraph`]：修订图，用于判断祖先关系。
//! - [`merge_heads`]：把多个头修订合并为确定的视图。
//! - [`HlcClock`]：混合逻辑时钟。

mod error;
mod graph;
mod hlc;
mod id_hex;
mod item;
mod json;
mod merge;
mod order;
mod record;
mod secret;

pub use error::{FormatError, Result};
pub use graph::{MAX_GRAPH_PARENTS, RevisionGraph};
pub use hlc::{Hlc, HlcClock, MAX_ADOPT_SKEW_MS};
pub use item::{FieldKind, ITEM_DETAILS_V2, ItemDoc, ItemOverview, ItemType, Purpose, VaultMeta};
pub use json::{from_canonical_json, from_json, to_json};
pub use merge::{Conflict, HeadState, Merged, PURGED_ATTR, TRASHED_ATTR, merge_heads};
pub use order::{MAX_ORDER_LEN, order_between, order_sequence};
pub use record::{
    AttachmentRef, CodeEntry, ConcurrentMap, FieldData, FieldValue, KvEntry, MAX_KEYS,
    MAX_SAFE_INT, MAX_VALUE_LEN, RecordKey, RecordMap, RecordValue, RecordVersion, SectionValue,
};
pub use secret::SecretString;

/// 明文格式版本（`spec/vault-format.md`）。
pub const FORMAT_VERSION: u32 = 1;
