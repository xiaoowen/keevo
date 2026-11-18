//! Keevo 的核心逻辑。
//!
//! [`Vault`] 持有唯一的解锁状态：锁定时内存中没有任何密钥；解锁后缓存账户密钥集与各保险库密钥，
//! 条目密钥按需解开、用后即弃。所有写入都会生成新的修订（`spec/revisions.md`），从不原地改写。

mod error;
pub mod local;
pub mod url_match;
mod vault;

pub use error::{CoreError, Result};
pub use local::{EnclaveError, EnclaveKey, EphemeralAgreement, LocalKeys, SecureEnclave};
pub use vault::{Edit, HistoryEntry, ItemSummary, ItemView, NewField, Vault, VaultInfo};

pub use keevo_crypto::{AccountSecretKey, Id128, KdfParams, LocalPurpose};
pub use keevo_format::{
    Conflict, FieldData, FieldKind, FieldValue, ItemDoc, ItemOverview, ItemType, KvEntry, Purpose,
    RecordKey, RecordValue, RecordVersion, SecretString,
};
pub use keevo_store::Store;
