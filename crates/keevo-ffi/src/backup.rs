//! 自动加密备份与恢复（`docs/product.md` §5.7，设计稿"macOS · 备份与恢复"）。
//!
//! 备份目录由 Swift 决定（默认 `~/Library/Application Support/Keevo/backups`，可以改到外部文件夹）；
//! 何时备份也由 Swift 决定：每天一次（[`auto_backup_due`]），以及导入与恢复之前。

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use keevo_core::CoreError;
use keevo_core::backup::{self, Kind};

use crate::{KeevoError, KeevoVault};

/// 一份备份。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BackupInfo {
    /// 文件路径。
    pub path: String,
    /// 创建时间（Unix 毫秒）。
    pub created_ms: u64,
    /// 原因：`auto`、`manual`、`import`、`delete`、`restore`。
    pub kind: String,
    /// 文件大小（字节）。
    pub size: u64,
}

impl From<backup::Backup> for BackupInfo {
    fn from(b: backup::Backup) -> Self {
        Self {
            path: b.path.to_string_lossy().into_owned(),
            created_ms: b.created_ms,
            kind: b.kind.as_str().to_owned(),
            size: b.size,
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// 备份文件的错误：`not_backup`（不是 Keevo 备份或已损坏）、`newer_version`（来自更新版本的 Keevo）、
/// `other_account`（属于另一个账户）。其余错误照常转换。
fn backup_error(e: CoreError) -> KeevoError {
    match e {
        CoreError::OtherAccount => KeevoError::Backup {
            code: "other_account".into(),
        },
        CoreError::Store(keevo_core::StoreError::UnsupportedSchema(_)) => KeevoError::Backup {
            code: "newer_version".into(),
        },
        CoreError::Store(
            keevo_core::StoreError::Corrupt(_) | keevo_core::StoreError::Sqlite(_),
        ) => KeevoError::Backup {
            code: "not_backup".into(),
        },
        other => other.into(),
    }
}

/// 目录中的备份，新的在前。
#[uniffi::export]
#[must_use]
pub fn list_backups(dir: String) -> Vec<BackupInfo> {
    backup::list(Path::new(&dir))
        .into_iter()
        .map(Into::into)
        .collect()
}

/// 是否该做每天的自动备份。
#[uniffi::export]
#[must_use]
pub fn auto_backup_due(dir: String) -> bool {
    backup::auto_due(Path::new(&dir), now_ms())
}

/// 只保留最新的 `keep` 份。返回删除的份数。
///
/// # Errors
/// 文件无法删除。
#[uniffi::export]
pub fn prune_backups(dir: String, keep: u32) -> Result<u32, KeevoError> {
    let keep = usize::try_from(keep).unwrap_or(usize::MAX);
    let removed = backup::prune(Path::new(&dir), keep, now_ms())?;
    Ok(u32::try_from(removed).unwrap_or(u32::MAX))
}

#[uniffi::export]
impl KeevoVault {
    /// 备份到 `dir`。`kind`：`auto`、`manual`、`import`、`delete`。锁定时也可以进行（备份中只有密文）。
    ///
    /// # Errors
    /// `kind` 不认识；目录无法创建或文件无法写入。
    pub fn create_backup(&self, dir: String, kind: String) -> Result<BackupInfo, KeevoError> {
        let kind = Kind::parse(&kind)
            .filter(|k| *k != Kind::Restore)
            .ok_or_else(|| KeevoError::InvalidInput {
                message: "backup kind".into(),
            })?;
        Ok(backup::create(&self.vault(), Path::new(&dir), kind, now_ms())?.into())
    }

    /// 检查 `path` 能否用来恢复这个保险库（不改变任何东西）。
    ///
    /// # Errors
    /// [`KeevoError::Backup`]。
    pub fn check_backup(&self, path: String) -> Result<(), KeevoError> {
        self.vault()
            .check_backup(Path::new(&path))
            .map_err(backup_error)
    }

    /// 从备份恢复：先把当前的保险库备份到 `dir`，再替换。之后保险库处于锁定状态，界面应回到解锁页。
    /// 返回恢复之前的那份备份。
    ///
    /// # Errors
    /// [`KeevoError::Backup`]；写入失败。失败时什么都不改变。
    pub fn restore_backup(&self, path: String, dir: String) -> Result<BackupInfo, KeevoError> {
        let safety = {
            let mut vault = self.vault();
            backup::restore(&mut vault, Path::new(&path), Path::new(&dir), now_ms())
                .map_err(backup_error)?
        };
        // 与锁定相同：丢弃内存中的秘密、检查结果与搜索索引
        self.lock();
        Ok(safety.into())
    }
}
