//! 自动加密备份（`docs/sync.md` §2、`docs/product.md` §5.7，设计稿"macOS · 备份与恢复"）。
//!
//! 一份备份是整个数据库的一致副本（[`keevo_store::Store::backup_to`]），一个文件，内容与数据库相同、
//! 仍然只有密文：打开它需要主密码与账户密钥。文件名记录时间与原因（UTC），例如
//! `keevo-20261119-143200-auto.keevo-backup`；不记录任何条目信息。
//!
//! 恢复替换整个数据库（[`Vault::restore_from`]）。恢复之前先备份当前的数据库，恢复之后保险库处于锁定状态。

use std::path::{Path, PathBuf};

use crate::error::{CoreError, Result};
use crate::vault::Vault;

/// 备份文件的扩展名。
pub const EXTENSION: &str = "keevo-backup";
/// 默认保留的份数。
pub const DEFAULT_KEEP: usize = 30;
/// 自动备份的间隔：每天一次。
pub const AUTO_INTERVAL_MS: u64 = 24 * 60 * 60 * 1000;

/// 备份的原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// 每天的自动备份。
    Auto,
    /// 用户点了"立即备份"。
    Manual,
    /// 导入之前。
    Import,
    /// 批量删除（清空最近删除）之前。
    Delete,
    /// 从备份恢复之前（当前的数据库）。
    Restore,
}

impl Kind {
    /// 文件名中的写法。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Manual => "manual",
            Self::Import => "import",
            Self::Delete => "delete",
            Self::Restore => "restore",
        }
    }

    /// 由文件名中的写法解析。
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "auto" => Self::Auto,
            "manual" => Self::Manual,
            "import" => Self::Import,
            "delete" => Self::Delete,
            "restore" => Self::Restore,
            _ => return None,
        })
    }
}

/// 一份备份。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backup {
    /// 文件路径。
    pub path: PathBuf,
    /// 创建时间（Unix 毫秒，取自文件名，精确到秒）。
    pub created_ms: u64,
    /// 原因。
    pub kind: Kind,
    /// 文件大小（字节）。
    pub size: u64,
}

/// 恢复前的检查结果（[`Vault::check_backup`]）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupCheck {
    /// 备份内记录的创建时间（Unix 毫秒）；较早的备份没有。文件名中的时间可以被改动，两者不一致时以它为准
    /// （第五轮预审 K17）。
    pub created_ms: Option<u64>,
    /// 备份的密钥集版本（`epoch`）早于当前：备份之后修改过主密码或轮换过密钥，恢复后要用备份时的旧主密码解锁。
    pub older_master_password: bool,
}

/// 文件名：`keevo-YYYYMMDD-HHMMSS-<原因>.keevo-backup`（UTC）。
#[must_use]
pub fn file_name(created_ms: u64, kind: Kind) -> String {
    let secs = created_ms / 1000;
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "keevo-{y:04}{m:02}{d:02}-{:02}{:02}{:02}-{}.{EXTENSION}",
        rem / 3600,
        (rem / 60) % 60,
        rem % 60,
        kind.as_str()
    )
}

/// 解析文件名，得到创建时间与原因。
#[must_use]
pub fn parse_file_name(name: &str) -> Option<(u64, Kind)> {
    let stem = name
        .strip_prefix("keevo-")?
        .strip_suffix(&format!(".{EXTENSION}"))?;
    let mut parts = stem.splitn(3, '-');
    let (date, time, kind) = (parts.next()?, parts.next()?, parts.next()?);
    if date.len() != 8
        || time.len() != 6
        || !date.chars().chain(time.chars()).all(|c| c.is_ascii_digit())
    {
        return None;
    }
    let num = |s: &str| s.parse::<i64>().ok();
    let (y, m, d) = (
        num(date.get(..4)?)?,
        num(date.get(4..6)?)?,
        num(date.get(6..)?)?,
    );
    let (hh, mm, ss) = (
        num(time.get(..2)?)?,
        num(time.get(2..4)?)?,
        num(time.get(4..)?)?,
    );
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 59 {
        return None;
    }
    let secs = days_from_civil(y, m, d).checked_mul(86_400)?.checked_add(
        hh.checked_mul(3600)?
            .checked_add(mm.checked_mul(60)?)?
            .checked_add(ss)?,
    )?;
    Some((
        u64::try_from(secs).ok()?.checked_mul(1000)?,
        Kind::parse(kind)?,
    ))
}

/// 目录中的备份，新的在前。目录不存在时为空。不认识的文件忽略。
#[must_use]
pub fn list(dir: &Path) -> Vec<Backup> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<Backup> = entries
        .filter_map(|e| {
            let e = e.ok()?;
            let name = e.file_name().into_string().ok()?;
            let (created_ms, kind) = parse_file_name(&name)?;
            let meta = e.metadata().ok().filter(std::fs::Metadata::is_file)?;
            Some(Backup {
                path: e.path(),
                created_ms,
                kind,
                size: meta.len(),
            })
        })
        .collect();
    out.sort_by(|a, b| {
        b.created_ms
            .cmp(&a.created_ms)
            .then_with(|| b.path.cmp(&a.path))
    });
    out
}

/// 备份到 `dir`（必要时创建，权限 0700；备份文件 0600）。同一秒内的同类备份不会覆盖：文件名已存在时稍后一秒。
///
/// # Errors
/// 目录无法创建、文件无法写入。
pub fn create(vault: &Vault, dir: &Path, kind: Kind, now_ms: u64) -> Result<Backup> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(io)?;
    let mut created = now_ms.saturating_sub(now_ms % 1000);
    let mut path = dir.join(file_name(created, kind));
    while path.exists() {
        created = created.saturating_add(1000);
        path = dir.join(file_name(created, kind));
    }
    vault.backup_to(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(io)?;
    // 文件名可以被改动；备份内另记一份创建时间，恢复时以它为准（第五轮预审 K17）
    // 记下与文件名相同的时间：文件没有被改名时两者完全一致
    if let Err(e) = keevo_store::Store::mark_backup(&path, created) {
        let _ = std::fs::remove_file(&path);
        return Err(e.into());
    }
    let size = std::fs::metadata(&path).map_err(io)?.len();
    Ok(Backup {
        path,
        created_ms: created,
        kind,
        size,
    })
}

/// 文件名时间晚于"现在"这么多的文件不参与清理：它们不是这台设备刚写的（同步盘中的其他写入，或曾经的时钟错误）。
pub const FUTURE_SLACK_MS: u64 = 60 * 60 * 1000;

/// 只保留最新的 `keep` 份，删除更早的。返回删除的份数。
///
/// 文件名时间晚于 `now_ms` 超过 [`FUTURE_SLACK_MS`] 的文件既不计入、也不删除，否则这样的文件会让每次清理都删掉
/// 刚刚创建的真实备份（第五轮预审 K7）。
///
/// # Errors
/// 文件无法删除。
pub fn prune(dir: &Path, keep: usize, now_ms: u64) -> Result<usize> {
    let mut removed = 0usize;
    let limit = now_ms.saturating_add(FUTURE_SLACK_MS);
    for b in list(dir)
        .into_iter()
        .filter(|b| b.created_ms <= limit)
        .skip(keep.max(1))
    {
        std::fs::remove_file(&b.path).map_err(io)?;
        removed = removed.saturating_add(1);
    }
    Ok(removed)
}

/// 是否该做每天的自动备份：没有自动备份，或最近一次已经超过 24 小时（时钟回拨时也算到期）。
#[must_use]
pub fn auto_due(dir: &Path, now_ms: u64) -> bool {
    list(dir)
        .into_iter()
        .find(|b| b.kind == Kind::Auto)
        .is_none_or(|b| {
            b.created_ms > now_ms || now_ms.saturating_sub(b.created_ms) >= AUTO_INTERVAL_MS
        })
}

/// 从备份恢复：先把当前的数据库备份到 `dir`（原因为"恢复之前"），再用 `src` 替换整个数据库。之后保险库处于锁定状态。
///
/// # Errors
/// 备份无效、来自更新版本，或写入失败。失败时数据库保持原样。
pub fn restore(vault: &mut Vault, src: &Path, dir: &Path, now_ms: u64) -> Result<Backup> {
    vault.check_backup(src)?;
    let safety = create(vault, dir, Kind::Restore, now_ms)?;
    vault.restore_from(src)?;
    Ok(safety)
}

#[allow(clippy::needless_pass_by_value, reason = "用于 map_err")]
fn io(e: std::io::Error) -> CoreError {
    CoreError::Io(e.kind())
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "日期在 1970–9999 年之间，不会溢出"
)]
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "日期在 1970–9999 年之间，不会溢出"
)]
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn file_names_round_trip() {
        // 2026-11-19 16:32:00 UTC
        let ms = 1_795_105_920_000;
        let name = file_name(ms, Kind::Import);
        assert_eq!(name, "keevo-20261119-163200-import.keevo-backup");
        assert_eq!(parse_file_name(&name), Some((ms, Kind::Import)));
        for bad in [
            "keevo-20261119-143200-other.keevo-backup",
            "keevo-2026111-143200-auto.keevo-backup",
            "vault.sqlite",
            "keevo-20261340-143200-auto.keevo-backup",
        ] {
            assert_eq!(parse_file_name(bad), None, "{bad}");
        }
        for days in [0, 19_000, 20_776, 2_932_896] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
    }

    #[test]
    fn create_list_prune_restore() {
        use keevo_crypto::KdfParams;
        let dir = std::env::temp_dir().join(format!(
            "keevo-backup-{}",
            keevo_crypto::Id128::random().unwrap().to_hex()
        ));
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());
        std::fs::create_dir_all(&dir).unwrap();
        let params = KdfParams::new(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1, [5; 16]).unwrap();
        let (mut v, sk) = Vault::create(&dir.join("vault.sqlite"), "pw", params).unwrap();
        let vault_id = v.vaults().unwrap()[0].id;
        let backups = dir.join("backups");
        let day = AUTO_INTERVAL_MS;
        let t0 = 1_795_105_920_000;

        assert!(auto_due(&backups, t0), "还没有自动备份");
        let first = create(&v, &backups, Kind::Auto, t0).unwrap();
        assert!(!auto_due(&backups, t0 + day - 1));
        assert!(auto_due(&backups, t0 + day));
        let again = create(&v, &backups, Kind::Auto, t0).unwrap();
        assert_ne!(again.path, first.path, "同一秒内不覆盖");
        // 备份内另记一份创建时间，不依赖文件名（第五轮预审 K17）
        assert_eq!(
            keevo_store::Store::inspect_backup(&first.path)
                .unwrap()
                .created_ms,
            Some(t0)
        );
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&first.path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        // 备份之后新建条目；从第一份备份恢复后条目不见了，保险库锁定，用原来的主密码解锁
        v.create_item(
            vault_id,
            keevo_format::ItemType::SecureNote,
            "备份之后",
            vec![],
        )
        .unwrap();
        let safety = restore(&mut v, &first.path, &backups, t0 + 5000).unwrap();
        assert_eq!(safety.kind, Kind::Restore);
        assert!(!v.is_unlocked());
        v.unlock("pw", &sk).unwrap();
        assert!(
            v.items()
                .unwrap()
                .iter()
                .all(|i| i.overview.title != "备份之后")
        );
        // 恢复之前的备份中仍有这个条目
        let listed = list(&backups);
        assert_eq!(listed.len(), 3);
        assert_eq!(listed[0].kind, Kind::Restore, "新的在前");

        assert_eq!(prune(&backups, 1, t0 + 10_000).unwrap(), 2);
        assert_eq!(list(&backups).len(), 1);
        let junk = dir.join("junk.keevo-backup");
        std::fs::write(&junk, b"junk").unwrap();
        assert!(restore(&mut v, &junk, &backups, t0 + 9000).is_err());
        assert!(v.is_unlocked(), "无效的备份不改变任何东西");
    }
}
