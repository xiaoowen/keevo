//! 导入与导出（`docs/product.md` §5.7，设计稿"macOS · 导入与导出"，`spec/export.md`）。
//!
//! 导入分两步：[`KeevoVault::prepare_import`] 读取并解析文件，返回预览（解析结果留在内存中）；用户确认后
//! [`KeevoVault::commit_import`] 在一个事务中写入。导入文件由这里直接读取，明文不经过 Swift。
//! 导出同样由这里直接写文件（权限 0600）；明文格式要求刚刚重新验证过用户（[`KeevoVault::reverify`]）。

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

use keevo_core::export::{self, Format};
use keevo_core::import::{self, ImportError, Imported, Source};

use crate::{KeevoError, KeevoVault, parse_id};

/// 明文导出须在重新验证之后多久之内进行。
const REVERIFY_WINDOW: Duration = Duration::from_secs(120);

/// 等待确认的导入。
pub(crate) struct Pending {
    items: Vec<Imported>,
    duplicates: Vec<bool>,
}

/// 预览中的一组：同一类型（以及作为安全笔记导入时的原类别）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ImportGroup {
    /// Keevo 中的类型（`login` 等）。
    pub item_type: String,
    /// 作为安全笔记导入时原来的类别（`credit_card`、`identity` 等）。
    pub original: Option<String>,
    /// 条目数。
    pub count: u32,
}

/// 导入预览。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ImportPreview {
    /// 将要导入的条目，按类型分组（不含重复的）。
    pub groups: Vec<ImportGroup>,
    /// 将要导入的条目数。
    pub total: u32,
    /// 与保险库中已有的登录完全相同、将跳过的条目数。
    pub duplicates: u32,
    /// 带有附件（暂不导入）的条目数。
    pub with_attachments: u32,
}

/// 导入结果。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ImportResult {
    /// 新条目的 ID（用于撤销与"查看导入的条目"）。
    pub item_ids: Vec<String>,
    /// 跳过的重复条目数。
    pub skipped: u32,
    /// 带有附件（暂不导入）的条目数。
    pub with_attachments: u32,
}

fn import_error(e: ImportError) -> KeevoError {
    KeevoError::Import {
        code: e.code().into(),
    }
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// 支持的导入来源：`keevo`、`1password`、`bitwarden`、`chrome`、`safari`、`firefox`、`lastpass`。
#[uniffi::export]
#[must_use]
pub fn import_sources() -> Vec<String> {
    Source::ALL.iter().map(|s| s.as_str().to_owned()).collect()
}

/// 文件是否为 Keevo 的加密导出文件（选择文件后决定是否先询问导出密码）。
#[uniffi::export]
#[must_use]
pub fn is_keevo_export(path: String) -> bool {
    use std::io::Read;
    let mut head = [0u8; 8];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok_and(|()| keevo_crypto_magic(&head))
}

fn keevo_crypto_magic(head: &[u8]) -> bool {
    head == b"KEEVOEXP"
}

#[uniffi::export]
impl KeevoVault {
    /// 读取并解析导入文件，返回预览。`password` 为有密码保护的文件的密码：需要而没有给出时返回
    /// `KeevoError::Import { code: "password_required" }`。耗时可能较长（解密、比对重复），请在后台线程调用。
    ///
    /// # Errors
    /// 已锁定；文件无法读取；[`KeevoError::Import`]（`not_recognized`、`password_required`、`wrong_password`、
    /// `account_restricted`、`too_large`、`malformed`、`empty`）。
    pub fn prepare_import(
        &self,
        path: String,
        source: String,
        password: Option<String>,
    ) -> Result<ImportPreview, KeevoError> {
        let source = Source::parse(&source).ok_or_else(|| KeevoError::InvalidInput {
            message: "import source".into(),
        })?;
        // 先确认已解锁，再读文件
        self.vault().vaults()?;
        let data = crate::read_bounded(&path, import::MAX_FILE_LEN)
            .map_err(|_| import_error(ImportError::NotRecognized))?
            .ok_or_else(|| import_error(ImportError::TooLarge))?;
        let password = password.map(zeroize::Zeroizing::new);
        let parsed = import::parse(source, &data, password.as_deref().map(String::as_str))
            .map_err(import_error)?;
        drop(data);
        let duplicates = import::duplicates(&self.vault(), &parsed.items)?;
        let mut groups: BTreeMap<(String, Option<String>), u32> = BTreeMap::new();
        let mut with_attachments = 0usize;
        for (item, dup) in parsed.items.iter().zip(&duplicates) {
            if *dup {
                continue;
            }
            let key = (
                crate::item_type_name(item.item_type).to_owned(),
                item.original.map(str::to_owned),
            );
            let n = groups.entry(key).or_default();
            *n = n.saturating_add(1);
            if item.attachments > 0 {
                with_attachments = with_attachments.saturating_add(1);
            }
        }
        let skipped = duplicates.iter().filter(|d| **d).count();
        let preview = ImportPreview {
            groups: groups
                .into_iter()
                .map(|((item_type, original), count)| ImportGroup {
                    item_type,
                    original,
                    count,
                })
                .collect(),
            total: count(parsed.items.len().saturating_sub(skipped)),
            duplicates: count(skipped),
            with_attachments: count(with_attachments),
        };
        *self.pending_import() = Some(Pending {
            items: parsed.items,
            duplicates,
        });
        Ok(preview)
    }

    /// 写入等待确认的导入：跳过重复的条目，每个条目加上 `tag`（例如"导入 · Bitwarden"）。在一个事务中完成，
    /// 失败时什么都不写。调用方之前应先备份（`create_backup(kind: "import")`）。
    ///
    /// # Errors
    /// 没有等待确认的导入；已锁定；保险库不存在；某个条目过大。
    pub fn commit_import(
        &self,
        vault_id: String,
        tag: Option<String>,
    ) -> Result<ImportResult, KeevoError> {
        let vault_id = parse_id(&vault_id)?;
        let pending = self
            .pending_import()
            .take()
            .ok_or_else(|| KeevoError::InvalidInput {
                message: "no pending import".into(),
            })?;
        let mut skipped = 0usize;
        let mut with_attachments = 0usize;
        let items: Vec<Imported> = pending
            .items
            .into_iter()
            .zip(pending.duplicates)
            .filter_map(|(item, dup)| {
                if dup {
                    skipped = skipped.saturating_add(1);
                    return None;
                }
                if item.attachments > 0 {
                    with_attachments = with_attachments.saturating_add(1);
                }
                Some(item)
            })
            .collect();
        let tag = tag.filter(|t| !t.trim().is_empty());
        let ids = self.vault().import_items(vault_id, items, tag.as_deref())?;
        Ok(ImportResult {
            item_ids: ids.iter().map(keevo_core::Id128::to_hex).collect(),
            skipped: count(skipped),
            with_attachments: count(with_attachments),
        })
    }

    /// 放弃等待确认的导入（清除内存中的解析结果）。
    pub fn cancel_import(&self) {
        *self.pending_import() = None;
    }

    /// 撤销导入：把这些条目移到最近删除（可以从那里恢复）。已经不存在的条目跳过。返回移动的条目数。
    ///
    /// # Errors
    /// 已锁定。
    pub fn undo_import(&self, item_ids: Vec<String>) -> Result<u32, KeevoError> {
        let mut vault = self.vault();
        let mut moved = 0u32;
        for id in &item_ids {
            match vault.trash_item(parse_id(id)?) {
                Ok(()) => moved = moved.saturating_add(1),
                Err(keevo_core::CoreError::NotFound) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(moved)
    }

    /// 导出到 `path`（新文件，权限 0600）。`format`：`keevo`（需要 `export_password`，满足 [`export_password_ok`]）、
    /// `json`、`csv`。`vault_id` 为 `None` 时导出全部保险库。任何格式都要求 2 分钟内为导出重新验证过用户
    /// （[`KeevoVault::reverify_for_export`]），且每次验证只能导出一次。返回导出的条目数。加密导出约需一秒。
    ///
    /// # Errors
    /// 已锁定；保险库不存在；导出密码不满足要求；没有为导出重新验证（`InvalidInput { message: "reverify" }`）；
    /// 文件无法写入。
    pub fn export_vault(
        &self,
        path: String,
        format: String,
        vault_id: Option<String>,
        export_password: Option<String>,
    ) -> Result<u32, KeevoError> {
        let format = Format::parse(&format).ok_or_else(|| KeevoError::InvalidInput {
            message: "export format".into(),
        })?;
        let only = vault_id.as_deref().map(parse_id).transpose()?;
        // 每次导出都要求刚刚为导出重新验证过（第五轮预审 K15）：加密导出也一样，拿到文件和导出密码的人就能
        // 读出全部条目。标记只由 reverify_for_export 签发，用一次即作废，其他用途的重新验证不算
        let fresh = self
            .reverified()
            .take()
            .is_some_and(|at| at.elapsed() <= REVERIFY_WINDOW);
        if !fresh {
            return Err(KeevoError::InvalidInput {
                message: "reverify".into(),
            });
        }
        let password = export_password.map(zeroize::Zeroizing::new);
        let exported = export::export(
            &self.vault(),
            format,
            only,
            password.as_deref().map(String::as_str),
        )?;
        write_new_file(Path::new(&path), &exported.bytes).map_err(|e| KeevoError::Internal {
            message: format!("write export: {e}"),
        })?;
        Ok(count(exported.count))
    }
}

/// 写入新文件（权限 0600）；已存在时替换（保存面板已经确认过覆盖）。先写临时文件再改名，不留下半个文件。
fn write_new_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{name}.keevo-tmp"));
    // 上次导出中途崩溃留下的临时文件（可能是明文）：先删掉，否则它一直留在用户选择的目录中，
    // 而且 create_new 会让这次导出失败（第五轮预审 K22）
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    let result = f.write_all(bytes).and_then(|()| f.sync_all());
    drop(f);
    if let Err(e) = result.and_then(|()| std::fs::rename(&tmp, path)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// 导出密码是否满足要求（`spec/export.md` §3）：至少 10 个字符、不全是空白、强度"很强"。界面用它决定能否继续。
#[uniffi::export]
#[must_use]
pub fn export_password_ok(password: String) -> bool {
    let password = zeroize::Zeroizing::new(password);
    export::export_password_ok(&password)
}

#[uniffi::export]
impl KeevoVault {
    /// 为导出重新验证用户（`password` 为 `None` 时用 Touch ID，会弹出提示，请在后台线程调用）。通过后签发一个
    /// 只能用于下一次导出的标记，2 分钟内有效（[`KeevoVault::export_vault`]）。
    ///
    /// # Errors
    /// 同 [`KeevoVault::reverify`]。
    pub fn reverify_for_export(&self, password: Option<String>) -> Result<(), KeevoError> {
        let proof = password.as_deref().map_or(
            keevo_core::Reverify::TouchId,
            keevo_core::Reverify::Password,
        );
        self.vault().reverify(proof)?;
        *self.reverified() = Some(Instant::now());
        Ok(())
    }
}

impl KeevoVault {
    /// 测试用：记下"刚刚为导出重新验证过"（`reverify_for_export` 成功时做的就是这件事）。
    #[cfg(test)]
    pub(crate) fn note_export_reverified(&self) {
        *self.reverified() = Some(Instant::now());
    }
}
