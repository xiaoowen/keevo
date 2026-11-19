//! 附件（`spec/crypto.md` §8.9，设计稿"macOS · 附件"）：添加、保存、预览。
//! 文件由这里直接读写，内容不经过 Swift。预览写到调用方给出的私有目录（权限 0700），由调用方在
//! 预览结束与锁定时删除。

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use keevo_core::CoreError;
use keevo_core::attachment::MAX_ATTACHMENT_LEN;

use crate::{AttachmentEntry, KeevoError, KeevoVault, parse_id};

fn attachment_error(code: &str) -> KeevoError {
    KeevoError::Attachment { code: code.into() }
}

#[uniffi::export]
impl KeevoVault {
    /// 添加附件：读取 `path`，加密保存到条目中。超过 50 MB 时返回
    /// `KeevoError::Attachment { code: "too_large" }`；文件无法读取时返回 `unreadable`。
    ///
    /// # Errors
    /// 见上；已锁定；条目不存在。
    pub fn add_attachment(
        &self,
        item_id: String,
        path: String,
    ) -> Result<AttachmentEntry, KeevoError> {
        let id = parse_id(&item_id)?;
        let meta = std::fs::metadata(&path).map_err(|_| attachment_error("unreadable"))?;
        if !meta.is_file() {
            return Err(attachment_error("unreadable"));
        }
        if meta.len() > u64::try_from(MAX_ATTACHMENT_LEN).unwrap_or(u64::MAX) {
            return Err(attachment_error("too_large"));
        }
        let data = zeroize::Zeroizing::new(
            std::fs::read(&path).map_err(|_| attachment_error("unreadable"))?,
        );
        let name = Path::new(&path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0));
        let r = self
            .vault()
            .add_attachment(id, &name, &data, now)
            .map_err(|e| match e {
                CoreError::OutOfRange => attachment_error("too_large"),
                other => other.into(),
            })?;
        Ok(AttachmentEntry {
            id: r.id.to_hex(),
            name: r.name,
            size: u64::try_from(r.size).unwrap_or(0),
            added_ms: u64::try_from(r.added).unwrap_or(0),
        })
    }

    /// 把附件保存到 `path`（替换已有文件；权限 0600）。
    ///
    /// # Errors
    /// 已锁定；附件不存在或已损坏；文件无法写入。
    pub fn save_attachment(
        &self,
        item_id: String,
        attachment_id: String,
        path: String,
    ) -> Result<(), KeevoError> {
        let data = self
            .vault()
            .attachment_data(parse_id(&item_id)?, parse_id(&attachment_id)?)?;
        write_private(Path::new(&path), &data).map_err(|e| KeevoError::Internal {
            message: format!("write attachment: {e}"),
        })
    }

    /// 写出附件供"快速查看"预览：在 `dir`（创建为 0700）中写入 `name`，返回完整路径。
    ///
    /// # Errors
    /// 同 [`KeevoVault::save_attachment`]。
    pub fn preview_attachment(
        &self,
        item_id: String,
        attachment_id: String,
        dir: String,
        name: String,
    ) -> Result<String, KeevoError> {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .map_err(|e| KeevoError::Internal {
                message: format!("preview dir: {e}"),
            })?;
        let name = keevo_core::attachment::clean_name(&name);
        let path = Path::new(&dir).join(name);
        self.save_attachment(item_id, attachment_id, path.to_string_lossy().into_owned())?;
        Ok(path.to_string_lossy().into_owned())
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{name}.keevo-tmp"));
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
