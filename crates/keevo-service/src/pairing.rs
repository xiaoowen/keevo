use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use keevo_ipc::service::{PairingRecord, PairingStore};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordJson {
    extension_public: String,
    extension_origin: String,
    browser: String,
    name: String,
    /// 配对时间（Unix 毫秒）。早期开发版文件没有此字段，读作 0。
    #[serde(default)]
    paired_at_ms: u64,
}

/// 以 JSON 文件保存配对记录（权限 0600）。**仅供开发服务使用**：记录只含公钥与来源，不是秘密，
/// 但文件未经认证，同用户进程可以写入伪造的配对。正式版本必须存入加密数据库，与保险库同等保护
/// （`spec/ipc.md` §4.2；评审 2026-11-18 记为发布前必须解决的集成差距）。
pub struct FilePairingStore {
    path: PathBuf,
    records: Vec<PairingRecord>,
}

impl FilePairingStore {
    /// 打开（不存在则为空）。
    ///
    /// # Errors
    /// 文件存在但无法读取或格式错误时返回错误。
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let records = match fs::read(path) {
            Ok(bytes) => {
                let parsed: Vec<RecordJson> = serde_json::from_slice(&bytes).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                })?;
                parsed.into_iter().filter_map(from_json).collect()
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e),
        };
        Ok(Self {
            path: path.to_owned(),
            records,
        })
    }

    /// 全部配对记录。
    #[must_use]
    pub fn records(&self) -> &[PairingRecord] {
        &self.records
    }

    fn persist(&self) -> std::io::Result<()> {
        let json: Vec<RecordJson> = self
            .records
            .iter()
            .map(|r| RecordJson {
                extension_public: r
                    .extension_public
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
                extension_origin: r.extension_origin.clone(),
                browser: r.browser.clone(),
                name: r.name.clone(),
                paired_at_ms: r.paired_at_ms,
            })
            .collect();
        let bytes = serde_json::to_vec_pretty(&json)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        let tmp = self.path.with_extension("tmp");
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, &self.path)
    }
}

fn from_json(r: RecordJson) -> Option<PairingRecord> {
    let bytes: Vec<u8> = (0..r.extension_public.len())
        .step_by(2)
        .map(|i| {
            r.extension_public
                .get(i..i.checked_add(2)?)
                .and_then(|s| u8::from_str_radix(s, 16).ok())
        })
        .collect::<Option<_>>()?;
    Some(PairingRecord {
        extension_public: bytes.try_into().ok()?,
        extension_origin: r.extension_origin,
        browser: r.browser,
        name: r.name,
        paired_at_ms: r.paired_at_ms,
    })
}

impl PairingStore for FilePairingStore {
    fn find(&self, extension_public: &[u8; 32]) -> Option<PairingRecord> {
        self.records
            .iter()
            .find(|r| &r.extension_public == extension_public)
            .cloned()
    }

    fn save(&mut self, record: PairingRecord) -> std::io::Result<()> {
        let mut next = self.records.clone();
        next.retain(|r| r.extension_public != record.extension_public);
        next.push(record);
        // 先写盘、成功后才更新内存：写盘失败时配对按拒绝处理，不会出现"扩展以为已配对、重启后却没有"
        let previous = std::mem::replace(&mut self.records, next);
        if let Err(e) = self.persist() {
            self.records = previous;
            return Err(e);
        }
        Ok(())
    }

    fn revoke(&mut self, extension_public: &[u8; 32]) -> std::io::Result<()> {
        // 先从内存删除：即使写盘失败，本次运行内撤销也立即生效
        self.records
            .retain(|r| &r.extension_public != extension_public);
        self.persist()
    }
}
