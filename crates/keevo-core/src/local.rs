//! 本机密钥包裹的文件与代次（`spec/crypto.md` §8.7）。
//!
//! 平台层通过 [`SecureEnclave`] 提供 Secure Enclave 的三项操作；密钥派生与加解密在
//! `keevo-crypto` 中完成，被包裹的材料不经过平台层。

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use keevo_crypto::{
    AccountSecretKey, CryptoError, Id128, LocalAgreement, LocalPurpose, LocalWrapHeader,
    MAX_LOCAL_WRAP_LEN, SymmetricKey, unwrap_auk, unwrap_device_marker, unwrap_secret_key,
};
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

/// Secure Enclave 密钥 blob 的长度上限（平台格式）。
pub const MAX_KEY_BLOB_LEN: usize = 4096;
const POINTER: &str = "current";
const POINTER_TMP: &str = "current.tmp";
const GEN_PREFIX: &str = "gen-";
/// 指针中代次的最大位数。
const MAX_GENERATION_DIGITS: usize = 15;
/// 开机标识的最大长度。
pub const MAX_BOOT_SESSION_LEN: usize = 64;

/// 平台层报告的错误（§8.7"失败与恢复"）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnclaveError {
    /// 用户取消或认证超时：什么都不改变。
    Cancelled,
    /// 暂时不可用（如屏幕锁定）或无法确定原因：什么都不改变。
    Unavailable,
    /// 能确定材料本身已失效：blob 无法解析、密钥因指纹变化而失效。
    Unusable,
    /// 用户在场验证未通过（指纹不匹配）。计入连续失败次数（`docs/security.md` §8）。
    Failed,
}

/// 平台层新建的 Secure Enclave 密钥。
pub struct EnclaveKey {
    /// 密钥 blob（平台格式），由核心层存成文件。
    pub blob: Vec<u8>,
    /// 公钥（X9.63 未压缩，65 字节）。
    pub public_key: Vec<u8>,
}

/// 包裹时的临时协商结果。
pub struct EphemeralAgreement {
    /// 临时公钥（X9.63 未压缩，65 字节）。
    pub ephemeral_public: Vec<u8>,
    /// 协商结果（32 字节）。
    pub shared: Zeroizing<Vec<u8>>,
}

/// 平台层的 Secure Enclave 操作（§8.7"分工"）。
pub trait SecureEnclave: Send + Sync {
    /// 按用途创建 Secure Enclave 密钥。用途 0x01 的访问控制要求 Touch ID。
    ///
    /// # Errors
    /// 见 [`EnclaveError`]。
    fn create_key(&self, purpose: LocalPurpose) -> core::result::Result<EnclaveKey, EnclaveError>;

    /// 生成临时 P-256 密钥并与 `public_key` 协商（软件运算）。
    ///
    /// # Errors
    /// 公钥无效时返回 [`EnclaveError::Unusable`]。
    fn agree_ephemeral(
        &self,
        public_key: &[u8],
    ) -> core::result::Result<EphemeralAgreement, EnclaveError>;

    /// 用 blob 恢复 Secure Enclave 私钥，与临时公钥协商。用途 0x01 在此要求 Touch ID。
    ///
    /// # Errors
    /// 见 [`EnclaveError`]。
    fn agree(
        &self,
        purpose: LocalPurpose,
        blob: &[u8],
        ephemeral_public: &[u8],
    ) -> core::result::Result<Zeroizing<Vec<u8>>, EnclaveError>;
}

/// 一个用途的文件：Secure Enclave 密钥 blob 与包裹。
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Entry {
    key: Vec<u8>,
    wrap: Vec<u8>,
}

/// 解包的结果：材料已失效时为 `Unusable`，与"这一代没有这个用途"区分开。
pub(crate) enum Unwrapped<T> {
    Ok(T),
    Missing,
    Unusable,
}

/// 一份包裹及其协商结果。
type WrapAndShared = (Vec<u8>, Zeroizing<Vec<u8>>);

/// 本机密钥目录：当前代次的全部包裹。
pub struct LocalKeys {
    dir: PathBuf,
    enclave: Arc<dyn SecureEnclave>,
    current: Option<u64>,
    entries: BTreeMap<LocalPurpose, Entry>,
    boot_session: Option<String>,
}

impl LocalKeys {
    /// 读取 `dir` 中的当前代次。目录不存在时为空。
    ///
    /// # Errors
    /// 读取文件失败时返回 [`CoreError::Io`]。
    pub fn load(dir: &Path, enclave: Arc<dyn SecureEnclave>) -> Result<Self> {
        let mut keys = Self {
            dir: dir.to_owned(),
            enclave,
            current: None,
            entries: BTreeMap::new(),
            boot_session: None,
        };
        let pointer = read_pointer(dir)?;
        let mut candidates = list_generations(dir)?;
        candidates.sort_unstable_by(|a, b| b.cmp(a));
        if let Some(p) = pointer {
            // 只读指针指向的那一代；它不完整时退回更早的完整代次。编号更大的是写到一半的残留
            candidates.retain(|n| *n <= p);
        }
        for n in candidates {
            if let Some(entries) = read_generation(&gen_dir(dir, n))? {
                keys.current = Some(n);
                keys.entries = entries;
                break;
            }
        }
        Ok(keys)
    }

    /// 设定本次开机的标识（macOS 上为 `kern.bootsessionuuid`），用于"重启后的首次解锁必须输入主密码"。
    /// 不设定或为空时，视为每次都是重启之后。
    #[must_use]
    pub fn with_boot_session(mut self, boot_session: &str) -> Self {
        self.boot_session = (!boot_session.is_empty()
            && boot_session.len() <= MAX_BOOT_SESSION_LEN)
            .then(|| boot_session.to_owned());
        self
    }

    pub(crate) fn boot_session(&self) -> Option<&str> {
        self.boot_session.as_deref()
    }

    /// 当前代次是否包含这个用途。
    #[must_use]
    pub fn has(&self, purpose: LocalPurpose) -> bool {
        self.entries.contains_key(&purpose)
    }

    /// 当前代次。
    #[must_use]
    pub const fn generation(&self) -> Option<u64> {
        self.current
    }

    fn shared(&self, purpose: LocalPurpose) -> Result<Unwrapped<WrapAndShared>> {
        let Some(entry) = self.entries.get(&purpose) else {
            return Ok(Unwrapped::Missing);
        };
        let Ok(header) = LocalWrapHeader::parse(&entry.wrap) else {
            return Ok(Unwrapped::Unusable);
        };
        if header.purpose != purpose {
            return Ok(Unwrapped::Unusable);
        }
        match self.enclave.agree(purpose, &entry.key, &header.eph_pub) {
            Ok(shared) => Ok(Unwrapped::Ok((entry.wrap.clone(), shared))),
            Err(EnclaveError::Unusable) => Ok(Unwrapped::Unusable),
            Err(e) => Err(e.into()),
        }
    }

    fn unwrap_with<T>(
        &self,
        purpose: LocalPurpose,
        open: impl FnOnce(&[u8], &[u8]) -> core::result::Result<T, CryptoError>,
    ) -> Result<Unwrapped<T>> {
        Ok(match self.shared(purpose)? {
            Unwrapped::Ok((wrap, shared)) => match open(&wrap, &shared) {
                Ok(v) => Unwrapped::Ok(v),
                Err(_) => Unwrapped::Unusable,
            },
            Unwrapped::Missing => Unwrapped::Missing,
            Unwrapped::Unusable => Unwrapped::Unusable,
        })
    }

    pub(crate) fn device_marker(&self, account_id: &Id128) -> Result<Unwrapped<Id128>> {
        self.unwrap_with(LocalPurpose::DeviceMarker, |w, s| {
            unwrap_device_marker(w, account_id, s)
        })
    }

    pub(crate) fn secret_key(
        &self,
        account_id: &Id128,
        device_id: &Id128,
    ) -> Result<Unwrapped<AccountSecretKey>> {
        self.unwrap_with(LocalPurpose::SecretKey, |w, s| {
            unwrap_secret_key(w, account_id, device_id, s)
        })
    }

    pub(crate) fn auk(
        &self,
        account_id: &Id128,
        device_id: &Id128,
    ) -> Result<Unwrapped<SymmetricKey>> {
        self.unwrap_with(LocalPurpose::Auk, |w, s| {
            unwrap_auk(w, account_id, device_id, s)
        })
    }

    /// 为 `purpose` 新建 Secure Enclave 密钥并包裹。
    pub(crate) fn new_entry(
        &self,
        purpose: LocalPurpose,
        seal: impl FnOnce(&LocalAgreement) -> core::result::Result<Vec<u8>, CryptoError>,
    ) -> Result<Entry> {
        let key = self.enclave.create_key(purpose)?;
        if key.blob.is_empty() || key.blob.len() > MAX_KEY_BLOB_LEN {
            return Err(CoreError::EnclaveUnavailable);
        }
        let agreement = self.enclave.agree_ephemeral(&key.public_key)?;
        let agreement = LocalAgreement::new(&agreement.ephemeral_public, &agreement.shared)
            .map_err(|_| CoreError::EnclaveUnavailable)?;
        Ok(Entry {
            key: key.blob,
            wrap: seal(&agreement)?,
        })
    }

    /// 当前代次的全部条目，用于在此基础上组成新一代。
    pub(crate) fn entries(&self) -> BTreeMap<LocalPurpose, Entry> {
        self.entries.clone()
    }

    /// 写出新一代并提交（§8.7"代次即事务"）。`verify` 对每个不要求用户在场的包裹确认可以解开。
    pub(crate) fn commit(
        &mut self,
        entries: BTreeMap<LocalPurpose, Entry>,
        verify: impl Fn(&Self, LocalPurpose) -> Result<bool>,
    ) -> Result<()> {
        if !entries.contains_key(&LocalPurpose::DeviceMarker) {
            return Err(CoreError::Tampered);
        }
        create_private_dir(&self.dir)?;
        let next = list_generations(&self.dir)?
            .into_iter()
            .chain(self.current)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(CoreError::Tampered)?;
        let dir = gen_dir(&self.dir, next);
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
        }
        create_private_dir(&dir)?;
        for (purpose, entry) in &entries {
            write_file(&dir.join(file_name(*purpose, "key")), &entry.key)?;
            write_file(&dir.join(file_name(*purpose, "wrap")), &entry.wrap)?;
        }
        sync_dir(&dir)?;

        // 验证新一代：用它的条目临时替换当前条目
        let previous = core::mem::replace(&mut self.entries, entries);
        let mut ok = true;
        for purpose in self.entries.keys().copied().collect::<Vec<_>>() {
            if !purpose.requires_presence() && !verify(self, purpose)? {
                ok = false;
                break;
            }
        }
        if !ok {
            self.entries = previous;
            let _ = fs::remove_dir_all(&dir);
            return Err(CoreError::EnclaveUnavailable);
        }

        let tmp = self.dir.join(POINTER_TMP);
        write_file(&tmp, next.to_string().as_bytes())?;
        fs::rename(&tmp, self.dir.join(POINTER))?;
        sync_dir(&self.dir)?;
        self.current = Some(next);
        Ok(())
    }

    /// 删除当前代次以外的各代。用当前代次成功解锁之后调用。
    ///
    /// # Errors
    /// 删除失败时返回 [`CoreError::Io`]。
    pub fn cleanup(&self) -> Result<()> {
        let Some(current) = self.current else {
            return Ok(());
        };
        for n in list_generations(&self.dir)? {
            if n != current {
                fs::remove_dir_all(gen_dir(&self.dir, n))?;
            }
        }
        Ok(())
    }
}

fn file_name(purpose: LocalPurpose, ext: &str) -> String {
    format!("{:02x}.{ext}", purpose.byte())
}

fn gen_dir(dir: &Path, n: u64) -> PathBuf {
    dir.join(format!("{GEN_PREFIX}{n}"))
}

/// 解析十进制代次：1–15 位，无前导零。
fn parse_generation(s: &str) -> Option<u64> {
    if s.is_empty()
        || s.len() > MAX_GENERATION_DIGITS
        || s.starts_with('0')
        || !s.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    s.parse().ok()
}

fn read_pointer(dir: &Path) -> Result<Option<u64>> {
    match read_limited(&dir.join(POINTER), MAX_GENERATION_DIGITS)? {
        Some(bytes) => Ok(std::str::from_utf8(&bytes).ok().and_then(parse_generation)),
        None => Ok(None),
    }
}

fn list_generations(dir: &Path) -> Result<Vec<u64>> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        if let Some(n) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.strip_prefix(GEN_PREFIX))
            .and_then(parse_generation)
        {
            out.push(n);
        }
    }
    Ok(out)
}

/// 读取一代。不完整（缺少设备标记，或 `.key` 与 `.wrap` 不成对、超长）时返回 `None`。
fn read_generation(dir: &Path) -> Result<Option<BTreeMap<LocalPurpose, Entry>>> {
    let mut entries = BTreeMap::new();
    for purpose in LocalPurpose::ALL {
        let key = read_limited(&dir.join(file_name(purpose, "key")), MAX_KEY_BLOB_LEN)?;
        let wrap = read_limited(&dir.join(file_name(purpose, "wrap")), MAX_LOCAL_WRAP_LEN)?;
        match (key, wrap) {
            (Some(key), Some(wrap)) if !key.is_empty() && !wrap.is_empty() => {
                entries.insert(purpose, Entry { key, wrap });
            }
            (None, None) => {}
            _ => return Ok(None),
        }
    }
    if !entries.contains_key(&LocalPurpose::DeviceMarker) {
        return Ok(None);
    }
    Ok(Some(entries))
}

/// 读取文件，超过 `limit` 字节视为损坏（返回空内容）。文件不存在时返回 `None`。
fn read_limited(path: &Path, limit: usize) -> Result<Option<Vec<u8>>> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut buf = Vec::new();
    let cap = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    file.take(cap).read_to_end(&mut buf)?;
    if buf.len() > limit {
        return Ok(Some(Vec::new()));
    }
    Ok(Some(buf))
}

fn create_private_dir(dir: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    Ok(())
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

fn sync_dir(dir: &Path) -> Result<()> {
    File::open(dir)?.sync_all()?;
    Ok(())
}

impl From<EnclaveError> for CoreError {
    fn from(e: EnclaveError) -> Self {
        match e {
            EnclaveError::Cancelled => Self::Cancelled,
            EnclaveError::Failed => Self::AuthenticationFailed,
            EnclaveError::Unavailable | EnclaveError::Unusable => Self::EnclaveUnavailable,
        }
    }
}

impl From<io::Error> for CoreError {
    fn from(e: io::Error) -> Self {
        Self::Io(e.kind())
    }
}

#[cfg(test)]
mod tests;
