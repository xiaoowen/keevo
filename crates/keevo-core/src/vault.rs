use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use keevo_crypto::{
    AadContext, AccountKeyset, AccountSecretKey, CryptoError, Id128, KdfParams, LocalPurpose,
    ObjectType, Part, SymmetricKey, derive_account_unlock_key, open, seal, wrap_auk,
    wrap_device_marker, wrap_secret_key,
};
use keevo_format::{
    Conflict, FORMAT_VERSION, FieldData, FieldKind, FieldValue, HeadState, Hlc, HlcClock, ItemDoc,
    ItemOverview, ItemType, Purpose, RecordKey, RecordValue, RevisionGraph, VaultMeta, merge_heads,
};
use keevo_store::{AccountRow, ObjectKind, RevisionRow, Store};

use crate::error::{CoreError, Result};
use crate::local::{LocalKeys, Unwrapped};

const META_DEVICE_ID: &str = "device_id";
const META_HLC: &str = "hlc_last";
/// 上次用主密码解锁的时间（Unix 毫秒，大端 u64）。
const META_PASSWORD_MS: &str = "password_unlock_ms";
/// 上次用主密码解锁时的开机标识。
const META_PASSWORD_BOOT: &str = "password_unlock_boot";
/// Touch ID 连续失败的次数（1 字节）。
const META_TOUCH_ID_FAILURES: &str = "touch_id_failures";
/// 必须重新输入主密码的间隔天数（1 字节）。
const META_PASSWORD_INTERVAL: &str = "password_interval_days";
/// 必须重新输入主密码的默认间隔（`docs/ux.md` §3.2）。
pub const DEFAULT_PASSWORD_INTERVAL_DAYS: u8 = 14;
/// 间隔的可选范围。
pub const PASSWORD_INTERVAL_DAYS: core::ops::RangeInclusive<u8> = 1..=30;
/// Touch ID 连续失败多少次后必须输入主密码。
pub const MAX_TOUCH_ID_FAILURES: u8 = 3;
const DAY_MS: u64 = 24 * 60 * 60 * 1000;
const DEFAULT_VAULT_NAME: &str = "个人";
const FIRST_EPOCH: u64 = 1;
/// 每个对象保留完整内容的修订数（`spec/revisions.md` §7）。
const HISTORY_KEEP: usize = 20;
/// 历史保留的时间下限（`spec/revisions.md` §7.2）：按 Keevo 的运行时间计，90 天内写入或收到的修订一律保留。
const HISTORY_MIN_AGE_MS: u64 = 90 * 24 * 60 * 60 * 1000;

/// 新字段。
#[derive(Debug, Clone)]
pub struct NewField {
    /// 字段类型。
    pub kind: FieldKind,
    /// 显示名。
    pub label: String,
    /// 自动填充用途。
    pub purpose: Option<Purpose>,
    /// 字段数据。
    pub data: FieldData,
}

/// 重新验证用户的方式（[`Vault::reverify`]）。
#[derive(Debug, Clone, Copy)]
pub enum Reverify<'a> {
    /// 主密码。
    Password(&'a str),
    /// Touch ID。
    TouchId,
}

/// 为什么这次不能用 Touch ID、必须输入主密码（`docs/security.md` §8、`docs/ux.md` §3.2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordReason {
    /// 没有启用 Touch ID。
    NotEnabled,
    /// Touch ID 已失效（例如指纹有变化）；用主密码解锁后自动恢复。
    Invalidated,
    /// Mac 重启后的首次解锁。
    Restarted,
    /// 距上次输入主密码超过了设定的天数。
    IntervalElapsed,
    /// Touch ID 连续失败次数过多。
    TooManyFailures,
}

/// 历史中的一个修订（[`Vault::history`]）。
#[derive(Debug, Clone)]
pub struct HistoryEntry {
    /// 修订 ID。
    pub rev_id: Id128,
    /// 父修订。多于一个表示这是一次合并（写时收敛）。
    pub parents: Vec<Id128>,
    /// 是否为永久删除留下的墓碑。
    pub deleted: bool,
    /// 内容是否已被清理（`spec/revisions.md` §7.2），只剩元数据。
    pub pruned: bool,
    /// 这一修订时的概要；墓碑或已清理时为 `None`。
    pub overview: Option<ItemOverview>,
}

/// 对条目的一次编辑。
#[derive(Debug, Clone)]
pub enum Edit {
    /// 修改标题。
    SetTitle(String),
    /// 收藏或取消收藏。
    SetFavorite(bool),
    /// 添加标签。
    AddTag(String),
    /// 移除标签。
    RemoveTag(String),
    /// 新增字段。
    AddField(NewField),
    /// 修改字段的数据。
    SetFieldData {
        /// 字段 ID。
        field_id: Id128,
        /// 新数据。
        data: FieldData,
    },
    /// 删除字段。
    RemoveField(Id128),
}

/// 保险库信息。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultInfo {
    /// 保险库 ID。
    pub id: Id128,
    /// 名称。
    pub name: String,
}

/// 条目列表中的一项。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemSummary {
    /// 条目 ID。
    pub id: Id128,
    /// 所属保险库。
    pub vault_id: Id128,
    /// 概要。
    pub overview: ItemOverview,
    /// 是否有未解决的并发冲突。
    pub has_conflicts: bool,
}

/// 打开的条目：合并后的完整内容。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemView {
    /// 条目 ID。
    pub id: Id128,
    /// 所属保险库。
    pub vault_id: Id128,
    /// 合并后的内容。
    pub doc: ItemDoc,
    /// 并发冲突。
    pub conflicts: Vec<Conflict>,
    /// 是否因为删除与修改并发而撤销了删除。
    pub resurrected: bool,
    /// 当前头修订数（大于 1 表示存在尚未收敛的并发修改）。
    pub head_count: usize,
    /// 出处不一致的记录键（`spec/revisions.md` §5.1 步骤 0），应提示用户查看历史。
    pub integrity_issues: Vec<RecordKey>,
}

struct Session {
    account_id: Id128,
    keyset: AccountKeyset,
    vault_keys: HashMap<Id128, SymmetricKey>,
}

/// 一个本地保险库数据库及其解锁状态。
pub struct Vault {
    store: Store,
    device_id: Id128,
    clock: HlcClock,
    session: Option<Session>,
    /// 解锁代次：每次成功解锁加 1。配对等跨越用户确认的操作据此判断"仍是同一次解锁"（`spec/ipc.md` §4.2）。
    unlock_epoch: u64,
    /// 本机密钥（`spec/crypto.md` §8.7）。测试与开发服务不使用。
    local: Option<LocalKeys>,
    /// 本机的账户密钥包裹已失效，用户输入账户密钥解锁后补登。
    secret_key_broken: bool,
    /// Touch ID 的包裹已失效，用主密码解锁后重新包裹。
    touch_id_broken: bool,
}

impl Vault {
    /// 在 `path` 创建新账户与默认保险库，返回已解锁的保险库与新生成的账户密钥。
    ///
    /// 调用方必须引导用户保存账户密钥（应急包），并把它存入本机钥匙串。
    ///
    /// # Errors
    /// 数据库中已有账户时返回 [`CoreError::AccountExists`]。
    pub fn create(
        path: &Path,
        password: &str,
        params: KdfParams,
    ) -> Result<(Self, AccountSecretKey)> {
        Self::create_with_store(Store::open(path)?, password, params)
    }

    /// 与 [`Vault::create`] 相同，但使用给定的存储（测试用内存数据库）。
    ///
    /// # Errors
    /// 见 [`Vault::create`]。
    pub fn create_with_store(
        mut store: Store,
        password: &str,
        params: KdfParams,
    ) -> Result<(Self, AccountSecretKey)> {
        if store.account()?.is_some() {
            return Err(CoreError::AccountExists);
        }
        let device_id = Id128::random()?;
        store.set_meta(META_DEVICE_ID, device_id.as_bytes())?;

        let account_id = Id128::random()?;
        let secret_key = AccountSecretKey::generate()?;
        let auk = derive_account_unlock_key(password, &secret_key, &account_id, &params)?;
        let keyset = AccountKeyset::generate()?;
        let keyset_ct = keyset.seal(&auk, &account_id, FIRST_EPOCH, &params)?;
        store.create_account(&AccountRow {
            id: account_id,
            format_version: FORMAT_VERSION,
            epoch: FIRST_EPOCH,
            kdf_params: params.encode().to_vec(),
            keyset_ct,
        })?;

        let mut vault = Self {
            store,
            device_id,
            clock: HlcClock::default(),
            session: Some(Session {
                account_id,
                keyset,
                vault_keys: HashMap::new(),
            }),
            unlock_epoch: 1,
            local: None,
            secret_key_broken: false,
            touch_id_broken: false,
        };
        vault.create_vault(DEFAULT_VAULT_NAME)?;
        Ok((vault, secret_key))
    }

    /// 新建账户，并把设备标记与账户密钥包裹到本机（`spec/crypto.md` §8.7"登记"）。
    /// 之后日常只需主密码；返回的账户密钥仍须由用户保存到应急包。
    ///
    /// # Errors
    /// 见 [`Vault::create`]；包裹失败时返回 [`CoreError::EnclaveUnavailable`] 等。
    pub fn create_with_local(
        store: Store,
        password: &str,
        params: KdfParams,
        mut local: LocalKeys,
    ) -> Result<(Self, AccountSecretKey)> {
        let (mut vault, secret_key) = Self::create_with_store(store, password, params)?;
        let account_id = vault.session()?.account_id;
        let device_id = vault.device_id;
        let mut entries = std::collections::BTreeMap::new();
        entries.insert(
            LocalPurpose::DeviceMarker,
            local.new_entry(LocalPurpose::DeviceMarker, |a| {
                wrap_device_marker(&device_id, &account_id, a)
            })?,
        );
        entries.insert(
            LocalPurpose::SecretKey,
            local.new_entry(LocalPurpose::SecretKey, |a| {
                wrap_secret_key(&secret_key, &account_id, &device_id, a)
            })?,
        );
        local.commit(entries, |keys, p| {
            verify_entry(keys, p, &account_id, &device_id)
        })?;
        vault.local = Some(local);
        vault.record_password_unlock()?;
        Ok((vault, secret_key))
    }

    /// 打开已有的数据库并接入本机密钥，初始为锁定状态。设备 ID 取自本机的设备标记；
    /// 标记不存在或已失效时生成新的设备 ID 并重新登记（`spec/revisions.md` §8）。
    ///
    /// # Errors
    /// 见 [`Vault::open`]；Secure Enclave 暂时不可用时返回 [`CoreError::EnclaveUnavailable`]，
    /// 此时什么都没有改变。
    pub fn open_with_local(store: Store, local: LocalKeys) -> Result<Self> {
        let mut vault = Self::open_with_store(store)?;
        vault.attach_local(local, false)?;
        Ok(vault)
    }

    /// 重新登记本机并打开：生成新的设备 ID，丢弃本机的全部包裹（`spec/crypto.md` §8.7）。
    /// 用于 [`Vault::open_with_local`] 一直返回 [`CoreError::EnclaveUnavailable`]、用户主动选择恢复的情形。
    /// 之后需要从应急包输入账户密钥。
    ///
    /// # Errors
    /// 包裹或写入失败时返回对应错误。
    pub fn open_reenrolling_local(store: Store, local: LocalKeys) -> Result<Self> {
        let mut vault = Self::open_with_store(store)?;
        vault.attach_local(local, true)?;
        Ok(vault)
    }

    fn attach_local(&mut self, mut local: LocalKeys, force_new: bool) -> Result<()> {
        let account = self.store.account()?.ok_or(CoreError::NoAccount)?;
        let marker = if force_new {
            Unwrapped::Unusable
        } else {
            local.device_marker(&account.id)?
        };
        match marker {
            Unwrapped::Ok(id) => {
                if id != self.device_id {
                    self.store.set_meta(META_DEVICE_ID, id.as_bytes())?;
                    self.device_id = id;
                }
                self.secret_key_broken = false;
            }
            Unwrapped::Missing | Unwrapped::Unusable => {
                // 其余包裹绑定旧的设备 ID，随之不可用：新一代只有设备标记
                let device_id = Id128::random()?;
                let mut entries = std::collections::BTreeMap::new();
                entries.insert(
                    LocalPurpose::DeviceMarker,
                    local.new_entry(LocalPurpose::DeviceMarker, |a| {
                        wrap_device_marker(&device_id, &account.id, a)
                    })?,
                );
                local.commit(entries, |keys, p| {
                    verify_entry(keys, p, &account.id, &device_id)
                })?;
                self.store.set_meta(META_DEVICE_ID, device_id.as_bytes())?;
                self.device_id = device_id;
                self.secret_key_broken = true;
            }
        }
        self.touch_id_broken = false;
        self.local = Some(local);
        Ok(())
    }

    /// 打开已有的数据库，初始为锁定状态。
    ///
    /// # Errors
    /// 数据库中没有账户时返回 [`CoreError::NoAccount`]。
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_store(Store::open(path)?)
    }

    /// 与 [`Vault::open`] 相同，但使用给定的存储。
    ///
    /// # Errors
    /// 见 [`Vault::open`]。
    pub fn open_with_store(store: Store) -> Result<Self> {
        if store.account()?.is_none() {
            return Err(CoreError::NoAccount);
        }
        let device_id = match store.meta(META_DEVICE_ID)? {
            Some(bytes) => id_from(&bytes)?,
            None => Id128::random()?,
        };
        let last = match store.meta(META_HLC)? {
            Some(bytes) => Hlc(u64::from_be_bytes(
                bytes.try_into().map_err(|_| CoreError::Tampered)?,
            )),
            None => Hlc::default(),
        };
        Ok(Self {
            store,
            device_id,
            clock: HlcClock::restore(last),
            session: None,
            unlock_epoch: 0,
            local: None,
            secret_key_broken: false,
            touch_id_broken: false,
        })
    }

    /// 是否已解锁。
    #[must_use]
    pub const fn is_unlocked(&self) -> bool {
        self.session.is_some()
    }

    /// 本机设备 ID。
    #[must_use]
    pub const fn device_id(&self) -> Id128 {
        self.device_id
    }

    /// 用主密码与账户密钥解锁。耗时约 0.5–1.5 秒（Argon2id），应在后台线程调用。
    ///
    /// # Errors
    /// 主密码或账户密钥错误时返回 [`CoreError::WrongCredentials`]；KDF 参数超出本机自动执行预算时返回
    /// [`CoreError::KdfNeedsConfirmation`]，此时不会执行任何派生。
    pub fn unlock(&mut self, password: &str, secret_key: &AccountSecretKey) -> Result<()> {
        self.unlock_inner(password, secret_key, None)
    }

    /// 账户当前的 KDF 参数，供界面在 [`CoreError::KdfNeedsConfirmation`] 时向用户展示。
    ///
    /// # Errors
    /// 没有账户或参数格式错误时返回错误。
    pub fn kdf_params(&self) -> Result<KdfParams> {
        let account = self.store.account()?.ok_or(CoreError::NoAccount)?;
        Ok(KdfParams::decode(&account.kdf_params)?)
    }

    /// 用户确认了 `confirmed` 这组参数后，以超出自动执行预算的参数解锁（可能耗时很久、占用大量内存）。
    ///
    /// 确认绑定到具体参数：若数据库中的参数已不是用户看到的那一组（例如确认期间被替换为更昂贵的参数），
    /// 返回 [`CoreError::KdfNeedsConfirmation`]，不执行派生。
    ///
    /// # Errors
    /// 同 [`Vault::unlock`]。
    pub fn unlock_confirmed_expensive_kdf(
        &mut self,
        password: &str,
        secret_key: &AccountSecretKey,
        confirmed: &KdfParams,
    ) -> Result<()> {
        self.unlock_inner(password, secret_key, Some(confirmed))
    }

    fn unlock_inner(
        &mut self,
        password: &str,
        secret_key: &AccountSecretKey,
        confirmed: Option<&KdfParams>,
    ) -> Result<()> {
        let account = self.store.account()?.ok_or(CoreError::NoAccount)?;
        let params = KdfParams::decode(&account.kdf_params)?;
        let allowed = match confirmed {
            Some(c) => *c == params,
            None => params.within_auto_budget(),
        };
        if !allowed {
            return Err(CoreError::KdfNeedsConfirmation);
        }
        let auk = derive_account_unlock_key(password, secret_key, &account.id, &params)?;
        self.open_session(&account, &params, &auk)?;
        self.record_password_unlock()?;
        self.after_password_unlock(&account.id, secret_key, &auk);
        Ok(())
    }

    /// 记下"刚刚输入过主密码"：时间、开机标识，并清零 Touch ID 的连续失败次数。
    fn record_password_unlock(&mut self) -> Result<()> {
        self.store
            .set_meta(META_PASSWORD_MS, &now_ms().to_be_bytes())?;
        let boot = self
            .local
            .as_ref()
            .and_then(LocalKeys::boot_session)
            .unwrap_or_default()
            .to_owned();
        self.store.set_meta(META_PASSWORD_BOOT, boot.as_bytes())?;
        self.store.set_meta(META_TOUCH_ID_FAILURES, &[0])?;
        Ok(())
    }

    /// 测试专用：改写元数据，模拟时间流逝或篡改。
    #[cfg(test)]
    pub(crate) fn set_meta_for_tests(&mut self, key: &str, value: &[u8]) {
        self.store.set_meta(key, value).unwrap_or_default();
    }

    fn touch_id_failures(&self) -> Result<u8> {
        Ok(match self.store.meta(META_TOUCH_ID_FAILURES)?.as_deref() {
            Some([n]) => *n,
            None => 0,
            // 格式不对时按已达上限处理（保守）
            Some(_) => MAX_TOUCH_ID_FAILURES,
        })
    }

    /// 必须重新输入主密码的间隔天数。
    ///
    /// # Errors
    /// SQLite 错误。
    pub fn password_interval_days(&self) -> Result<u8> {
        Ok(match self.store.meta(META_PASSWORD_INTERVAL)?.as_deref() {
            Some([n]) if PASSWORD_INTERVAL_DAYS.contains(n) => *n,
            _ => DEFAULT_PASSWORD_INTERVAL_DAYS,
        })
    }

    /// 设定必须重新输入主密码的间隔天数（1–30）。
    ///
    /// # Errors
    /// 超出范围返回 [`CoreError::OutOfRange`]；SQLite 错误。
    pub fn set_password_interval_days(&mut self, days: u8) -> Result<()> {
        if !PASSWORD_INTERVAL_DAYS.contains(&days) {
            return Err(CoreError::OutOfRange);
        }
        self.store.set_meta(META_PASSWORD_INTERVAL, &[days])?;
        Ok(())
    }

    /// 此时能否用 Touch ID 解锁；不能时返回原因，解锁界面据此说明为什么需要主密码。
    ///
    /// # Errors
    /// SQLite 错误。
    pub fn password_reason(&self) -> Result<Option<PasswordReason>> {
        if !self
            .local
            .as_ref()
            .is_some_and(|l| l.has(LocalPurpose::Auk))
        {
            return Ok(Some(PasswordReason::NotEnabled));
        }
        if self.touch_id_broken {
            return Ok(Some(PasswordReason::Invalidated));
        }
        let boot_now = self.local.as_ref().and_then(LocalKeys::boot_session);
        let boot_then = self.store.meta(META_PASSWORD_BOOT)?;
        if boot_now.is_none() || boot_then.as_deref() != boot_now.map(str::as_bytes) {
            return Ok(Some(PasswordReason::Restarted));
        }
        let then = self
            .store
            .meta(META_PASSWORD_MS)?
            .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
            .map(u64::from_be_bytes);
        let limit = u64::from(self.password_interval_days()?).saturating_mul(DAY_MS);
        // 时钟倒退（现在早于上次）也按超期处理
        let elapsed = then.and_then(|t| now_ms().checked_sub(t));
        if elapsed.is_none_or(|e| e > limit) {
            return Ok(Some(PasswordReason::IntervalElapsed));
        }
        if self.touch_id_failures()? >= MAX_TOUCH_ID_FAILURES {
            return Ok(Some(PasswordReason::TooManyFailures));
        }
        Ok(None)
    }

    /// 用 AUK 打开密钥集与各保险库密钥，建立会话。AUK 不对时返回 [`CoreError::WrongCredentials`]。
    fn open_session(
        &mut self,
        account: &AccountRow,
        params: &KdfParams,
        auk: &SymmetricKey,
    ) -> Result<()> {
        let keyset =
            AccountKeyset::open(auk, &account.id, account.epoch, params, &account.keyset_ct)
                .map_err(|e| match e {
                    CryptoError::KeyIdMismatch | CryptoError::DecryptionFailed => {
                        CoreError::WrongCredentials
                    }
                    other => CoreError::Crypto(other),
                })?;

        let mut vault_keys = HashMap::new();
        for vault_id in self.store.objects(ObjectKind::Vault)? {
            let head = self
                .store
                .heads(&vault_id)?
                .into_iter()
                .next()
                .ok_or(CoreError::Tampered)?;
            let wrapped = head.wrapped_key_ct.as_deref().ok_or(CoreError::Tampered)?;
            let ctx = context(
                account.id,
                ObjectType::Vault,
                Part::WrappedKey,
                vault_id,
                vault_id,
                head.rev_id,
            );
            vault_keys.insert(vault_id, keyset.account_key().unwrap_key(&ctx, wrapped)?);
        }
        self.session = Some(Session {
            account_id: account.id,
            keyset,
            vault_keys,
        });
        self.unlock_epoch = self.unlock_epoch.wrapping_add(1);
        Ok(())
    }

    /// 主密码解锁成功之后的本机维护：补登失效的账户密钥、重新包裹失效的 Touch ID、清理旧代次。
    /// 这些都是尽力而为：失败不影响这次解锁，下次解锁再试。
    fn after_password_unlock(
        &mut self,
        account_id: &Id128,
        secret_key: &AccountSecretKey,
        auk: &SymmetricKey,
    ) {
        let device_id = self.device_id;
        let Some(local) = self.local.as_mut() else {
            return;
        };
        let mut entries = local.entries();
        let mut changed = false;
        if (self.secret_key_broken || !local.has(LocalPurpose::SecretKey))
            && let Ok(entry) = local.new_entry(LocalPurpose::SecretKey, |a| {
                wrap_secret_key(secret_key, account_id, &device_id, a)
            })
        {
            entries.insert(LocalPurpose::SecretKey, entry);
            changed = true;
        }
        if self.touch_id_broken
            && local.has(LocalPurpose::Auk)
            && let Ok(entry) = local.new_entry(LocalPurpose::Auk, |a| {
                wrap_auk(auk, account_id, &device_id, a)
            })
        {
            entries.insert(LocalPurpose::Auk, entry);
            changed = true;
        }
        if changed
            && local
                .commit(entries, |keys, p| {
                    verify_entry(keys, p, account_id, &device_id)
                })
                .is_ok()
        {
            self.secret_key_broken = false;
            self.touch_id_broken = false;
        }
        let _ = local.cleanup();
    }

    /// 只用主密码解锁：账户密钥取自本机包裹（`spec/crypto.md` §8.7"免输账户密钥解锁"）。
    ///
    /// # Errors
    /// 本机没有可用的账户密钥时返回 [`CoreError::SecretKeyRequired`]，此时改用 [`Vault::unlock`]；
    /// 其余同 [`Vault::unlock`]。
    pub fn unlock_with_password(&mut self, password: &str) -> Result<()> {
        let secret_key = self.local_secret_key()?;
        self.unlock_inner(password, &secret_key, None)
    }

    /// 同 [`Vault::unlock_with_password`]，但用户已确认 `confirmed` 这组 KDF 参数（`spec/crypto.md` §5.3）。
    ///
    /// # Errors
    /// 同 [`Vault::unlock_with_password`]。
    pub fn unlock_with_password_confirmed(
        &mut self,
        password: &str,
        confirmed: &KdfParams,
    ) -> Result<()> {
        let secret_key = self.local_secret_key()?;
        self.unlock_inner(password, &secret_key, Some(confirmed))
    }

    fn local_secret_key(&mut self) -> Result<AccountSecretKey> {
        let account = self.store.account()?.ok_or(CoreError::NoAccount)?;
        let local = self.local.as_ref().ok_or(CoreError::SecretKeyRequired)?;
        match local.secret_key(&account.id, &self.device_id)? {
            Unwrapped::Ok(sk) => Ok(sk),
            Unwrapped::Missing => Err(CoreError::SecretKeyRequired),
            Unwrapped::Unusable => {
                self.secret_key_broken = true;
                Err(CoreError::SecretKeyRequired)
            }
        }
    }

    /// 本机是否有可用的账户密钥包裹（据此决定解锁界面是否询问账户密钥）。
    #[must_use]
    pub fn has_local_secret_key(&self) -> bool {
        !self.secret_key_broken
            && self
                .local
                .as_ref()
                .is_some_and(|l| l.has(LocalPurpose::SecretKey))
    }

    /// Touch ID 是否已启用且未失效。
    #[must_use]
    pub fn touch_id_enabled(&self) -> bool {
        !self.touch_id_broken
            && self
                .local
                .as_ref()
                .is_some_and(|l| l.has(LocalPurpose::Auk))
    }

    /// 启用 Touch ID：用户再输入一次主密码，确认无误后包裹 AUK（`spec/crypto.md` §8.7）。
    ///
    /// # Errors
    /// 已锁定返回 [`CoreError::Locked`]；主密码错误返回 [`CoreError::WrongCredentials`]；
    /// 本机没有账户密钥返回 [`CoreError::SecretKeyRequired`]。
    pub fn enable_touch_id(&mut self, password: &str) -> Result<()> {
        self.session()?;
        let account = self.store.account()?.ok_or(CoreError::NoAccount)?;
        let params = KdfParams::decode(&account.kdf_params)?;
        let secret_key = self.local_secret_key()?;
        let auk = derive_account_unlock_key(password, &secret_key, &account.id, &params)?;
        check_auk(&account, &params, &auk)?;
        let device_id = self.device_id;
        let local = self.local.as_mut().ok_or(CoreError::SecretKeyRequired)?;
        let mut entries = local.entries();
        entries.insert(
            LocalPurpose::Auk,
            local.new_entry(LocalPurpose::Auk, |a| {
                wrap_auk(&auk, &account.id, &device_id, a)
            })?,
        );
        local.commit(entries, |keys, p| {
            verify_entry(keys, p, &account.id, &device_id)
        })?;
        self.touch_id_broken = false;
        self.record_password_unlock()?;
        Ok(())
    }

    /// 重新验证用户（`docs/ux.md` §5"重新验证"）：敏感操作之前，在已解锁的会话里再确认一次是本人。
    /// 用主密码时同时记作"刚输入过主密码"；用 Touch ID 时服从 [`Vault::password_reason`]。
    ///
    /// # Errors
    /// 已锁定返回 [`CoreError::Locked`]；主密码错误返回 [`CoreError::WrongCredentials`]；
    /// Touch ID 的错误同 [`Vault::unlock_with_touch_id`]。
    pub fn reverify(&mut self, proof: Reverify<'_>) -> Result<()> {
        self.session()?;
        let account = self.store.account()?.ok_or(CoreError::NoAccount)?;
        let params = KdfParams::decode(&account.kdf_params)?;
        match proof {
            Reverify::Password(password) => {
                let secret_key = self.local_secret_key()?;
                let auk = derive_account_unlock_key(password, &secret_key, &account.id, &params)?;
                check_auk(&account, &params, &auk)?;
                self.record_password_unlock()
            }
            Reverify::TouchId => {
                let auk = self.auk_from_touch_id(&account)?;
                if let Err(e) = check_auk(&account, &params, &auk) {
                    if e == CoreError::WrongCredentials {
                        self.touch_id_broken = true;
                        return Err(CoreError::TouchIdUnavailable);
                    }
                    return Err(e);
                }
                self.store.set_meta(META_TOUCH_ID_FAILURES, &[0])?;
                Ok(())
            }
        }
    }

    /// 关闭 Touch ID：先重新验证（`docs/ux.md` §5），再在新一代中去掉 AUK 的包裹。
    ///
    /// # Errors
    /// 同 [`Vault::reverify`]；写入失败时返回对应错误。
    pub fn disable_touch_id(&mut self, proof: Reverify<'_>) -> Result<()> {
        if !self.touch_id_enabled() && !self.touch_id_broken {
            return Ok(());
        }
        // Touch ID 已失效时只能用主密码验证
        self.reverify(proof)?;
        let account = self.store.account()?.ok_or(CoreError::NoAccount)?;
        let device_id = self.device_id;
        let Some(local) = self.local.as_mut() else {
            return Ok(());
        };
        if !local.has(LocalPurpose::Auk) {
            return Ok(());
        }
        let mut entries = local.entries();
        entries.remove(&LocalPurpose::Auk);
        local.commit(entries, |keys, p| {
            verify_entry(keys, p, &account.id, &device_id)
        })?;
        self.touch_id_broken = false;
        Ok(())
    }

    /// 用 Touch ID 解锁：Secure Enclave 解开 AUK，直接打开密钥集，不执行 KDF。
    ///
    /// # Errors
    /// [`Vault::password_reason`] 不为空时返回 [`CoreError::TouchIdUnavailable`]，不弹出 Touch ID；
    /// 用户取消返回 [`CoreError::Cancelled`]；指纹不匹配返回 [`CoreError::AuthenticationFailed`]，
    /// 计入连续失败次数；已失效返回 [`CoreError::TouchIdUnavailable`]，用主密码解锁后自动重新包裹。
    pub fn unlock_with_touch_id(&mut self) -> Result<()> {
        if self.password_reason()?.is_some() {
            return Err(CoreError::TouchIdUnavailable);
        }
        let account = self.store.account()?.ok_or(CoreError::NoAccount)?;
        let params = KdfParams::decode(&account.kdf_params)?;
        let auk = self.auk_from_touch_id(&account)?;
        match self.open_session(&account, &params, &auk) {
            Ok(()) => {
                self.store.set_meta(META_TOUCH_ID_FAILURES, &[0])?;
                if let Some(local) = self.local.as_ref() {
                    let _ = local.cleanup();
                }
                Ok(())
            }
            Err(CoreError::WrongCredentials) => {
                // AUK 已不是当前的（例如主密码已更改）
                self.touch_id_broken = true;
                Err(CoreError::TouchIdUnavailable)
            }
            Err(e) => Err(e),
        }
    }

    /// 用 Touch ID 从 Secure Enclave 解开 AUK。服从 [`Vault::password_reason`]；指纹不匹配计入连续失败次数，
    /// 材料失效时标记 Touch ID 已失效。
    fn auk_from_touch_id(&mut self, account: &AccountRow) -> Result<SymmetricKey> {
        if self.password_reason()?.is_some() {
            return Err(CoreError::TouchIdUnavailable);
        }
        let local = self.local.as_ref().ok_or(CoreError::TouchIdUnavailable)?;
        let unwrapped = match local.auk(&account.id, &self.device_id) {
            Err(CoreError::AuthenticationFailed) => {
                let n = self.touch_id_failures()?.saturating_add(1);
                self.store.set_meta(META_TOUCH_ID_FAILURES, &[n])?;
                return Err(CoreError::AuthenticationFailed);
            }
            other => other?,
        };
        match unwrapped {
            Unwrapped::Ok(auk) => Ok(auk),
            Unwrapped::Missing => Err(CoreError::TouchIdUnavailable),
            Unwrapped::Unusable => {
                self.touch_id_broken = true;
                Err(CoreError::TouchIdUnavailable)
            }
        }
    }

    /// 当前的解锁代次；锁定时为 `None`。每次成功解锁都会得到一个新值，因此"锁定后又解锁"不等于同一次解锁。
    #[must_use]
    pub const fn unlock_epoch(&self) -> Option<u64> {
        if self.session.is_some() {
            Some(self.unlock_epoch)
        } else {
            None
        }
    }

    /// 锁定：清除内存中的全部密钥。
    pub fn lock(&mut self) {
        self.session = None;
    }

    /// 全部保险库，按名称排序。
    ///
    /// # Errors
    /// 已锁定时返回 [`CoreError::Locked`]。
    pub fn vaults(&self) -> Result<Vec<VaultInfo>> {
        let session = self.session()?;
        let mut out = Vec::new();
        for (vault_id, vk) in &session.vault_keys {
            let head = self
                .store
                .heads(vault_id)?
                .into_iter()
                .next()
                .ok_or(CoreError::Tampered)?;
            let ct = head.overview_ct.as_deref().ok_or(CoreError::Tampered)?;
            let ctx = context(
                session.account_id,
                ObjectType::Vault,
                Part::Overview,
                *vault_id,
                *vault_id,
                head.rev_id,
            );
            let meta = VaultMeta::decode(&open(vk, &ctx, ct)?)?;
            out.push(VaultInfo {
                id: *vault_id,
                name: meta.name,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
        Ok(out)
    }

    /// 新建保险库。
    ///
    /// # Errors
    /// 已锁定时返回 [`CoreError::Locked`]。
    pub fn create_vault(&mut self, name: &str) -> Result<Id128> {
        let hlc = self.tick()?;
        let session = self.session()?;
        let vault_id = Id128::random()?;
        let rev_id = Id128::random()?;
        let vk = SymmetricKey::generate()?;
        let wrap_ctx = context(
            session.account_id,
            ObjectType::Vault,
            Part::WrappedKey,
            vault_id,
            vault_id,
            rev_id,
        );
        let meta_ctx = context(
            session.account_id,
            ObjectType::Vault,
            Part::Overview,
            vault_id,
            vault_id,
            rev_id,
        );
        let row = RevisionRow {
            rev_id,
            object_id: vault_id,
            kind: ObjectKind::Vault,
            vault_id,
            parents: Vec::new(),
            origin_device: self.device_id,
            origin_seq: None,
            wrapped_key_ct: Some(session.keyset.account_key().wrap_key(&wrap_ctx, &vk)?),
            overview_ct: Some(seal(&vk, &meta_ctx, &VaultMeta::new(name, hlc).encode()?)?),
            details_ct: None,
            deleted: false,
            pruned: false,
        };
        self.store.insert_revision(&row)?;
        self.session_mut()?.vault_keys.insert(vault_id, vk);
        Ok(vault_id)
    }

    /// 新建条目。
    ///
    /// # Errors
    /// 已锁定返回 [`CoreError::Locked`]；保险库不存在返回 [`CoreError::NotFound`]。
    pub fn create_item(
        &mut self,
        vault_id: Id128,
        item_type: ItemType,
        title: &str,
        fields: Vec<NewField>,
    ) -> Result<Id128> {
        let hlc = self.tick()?;
        let item_id = Id128::random()?;
        let rev_id = Id128::random()?;
        let mut doc = ItemDoc::new(item_type);
        doc.set(
            RecordKey::attr("title"),
            RecordValue::Text(title.into()),
            hlc,
            rev_id,
        )?;
        for (i, field) in fields.into_iter().enumerate() {
            add_field(&mut doc, field, order_key(i), hlc, rev_id)?;
        }
        let ik = SymmetricKey::generate()?;
        self.write_item_revision(vault_id, item_id, rev_id, Vec::new(), &ik, Some(&doc))?;
        Ok(item_id)
    }

    /// 读取条目：合并全部头修订。
    ///
    /// # Errors
    /// 已锁定返回 [`CoreError::Locked`]；不存在或已永久删除返回 [`CoreError::NotFound`]。
    pub fn item(&self, item_id: Id128) -> Result<ItemView> {
        let heads = self.store.heads(&item_id)?;
        let vault_id = heads
            .first()
            .map(|h| h.vault_id)
            .ok_or(CoreError::NotFound)?;
        let docs = self.decrypt_heads(&heads)?;
        let graph = self.graph(&item_id)?;
        let states: Vec<HeadState<'_>> = heads
            .iter()
            .zip(&docs)
            .map(|(h, d)| match d {
                Some(doc) => HeadState::Live { rev: h.rev_id, doc },
                None => HeadState::Deleted { rev: h.rev_id },
            })
            .collect();
        let merged = merge_heads(&states, &graph)?;
        let doc = merged.doc.ok_or(CoreError::NotFound)?;
        Ok(ItemView {
            id: item_id,
            vault_id,
            doc,
            conflicts: merged.conflicts,
            resurrected: merged.resurrected,
            head_count: heads.len(),
            integrity_issues: merged.integrity_issues,
        })
    }

    /// 全部未永久删除的条目（含回收站与归档中的条目），按标题排序。
    ///
    /// 只有一个头的条目只解密概要；存在并发修改的条目才解密详情并合并。
    ///
    /// # Errors
    /// 已锁定时返回 [`CoreError::Locked`]。
    pub fn items(&self) -> Result<Vec<ItemSummary>> {
        let session = self.session()?;
        let mut out = Vec::new();
        for item_id in self.store.objects(ObjectKind::Item)? {
            let heads = self.store.heads(&item_id)?;
            match heads.as_slice() {
                [only] if only.deleted => {}
                [only] => {
                    let ik = self.item_key(session, only)?;
                    let ct = only.overview_ct.as_deref().ok_or(CoreError::Tampered)?;
                    let ctx = context(
                        session.account_id,
                        ObjectType::Item,
                        Part::Overview,
                        only.vault_id,
                        item_id,
                        only.rev_id,
                    );
                    let overview = ItemOverview::decode(&open(&ik, &ctx, ct)?)?;
                    out.push(ItemSummary {
                        id: item_id,
                        vault_id: only.vault_id,
                        has_conflicts: overview.conflicts,
                        overview,
                    });
                }
                _ => match self.item(item_id) {
                    Ok(view) => out.push(ItemSummary {
                        id: item_id,
                        vault_id: view.vault_id,
                        overview: view.doc.overview(),
                        has_conflicts: !view.conflicts.is_empty()
                            || view.resurrected
                            || !view.integrity_issues.is_empty(),
                    }),
                    Err(CoreError::NotFound) => {}
                    Err(e) => return Err(e),
                },
            }
        }
        out.sort_by(|a, b| {
            a.overview
                .title
                .cmp(&b.overview.title)
                .then(a.id.cmp(&b.id))
        });
        Ok(out)
    }

    /// 编辑条目：以合并视图为基础写入新修订，父修订为全部头，并发修改随之收敛。
    ///
    /// # Errors
    /// 已锁定返回 [`CoreError::Locked`]；条目或字段不存在返回 [`CoreError::NotFound`]。
    pub fn update_item(&mut self, item_id: Id128, edits: Vec<Edit>) -> Result<()> {
        self.revise(item_id, |doc, hlc, rev_id| {
            for edit in edits {
                apply(doc, edit, hlc, rev_id)?;
            }
            Ok(())
        })
    }

    /// 处理一个记录键上的冲突：保留写于 `keep` 的版本（`spec/revisions.md` §5.4）。
    /// 选中版本的值作为新版本写入，该键的其他并发版本随之被因果覆盖。
    ///
    /// # Errors
    /// 该键上没有写于 `keep` 的版本时返回 [`CoreError::Format`]；其余见 [`Vault::update_item`]。
    pub fn resolve_conflict(&mut self, item_id: Id128, key: &RecordKey, keep: Id128) -> Result<()> {
        self.revise(item_id, |doc, hlc, rev_id| {
            Ok(doc.resolve(key, keep, hlc, rev_id)?)
        })
    }

    /// 精简条目（`spec/revisions.md` §7.1）：在**一次**写入中处理冲突（保留指定版本）并删除指定记录。
    /// 条目合并后超过单个信封、普通保存返回 [`CoreError::ItemTooLarge`] 时，用它把状态缩小到可保存的大小。
    ///
    /// # Errors
    /// 指定的版本不存在时返回 [`CoreError::Format`]；精简后仍然过大时返回 [`CoreError::ItemTooLarge`]；
    /// 其余见 [`Vault::update_item`]。
    pub fn compact_item(
        &mut self,
        item_id: Id128,
        keep: &[(RecordKey, Id128)],
        remove: &[RecordKey],
    ) -> Result<()> {
        self.revise(item_id, |doc, hlc, rev_id| {
            for (key, version) in keep {
                doc.resolve(key, *version, hlc, rev_id)?;
            }
            for key in remove {
                doc.delete(key.clone(), hlc, rev_id)?;
            }
            Ok(())
        })
    }

    /// 写时收敛（§5.4）：以合并视图为基础、父修订为全部头，写入一个新修订。
    fn revise(
        &mut self,
        item_id: Id128,
        change: impl FnOnce(&mut ItemDoc, Hlc, Id128) -> Result<()>,
    ) -> Result<()> {
        let view = self.item(item_id)?;
        let heads = self.store.heads(&item_id)?;
        // 精简也回不到的状态：头太多（新修订必须以全部头为父），或键太多（删除只会留下墓碑，键数不减）
        if heads.len() > keevo_store::MAX_PARENTS || view.doc.key_count() > keevo_format::MAX_KEYS {
            return Err(CoreError::ItemNeedsRebuild);
        }
        let mut doc = view.doc;
        let hlc = self.tick()?;
        let rev_id = Id128::random()?;
        // 把"已撤销删除"写成墓碑，否则引发撤销的并发修改日后被覆盖时，删除会重新生效
        doc.settle_for_write(hlc, rev_id);
        change(&mut doc, hlc, rev_id)?;
        let ik = {
            let session = self.session()?;
            let live = heads
                .iter()
                .find(|h| !h.deleted)
                .ok_or(CoreError::NotFound)?;
            self.item_key(session, live)?
        };
        let parents = heads.iter().map(|h| h.rev_id).collect();
        self.write_item_revision(view.vault_id, item_id, rev_id, parents, &ik, Some(&doc))?;
        self.store
            .prune(&item_id, HISTORY_KEEP, HISTORY_MIN_AGE_MS)?;
        Ok(())
    }

    /// 移入回收站。
    ///
    /// # Errors
    /// 见 [`Vault::update_item`]。
    pub fn trash_item(&mut self, item_id: Id128) -> Result<()> {
        let now = i64::try_from(now_ms()).map_err(|_| CoreError::Tampered)?;
        self.edit_attr(item_id, "trashed", Some(RecordValue::Int(now)))
    }

    /// 从回收站恢复。
    ///
    /// # Errors
    /// 见 [`Vault::update_item`]。
    pub fn restore_item(&mut self, item_id: Id128) -> Result<()> {
        self.edit_attr(item_id, "trashed", None)
    }

    /// 永久删除：写入墓碑修订（`spec/revisions.md` §6）。
    ///
    /// # Errors
    /// 见 [`Vault::update_item`]。
    pub fn purge_item(&mut self, item_id: Id128) -> Result<()> {
        let view = self.item(item_id)?;
        let heads = self.store.heads(&item_id)?;
        let rows = self.tombstone_rows(
            view.vault_id,
            item_id,
            heads.iter().map(|h| h.rev_id).collect(),
        )?;
        self.store.insert_revisions(&rows)?;
        Ok(())
    }

    /// 重建条目（`spec/revisions.md` §7.1）：把当前视图中的值（不含墓碑、并发版本与 `drop` 中的键）
    /// 复制为一个新条目，再永久删除旧条目。用于超出上限、只能重建的条目（[`CoreError::ItemNeedsRebuild`]）。
    /// 新条目有新的 ID；旧条目的历史随永久删除进入正常清理。
    ///
    /// # Errors
    /// 复制后仍超过键数或大小上限时返回错误，调用方应让用户在 `drop` 中选出更多不保留的键。
    pub fn rebuild_item(&mut self, item_id: Id128, drop: &[RecordKey]) -> Result<Id128> {
        let view = self.item(item_id)?;
        let hlc = self.tick()?;
        let new_id = Id128::random()?;
        let rev_id = Id128::random()?;
        let mut doc = ItemDoc::new(view.doc.item_type);
        for (key, version) in &view.doc.records {
            if key.is_deletion_state() || drop.contains(key) {
                continue;
            }
            if let Some(value) = &version.value {
                doc.set(key.clone(), value.clone(), hlc, rev_id)?;
            }
        }
        let ik = SymmetricKey::generate()?;
        // 新条目与旧条目的墓碑在一个事务中写入：要么都成功，要么都不发生（第四轮评审 J2）
        let mut rows = vec![self.item_revision_row(
            view.vault_id,
            new_id,
            rev_id,
            Vec::new(),
            &ik,
            Some(&doc),
        )?];
        let heads = self.store.heads(&item_id)?;
        rows.extend(self.tombstone_rows(
            view.vault_id,
            item_id,
            heads.iter().map(|h| h.rev_id).collect(),
        )?);
        self.store.insert_revisions(&rows)?;
        Ok(new_id)
    }

    /// 条目的全部历史修订，从新到旧（本机写入或收到的顺序）。已清理与墓碑修订只有元数据。
    ///
    /// # Errors
    /// 已锁定返回 [`CoreError::Locked`]；数据被篡改时返回 [`CoreError::Tampered`]。
    pub fn history(&self, item_id: Id128) -> Result<Vec<HistoryEntry>> {
        self.store
            .history(&item_id)?
            .into_iter()
            .map(|row| {
                let overview = if row.deleted || row.pruned {
                    None
                } else {
                    Some(ItemOverview::decode(
                        &self.decrypt_part(&row, Part::Overview)?,
                    )?)
                };
                Ok(HistoryEntry {
                    rev_id: row.rev_id,
                    parents: row.parents,
                    deleted: row.deleted,
                    pruned: row.pruned,
                    overview,
                })
            })
            .collect()
    }

    /// 某个历史修订的完整内容。
    ///
    /// # Errors
    /// 修订不属于该条目、是墓碑或内容已被清理时返回 [`CoreError::NotFound`]。
    pub fn revision_doc(&self, item_id: Id128, rev_id: Id128) -> Result<ItemDoc> {
        let row = self
            .store
            .revision(&rev_id)?
            .filter(|r| r.object_id == item_id && !r.deleted && !r.pruned)
            .ok_or(CoreError::NotFound)?;
        Ok(ItemDoc::decode(&self.decrypt_part(&row, Part::Details)?)?)
    }

    /// 恢复到此版本（`spec/revisions.md` §7.2）：把历史修订中的记录值作为一次新的编辑写入，
    /// 而不是回退修订图。回收站状态保持当前的样子；这一版本之后新增的记录被删除；
    /// 被写入的键上若有未处理的冲突，也随之解决。
    ///
    /// # Errors
    /// 同 [`Vault::revision_doc`] 与 [`Vault::update_item`]。
    pub fn restore_version(&mut self, item_id: Id128, rev_id: Id128) -> Result<()> {
        let old = self.revision_doc(item_id, rev_id)?;
        self.revise(item_id, |doc, hlc, rev| {
            let keys: std::collections::BTreeSet<RecordKey> = doc
                .records
                .keys()
                .chain(old.records.keys())
                .filter(|k| !k.is_deletion_state())
                .cloned()
                .collect();
            for key in keys {
                let before = old.records.get(&key).and_then(|v| v.value.clone());
                let now = doc.records.get(&key).and_then(|v| v.value.clone());
                let contested = doc.concurrent.contains_key(&key);
                if before == now && !contested {
                    continue;
                }
                match before {
                    Some(value) => doc.set(key, value, hlc, rev)?,
                    None if now.is_some() || contested => doc.delete(key, hlc, rev)?,
                    None => {}
                }
            }
            Ok(())
        })
    }

    /// 条目的历史修订数（含已清理内容的修订）。
    ///
    /// # Errors
    /// SQLite 错误。
    pub fn revision_count(&self, item_id: Id128) -> Result<usize> {
        Ok(self.store.graph(&item_id)?.len())
    }

    // ------------------------------------------------------------ 内部

    fn session(&self) -> Result<&Session> {
        self.session.as_ref().ok_or(CoreError::Locked)
    }

    fn session_mut(&mut self) -> Result<&mut Session> {
        self.session.as_mut().ok_or(CoreError::Locked)
    }

    fn tick(&mut self) -> Result<Hlc> {
        let hlc = self.clock.next(now_ms())?;
        self.store.set_meta(META_HLC, &hlc.0.to_be_bytes())?;
        Ok(hlc)
    }

    fn graph(&self, object_id: &Id128) -> Result<RevisionGraph> {
        let mut graph = RevisionGraph::new();
        for m in self.store.graph(object_id)? {
            graph.insert(m.rev_id, m.parents, m.origin_device)?;
        }
        Ok(graph)
    }

    fn item_key(&self, session: &Session, head: &RevisionRow) -> Result<SymmetricKey> {
        let vk = session
            .vault_keys
            .get(&head.vault_id)
            .ok_or(CoreError::NotFound)?;
        let wrapped = head.wrapped_key_ct.as_deref().ok_or(CoreError::Tampered)?;
        let ctx = context(
            session.account_id,
            ObjectType::Item,
            Part::WrappedKey,
            head.vault_id,
            head.object_id,
            head.rev_id,
        );
        Ok(vk.unwrap_key(&ctx, wrapped)?)
    }

    fn decrypt_heads(&self, heads: &[RevisionRow]) -> Result<Vec<Option<ItemDoc>>> {
        heads
            .iter()
            .map(|h| {
                if h.deleted {
                    return Ok(None);
                }
                let bytes = self.decrypt_part(h, Part::Details)?;
                Ok(Some(ItemDoc::decode(&bytes)?))
            })
            .collect()
    }

    /// 解密一个条目修订的某个部分（概要或详情），上下文见 `spec/crypto.md` §8.6。
    fn decrypt_part(&self, row: &RevisionRow, part: Part) -> Result<keevo_crypto::SecretBytes> {
        let session = self.session()?;
        let ik = self.item_key(session, row)?;
        let ct = match part {
            Part::Overview => row.overview_ct.as_deref(),
            _ => row.details_ct.as_deref(),
        }
        .ok_or(CoreError::Tampered)?;
        let ctx = context(
            session.account_id,
            ObjectType::Item,
            part,
            row.vault_id,
            row.object_id,
            row.rev_id,
        );
        Ok(open(&ik, &ctx, ct)?)
    }

    fn write_item_revision(
        &mut self,
        vault_id: Id128,
        item_id: Id128,
        rev_id: Id128,
        parents: Vec<Id128>,
        ik: &SymmetricKey,
        doc: Option<&ItemDoc>,
    ) -> Result<()> {
        let row = self.item_revision_row(vault_id, item_id, rev_id, parents, ik, doc)?;
        self.store.insert_revision(&row)?;
        Ok(())
    }

    /// 构造一个条目修订（加密），但不写入。
    fn item_revision_row(
        &self,
        vault_id: Id128,
        item_id: Id128,
        rev_id: Id128,
        parents: Vec<Id128>,
        ik: &SymmetricKey,
        doc: Option<&ItemDoc>,
    ) -> Result<RevisionRow> {
        let session = self.session()?;
        let vk = session
            .vault_keys
            .get(&vault_id)
            .ok_or(CoreError::NotFound)?;
        let acct = session.account_id;
        let (wrapped, overview, details) = match doc {
            Some(doc) => (
                Some(vk.wrap_key(
                    &context(
                        acct,
                        ObjectType::Item,
                        Part::WrappedKey,
                        vault_id,
                        item_id,
                        rev_id,
                    ),
                    ik,
                )?),
                Some(seal(
                    ik,
                    &context(
                        acct,
                        ObjectType::Item,
                        Part::Overview,
                        vault_id,
                        item_id,
                        rev_id,
                    ),
                    &doc.overview().encode()?,
                )?),
                Some(seal(
                    ik,
                    &context(
                        acct,
                        ObjectType::Item,
                        Part::Details,
                        vault_id,
                        item_id,
                        rev_id,
                    ),
                    &doc.encode_for_write()?,
                )?),
            ),
            None => (None, None, None),
        };
        Ok(RevisionRow {
            rev_id,
            object_id: item_id,
            kind: ObjectKind::Item,
            vault_id,
            parents,
            origin_device: self.device_id,
            origin_seq: None,
            wrapped_key_ct: wrapped,
            overview_ct: overview,
            details_ct: details,
            deleted: doc.is_none(),
            pruned: false,
        })
    }

    /// 永久删除需要的墓碑修订（`spec/revisions.md` §6）。头不超过 [`keevo_store::MAX_TOMBSTONE_PARENTS`]
    /// 个时只有一个墓碑；更多时分批：每批一个墓碑，再用墓碑覆盖这些墓碑，直到只剩一个头。
    /// 调用方必须在**一个事务**中写入全部墓碑（第四轮评审 J2）。
    fn tombstone_rows(
        &self,
        vault_id: Id128,
        item_id: Id128,
        heads: Vec<Id128>,
    ) -> Result<Vec<RevisionRow>> {
        let plan = tombstone_plan(heads, keevo_store::MAX_TOMBSTONE_PARENTS, Id128::random)?;
        Ok(plan
            .into_iter()
            .map(|(rev_id, parents)| RevisionRow {
                rev_id,
                object_id: item_id,
                kind: ObjectKind::Item,
                vault_id,
                parents,
                origin_device: self.device_id,
                origin_seq: None,
                wrapped_key_ct: None,
                overview_ct: None,
                details_ct: None,
                deleted: true,
                pruned: false,
            })
            .collect())
    }

    /// 修改单个属性（回收站状态等）。与其他编辑一样经由写时收敛（[`Vault::revise`]），
    /// 包括确定"撤销删除"与历史清理。
    fn edit_attr(&mut self, item_id: Id128, name: &str, value: Option<RecordValue>) -> Result<()> {
        self.revise(item_id, |doc, hlc, rev_id| {
            match value {
                Some(v) => doc.set(RecordKey::attr(name), v, hlc, rev_id)?,
                None => doc.delete(RecordKey::attr(name), hlc, rev_id)?,
            }
            Ok(())
        })
    }
}

/// 墓碑的分批计划：返回按写入顺序排列的 (墓碑 ID, 父修订)。每个墓碑最多 `max` 个父修订；
/// 最后一个墓碑是唯一的头。头不超过 `max` 个时只有一个墓碑。
fn tombstone_plan(
    mut level: Vec<Id128>,
    max: usize,
    mut new_id: impl FnMut() -> keevo_crypto::Result<Id128>,
) -> Result<Vec<(Id128, Vec<Id128>)>> {
    let max = max.max(2);
    let mut plan = Vec::new();
    loop {
        let mut next = Vec::new();
        for chunk in level.chunks(max) {
            let id = new_id()?;
            plan.push((id, chunk.to_vec()));
            next.push(id);
        }
        if next.len() <= 1 {
            return Ok(plan);
        }
        level = next;
    }
}

fn context(
    account_id: Id128,
    object_type: ObjectType,
    part: Part,
    vault_id: Id128,
    object_id: Id128,
    rev_id: Id128,
) -> AadContext {
    AadContext {
        object_type,
        part,
        part_index: 0,
        account_id,
        vault_id,
        object_id,
        rev_id,
        binding: [0; 32],
    }
}

/// 字段排序键。M0 使用定宽十进制；M1.1 改为分数索引（`spec/revisions.md` §4.1）。
fn order_key(index: usize) -> String {
    format!("{:010}", index.saturating_mul(1024))
}

fn add_field(
    doc: &mut ItemDoc,
    field: NewField,
    order: String,
    hlc: Hlc,
    rev: Id128,
) -> Result<Id128> {
    let field_id = Id128::random()?;
    let value = FieldValue {
        section: None,
        order,
        kind: field.kind,
        label: field.label,
        purpose: field.purpose,
        data: field.data,
    };
    doc.set(
        RecordKey::Field(field_id),
        RecordValue::Field(value),
        hlc,
        rev,
    )?;
    Ok(field_id)
}

fn apply(doc: &mut ItemDoc, edit: Edit, hlc: Hlc, rev: Id128) -> Result<()> {
    match edit {
        Edit::SetTitle(t) => doc.set(
            RecordKey::attr("title"),
            RecordValue::Text(t.as_str().into()),
            hlc,
            rev,
        )?,
        Edit::SetFavorite(f) => {
            doc.set(RecordKey::attr("favorite"), RecordValue::Bool(f), hlc, rev)?
        }
        Edit::AddTag(t) => doc.set(RecordKey::Tag(t), RecordValue::Tag, hlc, rev)?,
        Edit::RemoveTag(t) => doc.delete(RecordKey::Tag(t), hlc, rev)?,
        Edit::AddField(field) => {
            let next = doc
                .records
                .keys()
                .filter(|k| matches!(k, RecordKey::Field(_)))
                .count();
            add_field(doc, field, order_key(next), hlc, rev)?;
        }
        Edit::SetFieldData { field_id, data } => {
            let key = RecordKey::Field(field_id);
            let Some(RecordValue::Field(current)) = doc.get(&key).cloned() else {
                return Err(CoreError::NotFound);
            };
            doc.set(
                key,
                RecordValue::Field(FieldValue { data, ..current }),
                hlc,
                rev,
            )?;
        }
        Edit::RemoveField(field_id) => {
            let key = RecordKey::Field(field_id);
            if doc.get(&key).is_none() {
                return Err(CoreError::NotFound);
            }
            doc.delete(key, hlc, rev)?;
        }
    }
    Ok(())
}

/// 测试专用：核心层使用的当前时间。
#[cfg(test)]
pub(crate) fn vault_now_ms_for_tests() -> u64 {
    now_ms()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn id_from(bytes: &[u8]) -> Result<Id128> {
    let arr: [u8; 16] = bytes.try_into().map_err(|_| CoreError::Tampered)?;
    Ok(Id128::from_bytes(arr))
}

/// AUK 能否打开账户密钥集：不能时返回 [`CoreError::WrongCredentials`]。
fn check_auk(account: &AccountRow, params: &KdfParams, auk: &SymmetricKey) -> Result<()> {
    AccountKeyset::open(auk, &account.id, account.epoch, params, &account.keyset_ct)
        .map(drop)
        .map_err(|e| match e {
            CryptoError::KeyIdMismatch | CryptoError::DecryptionFailed => {
                CoreError::WrongCredentials
            }
            other => CoreError::Crypto(other),
        })
}

/// 提交新一代前的验证：不要求用户在场的包裹必须能解开（`spec/crypto.md` §8.7）。
fn verify_entry(
    keys: &LocalKeys,
    purpose: LocalPurpose,
    account_id: &Id128,
    device_id: &Id128,
) -> Result<bool> {
    Ok(match purpose {
        LocalPurpose::DeviceMarker => {
            matches!(keys.device_marker(account_id)?, Unwrapped::Ok(id) if id == *device_id)
        }
        LocalPurpose::SecretKey => {
            matches!(keys.secret_key(account_id, device_id)?, Unwrapped::Ok(_))
        }
        LocalPurpose::Auk | LocalPurpose::ServiceStatic => true,
    })
}

#[cfg(test)]
mod tests;
