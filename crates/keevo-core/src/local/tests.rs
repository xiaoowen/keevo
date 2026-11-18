use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::sync::Mutex;

use keevo_crypto::KdfParams;
use keevo_store::Store;

use super::*;
use crate::Vault;

/// 模拟的 Secure Enclave。协商结果随机生成并记在表里，`agree` 只有拿着创建时的 blob 才能查到。
#[derive(Default)]
struct FakeEnclave {
    state: Mutex<FakeState>,
}

#[derive(Default)]
struct FakeState {
    /// blob → (用途, 公钥)
    keys: HashMap<Vec<u8>, (LocalPurpose, Vec<u8>)>,
    /// (公钥, 临时公钥) → 协商结果
    agreements: HashMap<(Vec<u8>, Vec<u8>), Vec<u8>>,
    /// 下一次 `agree` 对这个用途报告的错误。
    fail: HashMap<LocalPurpose, EnclaveError>,
    /// 一直报告错误的用途（模拟锁屏期间）。
    fail_always: HashMap<LocalPurpose, EnclaveError>,
    /// 对这个用途，`agree` 返回错误的协商结果（模拟验证失败）。
    corrupt: Option<LocalPurpose>,
    /// 要求用户在场的协商次数（Touch ID 提示次数）。
    prompts: usize,
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    while out.len() < n {
        out.extend_from_slice(Id128::random().unwrap().as_bytes());
    }
    out.truncate(n);
    out
}

fn point() -> Vec<u8> {
    let mut p = random_bytes(65);
    p[0] = 0x04;
    p
}

impl FakeEnclave {
    fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.state.lock().unwrap()
    }

    /// 模拟指纹变化：这个用途的全部 Secure Enclave 密钥失效。
    fn invalidate(&self, purpose: LocalPurpose) {
        self.state().keys.retain(|_, (p, _)| *p != purpose);
    }
}

impl SecureEnclave for FakeEnclave {
    fn create_key(&self, purpose: LocalPurpose) -> core::result::Result<EnclaveKey, EnclaveError> {
        let blob = random_bytes(300);
        let public_key = point();
        self.state()
            .keys
            .insert(blob.clone(), (purpose, public_key.clone()));
        Ok(EnclaveKey { blob, public_key })
    }

    fn agree_ephemeral(
        &self,
        public_key: &[u8],
    ) -> core::result::Result<EphemeralAgreement, EnclaveError> {
        let eph = point();
        let shared = random_bytes(32);
        self.state()
            .agreements
            .insert((public_key.to_vec(), eph.clone()), shared.clone());
        Ok(EphemeralAgreement {
            ephemeral_public: eph,
            shared: Zeroizing::new(shared),
        })
    }

    fn agree(
        &self,
        purpose: LocalPurpose,
        blob: &[u8],
        ephemeral_public: &[u8],
    ) -> core::result::Result<Zeroizing<Vec<u8>>, EnclaveError> {
        let mut s = self.state();
        if purpose.requires_presence() {
            s.prompts = s.prompts.saturating_add(1);
        }
        if let Some(e) = s.fail.remove(&purpose) {
            return Err(e);
        }
        if let Some(e) = s.fail_always.get(&purpose) {
            return Err(*e);
        }
        let Some((p, public)) = s.keys.get(blob).cloned() else {
            return Err(EnclaveError::Unusable);
        };
        if p != purpose {
            return Err(EnclaveError::Unusable);
        }
        if s.corrupt == Some(purpose) {
            return Ok(Zeroizing::new(random_bytes(32)));
        }
        s.agreements
            .get(&(public, ephemeral_public.to_vec()))
            .cloned()
            .map(Zeroizing::new)
            .ok_or(EnclaveError::Unusable)
    }
}

fn fast_params() -> KdfParams {
    KdfParams::new(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1, [4u8; 16]).unwrap()
}

struct Mac {
    root: PathBuf,
    enclave: Arc<FakeEnclave>,
}

impl Mac {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "keevo-local-test-{}",
            Id128::random().unwrap().to_hex()
        ));
        fs::create_dir_all(&root).unwrap();
        Self {
            root,
            enclave: Arc::new(FakeEnclave::default()),
        }
    }

    fn db(&self) -> PathBuf {
        self.root.join("vault.sqlite")
    }

    fn local_dir(&self) -> PathBuf {
        self.root.join("local")
    }

    fn keys(&self) -> LocalKeys {
        self.keys_booted("boot-1")
    }

    /// 模拟另一次开机。
    fn keys_booted(&self, boot: &str) -> LocalKeys {
        LocalKeys::load(&self.local_dir(), self.enclave.clone())
            .unwrap()
            .with_boot_session(boot)
    }

    fn create(&self) -> (Vault, AccountSecretKey) {
        Vault::create_with_local(
            Store::open(&self.db()).unwrap(),
            "pw",
            fast_params(),
            self.keys(),
        )
        .unwrap()
    }

    fn open(&self) -> Result<Vault> {
        Vault::open_with_local(Store::open(&self.db()).unwrap(), self.keys())
    }

    fn generations(&self) -> Vec<u64> {
        let mut g = list_generations(&self.local_dir()).unwrap();
        g.sort_unstable();
        g
    }

    /// 把数据库"恢复"到另一台 Mac：同一个数据库文件，另一个 Secure Enclave，没有本机密钥目录。
    fn restore_to_another_mac(&self) -> Self {
        let other = Self::new();
        fs::copy(self.db(), other.db()).unwrap();
        other
    }
}

impl Drop for Mac {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// 新建账户后，重新打开只需主密码；设备 ID 来自设备标记；文件权限为 0600 / 0700。
#[test]
fn password_only_unlock_after_reopen() {
    let mac = Mac::new();
    let (vault, _sk) = mac.create();
    let device_id = vault.device_id();
    assert!(vault.has_local_secret_key());
    assert!(!vault.touch_id_enabled());
    drop(vault);

    let mut vault = mac.open().unwrap();
    assert_eq!(vault.device_id(), device_id, "设备 ID 取自设备标记");
    assert!(!vault.is_unlocked());
    assert_eq!(
        vault.unlock_with_password("wrong").err(),
        Some(CoreError::WrongCredentials)
    );
    vault.unlock_with_password("pw").unwrap();
    assert!(vault.is_unlocked());

    assert_eq!(mac.generations(), [1]);
    let dir_mode = fs::metadata(mac.local_dir()).unwrap().permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700);
    for name in ["02.key", "02.wrap", "04.key", "04.wrap"] {
        let mode = fs::metadata(mac.local_dir().join("gen-1").join(name))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "{name}");
    }
    assert!(!mac.local_dir().join("gen-1").join("01.key").exists());
}

/// 数据库恢复到另一台 Mac：设备标记解不开，生成新的设备 ID；账户密钥需要从应急包输入，
/// 输入并解锁成功后补登，之后只需主密码。
#[test]
fn restored_database_gets_new_device_id_and_asks_for_secret_key() {
    let mac = Mac::new();
    let (vault, sk) = mac.create();
    let old_device = vault.device_id();
    drop(vault);

    let other = mac.restore_to_another_mac();
    let mut vault = other.open().unwrap();
    assert_ne!(vault.device_id(), old_device, "revisions.md §8");
    assert!(!vault.has_local_secret_key());
    assert_eq!(
        vault.unlock_with_password("pw").err(),
        Some(CoreError::SecretKeyRequired)
    );
    vault.unlock("pw", &sk).unwrap();
    assert!(vault.has_local_secret_key(), "解锁成功后补登账户密钥");
    let new_device = vault.device_id();
    drop(vault);

    let mut vault = other.open().unwrap();
    assert_eq!(vault.device_id(), new_device);
    vault.unlock_with_password("pw").unwrap();
    assert_eq!(other.generations().len(), 1, "成功解锁后清理旧代次");
}

/// 原 Mac 的本机密钥目录被一起复制过去也一样：另一台 Mac 的 Secure Enclave 用不了这些 blob。
#[test]
fn copied_local_directory_is_useless_on_another_mac() {
    let mac = Mac::new();
    let (vault, _) = mac.create();
    let old_device = vault.device_id();
    drop(vault);
    let other = mac.restore_to_another_mac();
    copy_dir(&mac.local_dir(), &other.local_dir());
    let mut vault = other.open().unwrap();
    assert_ne!(vault.device_id(), old_device);
    assert_eq!(
        vault.unlock_with_password("pw").err(),
        Some(CoreError::SecretKeyRequired)
    );
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// 暂时不可用（锁屏）不是失败：打开失败但什么都不改变；恢复后设备 ID 与包裹照旧。
#[test]
fn temporary_unavailability_changes_nothing() {
    let mac = Mac::new();
    let (vault, _) = mac.create();
    let device_id = vault.device_id();
    drop(vault);

    mac.enclave
        .state()
        .fail_always
        .insert(LocalPurpose::DeviceMarker, EnclaveError::Unavailable);
    assert_eq!(mac.open().err(), Some(CoreError::EnclaveUnavailable));
    assert_eq!(mac.generations(), [1], "没有写出新一代");

    mac.enclave.state().fail_always.clear();
    mac.enclave
        .state()
        .fail_always
        .insert(LocalPurpose::SecretKey, EnclaveError::Unavailable);
    let mut vault = mac.open().unwrap();
    assert_eq!(vault.device_id(), device_id);
    assert_eq!(
        vault.unlock_with_password("pw").err(),
        Some(CoreError::EnclaveUnavailable)
    );
    assert!(vault.has_local_secret_key(), "暂时不可用不等于失效");

    mac.enclave.state().fail_always.clear();
    vault.unlock_with_password("pw").unwrap();
    assert_eq!(mac.generations(), [1]);
}

/// 一直暂时不可用时，用户可以主动重新登记本机：新的设备 ID，之后需要输入账户密钥。
#[test]
fn user_can_reenroll_when_enclave_stays_unavailable() {
    let mac = Mac::new();
    let (vault, sk) = mac.create();
    let device_id = vault.device_id();
    drop(vault);
    mac.enclave
        .state()
        .fail_always
        .insert(LocalPurpose::DeviceMarker, EnclaveError::Unavailable);
    assert_eq!(mac.open().err(), Some(CoreError::EnclaveUnavailable));
    mac.enclave.state().fail_always.clear();

    let mut vault =
        Vault::open_reenrolling_local(Store::open(&mac.db()).unwrap(), mac.keys()).unwrap();
    assert_ne!(vault.device_id(), device_id);
    assert_eq!(
        vault.unlock_with_password("pw").err(),
        Some(CoreError::SecretKeyRequired)
    );
    vault.unlock("pw", &sk).unwrap();
    assert!(vault.has_local_secret_key());
}

/// Touch ID：启用要再输一次主密码；解锁时提示一次；取消什么都不改变；
/// 指纹变化后失效，用主密码解锁成功时自动重新包裹。
#[test]
fn touch_id_lifecycle() {
    let mac = Mac::new();
    let (mut vault, _) = mac.create();
    assert_eq!(
        vault.unlock_with_touch_id().err(),
        Some(CoreError::TouchIdUnavailable)
    );
    assert_eq!(
        vault.enable_touch_id("wrong").err(),
        Some(CoreError::WrongCredentials)
    );
    assert!(!vault.touch_id_enabled());
    vault.enable_touch_id("pw").unwrap();
    assert!(vault.touch_id_enabled());
    assert_eq!(
        mac.enclave.state().prompts,
        0,
        "启用时不提示：新一代中的 AUK 包裹在首次使用时验证"
    );
    drop(vault);

    let mut vault = mac.open().unwrap();
    assert!(vault.touch_id_enabled());
    vault.unlock_with_touch_id().unwrap();
    assert!(vault.is_unlocked());
    assert_eq!(mac.enclave.state().prompts, 1);
    assert_eq!(mac.generations(), [2], "成功解锁后清理旧代次");

    // 取消：什么都不改变
    vault.lock();
    mac.enclave
        .state()
        .fail
        .insert(LocalPurpose::Auk, EnclaveError::Cancelled);
    assert_eq!(
        vault.unlock_with_touch_id().err(),
        Some(CoreError::Cancelled)
    );
    assert!(vault.touch_id_enabled());
    assert_eq!(mac.generations(), [2]);
    vault.unlock_with_touch_id().unwrap();

    // 指纹变化
    vault.lock();
    mac.enclave.invalidate(LocalPurpose::Auk);
    assert_eq!(
        vault.unlock_with_touch_id().err(),
        Some(CoreError::TouchIdUnavailable)
    );
    assert!(!vault.touch_id_enabled());
    assert_eq!(
        vault.unlock_with_touch_id().err(),
        Some(CoreError::TouchIdUnavailable),
        "失效后不再提示"
    );
    vault.unlock_with_password("pw").unwrap();
    assert!(vault.touch_id_enabled(), "主密码解锁后重新包裹");
    vault.lock();
    vault.unlock_with_touch_id().unwrap();

    // 关闭前必须重新验证：主密码错误时不关闭；Touch ID 取消时不关闭
    assert_eq!(
        vault
            .disable_touch_id(crate::Reverify::Password("wrong"))
            .err(),
        Some(CoreError::WrongCredentials)
    );
    mac.enclave
        .state()
        .fail
        .insert(LocalPurpose::Auk, EnclaveError::Cancelled);
    assert_eq!(
        vault.disable_touch_id(crate::Reverify::TouchId).err(),
        Some(CoreError::Cancelled)
    );
    assert!(vault.touch_id_enabled());
    let prompts = mac.enclave.state().prompts;
    vault.disable_touch_id(crate::Reverify::TouchId).unwrap();
    assert_eq!(mac.enclave.state().prompts, prompts + 1, "用 Touch ID 验证");
    assert!(!vault.touch_id_enabled());
    drop(vault);
    let vault = mac.open().unwrap();
    assert!(!vault.touch_id_enabled());
}

/// 新一代验证失败时不提交：指针与当前代次不变，写到一半的目录被删除。
#[test]
fn failed_verification_does_not_commit() {
    let mac = Mac::new();
    let (mut vault, _) = mac.create();
    mac.enclave.state().corrupt = Some(LocalPurpose::DeviceMarker);
    assert_eq!(
        vault.enable_touch_id("pw").err(),
        Some(CoreError::EnclaveUnavailable)
    );
    assert!(!vault.touch_id_enabled());
    assert_eq!(mac.generations(), [1]);
    assert_eq!(read_pointer(&mac.local_dir()).unwrap(), Some(1));
    mac.enclave.state().corrupt = None;
    drop(vault);
    let mut vault = mac.open().unwrap();
    vault.unlock_with_password("pw").unwrap();
}

/// 读取规则：只读指针指向的一代；编号更大的是残留；指针缺失时取编号最大的完整一代；
/// 那一代不完整时退回更早的一代。
#[test]
fn generation_selection_and_fallback() {
    let mac = Mac::new();
    let (mut vault, _) = mac.create();
    vault.enable_touch_id("pw").unwrap();
    drop(vault);
    assert_eq!(mac.generations(), [1, 2]);

    // 写到一半的第 3 代：指针仍指向 2
    let partial = mac.local_dir().join("gen-3");
    fs::create_dir_all(&partial).unwrap();
    fs::write(partial.join("04.key"), b"x").unwrap();
    assert_eq!(mac.keys().generation(), Some(2));

    // 指针缺失：取编号最大的完整一代（第 3 代不完整）
    fs::remove_file(mac.local_dir().join("current")).unwrap();
    assert_eq!(mac.keys().generation(), Some(2));

    // 指针无法解析
    for bad in ["", "02", "2\n", "x", "9999999999999999"] {
        fs::write(mac.local_dir().join("current"), bad).unwrap();
        assert_eq!(mac.keys().generation(), Some(2), "{bad:?}");
    }

    // 第 2 代损坏（文件超长）：退回第 1 代
    fs::write(mac.local_dir().join("current"), "2").unwrap();
    fs::write(mac.local_dir().join("gen-2").join("01.wrap"), [0u8; 200]).unwrap();
    let keys = mac.keys();
    assert_eq!(keys.generation(), Some(1));
    assert!(!keys.has(LocalPurpose::Auk));
    let mut vault = mac.open().unwrap();
    vault.unlock_with_password("pw").unwrap();
    assert_eq!(mac.generations(), [1], "成功解锁后删除其他各代，包括残留");
}

#[test]
fn generation_numbers_are_strict() {
    assert_eq!(parse_generation("1"), Some(1));
    assert_eq!(
        parse_generation("123456789012345"),
        Some(123_456_789_012_345)
    );
    for bad in ["", "0", "01", "1234567890123456", "+1", "-1", "1 ", "١"] {
        assert_eq!(parse_generation(bad), None, "{bad:?}");
    }
}

/// 必须输入主密码的情形（docs/security.md §8）：重启后、超过间隔天数、时钟倒退、连续失败 3 次。
/// 这些情形下不弹出 Touch ID；用主密码解锁后恢复。
#[test]
fn password_is_required_after_restart_interval_and_failures() {
    use crate::{MAX_TOUCH_ID_FAILURES, PasswordReason};

    let mac = Mac::new();
    let (mut vault, _) = mac.create();
    assert_eq!(
        vault.password_reason().unwrap(),
        Some(PasswordReason::NotEnabled)
    );
    vault.enable_touch_id("pw").unwrap();
    assert_eq!(vault.password_reason().unwrap(), None);
    drop(vault);

    // 重启：开机标识不同；没有开机标识时同样按重启处理
    for boot in ["boot-2", ""] {
        let mut vault =
            Vault::open_with_local(Store::open(&mac.db()).unwrap(), mac.keys_booted(boot)).unwrap();
        assert_eq!(
            vault.password_reason().unwrap(),
            Some(PasswordReason::Restarted),
            "{boot:?}"
        );
        let prompts = mac.enclave.state().prompts;
        assert_eq!(
            vault.unlock_with_touch_id().err(),
            Some(CoreError::TouchIdUnavailable)
        );
        assert_eq!(mac.enclave.state().prompts, prompts, "不弹出 Touch ID");
    }
    let mut vault =
        Vault::open_with_local(Store::open(&mac.db()).unwrap(), mac.keys_booted("boot-2")).unwrap();
    vault.unlock_with_password("pw").unwrap();
    vault.lock();
    assert_eq!(
        vault.password_reason().unwrap(),
        None,
        "这次开机已输入过主密码"
    );
    vault.unlock_with_touch_id().unwrap();
    vault.lock();

    // 超过间隔天数；时钟倒退
    let day = 24 * 60 * 60 * 1000u64;
    let now = crate::vault_now_ms_for_tests();
    vault.set_meta_for_tests("password_unlock_ms", &(now - 15 * day).to_be_bytes());
    assert_eq!(
        vault.password_reason().unwrap(),
        Some(PasswordReason::IntervalElapsed)
    );
    vault.set_password_interval_days(30).unwrap();
    assert_eq!(vault.password_reason().unwrap(), None);
    assert_eq!(
        vault.set_password_interval_days(0).err(),
        Some(CoreError::OutOfRange)
    );
    assert_eq!(
        vault.set_password_interval_days(31).err(),
        Some(CoreError::OutOfRange)
    );
    assert_eq!(vault.password_interval_days().unwrap(), 30);
    vault.set_meta_for_tests("password_unlock_ms", &(now + day).to_be_bytes());
    assert_eq!(
        vault.password_reason().unwrap(),
        Some(PasswordReason::IntervalElapsed),
        "时钟倒退按超期处理"
    );
    vault.set_meta_for_tests("password_unlock_ms", &now.to_be_bytes());
    vault.set_meta_for_tests("password_interval_days", &[200]);
    assert_eq!(
        vault.password_interval_days().unwrap(),
        14,
        "格式不对时用默认值"
    );

    // 连续失败：指纹不匹配计数，成功清零，达到上限后必须输入主密码
    for i in 1..=MAX_TOUCH_ID_FAILURES {
        mac.enclave
            .state()
            .fail
            .insert(LocalPurpose::Auk, EnclaveError::Failed);
        assert_eq!(
            vault.unlock_with_touch_id().err(),
            Some(CoreError::AuthenticationFailed),
            "第 {i} 次"
        );
        if i == 1 {
            vault.unlock_with_touch_id().unwrap();
            vault.lock();
            mac.enclave
                .state()
                .fail
                .insert(LocalPurpose::Auk, EnclaveError::Failed);
            assert_eq!(
                vault.unlock_with_touch_id().err(),
                Some(CoreError::AuthenticationFailed)
            );
        }
    }
    assert_eq!(
        vault.password_reason().unwrap(),
        Some(PasswordReason::TooManyFailures)
    );
    assert!(vault.touch_id_enabled(), "失败次数过多不等于失效");
    vault.unlock_with_password("pw").unwrap();
    vault.lock();
    assert_eq!(vault.password_reason().unwrap(), None);
    vault.set_meta_for_tests("touch_id_failures", &[0, 0]);
    assert_eq!(
        vault.password_reason().unwrap(),
        Some(PasswordReason::TooManyFailures),
        "计数格式不对时按已达上限处理"
    );

    // 失效
    vault.unlock_with_password("pw").unwrap();
    vault.lock();
    mac.enclave.invalidate(LocalPurpose::Auk);
    assert_eq!(
        vault.unlock_with_touch_id().err(),
        Some(CoreError::TouchIdUnavailable)
    );
    assert_eq!(
        vault.password_reason().unwrap(),
        Some(PasswordReason::Invalidated)
    );
}

/// 重新验证：锁定时不可用；主密码验证记作刚输入过主密码；Touch ID 服从必须输入主密码的情形。
#[test]
fn reverify_requires_unlocked_session_and_follows_policy() {
    use crate::{PasswordReason, Reverify};

    let mac = Mac::new();
    let (mut vault, _) = mac.create();
    vault.enable_touch_id("pw").unwrap();
    vault.reverify(Reverify::Password("pw")).unwrap();
    vault.reverify(Reverify::TouchId).unwrap();
    assert_eq!(
        vault.reverify(Reverify::Password("nope")).err(),
        Some(CoreError::WrongCredentials)
    );
    vault.lock();
    assert_eq!(
        vault.reverify(Reverify::Password("pw")).err(),
        Some(CoreError::Locked)
    );
    assert_eq!(
        vault.disable_touch_id(Reverify::Password("pw")).err(),
        Some(CoreError::Locked)
    );
    assert!(vault.touch_id_enabled());

    vault.unlock_with_password("pw").unwrap();
    let day = 24 * 60 * 60 * 1000u64;
    vault.set_meta_for_tests(
        "password_unlock_ms",
        &(crate::vault_now_ms_for_tests() - 20 * day).to_be_bytes(),
    );
    assert_eq!(
        vault.password_reason().unwrap(),
        Some(PasswordReason::IntervalElapsed)
    );
    assert_eq!(
        vault.reverify(Reverify::TouchId).err(),
        Some(CoreError::TouchIdUnavailable)
    );
    vault.reverify(Reverify::Password("pw")).unwrap();
    assert_eq!(
        vault.password_reason().unwrap(),
        None,
        "主密码验证记作刚输入过主密码"
    );
}
