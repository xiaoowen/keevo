use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use keevo_crypto::{
    AadContext, AccountKeyset, AccountSecretKey, CryptoError, Id128, KdfParams, ObjectType, Part,
    SymmetricKey, derive_account_unlock_key, open, seal,
};
use keevo_format::{
    Conflict, FORMAT_VERSION, FieldData, FieldKind, FieldValue, HeadState, Hlc, HlcClock, ItemDoc,
    ItemOverview, ItemType, Purpose, RecordKey, RecordValue, RevisionGraph, VaultMeta, merge_heads,
};
use keevo_store::{AccountRow, ObjectKind, RevisionRow, Store};

use crate::error::{CoreError, Result};

const META_DEVICE_ID: &str = "device_id";
const META_HLC: &str = "hlc_last";
const DEFAULT_VAULT_NAME: &str = "个人";
const FIRST_EPOCH: u64 = 1;
/// 每个对象保留完整内容的修订数（`spec/revisions.md` §7）。
const HISTORY_KEEP: usize = 20;
/// 历史保留的时间下限（`spec/revisions.md` §7.2）：按本机有效时间计，90 天内写入或收到的修订一律保留。
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
        };
        vault.create_vault(DEFAULT_VAULT_NAME)?;
        Ok((vault, secret_key))
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
        let keyset = AccountKeyset::open(
            &auk,
            &account.id,
            account.epoch,
            &params,
            &account.keyset_ct,
        )
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
        Ok(())
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
                doc.delete(key.clone(), hlc, rev_id);
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
            .prune(&item_id, HISTORY_KEEP, HISTORY_MIN_AGE_MS, now_ms())?;
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
        let rev_id = Id128::random()?;
        self.store.insert_revision(&RevisionRow {
            rev_id,
            object_id: item_id,
            kind: ObjectKind::Item,
            vault_id: view.vault_id,
            parents: heads.iter().map(|h| h.rev_id).collect(),
            origin_device: self.device_id,
            origin_seq: None,
            wrapped_key_ct: None,
            overview_ct: None,
            details_ct: None,
            deleted: true,
            pruned: false,
        })?;
        Ok(())
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
        let session = self.session()?;
        heads
            .iter()
            .map(|h| {
                if h.deleted {
                    return Ok(None);
                }
                let ik = self.item_key(session, h)?;
                let ct = h.details_ct.as_deref().ok_or(CoreError::Tampered)?;
                let ctx = context(
                    session.account_id,
                    ObjectType::Item,
                    Part::Details,
                    h.vault_id,
                    h.object_id,
                    h.rev_id,
                );
                Ok(Some(ItemDoc::decode(&open(&ik, &ctx, ct)?)?))
            })
            .collect()
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
        self.store.insert_revision(&RevisionRow {
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
        })?;
        Ok(())
    }

    fn edit_attr(&mut self, item_id: Id128, name: &str, value: Option<RecordValue>) -> Result<()> {
        let view = self.item(item_id)?;
        let heads = self.store.heads(&item_id)?;
        let mut doc = view.doc;
        let hlc = self.tick()?;
        let rev_id = Id128::random()?;
        match value {
            Some(v) => doc.set(RecordKey::attr(name), v, hlc, rev_id)?,
            None => doc.delete(RecordKey::attr(name), hlc, rev_id),
        }
        let ik = {
            let session = self.session()?;
            let live = heads
                .iter()
                .find(|h| !h.deleted)
                .ok_or(CoreError::NotFound)?;
            self.item_key(session, live)?
        };
        let parents = heads.iter().map(|h| h.rev_id).collect();
        self.write_item_revision(view.vault_id, item_id, rev_id, parents, &ik, Some(&doc))
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
        Edit::RemoveTag(t) => doc.delete(RecordKey::Tag(t), hlc, rev),
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
            doc.delete(key, hlc, rev);
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests;
