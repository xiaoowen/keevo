//! Keevo 的本地持久化（`docs/sync.md` §2）。
//!
//! 数据库中只有密文（`*_ct` 列，均为 `spec/crypto.md` 的 Envelope）与合并、校验必需的少量
//! 明文元数据（ID、父修订、墓碑与清理标记）。本 crate 不解密任何内容。
//!
//! 每次写入都在一个事务中完成；数据库使用 WAL 模式加 `synchronous = FULL`，断电后不会损坏。

use core::fmt;
use std::path::Path;

use keevo_crypto::Id128;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

/// 当前 schema 版本。
pub const SCHEMA_VERSION: u32 = 2;

const SCHEMA_V1: &str = r"
CREATE TABLE meta (
  key             TEXT PRIMARY KEY,
  value           BLOB NOT NULL
) STRICT;

CREATE TABLE account (
  id              BLOB PRIMARY KEY,
  format_version  INTEGER NOT NULL,
  epoch           INTEGER NOT NULL,
  kdf_params      BLOB NOT NULL,
  keyset_ct       BLOB NOT NULL
) STRICT;

CREATE TABLE revision (
  seq             INTEGER PRIMARY KEY AUTOINCREMENT,  -- 本地写入顺序，仅用于清理策略
  rev_id          BLOB NOT NULL UNIQUE,
  object_id       BLOB NOT NULL,
  object_type     INTEGER NOT NULL,
  vault_id        BLOB NOT NULL,
  parents         BLOB NOT NULL,
  origin_device   BLOB NOT NULL,
  origin_seq      INTEGER,
  wrapped_key_ct  BLOB,
  overview_ct     BLOB,
  details_ct      BLOB,
  deleted         INTEGER NOT NULL DEFAULT 0,
  pruned          INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE INDEX revision_by_object ON revision(object_id);

CREATE TABLE head (
  object_id       BLOB NOT NULL,
  rev_id          BLOB NOT NULL,
  PRIMARY KEY (object_id, rev_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE attachment (
  id              BLOB PRIMARY KEY,
  item_id         BLOB NOT NULL,
  wrapped_key_ct  BLOB NOT NULL,
  meta_ct         BLOB NOT NULL,
  chunk_count     INTEGER NOT NULL
) STRICT;

CREATE TABLE device (
  id              BLOB PRIMARY KEY,
  cert            BLOB NOT NULL,
  revoked_after   INTEGER,
  high_seq        INTEGER NOT NULL DEFAULT 0,
  high_hash       BLOB
) STRICT;
";

/// v1 → v2：记录本机写入或收到每个修订时的有效时间，用于"至少保留 90 天"的清理规则
/// （`spec/revisions.md` §7.2）。迁移前已有的修订年龄未知，按迁移时间记（第二轮评审 G3）。
const MIGRATE_V2: &str = "ALTER TABLE revision ADD COLUMN stored_ms INTEGER NOT NULL DEFAULT 0;";

/// 每个修订最多的父修订数（`spec/revisions.md` §2）。
pub const MAX_PARENTS: usize = 256;

/// 有效时间单次最多前进的量：1 天。墙上时钟被调快、长期未使用时，有效时间都只前进这么多，
/// 因此只会让保留期变长，不会提前清理（`spec/revisions.md` §7.2）。
pub const MAX_CLOCK_STEP_MS: u64 = 24 * 60 * 60 * 1000;
const META_CLOCK_EFFECTIVE: &str = "clock.effective_ms";
const META_CLOCK_WALL: &str = "clock.last_wall_ms";

/// 存储层错误。不携带任何明文内容。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StoreError {
    /// SQLite 错误。
    Sqlite(String),
    /// 账户已存在。
    AccountExists,
    /// 修订的父修订尚未写入（修订必须按拓扑顺序写入）。
    MissingParent,
    /// 修订已存在。
    DuplicateRevision,
    /// 修订的父修订超过 [`MAX_PARENTS`] 个，或内容超过信封上限。
    TooLarge,
    /// 数据库内容不符合预期。
    Corrupt(&'static str),
    /// 数据库来自更新版本的 Keevo。
    UnsupportedSchema(u32),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(e) => write!(f, "sqlite: {e}"),
            Self::AccountExists => f.write_str("account already exists"),
            Self::MissingParent => f.write_str("parent revision missing"),
            Self::DuplicateRevision => f.write_str("revision already exists"),
            Self::TooLarge => f.write_str("revision exceeds size limits"),
            Self::Corrupt(what) => write!(f, "corrupt database: {what}"),
            Self::UnsupportedSchema(v) => write!(f, "unsupported schema version {v}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e.to_string())
    }
}

/// `keevo-store` 的结果类型。
pub type Result<T> = core::result::Result<T, StoreError>;

/// 对象类型，取值与 `spec/crypto.md` §9.1 一致。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectKind {
    /// 保险库。
    Vault,
    /// 条目。
    Item,
}

impl ObjectKind {
    const fn code(self) -> i64 {
        match self {
            Self::Vault => 2,
            Self::Item => 3,
        }
    }

    const fn from_code(code: i64) -> Option<Self> {
        match code {
            2 => Some(Self::Vault),
            3 => Some(Self::Item),
            _ => None,
        }
    }
}

/// 账户行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRow {
    /// 账户 ID。
    pub id: Id128,
    /// 明文格式版本。
    pub format_version: u32,
    /// 密钥集版本，修改主密码或轮换密钥时递增。
    pub epoch: u64,
    /// 编码后的 KDF 参数（不是秘密）。
    pub kdf_params: Vec<u8>,
    /// AUK 封装的密钥集。
    pub keyset_ct: Vec<u8>,
}

/// 修订行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionRow {
    /// 修订 ID。
    pub rev_id: Id128,
    /// 对象 ID。
    pub object_id: Id128,
    /// 对象类型。
    pub kind: ObjectKind,
    /// 所属保险库（保险库对象为其自身 ID）。
    pub vault_id: Id128,
    /// 父修订。
    pub parents: Vec<Id128>,
    /// 写入该修订的设备。
    pub origin_device: Id128,
    /// 写入同步日志后的段序号（M2）。
    pub origin_seq: Option<u64>,
    /// 被包裹的对象密钥。
    pub wrapped_key_ct: Option<Vec<u8>>,
    /// 概要密文。
    pub overview_ct: Option<Vec<u8>>,
    /// 详情密文。
    pub details_ct: Option<Vec<u8>>,
    /// 是否为墓碑修订。
    pub deleted: bool,
    /// 内容是否已被清理（只保留元数据）。
    pub pruned: bool,
}

/// 修订图中一个节点的元数据。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionMeta {
    /// 修订 ID。
    pub rev_id: Id128,
    /// 父修订。
    pub parents: Vec<Id128>,
    /// 来源设备。
    pub origin_device: Id128,
}

/// 本地数据库。
pub struct Store {
    conn: Connection,
}

impl Store {
    /// 打开（必要时创建并迁移）数据库文件。
    ///
    /// # Errors
    /// SQLite 错误，或数据库来自更新版本时返回对应错误。
    pub fn open(path: &Path) -> Result<Self> {
        Self::init(Connection::open(path)?, true)
    }

    /// 内存数据库，仅用于测试。
    ///
    /// # Errors
    /// SQLite 错误。
    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?, false)
    }

    fn init(conn: Connection, wal: bool) -> Result<Self> {
        if wal {
            conn.pragma_update(None, "journal_mode", "WAL")?;
        }
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // 删除的内容用零覆盖（虽然都是密文，仍尽量不留痕迹）
        conn.pragma_update(None, "secure_delete", "ON")?;
        let mut store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&mut self) -> Result<()> {
        let version: u32 = self
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(StoreError::UnsupportedSchema(version));
        }
        if version == SCHEMA_VERSION {
            return Ok(());
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Exclusive)?;
        if version < 1 {
            tx.execute_batch(SCHEMA_V1)?;
        }
        if version < 2 {
            tx.execute_batch(MIGRATE_V2)?;
            let now = now_ms();
            tx.execute("UPDATE revision SET stored_ms = ?1", [now])?;
            for key in [META_CLOCK_EFFECTIVE, META_CLOCK_WALL] {
                tx.execute(
                    "INSERT INTO meta (key, value) VALUES (?1, ?2)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    params![key, now.to_be_bytes().to_vec()],
                )?;
            }
        }
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tx.commit()?;
        Ok(())
    }

    /// 当前 schema 版本。
    ///
    /// # Errors
    /// SQLite 错误。
    pub fn schema_version(&self) -> Result<u32> {
        Ok(self
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))?)
    }

    /// 读取元数据（如本机设备 ID、HLC）。
    ///
    /// # Errors
    /// SQLite 错误。
    pub fn meta(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()?)
    }

    /// 写入元数据。
    ///
    /// # Errors
    /// SQLite 错误。
    pub fn set_meta(&mut self, key: &str, value: &[u8]) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// 读取账户。
    ///
    /// # Errors
    /// SQLite 错误或数据损坏。
    pub fn account(&self) -> Result<Option<AccountRow>> {
        let env = keevo_crypto::MAX_ENVELOPE_LEN;
        let oversized: bool = self.conn.query_row(
            &format!(
                "SELECT EXISTS(SELECT 1 FROM account WHERE length(id) != 16
                   OR length(kdf_params) != {} OR length(keyset_ct) > {env})",
                keevo_crypto::KdfParams::ENCODED_LEN
            ),
            [],
            |r| r.get(0),
        )?;
        if oversized {
            return Err(StoreError::Corrupt("account column exceeds its size limit"));
        }
        self.conn
            .query_row(
                "SELECT id, format_version, epoch, kdf_params, keyset_ct FROM account",
                [],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, Vec<u8>>(3)?,
                        r.get::<_, Vec<u8>>(4)?,
                    ))
                },
            )
            .optional()?
            .map(|(id, fv, epoch, kdf_params, keyset_ct)| {
                Ok(AccountRow {
                    id: id_from(&id)?,
                    format_version: u32::try_from(fv)
                        .map_err(|_| StoreError::Corrupt("format_version"))?,
                    epoch: u64::try_from(epoch).map_err(|_| StoreError::Corrupt("epoch"))?,
                    kdf_params,
                    keyset_ct,
                })
            })
            .transpose()
    }

    /// 创建账户。一个数据库只有一个账户。
    ///
    /// # Errors
    /// 已存在账户时返回 [`StoreError::AccountExists`]。
    pub fn create_account(&mut self, row: &AccountRow) -> Result<()> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: i64 = tx.query_row("SELECT COUNT(*) FROM account", [], |r| r.get(0))?;
        if exists > 0 {
            return Err(StoreError::AccountExists);
        }
        tx.execute(
            "INSERT INTO account (id, format_version, epoch, kdf_params, keyset_ct)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                row.id.as_bytes().as_slice(),
                i64::from(row.format_version),
                i64::try_from(row.epoch).map_err(|_| StoreError::Corrupt("epoch"))?,
                row.kdf_params,
                row.keyset_ct
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// 写入一个修订并更新头集合（`spec/revisions.md` §2）。
    ///
    /// 修订必须按拓扑顺序写入：所有父修订都必须已存在。写入后，父修订不再是头，新修订成为头。
    ///
    /// # Errors
    /// 父修订缺失返回 [`StoreError::MissingParent`]，修订重复返回 [`StoreError::DuplicateRevision`]。
    pub fn insert_revision(&mut self, row: &RevisionRow) -> Result<()> {
        // 写入与读取（`check_sizes`）用同一套上限，写进去的东西一定读得出来
        let env = keevo_crypto::MAX_ENVELOPE_LEN;
        if row.parents.len() > MAX_PARENTS
            || [&row.wrapped_key_ct, &row.overview_ct, &row.details_ct]
                .iter()
                .any(|c| c.as_ref().is_some_and(|c| c.len() > env))
        {
            return Err(StoreError::TooLarge);
        }
        let stored = i64::try_from(self.advance_clock(u64::try_from(now_ms()).unwrap_or(0))?)
            .map_err(|_| StoreError::Corrupt("clock"))?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: i64 = tx.query_row(
            "SELECT COUNT(*) FROM revision WHERE rev_id = ?1",
            [row.rev_id.as_bytes().as_slice()],
            |r| r.get(0),
        )?;
        if exists > 0 {
            return Err(StoreError::DuplicateRevision);
        }
        for parent in &row.parents {
            let found: i64 = tx.query_row(
                "SELECT COUNT(*) FROM revision WHERE rev_id = ?1 AND object_id = ?2",
                [
                    parent.as_bytes().as_slice(),
                    row.object_id.as_bytes().as_slice(),
                ],
                |r| r.get(0),
            )?;
            if found == 0 {
                return Err(StoreError::MissingParent);
            }
        }
        tx.execute(
            "INSERT INTO revision (rev_id, object_id, object_type, vault_id, parents, origin_device,
                                   origin_seq, wrapped_key_ct, overview_ct, details_ct, deleted, pruned,
                                   stored_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                row.rev_id.as_bytes().as_slice(),
                row.object_id.as_bytes().as_slice(),
                row.kind.code(),
                row.vault_id.as_bytes().as_slice(),
                encode_ids(&row.parents),
                row.origin_device.as_bytes().as_slice(),
                row.origin_seq.map(i64::try_from).transpose().map_err(|_| StoreError::Corrupt("origin_seq"))?,
                row.wrapped_key_ct,
                row.overview_ct,
                row.details_ct,
                row.deleted,
                row.pruned,
                stored,
            ],
        )?;
        for parent in &row.parents {
            tx.execute(
                "DELETE FROM head WHERE object_id = ?1 AND rev_id = ?2",
                [
                    row.object_id.as_bytes().as_slice(),
                    parent.as_bytes().as_slice(),
                ],
            )?;
        }
        tx.execute(
            "INSERT INTO head (object_id, rev_id) VALUES (?1, ?2)",
            [
                row.object_id.as_bytes().as_slice(),
                row.rev_id.as_bytes().as_slice(),
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// 读取单个修订。
    ///
    /// # Errors
    /// SQLite 错误或数据损坏。
    pub fn revision(&self, rev_id: &Id128) -> Result<Option<RevisionRow>> {
        self.check_sizes("rev_id = ?1", rev_id)?;
        self.conn
            .query_row(
                &format!("SELECT {REVISION_COLUMNS} FROM revision WHERE rev_id = ?1"),
                [rev_id.as_bytes().as_slice()],
                raw_revision,
            )
            .optional()?
            .map(RawRevision::into_row)
            .transpose()
    }

    /// 对象的全部头修订，按 `rev_id` 排序。
    ///
    /// # Errors
    /// SQLite 错误或数据损坏。
    pub fn heads(&self, object_id: &Id128) -> Result<Vec<RevisionRow>> {
        self.check_sizes(
            "rev_id IN (SELECT rev_id FROM head WHERE object_id = ?1)",
            object_id,
        )?;
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {REVISION_COLUMNS} FROM revision
             WHERE rev_id IN (SELECT rev_id FROM head WHERE object_id = ?1)
             ORDER BY rev_id"
        ))?;
        let rows = stmt.query_map([object_id.as_bytes().as_slice()], raw_revision)?;
        rows.map(|r| r.map_err(StoreError::from).and_then(RawRevision::into_row))
            .collect()
    }

    /// 某类型的全部对象 ID，按 ID 排序。
    ///
    /// # Errors
    /// SQLite 错误或数据损坏。
    pub fn objects(&self, kind: ObjectKind) -> Result<Vec<Id128>> {
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT h.object_id FROM head h JOIN revision r ON r.rev_id = h.rev_id
             WHERE r.object_type = ?1 ORDER BY h.object_id",
        )?;
        let rows = stmt.query_map([kind.code()], |r| r.get::<_, Vec<u8>>(0))?;
        rows.map(|r| r.map_err(StoreError::from).and_then(|b| id_from(&b)))
            .collect()
    }

    /// 对象的修订图元数据（含已清理内容的修订）。
    ///
    /// # Errors
    /// SQLite 错误或数据损坏。
    pub fn graph(&self, object_id: &Id128) -> Result<Vec<RevisionMeta>> {
        self.check_sizes("object_id = ?1", object_id)?;
        let mut stmt = self.conn.prepare(
            "SELECT rev_id, parents, origin_device FROM revision WHERE object_id = ?1 ORDER BY seq",
        )?;
        let rows = stmt.query_map([object_id.as_bytes().as_slice()], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        rows.map(|r| {
            let (rev, parents, origin) = r?;
            Ok(RevisionMeta {
                rev_id: id_from(&rev)?,
                parents: decode_ids(&parents)?,
                origin_device: id_from(&origin)?,
            })
        })
        .collect()
    }

    /// 对象的全部修订（含内容），按本地写入顺序从新到旧排列，用于历史视图。
    ///
    /// # Errors
    /// SQLite 错误或数据损坏。
    pub fn history(&self, object_id: &Id128) -> Result<Vec<RevisionRow>> {
        self.check_sizes("object_id = ?1", object_id)?;
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {REVISION_COLUMNS} FROM revision WHERE object_id = ?1 ORDER BY seq DESC"
        ))?;
        let rows = stmt.query_map([object_id.as_bytes().as_slice()], raw_revision)?;
        rows.map(|r| r.map_err(StoreError::from).and_then(RawRevision::into_row))
            .collect()
    }

    /// 读取修订之前先检查各列长度（第二轮评审 G4）。只在 WHERE 中计算 `length()`，SQLite 不会因此读入
    /// BLOB 内容；若与内容列放在同一个 SELECT 中，取出这一行时整个 BLOB 就已经读进内存了。
    fn check_sizes(&self, filter: &str, id: &Id128) -> Result<()> {
        let env = keevo_crypto::MAX_ENVELOPE_LEN;
        let parents = MAX_PARENTS * 16;
        let oversized: bool = self.conn.query_row(
            &format!(
                "SELECT EXISTS(SELECT 1 FROM revision WHERE ({filter}) AND (
                   length(rev_id) != 16 OR length(object_id) != 16 OR length(vault_id) != 16
                   OR length(origin_device) != 16 OR length(parents) > {parents} OR length(parents) % 16 != 0
                   OR coalesce(length(wrapped_key_ct), 0) > {env}
                   OR coalesce(length(overview_ct), 0) > {env}
                   OR coalesce(length(details_ct), 0) > {env}))"
            ),
            [id.as_bytes().as_slice()],
            |r| r.get(0),
        )?;
        if oversized {
            return Err(StoreError::Corrupt("column exceeds its size limit"));
        }
        Ok(())
    }

    /// 推进并返回本机的有效时间（`spec/revisions.md` §7.2）：前进量为墙上时间的增量，单次最多
    /// [`MAX_CLOCK_STEP_MS`]；墙上时间倒退时有效时间不变。首次调用时有效时间取当前墙上时间。
    ///
    /// # Errors
    /// SQLite 错误，或持久化的时钟值格式错误。
    pub fn advance_clock(&mut self, wall_ms: u64) -> Result<u64> {
        let read = |store: &Self, key: &str| -> Result<Option<u64>> {
            store
                .meta(key)?
                .map(|v| {
                    <[u8; 8]>::try_from(v.as_slice())
                        .map(u64::from_be_bytes)
                        .map_err(|_| StoreError::Corrupt("clock"))
                })
                .transpose()
        };
        let effective = match (
            read(self, META_CLOCK_EFFECTIVE)?,
            read(self, META_CLOCK_WALL)?,
        ) {
            (Some(eff), Some(last)) => {
                eff.saturating_add(wall_ms.saturating_sub(last).min(MAX_CLOCK_STEP_MS))
            }
            _ => wall_ms,
        };
        self.set_meta(META_CLOCK_EFFECTIVE, &effective.to_be_bytes())?;
        self.set_meta(META_CLOCK_WALL, &wall_ms.to_be_bytes())?;
        Ok(effective)
    }

    /// 清理对象的旧修订内容（`spec/revisions.md` §7），其余只留元数据。返回清理数量。
    ///
    /// 只清理同时满足以下条件的修订：不是头修订；不在最近 `keep` 个修订之内；按有效时间计已保存满
    /// `min_age_ms`。`wall_now_ms` 是当前墙上时间，用来推进有效时间（[`Store::advance_clock`]）。
    ///
    /// # Errors
    /// SQLite 错误。
    pub fn prune(
        &mut self,
        object_id: &Id128,
        keep: usize,
        min_age_ms: u64,
        wall_now_ms: u64,
    ) -> Result<usize> {
        let keep = i64::try_from(keep).map_err(|_| StoreError::Corrupt("keep"))?;
        let effective = self.advance_clock(wall_now_ms)?;
        let cutoff = i64::try_from(effective.saturating_sub(min_age_ms)).unwrap_or(i64::MAX);
        let n = self.conn.execute(
            "UPDATE revision SET wrapped_key_ct = NULL, overview_ct = NULL, details_ct = NULL, pruned = 1
             WHERE object_id = ?1 AND pruned = 0 AND stored_ms <= ?3
               AND rev_id NOT IN (SELECT rev_id FROM head WHERE object_id = ?1)
               AND seq NOT IN (SELECT seq FROM revision WHERE object_id = ?1 ORDER BY seq DESC LIMIT ?2)",
            params![object_id.as_bytes().as_slice(), keep, cutoff],
        )?;
        Ok(n)
    }
}

const REVISION_COLUMNS: &str = "rev_id, object_id, object_type, vault_id, parents, origin_device, \
     origin_seq, wrapped_key_ct, overview_ct, details_ct, deleted, pruned";

struct RawRevision {
    rev_id: Vec<u8>,
    object_id: Vec<u8>,
    object_type: i64,
    vault_id: Vec<u8>,
    parents: Vec<u8>,
    origin_device: Vec<u8>,
    origin_seq: Option<i64>,
    wrapped_key_ct: Option<Vec<u8>>,
    overview_ct: Option<Vec<u8>>,
    details_ct: Option<Vec<u8>>,
    deleted: bool,
    pruned: bool,
}

fn raw_revision(r: &rusqlite::Row<'_>) -> rusqlite::Result<RawRevision> {
    Ok(RawRevision {
        rev_id: r.get(0)?,
        object_id: r.get(1)?,
        object_type: r.get(2)?,
        vault_id: r.get(3)?,
        parents: r.get(4)?,
        origin_device: r.get(5)?,
        origin_seq: r.get(6)?,
        wrapped_key_ct: r.get(7)?,
        overview_ct: r.get(8)?,
        details_ct: r.get(9)?,
        deleted: r.get(10)?,
        pruned: r.get(11)?,
    })
}

impl RawRevision {
    fn into_row(self) -> Result<RevisionRow> {
        Ok(RevisionRow {
            rev_id: id_from(&self.rev_id)?,
            object_id: id_from(&self.object_id)?,
            kind: ObjectKind::from_code(self.object_type)
                .ok_or(StoreError::Corrupt("object_type"))?,
            vault_id: id_from(&self.vault_id)?,
            parents: decode_ids(&self.parents)?,
            origin_device: id_from(&self.origin_device)?,
            origin_seq: self
                .origin_seq
                .map(u64::try_from)
                .transpose()
                .map_err(|_| StoreError::Corrupt("origin_seq"))?,
            wrapped_key_ct: self.wrapped_key_ct,
            overview_ct: self.overview_ct,
            details_ct: self.details_ct,
            deleted: self.deleted,
            pruned: self.pruned,
        })
    }
}

fn id_from(bytes: &[u8]) -> Result<Id128> {
    let arr: [u8; 16] = bytes
        .try_into()
        .map_err(|_| StoreError::Corrupt("id length"))?;
    Ok(Id128::from_bytes(arr))
}

fn encode_ids(ids: &[Id128]) -> Vec<u8> {
    ids.iter()
        .flat_map(|id| id.as_bytes().iter().copied())
        .collect()
}

fn decode_ids(bytes: &[u8]) -> Result<Vec<Id128>> {
    if !bytes.len().is_multiple_of(16) {
        return Err(StoreError::Corrupt("parents length"));
    }
    bytes.chunks_exact(16).map(id_from).collect()
}

#[cfg(test)]
mod tests;

/// 当前 Unix 毫秒。系统时钟早于 1970 年时记为 0（这些修订只按数量规则保留）。
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}
