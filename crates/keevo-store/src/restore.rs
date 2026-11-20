//! 从备份恢复（`docs/sync.md` §2"本地备份"）。备份文件来自外部（可能在同步盘中），一律当作不可信输入：
//!
//! 1. 只读打开，关闭触发器、视图与不可信的 schema（`SQLITE_DBCONFIG_DEFENSIVE`），拒绝任何触发器、视图、
//!    虚拟表与生成列，只认 Keevo 自己的表与列；
//! 2. 在一个由 Keevo 新建的临时数据库中逐行导入，每一列按与读取时相同的规则检查长度与取值（`spec/crypto.md`
//!    §8.5、§8.9）；父修订必须存在，头修订由修订图重算，不信任备份中的 `head` 表；修订的保存时间不超过恢复前的
//!    有效时间（`spec/revisions.md` §7.2），被篡改的备份不能让清理提前生效；
//! 3. 临时数据库中写入恢复前的本机状态（`meta` 与 `local_record`）；
//! 4. 用 SQLite 在线备份接口一次性把临时数据库换入主数据库：单个写事务，中途失败时主数据库保持原样。
//!
//! 第五轮预审（2026-11-20）K1、K2。备份的内容本身仍然没有认证：能改写备份的人可以删去新的修订，让条目回到旧版本，
//! 这与"恢复一份旧备份"的效果相同。对整个备份做认证在 M2 随同步格式定义。

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use keevo_crypto::Id128;
use rusqlite::config::DbConfig;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

use crate::{
    ATTACHMENT_CHUNK_CT_LEN, ATTACHMENT_KEY_CT_LEN, AccountRow, MAX_ATTACHMENT_CHUNKS,
    MAX_ATTACHMENT_META_CT_LEN, MAX_PARENTS, MAX_TOMBSTONE_PARENTS, ObjectKind, Result,
    SCHEMA_VERSION, Store, StoreError, decode_ids, id_from,
};

/// 备份中记录创建时间的元数据键（备份自己的 `meta` 表；恢复时不进入当前数据库）。
pub(crate) const META_BACKUP_CREATED: &str = "backup_created_ms";

/// 备份的概要：所属账户与备份内记录的创建时间。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupSummary {
    /// 账户行（明文：ID、密钥集版本、KDF 参数）。
    pub account: AccountRow,
    /// 备份内记录的创建时间（Unix 毫秒）；早期的备份没有。与其余内容一样未经认证。
    pub created_ms: Option<u64>,
}

fn corrupt(what: &'static str) -> StoreError {
    StoreError::Corrupt(what)
}

/// 只读打开备份并检查结构，返回连接与 schema 版本。
fn open_untrusted(src: &Path) -> Result<(Connection, u32)> {
    let conn = Connection::open_with_flags(
        src,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| corrupt("not a keevo database"))?;
    // 不执行备份中的任何 schema 代码
    for (option, on) in [
        (DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true),
        (DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false),
        (DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false),
        (DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW, false),
    ] {
        conn.set_db_config(option, on)?;
    }
    let version: i64 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(|_| corrupt("not a keevo database"))?;
    let version = u32::try_from(version).map_err(|_| corrupt("not a keevo database"))?;
    if version == 0 {
        return Err(corrupt("not a keevo database"));
    }
    if version > SCHEMA_VERSION {
        return Err(StoreError::UnsupportedSchema(version));
    }
    let foreign: i64 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master
             WHERE type IN ('trigger', 'view') OR (type = 'table' AND sql LIKE 'CREATE VIRTUAL%')",
            [],
            |r| r.get(0),
        )
        .map_err(|_| corrupt("not a keevo database"))?;
    if foreign > 0 {
        return Err(corrupt("backup contains foreign schema objects"));
    }
    for (table, columns) in expected_tables(version) {
        let kind: Option<String> = conn
            .query_row(
                "SELECT type FROM sqlite_master WHERE name = ?1",
                [table],
                |r| r.get(0),
            )
            .optional()?;
        if kind.as_deref() != Some("table") {
            return Err(corrupt("backup schema does not match"));
        }
        // 每一列都必须是普通列（不是生成列），且 Keevo 需要的列都在
        let mut stmt = conn.prepare(&format!(
            "SELECT name, hidden FROM pragma_table_xinfo('{table}')"
        ))?;
        let found: HashMap<String, i64> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        if found.values().any(|h| *h != 0) || columns.iter().any(|c| !found.contains_key(*c)) {
            return Err(corrupt("backup schema does not match"));
        }
    }
    Ok((conn, version))
}

/// 各版本 schema 中 Keevo 会读取的表与列。
fn expected_tables(version: u32) -> Vec<(&'static str, Vec<&'static str>)> {
    let mut revision = vec![
        "seq",
        "rev_id",
        "object_id",
        "object_type",
        "vault_id",
        "parents",
        "origin_device",
        "origin_seq",
        "wrapped_key_ct",
        "overview_ct",
        "details_ct",
        "deleted",
        "pruned",
    ];
    if version >= 2 {
        revision.push("stored_ms");
    }
    let mut out = vec![
        ("meta", vec!["key", "value"]),
        (
            "account",
            vec!["id", "format_version", "epoch", "kdf_params", "keyset_ct"],
        ),
        ("revision", revision),
        (
            "attachment",
            vec!["id", "item_id", "wrapped_key_ct", "meta_ct", "chunk_count"],
        ),
        ("device", vec!["id"]),
    ];
    if version >= 5 {
        out.push(("attachment_chunk", vec!["attachment_id", "idx", "ct"]));
    }
    out
}

fn read_account(conn: &Connection) -> Result<AccountRow> {
    let env = i64::try_from(keevo_crypto::MAX_ENVELOPE_LEN).unwrap_or(i64::MAX);
    let (count, bad): (i64, i64) = conn.query_row(
        &format!(
            "SELECT count(*), coalesce(sum(length(id) != 16 OR typeof(id) != 'blob' OR length(kdf_params) != {}
               OR typeof(kdf_params) != 'blob' OR typeof(keyset_ct) != 'blob' OR length(keyset_ct) > {env}
               OR typeof(format_version) != 'integer' OR typeof(epoch) != 'integer' OR epoch < 0), 0)
             FROM account",
            keevo_crypto::KdfParams::ENCODED_LEN
        ),
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if count != 1 || bad != 0 {
        return Err(corrupt("no account"));
    }
    let (id, format_version, epoch, kdf_params, keyset_ct): (Vec<u8>, i64, i64, Vec<u8>, Vec<u8>) =
        conn.query_row(
            "SELECT id, format_version, epoch, kdf_params, keyset_ct FROM account",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )?;
    Ok(AccountRow {
        id: id_from(&id)?,
        format_version: u32::try_from(format_version).map_err(|_| corrupt("account"))?,
        epoch: u64::try_from(epoch).map_err(|_| corrupt("account"))?,
        kdf_params,
        keyset_ct,
    })
}

impl Store {
    /// 检查 `src` 能否用来恢复：结构是 Keevo 的、schema 不新于当前版本、有且只有一个账户。只读，不修改它。
    /// 完整的逐行检查在恢复时进行（[`Store::restore_from`]）。
    ///
    /// # Errors
    /// 不是 Keevo 数据库或结构不符时返回 [`StoreError::Corrupt`]；来自更新版本时返回 [`StoreError::UnsupportedSchema`]。
    pub fn inspect_backup(src: &Path) -> Result<BackupSummary> {
        let (conn, _) = open_untrusted(src)?;
        let account = read_account(&conn)?;
        let created: Option<Vec<u8>> = conn
            .query_row(
                "SELECT CASE WHEN typeof(value) = 'blob' AND length(value) = 8 THEN value END FROM meta WHERE key = ?1",
                [META_BACKUP_CREATED],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        let created_ms = created
            .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
            .map(u64::from_be_bytes);
        Ok(BackupSummary {
            account,
            created_ms,
        })
    }

    /// 在备份文件中记下创建时间（刚由 [`Store::backup_to`] 写出、尚未交给用户的文件）。
    ///
    /// # Errors
    /// SQLite 错误。
    pub fn mark_backup(dest: &Path, created_ms: u64) -> Result<()> {
        let conn = Connection::open(dest)?;
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
            params![META_BACKUP_CREATED, created_ms.to_be_bytes().as_slice()],
        )?;
        Ok(())
    }

    /// 用 `src` 处的备份替换保险库内容（模块说明中的四步）。连接保持不变，持有这个 `Store` 的对象不需要重新打开。
    ///
    /// 本机状态不随备份回退：`meta`（设备 ID、HLC、解锁策略与失败计数）与 `local_record`（浏览器配对、授权、
    /// SSH Agent 的使用方式）保持恢复前的内容。
    ///
    /// # Errors
    /// 备份无效时返回 [`StoreError::Corrupt`] 或 [`StoreError::UnsupportedSchema`]；SQLite 错误。
    /// 任何失败都不改变主数据库。
    pub fn restore_from(&mut self, src: &Path) -> Result<()> {
        let (source, version) = open_untrusted(src)?;
        let effective = i64::try_from(self.effective_now()?).map_err(|_| corrupt("clock"))?;
        let staging = staging_path(&self.conn);
        let _cleanup = Cleanup(staging.clone());
        let _ = remove_database(&staging);
        let mut staged = Self::init(Connection::open(&staging)?, false)?;
        {
            // 读取在一个快照中进行：检查与读取之间备份不会被换掉（第三轮评审 H3）
            let snapshot = source.unchecked_transaction()?;
            let tx = staged.conn.transaction()?;
            let account = read_account(&snapshot)?;
            tx.execute(
                "INSERT INTO account (id, format_version, epoch, kdf_params, keyset_ct) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    account.id.as_bytes().as_slice(),
                    account.format_version,
                    i64::try_from(account.epoch).map_err(|_| corrupt("account"))?,
                    account.kdf_params,
                    account.keyset_ct
                ],
            )?;
            copy_revisions(&snapshot, &tx, version, effective)?;
            copy_attachments(&snapshot, &tx, version)?;
            let devices: i64 =
                snapshot.query_row("SELECT count(*) FROM device", [], |r| r.get(0))?;
            if devices != 0 {
                // M1 不写设备表；有内容说明不是这个版本的 Keevo 写出的
                return Err(corrupt("unexpected device rows"));
            }
            // 本机状态取自恢复前的主数据库
            {
                let mut stmt = self.conn.prepare("SELECT key, value FROM meta")?;
                let rows = stmt.query_map([], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
                })?;
                for row in rows {
                    let (key, value) = row?;
                    tx.execute(
                        "INSERT INTO meta (key, value) VALUES (?1, ?2)",
                        params![key, value],
                    )?;
                }
            }
            {
                let mut stmt = self.conn.prepare("SELECT kind, id, ct FROM local_record")?;
                let rows = stmt.query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                    ))
                })?;
                for row in rows {
                    let (kind, id, ct) = row?;
                    tx.execute(
                        "INSERT INTO local_record (kind, id, ct) VALUES (?1, ?2, ?3)",
                        params![kind, id, ct],
                    )?;
                }
            }
            tx.commit()?;
            snapshot.commit()?;
        }
        drop(source);
        // 一次性换入：sqlite3_backup_step(-1) 在单个写事务中复制全部页并提交
        {
            let backup = rusqlite::backup::Backup::new(&staged.conn, &mut self.conn)?;
            match backup.step(-1)? {
                rusqlite::backup::StepResult::Done => {}
                _ => return Err(StoreError::Sqlite("restore did not complete".into())),
            }
        }
        staged.conn.close().map_err(|(_, e)| StoreError::from(e))?;
        self.clock = None;
        Ok(())
    }
}

/// 临时数据库的路径：主数据库旁边（同一卷、同样的目录权限）；内存数据库用系统临时目录。
fn staging_path(conn: &Connection) -> PathBuf {
    let random = Id128::random().map(|i| i.to_hex()).unwrap_or_default();
    match conn.path().filter(|p| !p.is_empty()) {
        Some(p) => PathBuf::from(format!("{p}.restore-{random}")),
        None => std::env::temp_dir().join(format!("keevo-restore-{random}.sqlite")),
    }
}

fn remove_database(path: &Path) -> std::io::Result<()> {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut p = path.as_os_str().to_owned();
        p.push(suffix);
        match std::fs::remove_file(PathBuf::from(p)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = remove_database(&self.0);
    }
}

/// 逐行导入修订，检查长度与取值；父修订必须存在；头修订由修订图重算。
fn copy_revisions(
    src: &rusqlite::Transaction<'_>,
    dst: &rusqlite::Transaction<'_>,
    version: u32,
    effective: i64,
) -> Result<()> {
    let env = keevo_crypto::MAX_ENVELOPE_LEN;
    let parents = MAX_PARENTS * 16;
    let tomb_parents = MAX_TOMBSTONE_PARENTS * 16;
    let stored = if version >= 3 { "stored_ms" } else { "0" };
    let stored_check = if version >= 3 {
        "OR typeof(stored_ms) != 'integer' OR stored_ms < 0"
    } else {
        ""
    };
    // 先在不读取内容的情况下检查每一列（与 check_sizes 相同的规则），再读取
    let bad: i64 = src.query_row(
        &format!(
            "SELECT count(*) FROM revision WHERE
               typeof(rev_id) != 'blob' OR length(rev_id) != 16 OR typeof(object_id) != 'blob' OR length(object_id) != 16
               OR typeof(vault_id) != 'blob' OR length(vault_id) != 16
               OR typeof(origin_device) != 'blob' OR length(origin_device) != 16
               OR typeof(parents) != 'blob' OR length(parents) % 16 != 0
               OR deleted NOT IN (0, 1) OR pruned NOT IN (0, 1) OR typeof(seq) != 'integer'
               OR length(parents) > (CASE WHEN deleted THEN {tomb_parents} ELSE {parents} END)
               OR object_type NOT IN ({vault}, {item})
               OR (origin_seq IS NOT NULL AND typeof(origin_seq) != 'integer')
               OR (wrapped_key_ct IS NOT NULL AND (typeof(wrapped_key_ct) != 'blob' OR length(wrapped_key_ct) > {env}))
               OR (overview_ct IS NOT NULL AND (typeof(overview_ct) != 'blob' OR length(overview_ct) > {env}))
               OR (details_ct IS NOT NULL AND (typeof(details_ct) != 'blob' OR length(details_ct) > {env}))
               OR ((deleted OR pruned) AND (wrapped_key_ct IS NOT NULL OR overview_ct IS NOT NULL OR details_ct IS NOT NULL))
               OR (NOT (deleted OR pruned) AND (wrapped_key_ct IS NULL OR overview_ct IS NULL))
               {stored_check}",
            vault = ObjectKind::Vault.code(),
            item = ObjectKind::Item.code(),
        ),
        [],
        |r| r.get(0),
    )?;
    if bad != 0 {
        return Err(corrupt("backup revision exceeds its limits"));
    }
    let mut known: HashSet<(Vec<u8>, Vec<u8>)> = HashSet::new();
    let mut edges: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new();
    {
        let mut stmt = src.prepare(&format!(
            "SELECT rev_id, object_id, object_type, vault_id, parents, origin_device, origin_seq,
                    wrapped_key_ct, overview_ct, details_ct, deleted, pruned, {stored}
             FROM revision ORDER BY seq"
        ))?;
        let mut insert = dst.prepare(
            "INSERT INTO revision (rev_id, object_id, object_type, vault_id, parents, origin_device, origin_seq,
                                   wrapped_key_ct, overview_ct, details_ct, deleted, pruned, stored_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            let rev_id: Vec<u8> = r.get(0)?;
            let object_id: Vec<u8> = r.get(1)?;
            let parents: Vec<u8> = r.get(4)?;
            let deleted: bool = r.get(10)?;
            let pruned: bool = r.get(11)?;
            let wrapped: Option<Vec<u8>> = r.get(7)?;
            let overview: Option<Vec<u8>> = r.get(8)?;
            let details: Option<Vec<u8>> = r.get(9)?;
            // 保存时间不超过恢复前的有效时间：被篡改的备份不能让清理提前生效（第五轮预审 K1）
            let stored_ms: i64 = r.get::<_, i64>(12)?.clamp(0, effective);
            insert.execute(params![
                rev_id,
                object_id,
                r.get::<_, i64>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                parents,
                r.get::<_, Vec<u8>>(5)?,
                r.get::<_, Option<i64>>(6)?,
                wrapped,
                overview,
                details,
                deleted,
                pruned,
                stored_ms,
            ])?;
            if !known.insert((object_id.clone(), rev_id.clone())) {
                return Err(corrupt("duplicate revision in backup"));
            }
            edges.push((object_id, rev_id, parents));
        }
    }
    // 父修订必须存在于同一对象中；头修订 = 没有子修订的修订
    let mut has_child: HashSet<(Vec<u8>, Vec<u8>)> = HashSet::new();
    for (object_id, _, parents) in &edges {
        for p in decode_ids(parents)? {
            let key = (object_id.clone(), p.as_bytes().to_vec());
            if !known.contains(&key) {
                return Err(corrupt("backup revision has a missing parent"));
            }
            has_child.insert(key);
        }
    }
    let mut insert_head = dst.prepare("INSERT INTO head (object_id, rev_id) VALUES (?1, ?2)")?;
    for (object_id, rev_id, _) in &edges {
        if !has_child.contains(&(object_id.clone(), rev_id.clone())) {
            insert_head.execute(params![object_id, rev_id])?;
        }
    }
    Ok(())
}

/// 逐行导入附件与块：各部分的长度按 `spec/crypto.md` §8.9 精确检查，块序号连续、块数与 `chunk_count` 相同。
fn copy_attachments(
    src: &rusqlite::Transaction<'_>,
    dst: &rusqlite::Transaction<'_>,
    version: u32,
) -> Result<()> {
    let bad: i64 = src.query_row(
        &format!(
            "SELECT count(*) FROM attachment WHERE
               typeof(id) != 'blob' OR length(id) != 16 OR typeof(item_id) != 'blob' OR length(item_id) != 16
               OR typeof(wrapped_key_ct) != 'blob' OR length(wrapped_key_ct) != {key}
               OR typeof(meta_ct) != 'blob' OR length(meta_ct) < {min} OR length(meta_ct) > {meta}
               OR typeof(chunk_count) != 'integer' OR chunk_count < 0 OR chunk_count > {max}",
            key = ATTACHMENT_KEY_CT_LEN,
            min = keevo_crypto::MIN_ENVELOPE_LEN,
            meta = MAX_ATTACHMENT_META_CT_LEN,
            max = MAX_ATTACHMENT_CHUNKS,
        ),
        [],
        |r| r.get(0),
    )?;
    if bad != 0 {
        return Err(corrupt("backup attachment exceeds its limits"));
    }
    // (id, item_id, wrapped_key_ct, meta_ct, chunk_count)
    type Row = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64);
    let attachments: Vec<Row> = {
        let mut stmt = src.prepare(
            "SELECT id, item_id, wrapped_key_ct, meta_ct, chunk_count FROM attachment ORDER BY id",
        )?;
        stmt.query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?
        .collect::<rusqlite::Result<_>>()?
    };
    if version < 5 {
        // 没有块表的版本不可能有附件内容
        return if attachments.is_empty() {
            Ok(())
        } else {
            Err(corrupt("backup attachment without chunks"))
        };
    }
    let bad_chunks: i64 = src.query_row(
        &format!(
            "SELECT count(*) FROM attachment_chunk c LEFT JOIN attachment a ON a.id = c.attachment_id WHERE
               a.id IS NULL OR typeof(c.idx) != 'integer' OR c.idx < 0 OR c.idx >= a.chunk_count
               OR typeof(c.ct) != 'blob' OR length(c.ct) < {min} OR length(c.ct) > {full}
               OR (c.idx < a.chunk_count - 1 AND length(c.ct) != {full})",
            min = keevo_crypto::MIN_ENVELOPE_LEN,
            full = ATTACHMENT_CHUNK_CT_LEN,
        ),
        [],
        |r| r.get(0),
    )?;
    if bad_chunks != 0 {
        return Err(corrupt("backup attachment chunk exceeds its limits"));
    }
    let mut insert = dst.prepare(
        "INSERT INTO attachment (id, item_id, wrapped_key_ct, meta_ct, chunk_count) VALUES (?1, ?2, ?3, ?4, ?5)",
    )?;
    let mut insert_chunk =
        dst.prepare("INSERT INTO attachment_chunk (attachment_id, idx, ct) VALUES (?1, ?2, ?3)")?;
    let mut chunks =
        src.prepare("SELECT idx, ct FROM attachment_chunk WHERE attachment_id = ?1 ORDER BY idx")?;
    for (id, item_id, wrapped, meta, count) in attachments {
        insert.execute(params![id, item_id, wrapped, meta, count])?;
        let mut rows = chunks.query([id.as_slice()])?;
        let mut expected = 0i64;
        while let Some(r) = rows.next()? {
            if r.get::<_, i64>(0)? != expected {
                return Err(corrupt("backup attachment chunk index"));
            }
            insert_chunk.execute(params![id, expected, r.get::<_, Vec<u8>>(1)?])?;
            expected = expected.saturating_add(1);
        }
        if expected != count {
            return Err(corrupt("backup attachment chunk count"));
        }
    }
    Ok(())
}
