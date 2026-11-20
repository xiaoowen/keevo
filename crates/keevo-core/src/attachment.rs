//! 附件（`spec/crypto.md` §8.9、`spec/vault-format.md` §2.5，设计稿"macOS · 附件"）。
//!
//! 一个附件是一个不可变的文件：附件密钥 AK（随机）由所属保险库的 VK 包裹；元数据（所属条目、文件名、大小、
//! 块数）与内容都由 AK 封装为信封 v1。内容按 64 KiB 分块，每块的 AAD 带块序号（`part_index`）与总块数
//! （`binding`），因此块不能被调换、截断或拼接到另一个附件。条目中只有附件引用（`attachment` 字段）。
//!
//! 附件内容存放在本机数据库中（随备份一起保存）。删除附件字段后，内容仍被历史版本引用；条目永久删除、
//! 或引用它的历史版本都被清理之后才删除（[`crate::Vault`] 的回收）。

use keevo_crypto::{AadContext, Id128, ObjectType, Part, SymmetricKey};
use keevo_format::AttachmentRef;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

/// 单个附件的大小上限：50 MiB。
pub const MAX_ATTACHMENT_LEN: usize = 50 * 1024 * 1024;
/// 块的明文长度：除最后一块外都恰好是这么长。
pub const CHUNK_LEN: usize = 64 * 1024;
/// 文件名的长度上限（UTF-8 字节）。
pub const MAX_NAME_LEN: usize = 255;

/// 附件元数据（AK 封装，`part = Content`）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Meta {
    /// 格式版本，当前为 1。
    pub(crate) v: u32,
    /// 所属条目（十六进制）。
    pub(crate) item: String,
    /// 文件名。
    pub(crate) name: String,
    /// 大小（字节）。
    pub(crate) size: u64,
    /// 块数。
    pub(crate) chunks: u32,
}

/// 附件各部分的信封上下文：`rev_id` 为零（附件不可变，没有修订）。
pub(crate) const fn context(
    account_id: Id128,
    vault_id: Id128,
    attachment_id: Id128,
    part: Part,
    part_index: u32,
    binding: [u8; 32],
) -> AadContext {
    AadContext {
        object_type: ObjectType::Attachment,
        part,
        part_index,
        account_id,
        vault_id,
        object_id: attachment_id,
        rev_id: Id128::from_bytes([0; 16]),
        binding,
    }
}

/// 块的绑定值：总块数（4 字节大端）后补零。
pub(crate) fn chunk_binding(chunks: u32) -> [u8; 32] {
    let mut b = [0u8; 32];
    if let Some(head) = b.get_mut(..4) {
        head.copy_from_slice(&chunks.to_be_bytes());
    }
    b
}

/// 按 `spec/crypto.md` §8.9"读取"打开一个附件：解开 VK 包裹的 AK，核对元数据（规范编码、所属条目、块数、与引用
/// 一致的文件名与大小），依次打开每块并核对长度，最后核对引用中的 `sha256`。读取路径与跨实现测试向量共用。
///
/// # Errors
/// 任何一项不符时返回 [`CoreError::Tampered`]；认证失败时返回对应的密码学错误。
pub(crate) fn open_parts(
    vk: &SymmetricKey,
    account_id: Id128,
    vault_id: Id128,
    item_id: Id128,
    row: &keevo_store::AttachmentRow,
    chunks: &[Vec<u8>],
    reference: &AttachmentRef,
) -> Result<Zeroizing<Vec<u8>>> {
    let attachment_id = row.id;
    if reference.id != attachment_id {
        return Err(CoreError::Tampered);
    }
    let ctx =
        |part, index, binding| context(account_id, vault_id, attachment_id, part, index, binding);
    let ak = vk.unwrap_key(&ctx(Part::WrappedKey, 0, [0; 32]), &row.wrapped_key_ct)?;
    let meta_json = keevo_crypto::open(&ak, &ctx(Part::Content, 0, [0; 32]), &row.meta_ct)?;
    let meta: Meta = serde_json::from_slice(&meta_json).map_err(|_| CoreError::Tampered)?;
    // 元数据只接受规范编码，并与条目中的引用一致（第五轮预审 K12、S3）
    let canonical = serde_json::to_vec(&meta).map_err(|_| CoreError::Tampered)?;
    if canonical.as_slice() != meta_json.as_slice()
        || meta.v != 1
        || meta.item != item_id.to_hex()
        || meta.chunks != row.chunk_count
        || meta.name != reference.name
        || i64::try_from(meta.size).ok() != Some(reference.size)
    {
        return Err(CoreError::Tampered);
    }
    let size = usize::try_from(meta.size).map_err(|_| CoreError::Tampered)?;
    if size > MAX_ATTACHMENT_LEN || size.div_ceil(CHUNK_LEN) != chunks.len() {
        return Err(CoreError::Tampered);
    }
    let binding = chunk_binding(meta.chunks);
    let mut out = Zeroizing::new(Vec::with_capacity(size));
    let last = chunks.len().saturating_sub(1);
    for ((i, ct), idx) in chunks.iter().enumerate().zip(0u32..) {
        let plain = keevo_crypto::open(&ak, &ctx(Part::Chunk, idx, binding), ct)?;
        let ok = if i == last {
            !plain.is_empty() && plain.len() <= CHUNK_LEN
        } else {
            plain.len() == CHUNK_LEN
        };
        if !ok {
            return Err(CoreError::Tampered);
        }
        out.extend_from_slice(&plain);
    }
    if out.len() != size
        || reference
            .sha256
            .is_some_and(|digest| keevo_crypto::sha256(&out) != digest)
    {
        return Err(CoreError::Tampered);
    }
    Ok(out)
}

/// 规范化文件名：去掉路径与控制字符，截断到 [`MAX_NAME_LEN`] 字节；为空时用"附件"。
#[must_use]
pub fn clean_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let mut out: String = base.chars().filter(|c| !c.is_control()).collect();
    out = out.trim().to_owned();
    if out.len() > MAX_NAME_LEN {
        let mut end = MAX_NAME_LEN;
        while !out.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        out.truncate(end);
    }
    if out.is_empty() {
        "附件".to_owned()
    } else {
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::{CoreError, Edit, Vault};
    use keevo_format::{FieldData, ItemType, RecordKey, RecordValue};

    struct Temp(std::path::PathBuf, Vault);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn vault() -> Temp {
        let dir =
            std::env::temp_dir().join(format!("keevo-att-{}", Id128::random().unwrap().to_hex()));
        std::fs::create_dir_all(&dir).unwrap();
        let params = keevo_crypto::KdfParams::new(
            keevo_crypto::KdfParams::MIN_M_KIB,
            keevo_crypto::KdfParams::MIN_T,
            1,
            [1; 16],
        )
        .unwrap();
        let (v, _) = Vault::create(&dir.join("vault.sqlite"), "pw", params).unwrap();
        Temp(dir, v)
    }

    fn attachment_field(v: &Vault, item: Id128) -> Option<(Id128, keevo_format::AttachmentRef)> {
        v.item(item)
            .unwrap()
            .doc
            .records
            .iter()
            .find_map(|(k, r)| match (k, &r.value) {
                (RecordKey::Field(id), Some(RecordValue::Field(f))) => match &f.data {
                    FieldData::Attachment(a) => Some((*id, a.clone())),
                    _ => None,
                },
                _ => None,
            })
    }

    /// 跨实现测试向量（`spec/test-vectors/attachment-v1.json`，由独立的 Python 参考实现生成）：读取方得到同样的
    /// 内容，写入方产生同样的元数据编码；各部分的长度符合 §8.9 的表；反例报告篡改。
    #[test]
    fn cross_implementation_vectors() {
        const VECTORS: &str = include_str!("../../../spec/test-vectors/attachment-v1.json");
        let doc: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
        let hex = |v: &serde_json::Value| -> Vec<u8> {
            let s = v.as_str().unwrap().as_bytes();
            s.chunks_exact(2)
                .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
                .collect()
        };
        let id = |v: &serde_json::Value| Id128::from_bytes(hex(v).try_into().unwrap());
        let run = |case: &serde_json::Value| {
            let vk = SymmetricKey::from_raw_for_tests(
                hex(&case["vk_kid"]).try_into().unwrap(),
                hex(&case["vk"]).try_into().unwrap(),
            );
            let chunks: Vec<Vec<u8>> = case["chunks"].as_array().unwrap().iter().map(hex).collect();
            let row = keevo_store::AttachmentRow {
                id: id(&case["attachment_id"]),
                item_id: id(&case["item_id"]),
                wrapped_key_ct: hex(&case["wrapped_key"]),
                meta_ct: hex(&case["meta_ct"]),
                chunk_count: u32::try_from(chunks.len()).unwrap(),
            };
            let r = &case["reference"];
            let reference = AttachmentRef {
                id: row.id,
                name: r["name"].as_str().unwrap().to_owned(),
                size: r["size"].as_i64().unwrap(),
                added: 0,
                sha256: Some(hex(&r["sha256"]).try_into().unwrap()),
            };
            let opened = open_parts(
                &vk,
                id(&case["account_id"]),
                id(&case["vault_id"]),
                row.item_id,
                &row,
                &chunks,
                &reference,
            );
            (row, chunks, opened)
        };
        let valid = doc["valid"].as_array().unwrap();
        assert!(valid.len() >= 3);
        for case in valid {
            let name = case["name"].as_str().unwrap();
            let (row, chunks, opened) = run(case);
            let data = opened.unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert_eq!(
                u64::try_from(data.len()).unwrap(),
                case["content_len"].as_u64().unwrap(),
                "{name}"
            );
            assert_eq!(
                keevo_crypto::sha256(&data).to_vec(),
                hex(&case["content_sha256"]),
                "{name}"
            );
            // 写入方的元数据编码与参考实现逐字节相同
            let meta = Meta {
                v: 1,
                item: row.item_id.to_hex(),
                name: case["reference"]["name"].as_str().unwrap().to_owned(),
                size: u64::try_from(data.len()).unwrap(),
                chunks: row.chunk_count,
            };
            assert_eq!(
                serde_json::to_vec(&meta).unwrap(),
                case["meta"].as_str().unwrap().as_bytes(),
                "{name}: 元数据的规范编码"
            );
            // 各部分的长度符合 §8.9 的表：存储层接受它们
            keevo_store::Store::open_in_memory()
                .unwrap()
                .insert_attachment(&row, &chunks)
                .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        }
        let invalid = doc["invalid"].as_array().unwrap();
        assert!(invalid.len() >= 6);
        for case in invalid {
            let name = case["name"].as_str().unwrap();
            assert_eq!(case["error"], "tampered", "{name}");
            assert_eq!(run(case).2.err(), Some(CoreError::Tampered), "{name}");
        }
    }

    #[test]
    fn add_read_tamper_and_collect() {
        let mut t = vault();
        let v = &mut t.1;
        let vault_id = v.vaults().unwrap()[0].id;
        let item = v
            .create_item(vault_id, ItemType::SecureNote, "带附件", vec![])
            .unwrap();
        // 恰好两块多一点，以及空文件
        let data: Vec<u8> = (0..(2 * CHUNK_LEN + 17))
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let r = v
            .add_attachment(item, "/tmp/备份.sql", &data, 1_700_000_000_000)
            .unwrap();
        assert_eq!(
            (r.name.as_str(), r.size),
            ("备份.sql", i64::try_from(data.len()).unwrap())
        );
        assert_eq!(v.attachment_data(item, r.id).unwrap().as_slice(), data);
        let empty = v.add_attachment(item, "empty.txt", b"", 1).unwrap();
        assert!(v.attachment_data(item, empty.id).unwrap().is_empty());
        // 条目详情升为 v2
        assert_eq!(
            v.item(item).unwrap().doc.version(),
            keevo_format::ITEM_DETAILS_V2
        );

        // 不属于这个条目
        let other = v
            .create_item(vault_id, ItemType::SecureNote, "别的", vec![])
            .unwrap();
        assert_eq!(
            v.attachment_data(other, r.id).err(),
            Some(CoreError::NotFound)
        );
        // 引用承诺内容（第五轮预审 K13）：同一个附件 ID 的引用若与内容的摘要、大小或文件名不符，读取失败
        assert_eq!(empty.sha256, Some(keevo_crypto::sha256(b"")));
        let empty_field = v
            .item(item)
            .unwrap()
            .doc
            .records
            .iter()
            .find_map(|(k, r)| match (k, &r.value) {
                (RecordKey::Field(id), Some(RecordValue::Field(f)))
                    if matches!(&f.data, FieldData::Attachment(a) if a.id == empty.id) =>
                {
                    Some(*id)
                }
                _ => None,
            })
            .unwrap();
        v.update_item(item, vec![Edit::RemoveField(empty_field)])
            .unwrap();
        for forged in [
            keevo_format::AttachmentRef {
                sha256: Some([0; 32]),
                ..empty.clone()
            },
            keevo_format::AttachmentRef {
                size: 1,
                ..empty.clone()
            },
            keevo_format::AttachmentRef {
                name: "other.txt".into(),
                ..empty.clone()
            },
        ] {
            v.update_item(
                item,
                vec![Edit::AddField(crate::NewField {
                    kind: keevo_format::FieldKind::Attachment,
                    label: "x".into(),
                    purpose: None,
                    data: FieldData::Attachment(forged),
                })],
            )
            .unwrap();
            assert_eq!(
                v.attachment_data(item, empty.id).err(),
                Some(CoreError::Tampered)
            );
            let id = v
                .item(item)
                .unwrap()
                .doc
                .records
                .iter()
                .find_map(|(k, r)| match (k, &r.value) {
                    (RecordKey::Field(id), Some(RecordValue::Field(f)))
                        if matches!(&f.data, FieldData::Attachment(a) if a.id == empty.id) =>
                    {
                        Some(*id)
                    }
                    _ => None,
                })
                .unwrap();
            v.update_item(item, vec![Edit::RemoveField(id)]).unwrap();
        }
        // 超过上限：什么都不留下
        let before = v.store_for_tests().attachments_of(&item).unwrap().len();
        assert_eq!(
            v.add_attachment(item, "big", &vec![0; MAX_ATTACHMENT_LEN + 1], 1)
                .err(),
            Some(CoreError::OutOfRange)
        );
        assert_eq!(
            v.store_for_tests().attachments_of(&item).unwrap().len(),
            before
        );

        // 调换两块、篡改一块：都被发现
        v.store_for_tests()
            .execute_for_tests(&format!(
                "UPDATE attachment_chunk SET idx = 9 WHERE attachment_id = x'{0}' AND idx = 0;
                 UPDATE attachment_chunk SET idx = 0 WHERE attachment_id = x'{0}' AND idx = 1;
                 UPDATE attachment_chunk SET idx = 1 WHERE attachment_id = x'{0}' AND idx = 9;",
                r.id.to_hex()
            ))
            .unwrap();
        assert!(v.attachment_data(item, r.id).is_err());

        // 删除附件字段：历史版本仍引用，内容保留
        let (field_id, _) = attachment_field(v, item).unwrap();
        v.update_item(item, vec![Edit::RemoveField(field_id)])
            .unwrap();
        assert!(
            v.store_for_tests()
                .attachments_of(&item)
                .unwrap()
                .contains(&r.id)
        );
        // 永久删除条目：附件随之删除
        v.trash_item(item).unwrap();
        v.purge_item(item).unwrap();
        assert!(
            v.store_for_tests()
                .attachments_of(&item)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn names_and_binding() {
        assert_eq!(clean_name("/tmp/a/b.pem"), "b.pem");
        assert_eq!(clean_name("..\\x\u{0}y.txt"), "xy.txt");
        assert_eq!(clean_name("   "), "附件");
        assert!(clean_name(&"长".repeat(200)).len() <= MAX_NAME_LEN);
        assert_eq!(chunk_binding(0x0102_0304)[..5], [1, 2, 3, 4, 0]);
    }
}
