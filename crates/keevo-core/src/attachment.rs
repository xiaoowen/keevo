//! 附件（`spec/crypto.md` §8.9、`spec/vault-format.md` §2.5，设计稿"macOS · 附件"）。
//!
//! 一个附件是一个不可变的文件：附件密钥 AK（随机）由所属保险库的 VK 包裹；元数据（所属条目、文件名、大小、
//! 块数）与内容都由 AK 封装为信封 v1。内容按 64 KiB 分块，每块的 AAD 带块序号（`part_index`）与总块数
//! （`binding`），因此块不能被调换、截断或拼接到另一个附件。条目中只有附件引用（`attachment` 字段）。
//!
//! 附件内容存放在本机数据库中（随备份一起保存）。删除附件字段后，内容仍被历史版本引用；条目永久删除、
//! 或引用它的历史版本都被清理之后才删除（[`crate::Vault`] 的回收）。

use keevo_crypto::{AadContext, Id128, ObjectType, Part};
use serde::{Deserialize, Serialize};

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
