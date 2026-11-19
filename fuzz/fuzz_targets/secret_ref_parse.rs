//! `keevo://` 引用的解析（`spec/secret-refs.md` §1）：任意输入都不得 panic；解析成功时各段非空、长度在上限内、
//! 不含控制字符。
#![no_main]

use keevo_core::secret_ref::{MAX_SEGMENT_LEN, SecretRef};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(r) = SecretRef::parse(text) {
        for seg in [Some(&r.vault), Some(&r.item), r.section.as_ref(), Some(&r.field)].into_iter().flatten() {
            assert!(!seg.is_empty());
            assert!(seg.len() <= MAX_SEGMENT_LEN * 3, "NFC 之后最多膨胀为 3 倍");
            assert!(!seg.chars().any(char::is_control));
        }
    }
});
