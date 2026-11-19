//! 导入文件的解析（1PUX 的 zip 与 JSON、Bitwarden JSON、浏览器与 LastPass 的 CSV、Keevo 导出）：
//! 第一个字节选择来源，其余为文件内容。任意输入都不得 panic；解析成功时每个条目都有标题，且不超过上限。
//! 不提供密码：有密码保护的文件停在 password_required，避免模糊测试把时间花在 KDF 上。
#![no_main]

use keevo_core::import::{self, Source};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, file)) = data.split_first() else {
        return;
    };
    let source = Source::ALL[usize::from(selector) % Source::ALL.len()];
    if let Ok(parsed) = import::parse(source, file, None) {
        assert!(!parsed.items.is_empty());
        assert!(parsed.items.len() <= import::MAX_ITEMS);
        for item in &parsed.items {
            assert!(!item.title.is_empty());
            assert!(item.fields.iter().all(|(s, _)| s.is_none_or(|i| i < item.sections.len())));
        }
    }
});
