//! 泄露检查的响应（Have I Been Pwned 的 range 接口，来自网络）：任意前缀与响应都不得 panic。
#![no_main]

use keevo_core::security::Breaches;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let (prefix, body) = text.split_at(text.char_indices().nth(5).map_or(text.len(), |(i, _)| i));
    let mut b = Breaches::default();
    let _ = b.record(prefix, body);
    let _ = b.complete();
});
