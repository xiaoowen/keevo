//! Keevo 加密导出文件的打开（spec/export.md §3，来自外部的文件）：任意输入都不得 panic。
//! KDF 参数超出自动执行预算的文件在派生前被拒绝；合法参数的文件会真的跑一次 Argon2id，因此只取最小参数。
#![no_main]

use keevo_crypto::{KdfParams, open_export};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 跳过会触发昂贵派生的输入：只有参数恰好是最小值时才真正解密
    if data.len() > 38
        && let Ok(p) = KdfParams::decode(data.get(9..38).unwrap_or_default())
        && (p.memory_kib() != KdfParams::MIN_M_KIB || p.iterations() != KdfParams::MIN_T || p.parallelism() != 1)
        && p.within_auto_budget()
    {
        return;
    }
    let _ = open_export("fuzz password", data);
});
