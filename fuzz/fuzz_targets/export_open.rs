//! Keevo 加密导出文件的打开（spec/export.md §3，来自外部的文件）：任意输入都不得 panic。
//! KDF 参数超出自动执行预算的文件在派生前被拒绝，这条路径照常测试。参数合法的文件之后只剩 Argon2id 派生与
//! 解密：用固定的测试密码解密必然失败，派生不增加任何覆盖，却要一次 Argon2id（最小参数 64 MiB、3 次迭代，
//! 插桩构建中超过 10 秒，第 24 小时模糊测试的慢输入），因此跳过。解密失败的路径由单元测试覆盖。
#![no_main]

use keevo_crypto::{KdfParams, open_export};
use libfuzzer_sys::fuzz_target;

/// 魔数（8 字节）与版本（1 字节）之后是 KDF 参数，再之后是 nonce（24 字节）与密文（spec/export.md §3）。
const PARAMS_AT: usize = 9;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

fuzz_target!(|data: &[u8]| {
    // 只跳过真正会走到派生的输入：参数合法、在自动执行预算内，长度也通过派生之前的检查。其余的照常打开
    let body_at = PARAMS_AT + KdfParams::ENCODED_LEN + NONCE_LEN;
    if data.starts_with(b"KEEVOEXP\x01")
        && data.len() >= body_at + TAG_LEN
        && let Some(params) = data.get(PARAMS_AT..PARAMS_AT + KdfParams::ENCODED_LEN)
        && KdfParams::decode(params).is_ok_and(|p| p.within_auto_budget())
    {
        return;
    }
    let _ = open_export("fuzz password", data);
});
