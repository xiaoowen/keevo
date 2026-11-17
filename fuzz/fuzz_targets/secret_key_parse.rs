//! 账户密钥解析：任意输入都不得 panic；解析成功时，显示形式必须能原样解析回来。
#![no_main]

use keevo_crypto::AccountSecretKey;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    if let Ok(sk) = AccountSecretKey::parse(text) {
        let shown = sk.to_display_string();
        let again = AccountSecretKey::parse(&shown).expect("显示形式必须可解析");
        assert_eq!(*again.to_display_string(), *shown);
    }
});
