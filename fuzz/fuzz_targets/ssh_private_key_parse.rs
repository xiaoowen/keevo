//! OpenSSH 私钥的解析（`spec/ssh-agent.md` §3）：任意输入都不得 panic；解析成功时重新编码后能解析为同一把密钥，
//! 签名能被公钥验证。
#![no_main]

use keevo_ssh::{PrivateKey, PublicKey};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(key) = PrivateKey::parse(text) {
        let again = PrivateKey::parse(&key.to_openssh().expect("编码")).expect("重新解析");
        assert_eq!(again.public_key(), key.public_key());
        assert!(key.public_key().verify(b"x", &key.sign(b"x")));
    }
    let _ = PublicKey::parse_line(text);
});
