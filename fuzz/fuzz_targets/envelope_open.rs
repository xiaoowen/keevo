//! 信封解析与解密：任意输入都不得 panic，伪造的信封绝不能通过认证。
#![no_main]

use std::sync::OnceLock;

use keevo_crypto::{AadContext, Id128, ObjectType, Part, SymmetricKey, envelope_key_id, open};
use libfuzzer_sys::fuzz_target;

fn key() -> &'static SymmetricKey {
    static KEY: OnceLock<SymmetricKey> = OnceLock::new();
    KEY.get_or_init(|| SymmetricKey::generate().expect("随机数"))
}

const CTX: AadContext = AadContext {
    object_type: ObjectType::Item,
    part: Part::Details,
    part_index: 0,
    account_id: Id128::ZERO,
    vault_id: Id128::ZERO,
    object_id: Id128::ZERO,
    rev_id: Id128::ZERO,
    binding: [0; 32],
};

fuzz_target!(|data: &[u8]| {
    let _ = envelope_key_id(data);
    assert!(open(key(), &CTX, data).is_err());

    // 补上正确的版本、算法与 kid，让输入越过头部检查，直达认证与解填充
    let mut forged = vec![0x01, 0x01];
    forged.extend_from_slice(key().id().as_bytes());
    forged.extend_from_slice(data);
    assert!(open(key(), &CTX, &forged).is_err(), "伪造的信封通过了认证");
});
