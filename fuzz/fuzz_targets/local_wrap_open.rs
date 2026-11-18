//! 本机密钥包裹的解析与解包（`spec/crypto.md` §8.7）：任意输入都不得 panic，伪造的包裹绝不能通过认证。
#![no_main]

use keevo_crypto::{Id128, LocalWrapHeader, unwrap_auk, unwrap_device_marker, unwrap_secret_key};
use libfuzzer_sys::fuzz_target;

const ACCOUNT: Id128 = Id128::ZERO;

fuzz_target!(|data: &[u8]| {
    let header = LocalWrapHeader::parse(data);
    // 协商结果取自输入的前 32 字节：即使攻击者控制它，也不能伪造出另一个协商结果下的包裹
    let shared: Vec<u8> = data.iter().copied().take(32).collect();
    let auk = unwrap_auk(data, &ACCOUNT, &ACCOUNT, &shared);
    let sk = unwrap_secret_key(data, &ACCOUNT, &ACCOUNT, &shared);
    let marker = unwrap_device_marker(data, &ACCOUNT, &shared);
    if header.is_err() {
        assert!(auk.is_err() && sk.is_err() && marker.is_err(), "头部无效却解开了");
    }

    // 补上合法的头部，让输入直达认证
    for (purpose, body) in [(0x01u8, 24 + 32 + 16), (0x02, 24 + 16 + 16), (0x04, 24 + 16 + 16)] {
        let mut forged = vec![0x01, purpose, 0x04];
        forged.extend(data.iter().copied().cycle().take(64 + body));
        assert!(
            unwrap_auk(&forged, &ACCOUNT, &ACCOUNT, &[7; 32]).is_err()
                && unwrap_secret_key(&forged, &ACCOUNT, &ACCOUNT, &[7; 32]).is_err()
                && unwrap_device_marker(&forged, &ACCOUNT, &[7; 32]).is_err(),
            "伪造的包裹通过了认证"
        );
    }
});
