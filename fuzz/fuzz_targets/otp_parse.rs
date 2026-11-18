//! 一次性密码配置的解析（`otpauth://` URI 与 Base32 密钥）：任意输入都不得 panic，解析成功时必须能算出验证码。
#![no_main]

use keevo_core::otp::OtpConfig;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(config) = OtpConfig::parse(text) {
        let code = config.code_at(1_763_366_400_000).expect("解析成功的配置必须能计算验证码");
        assert_eq!(code.code.len(), usize::try_from(config.digits).unwrap());
        assert!(code.code.bytes().all(|b| b.is_ascii_digit()));
    }
});
