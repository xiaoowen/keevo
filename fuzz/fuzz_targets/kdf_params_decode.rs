//! KDF 参数解码：任意输入都不得 panic；解码成功时必须满足上下限，且编码结果与输入一致。
#![no_main]

use keevo_crypto::KdfParams;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = KdfParams::decode(data) {
        assert!(p.memory_kib() >= KdfParams::MIN_M_KIB && p.memory_kib() <= KdfParams::MAX_M_KIB);
        assert!(p.iterations() >= KdfParams::MIN_T && p.iterations() <= KdfParams::MAX_T);
        assert!(p.parallelism() >= KdfParams::MIN_P && p.parallelism() <= KdfParams::MAX_P);
        assert_eq!(p.encode().as_slice(), data);
    }
});
