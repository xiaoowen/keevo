//! 概要与保险库元数据解码：任意输入都不得 panic。
#![no_main]

use keevo_format::{ItemOverview, VaultMeta};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(o) = ItemOverview::decode(data) {
        assert_eq!(ItemOverview::decode(&o.encode().expect("编码")).expect("往返"), o);
    }
    let _ = VaultMeta::decode(data);
});
