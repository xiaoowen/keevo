//! 条目详情解码：任意输入都不得 panic；解码成功的文档编码后再解码必须得到相同结果。
#![no_main]

use keevo_format::ItemDoc;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(doc) = ItemDoc::decode(data) {
        let _ = doc.overview();
        let encoded = doc.encode().expect("可解码的文档必须可编码");
        assert_eq!(ItemDoc::decode(&encoded).expect("往返"), doc);
    }
});
