//! Vault Service 的 IPC 状态机：任意帧序列都不得 panic，也不得在未配对时建立会话。
#![no_main]

use std::sync::{Arc, OnceLock};

use keevo_crypto::StaticKeypair;
use keevo_ipc::message::{Candidate, FillData};
use keevo_ipc::service::{MemoryPairingStore, ServiceConnection, VaultBackend};
use libfuzzer_sys::fuzz_target;

struct Backend;

impl VaultBackend for Backend {
    fn is_locked(&self) -> bool {
        false
    }
    fn candidates(&self, _: &str) -> Vec<Candidate> {
        Vec::new()
    }
    fn item_matches(&self, _: &str, _: &str) -> Option<bool> {
        None
    }
    fn fill(&self, _: &str) -> Option<FillData> {
        None
    }
}

fn key() -> Arc<StaticKeypair> {
    static KEY: OnceLock<Arc<StaticKeypair>> = OnceLock::new();
    KEY.get_or_init(|| Arc::new(StaticKeypair::generate().expect("随机数"))).clone()
}

const HELLO: &[u8] = br#"{"v":1,"client":"native-host","extension_origin":"chrome-extension://x/","browser":"b"}"#;

fuzz_target!(|data: &[u8]| {
    let mut store = MemoryPairingStore::default();
    // 输入按 0xff 切分为多帧
    let frames: Vec<&[u8]> = data.split(|b| *b == 0xff).collect();

    // 情形一：任意帧直接作为第一帧
    let mut conn = ServiceConnection::new(key());
    for f in &frames {
        let _ = conn.on_frame(f, &mut store, &Backend);
    }

    // 情形二：合法 HostHello 之后的任意帧序列。配对存储为空，因此绝不能建立会话
    let mut conn = ServiceConnection::new(key());
    let _ = conn.on_frame(HELLO, &mut store, &Backend);
    for f in &frames {
        let _ = conn.on_frame(f, &mut store, &Backend);
        assert!(!conn.is_established(), "未配对却建立了会话");
    }
});
