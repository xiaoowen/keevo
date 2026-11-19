//! SSH agent 消息的解析（`spec/ssh-agent.md` §2、§5）：任意输入都不得 panic，session-bind 的验证也不得 panic。
#![no_main]

use keevo_ssh::agent::{Request, parse_request};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(Request::SessionBind(bind)) = parse_request(data) {
        let _ = bind.check();
        let _ = bind.host_fingerprint();
        let _ = bind.host_algorithm();
    }
    let _ = keevo_ssh::PublicKey::from_blob(data);
});
