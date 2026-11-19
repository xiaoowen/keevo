//! 密码强度评估（任意用户输入）：不得 panic；分数在 0–4 之间，猜测次数为正数。
#![no_main]

use keevo_core::strength;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let s = strength::estimate(text);
    assert!(s.score <= 4);
    assert!(s.guesses >= 1.0 && s.guesses.is_finite());
});
