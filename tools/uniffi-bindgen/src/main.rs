//! UniFFI 绑定生成器：`cargo run -p uniffi-bindgen -- generate --library <lib> --language swift --out-dir <dir>`。

fn main() {
    uniffi::uniffi_bindgen_main();
}
