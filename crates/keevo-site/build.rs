//! 从原样保存的 `src/public_suffix_list.dat` 中取出规则（每行第一个词，去掉注释与空行），写到 `OUT_DIR/rules.txt`
//! 供 `include_str!` 嵌入：列表一半以上是注释，WASM 中不需要它们。

#![allow(clippy::print_stdout, reason = "build.rs 通过标准输出与 Cargo 通信")]

use std::path::PathBuf;
use std::{env, fs, io};

fn main() -> io::Result<()> {
    let src = "src/public_suffix_list.dat";
    println!("cargo::rerun-if-changed={src}");
    let list = fs::read_to_string(src)?;
    let rules: Vec<&str> = list
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|rule| !rule.starts_with("//"))
        .collect();
    let out_dir = env::var_os("OUT_DIR").ok_or_else(|| io::Error::other("缺少 OUT_DIR"))?;
    fs::write(PathBuf::from(out_dir).join("rules.txt"), rules.join("\n"))
}
