#!/usr/bin/env bash
# 构建 macOS 空壳应用：编译 Rust 静态库 → 生成 UniFFI Swift 绑定 → SwiftPM 构建。
#
# 用法：
#   scripts/build-macos.sh            # 构建
#   scripts/build-macos.sh --smoke    # 构建并运行端到端冒烟测试
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="$ROOT/apps/macos"
LIB_DIR="$ROOT/target/release"

cd "$ROOT"
cargo build -p keevo-ffi --release --locked
cargo build -p uniffi-bindgen --release --locked

GEN="$(mktemp -d)"
trap 'rm -rf "$GEN"' EXIT
"$ROOT/target/release/uniffi-bindgen" generate \
  --library "$LIB_DIR/libkeevo_ffi.dylib" --language swift --out-dir "$GEN"

mkdir -p "$APP/Sources/keevo_ffiFFI/include" "$APP/Sources/KeevoKit/Generated"
cp "$GEN/keevo_ffiFFI.h" "$APP/Sources/keevo_ffiFFI/include/keevo_ffiFFI.h"
cp "$GEN/keevo_ffiFFI.modulemap" "$APP/Sources/keevo_ffiFFI/include/module.modulemap"
cp "$GEN/keevo_ffi.swift" "$APP/Sources/KeevoKit/Generated/keevo_ffi.swift"

cd "$APP"
# 只装了 Command Line Tools 时，默认构建系统无法初始化，需使用原生构建系统。
# 过滤掉弃用警告；构建失败时必须退出，否则后面会运行上一次构建留下的旧二进制。
KEEVO_RUST_LIB_DIR="$LIB_DIR" swift build --build-system native -c release 2>&1 \
  | { grep -v "has been deprecated" || true; }
test -x "$APP/.build/release/Keevo" && test -x "$APP/.build/release/keevo-smoke"

if [[ "${1:-}" == "--smoke" ]]; then
  "$APP/.build/release/keevo-smoke"
fi
echo "构建完成：$APP/.build/release/Keevo"
