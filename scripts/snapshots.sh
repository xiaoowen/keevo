#!/usr/bin/env bash
# 界面截图：用示例数据把各个页面离屏渲染为 PNG（浅色与深色），用于对照设计稿检查界面。
# 不显示任何窗口，不读写用户的数据。
#
# 用法：scripts/snapshots.sh [输出目录] [只截的页面名称…]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/target/snapshots}"
shift || true
# Rust 静态库与 UniFFI 绑定由 build-macos.sh 生成；之后以 debug 构建截图程序（截图代码只在 debug 构建中编译）
"$ROOT/scripts/build-macos.sh" >/dev/null
cd "$ROOT/apps/macos"
KEEVO_RUST_LIB_DIR="$ROOT/target/release" swift build --build-system native --product keevo-snapshots 2>&1 \
  | { grep -E "error|warning: unre" || true; }
mkdir -p "$OUT"
".build/debug/keevo-snapshots" "$OUT" "$@"
