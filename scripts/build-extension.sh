#!/usr/bin/env bash
# 构建浏览器扩展：Rust → WASM（keevo-wasm）→ JS 绑定 → TypeScript → apps/browser-extension/dist
#
# 用法：
#   scripts/build-extension.sh          # 构建
#   scripts/build-extension.sh --test   # 构建，并用真实的 native host 与开发服务跑端到端测试；
#                                       # 有 Chrome 时再跑真实浏览器测试（页内菜单与点击劫持防护）
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXT="$ROOT/apps/browser-extension"
WASM_BINDGEN_VERSION="0.2.130"   # 必须与 crates/keevo-wasm 中锁定的 wasm-bindgen 版本一致

if ! wasm-bindgen --version 2>/dev/null | grep -q " $WASM_BINDGEN_VERSION"; then
  echo "需要 wasm-bindgen-cli $WASM_BINDGEN_VERSION：cargo install wasm-bindgen-cli --version $WASM_BINDGEN_VERSION --locked" >&2
  exit 1
fi

cd "$ROOT"
cargo build -p keevo-wasm --target wasm32-unknown-unknown --release --locked
rm -rf "$EXT/src/wasm"
wasm-bindgen --target web --out-dir "$EXT/src/wasm" \
  "$ROOT/target/wasm32-unknown-unknown/release/keevo_wasm.wasm"

cd "$EXT"
[[ -d node_modules ]] || npm ci --ignore-scripts --no-audit --no-fund
rm -rf dist
npx tsc -p .
cp static/* dist/
mkdir -p dist/wasm
cp src/wasm/keevo_wasm.js src/wasm/keevo_wasm_bg.wasm dist/wasm/
echo "扩展已构建：$EXT/dist（在 chrome://extensions 中用「加载已解压的扩展程序」载入）"

if [[ "${1:-}" == "--test" ]]; then
  cd "$ROOT"
  cargo build -p keevo-native-host -p keevo-service --locked
  node "$EXT/test/e2e.mjs"
  node "$EXT/test/browser.mjs"
fi
