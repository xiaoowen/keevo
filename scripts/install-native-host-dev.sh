#!/usr/bin/env bash
# 为本机 Chrome 安装开发版 native host 清单，使"Keevo（开发版）"扩展能连接 keevo-native-host。
#
# 用法：
#   scripts/install-native-host-dev.sh              # 安装
#   scripts/install-native-host-dev.sh --uninstall  # 卸载
#
# 写入：~/Library/Application Support/Google/Chrome/NativeMessagingHosts/app.keevo.native_host.json
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
MANIFEST="$DIR/app.keevo.native_host.json"

if [[ "${1:-}" == "--uninstall" ]]; then
  rm -f "$MANIFEST"
  echo "已卸载：$MANIFEST"
  exit 0
fi

cd "$ROOT"
cargo build -p keevo-native-host --locked
HOST_BIN="$ROOT/target/debug/keevo-native-host"

# 扩展 ID 由 static/manifest.json 中的公钥决定：SHA-256 的前 16 字节，十六进制映射到 a–p
EXT_ID="$(python3 - "$ROOT/apps/browser-extension/static/manifest.json" <<'PY'
import base64, hashlib, json, sys
key = json.load(open(sys.argv[1]))["key"]
digest = hashlib.sha256(base64.b64decode(key)).hexdigest()[:32]
print("".join(chr(ord("a") + int(c, 16)) for c in digest))
PY
)"

mkdir -p "$DIR"
cat > "$MANIFEST" <<JSON
{
  "name": "app.keevo.native_host",
  "description": "Keevo native messaging host (development build)",
  "path": "$HOST_BIN",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://$EXT_ID/"]
}
JSON
echo "已安装：$MANIFEST"
echo "扩展 ID：$EXT_ID"
