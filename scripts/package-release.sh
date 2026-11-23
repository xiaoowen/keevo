#!/usr/bin/env bash
# 组装发布包：Keevo.app（临时签名，并实测进程加固）与 Chrome 扩展，各打成一个 zip，附 SHA-256 校验和。
#
# 用法：
#   scripts/package-release.sh
#
# 产物（target/release-artifacts/）：
#   Keevo-<版本>-macos.zip              Keevo.app（含 native host 与 keevo 命令行工具）
#   Keevo-<版本>-chrome-extension.zip   解压后在 chrome://extensions 中"加载已解压的扩展程序"
#   SHA256SUMS
#
# 发布包必须来自已提交的源码：工作区有改动时拒绝。校验和只用来核对与可信的摘要是否一致，
# 不证明来源（ADR-0003 第 6 条）。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)"
OUT="$ROOT/target/release-artifacts"

if [[ -n "$(git -C "$ROOT" status --porcelain)" ]]; then
  echo "工作区有未提交的改动：发布包必须来自已提交的源码" >&2
  exit 1
fi
COMMIT="$(git -C "$ROOT" rev-parse HEAD)"

# 1. 应用：组装、签名，并实测 Secure Enclave、DYLD 注入与 Library Validation
"$ROOT/scripts/package-macos.sh" --verify

# 2. 扩展
"$ROOT/scripts/build-extension.sh" >/dev/null

# 3. 打包
rm -rf "$OUT"
mkdir -p "$OUT/stage"
APP_ZIP="Keevo-$VERSION-macos.zip"
EXT_ZIP="Keevo-$VERSION-chrome-extension.zip"
# ditto 保留代码签名所需的扩展属性与符号链接
ditto -c -k --sequesterRsrc --keepParent "$ROOT/target/macos/Keevo.app" "$OUT/$APP_ZIP"
cp -R "$ROOT/apps/browser-extension/dist" "$OUT/stage/keevo-chrome-extension"
(cd "$OUT/stage" && zip -qrX "../$EXT_ZIP" keevo-chrome-extension)
rm -rf "$OUT/stage"

# 4. 核对：解压后的应用签名完整，扩展清单的版本与工作区一致
CHECK="$(mktemp -d)"
trap 'rm -rf "$CHECK"' EXIT
ditto -x -k "$OUT/$APP_ZIP" "$CHECK"
codesign --verify --strict --deep "$CHECK/Keevo.app"
unzip -q "$OUT/$EXT_ZIP" -d "$CHECK"
node -e '
  const m = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
  const want = process.argv[2];
  if ((m.version_name ?? m.version) !== want) { console.error(`扩展版本 ${m.version_name ?? m.version} 与 ${want} 不一致`); process.exit(1); }
' "$CHECK/keevo-chrome-extension/manifest.json" "$VERSION"

(cd "$OUT" && shasum -a 256 "$APP_ZIP" "$EXT_ZIP" > SHA256SUMS)
echo
echo "发布包（${VERSION}，提交 ${COMMIT:0:12}）："
(cd "$OUT" && ls -l "$APP_ZIP" "$EXT_ZIP" | awk '{print "  " $5 "\t" $9}' && sed 's/^/  /' SHA256SUMS)
