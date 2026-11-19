#!/usr/bin/env bash
# 组装并签名 Keevo.app（ADR-0003）：临时签名 + Hardened Runtime，不带任何 entitlement，
# 保留默认的 Library Validation；Rust 核心静态链接进主程序。
#
# 用法：
#   scripts/package-macos.sh             构建、组装、签名，并做静态检查
#   scripts/package-macos.sh --verify    另外实测进程加固：Secure Enclave、DYLD 注入、Library Validation
#   scripts/package-macos.sh --launch    另外启动一次应用，确认能正常运行（会短暂打开窗口）
#
# 产物：target/macos/Keevo.app
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP_SRC="$ROOT/apps/macos"
OUT="$ROOT/target/macos"
APP="$OUT/Keevo.app"
BUNDLE_ID="io.github.xiaoowen.keevo"
VERIFY=0
LAUNCH=0
for arg in "$@"; do
  case "$arg" in
    --verify) VERIFY=1 ;;
    --launch) VERIFY=1; LAUNCH=1 ;;
    *) echo "未知参数：$arg" >&2; exit 2 ;;
  esac
done

fail() { echo "✗ $*" >&2; exit 1; }
pass() { echo "  ✓ $*"; }

# 1. 先构建并签名 native host 与命令行工具，取得它们的 cdhash（spec/ipc.md §3.1、spec/cli.md §2）
HOST_STAGE="$OUT/stage"
rm -rf "$HOST_STAGE"
mkdir -p "$HOST_STAGE"
(cd "$ROOT" && cargo build -p keevo-native-host -p keevo-cli --release --locked)
cp "$ROOT/target/release/keevo-native-host" "$HOST_STAGE/keevo-native-host"
codesign --force --sign - --options runtime --identifier "$BUNDLE_ID.native-host" --timestamp=none "$HOST_STAGE/keevo-native-host"
HOST_CDHASH="$(codesign -dvvv "$HOST_STAGE/keevo-native-host" 2>&1 | sed -n 's/^CDHash=//p')"
[[ ${#HOST_CDHASH} == 40 ]] || fail "读不到 native host 的 cdhash"
cp "$ROOT/target/release/keevo" "$HOST_STAGE/keevo"
codesign --force --sign - --options runtime --identifier "$BUNDLE_ID.cli" --timestamp=none "$HOST_STAGE/keevo"
CLI_CDHASH="$(codesign -dvvv "$HOST_STAGE/keevo" 2>&1 | sed -n 's/^CDHash=//p')"
[[ ${#CLI_CDHASH} == 40 ]] || fail "读不到命令行工具的 cdhash"

# 2. 把 cdhash 编译进主程序，再构建应用。运行时不从磁盘读取（§3.1，第二轮评审 G6）
KEEVO_HOST_CDHASHES="$HOST_CDHASH" KEEVO_CLI_CDHASHES="$CLI_CDHASH" "$ROOT/scripts/build-macos.sh" >/dev/null

# 版本：短版本取自 Cargo 工作区，构建号为提交数（可复现，不含时间戳）
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)"
BUILD="$(git -C "$ROOT" rev-list --count HEAD)"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$APP/Contents/Helpers"
cp "$APP_SRC/.build/release/Keevo" "$APP/Contents/MacOS/Keevo"
# 3. 放入已签名的 host（复制不改变签名），之后签名整个应用包，host 的签名作为嵌套代码被封存
cp "$HOST_STAGE/keevo-native-host" "$APP/Contents/Helpers/keevo-native-host"
cp "$HOST_STAGE/keevo" "$APP/Contents/Helpers/keevo"
# SwiftPM 会加上 @loader_path 与构建机上工具链的绝对路径作为 rpath。主程序不引用任何 @rpath 库，
# 这些 rpath 用不到，却给"在旁边放一个同名库"留了入口，也让产物带上构建机的路径。只保留系统的 /usr/lib/swift。
rpaths() { otool -l "$1" | awk '/cmd LC_RPATH/{getline; getline; print $2}'; }
while read -r rp; do
  [[ -n "$rp" && "$rp" != "/usr/lib/swift" ]] && install_name_tool -delete_rpath "$rp" "$APP/Contents/MacOS/Keevo"
done < <(rpaths "$APP/Contents/MacOS/Keevo")
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key><string>zh-Hans</string>
  <key>CFBundleDisplayName</key><string>Keevo</string>
  <key>CFBundleExecutable</key><string>Keevo</string>
  <key>CFBundleIdentifier</key><string>$BUNDLE_ID</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleName</key><string>Keevo</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$BUILD</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.productivity</string>
  <key>LSMinimumSystemVersion</key><string>15.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST
plutil -lint -s "$APP/Contents/Info.plist" || fail "Info.plist 格式错误"

# 临时签名（-s -）、Hardened Runtime（--options runtime）、不带 entitlement、不加时间戳
codesign --force --sign - --options runtime --identifier "$BUNDLE_ID" --timestamp=none "$APP"

echo "静态检查"
codesign --verify --strict --verbose=1 "$APP" 2>/dev/null || fail "签名校验失败"
pass "签名完整（codesign --verify --strict）"
INFO="$(codesign -dvvv "$APP" 2>&1)"
grep -q "flags=0x10002(adhoc,runtime)" <<<"$INFO" || fail "签名标志不是 adhoc + runtime：$(grep flags <<<"$INFO")"
pass "临时签名 + Hardened Runtime（flags=0x10002）"
grep -q "TeamIdentifier=not set" <<<"$INFO" || fail "签名带有 Team ID"
pass "不绑定任何团队（TeamIdentifier=not set）"
ENT="$(codesign -d --entitlements - --xml "$APP" 2>/dev/null || true)"
[[ -z "$ENT" ]] || fail "签名带有 entitlement：$ENT"
pass "没有任何 entitlement（不禁用 Library Validation，不允许 DYLD 环境变量）"
DEPS="$(otool -L "$APP/Contents/MacOS/Keevo" | tail -n +2 | awk '{print $1}')"
NON_SYSTEM="$(grep -vE '^(/usr/lib/|/System/Library/)' <<<"$DEPS" || true)"
[[ -z "$NON_SYSTEM" ]] || fail "依赖了系统以外的动态库：$NON_SYSTEM"
pass "只链接系统库，Rust 核心为静态链接（$(wc -l <<<"$DEPS" | tr -d ' ') 个系统库）"
grep -q '@rpath' <<<"$DEPS" && fail "主程序引用了 @rpath 库"
EXTRA_RPATH="$(rpaths "$APP/Contents/MacOS/Keevo" | grep -vx '/usr/lib/swift' || true)"
[[ -z "$EXTRA_RPATH" ]] || fail "主程序带有系统以外的 rpath：$EXTRA_RPATH"
pass "rpath 只有 /usr/lib/swift，不引用 @rpath 库"
CDHASH="$(sed -n 's/^CDHash=//p' <<<"$INFO")"
[[ -n "$CDHASH" ]] || fail "读不到 cdhash"
echo "  · cdhash：$CDHASH"
HOST_INFO="$(codesign -dvvv "$APP/Contents/Helpers/keevo-native-host" 2>&1)"
BUNDLED_HOST_CDHASH="$(sed -n 's/^CDHash=//p' <<<"$HOST_INFO")"
[[ "$BUNDLED_HOST_CDHASH" == "$HOST_CDHASH" ]] || fail "应用包内 host 的 cdhash 与编译进主程序的不一致"
grep -q "$HOST_CDHASH" "$APP/Contents/MacOS/Keevo" || fail "主程序中没有编译进 host 的 cdhash"
grep -q "flags=0x10002(adhoc,runtime)" <<<"$HOST_INFO" || fail "host 不是 adhoc + runtime 签名"
pass "native host 已签名并放入应用包，它的 cdhash 已编译进主程序（${HOST_CDHASH}）"
CLI_INFO="$(codesign -dvvv "$APP/Contents/Helpers/keevo" 2>&1)"
[[ "$(sed -n 's/^CDHash=//p' <<<"$CLI_INFO")" == "$CLI_CDHASH" ]] || fail "应用包内命令行工具的 cdhash 与编译进主程序的不一致"
grep -q "$CLI_CDHASH" "$APP/Contents/MacOS/Keevo" || fail "主程序中没有编译进命令行工具的 cdhash"
pass "命令行工具已签名并放入应用包，它的 cdhash 已编译进主程序（${CLI_CDHASH}）"

if [[ "$VERIFY" == 1 ]]; then
  echo "进程加固实测"
  WORK="$(mktemp -d)"
  trap 'rm -rf "$WORK"' EXIT
  SMOKE="$APP_SRC/.build/release/keevo-smoke"

  # 与应用相同的签名方式签一份冒烟测试，另签一份不带 Hardened Runtime 的作对照
  cp "$SMOKE" "$WORK/smoke-runtime"
  cp "$SMOKE" "$WORK/smoke-plain"
  codesign --force --sign - --options runtime --timestamp=none "$WORK/smoke-runtime"
  codesign --force --sign - --timestamp=none "$WORK/smoke-plain"

  # 1. Secure Enclave、Rust 核心在 Hardened Runtime 下正常工作
  "$WORK/smoke-runtime" >"$WORK/smoke.log" 2>&1 || { cat "$WORK/smoke.log"; fail "Hardened Runtime 下冒烟测试失败"; }
  grep -q "全部通过" "$WORK/smoke.log" || fail "冒烟测试没有通过"
  pass "Hardened Runtime 下冒烟测试通过（$(grep -o '本机密钥包裹（[^）]*）' "$WORK/smoke.log" | head -1)）"

  # 一个临时签名的动态库：加载时写下标记文件
  cat > "$WORK/inject.c" <<'C'
#include <stdio.h>
#include <stdlib.h>
__attribute__((constructor)) static void injected(void) {
  const char *marker = getenv("KEEVO_INJECT_MARKER");
  if (marker) { FILE *f = fopen(marker, "w"); if (f) { fputs("injected", f); fclose(f); } }
}
C
  clang -dynamiclib -o "$WORK/inject.dylib" "$WORK/inject.c"
  codesign --force --sign - --timestamp=none "$WORK/inject.dylib"

  # 2. DYLD_INSERT_LIBRARIES：对照组被注入，Hardened Runtime 下被忽略
  KEEVO_INJECT_MARKER="$WORK/plain.marker" DYLD_INSERT_LIBRARIES="$WORK/inject.dylib" \
    "$WORK/smoke-plain" --dlopen /usr/lib/libz.dylib >/dev/null 2>&1 || true
  [[ -f "$WORK/plain.marker" ]] || fail "对照组没有被注入，测试本身无效"
  KEEVO_INJECT_MARKER="$WORK/runtime.marker" DYLD_INSERT_LIBRARIES="$WORK/inject.dylib" \
    "$WORK/smoke-runtime" --dlopen /usr/lib/libz.dylib >/dev/null 2>&1 || true
  [[ ! -f "$WORK/runtime.marker" ]] || fail "Hardened Runtime 下 DYLD_INSERT_LIBRARIES 仍然生效"
  pass "DYLD_INSERT_LIBRARIES 被忽略（对照组被注入）"

  # 3. Library Validation：系统库可以加载，临时签名的库被拒绝；对照组可以加载
  "$WORK/smoke-runtime" --dlopen /usr/lib/libz.dylib >/dev/null || fail "Hardened Runtime 下无法加载系统库"
  "$WORK/smoke-plain" --dlopen "$WORK/inject.dylib" >/dev/null || fail "对照组无法加载临时签名的库，测试本身无效"
  set +e
  REFUSED="$("$WORK/smoke-runtime" --dlopen "$WORK/inject.dylib")"
  CODE=$?
  set -e
  [[ "$CODE" == 3 ]] || fail "Library Validation 没有拒绝临时签名的库：$REFUSED"
  REASON="$(grep -oE 'not valid for use in process: [^,]*' <<<"$REFUSED" | head -1 | sed 's/)$//')"
  pass "Library Validation 拒绝临时签名的库，放行系统库（${REASON:-$REFUSED}）"

  # 命令行工具与 SSH Agent（spec/cli.md、spec/ssh-agent.md）：服务由 keevo-smoke 提供（同一份 Rust 静态库），
  # HOME 指向临时目录，socket 随之放在那里
  echo "命令行工具与 SSH Agent"
  # socket 路径不能超过 104 字节：临时 HOME 放在短路径下
  DEV_HOME="$(mktemp -d /tmp/kv.XXXXXX)"
  mkfifo "$WORK/dev.in"
  HOME="$DEV_HOME" "$WORK/smoke-runtime" --developer-service <"$WORK/dev.in" >"$WORK/dev.log" 2>&1 &
  DEV_PID=$!
  exec 3>"$WORK/dev.in"
  for _ in $(seq 1 100); do grep -q '^READY' "$WORK/dev.log" && break; sleep 0.2; done
  grep -q '^READY' "$WORK/dev.log" || { cat "$WORK/dev.log"; fail "开发者服务没有启动"; }
  DEV_VAULT="$(sed -n 's/^VAULT //p' "$WORK/dev.log")"
  CLI="$APP/Contents/Helpers/keevo"
  HOME="$DEV_HOME" "$CLI" status | grep -q "已解锁" || fail "应用包内的 keevo 无法连接服务"
  VALUE="$(HOME="$DEV_HOME" "$CLI" read "keevo://${DEV_VAULT}/打包测试/密码")"
  [[ "$VALUE" == "packaged-cli-pass" ]] || fail "keevo read 的结果不对：$VALUE"
  pass "应用包内的 keevo 通过 cdhash 校验，经终端会话授权读取引用"
  cp "$CLI" "$WORK/keevo-resigned"
  codesign --force --sign - --options runtime --identifier "$BUNDLE_ID.other" --timestamp=none "$WORK/keevo-resigned"
  set +e
  HOME="$DEV_HOME" "$WORK/keevo-resigned" status >/dev/null 2>&1
  CODE=$?
  set -e
  [[ "$CODE" == 3 ]] || fail "重新签名的 keevo 没有被拒绝（退出码 $CODE）"
  pass "同一份代码、没有经过打包签名的 keevo 被服务拒绝（退出码 3）"
  AGENT_SOCK="$DEV_HOME/Library/Application Support/Keevo/ssh/agent.sock"
  SSH_AUTH_SOCK="$AGENT_SOCK" ssh-add -L >"$WORK/agent.pub" || fail "ssh-add -L 失败"
  grep -q "^ssh-ed25519 .* 打包测试密钥$" "$WORK/agent.pub" || fail "Agent 没有列出保险库中的密钥：$(cat "$WORK/agent.pub")"
  ln -s "$CLI" "$WORK/keevo-ssh-sign"
  printf 'signed by keevo\n' >"$WORK/msg.txt"
  HOME="$DEV_HOME" "$WORK/keevo-ssh-sign" -Y sign -n git -f "$WORK/agent.pub" "$WORK/msg.txt" >/dev/null 2>&1 \
    || fail "keevo-ssh-sign 签名失败"
  echo "me $(cat "$WORK/agent.pub")" >"$WORK/allowed_signers"
  ssh-keygen -Y verify -n git -I me -f "$WORK/allowed_signers" -s "$WORK/msg.txt.sig" <"$WORK/msg.txt" >/dev/null 2>&1 \
    || fail "ssh-keygen -Y verify 没有通过"
  pass "SSH Agent 列出保险库中的密钥；keevo-ssh-sign 经 Agent 签名，ssh-keygen -Y verify 通过"
  exec 3>&-
  wait "$DEV_PID" 2>/dev/null || true
  rm -rf "$DEV_HOME"

  # 真实 Chrome 启动应用包内的 host：父进程校验与 cdhash 校验（spec/ipc.md §3），反例为没有经过打包签名的 host
  echo "真实浏览器链路"
  CHROME_BIN="${KEEVO_CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
  if [[ ! -x "$CHROME_BIN" ]]; then
    echo "  · 跳过：没有找到 Chrome（可用 KEEVO_CHROME 指定）"
  elif ! command -v node >/dev/null; then
    echo "  · 跳过：没有 Node.js"
  elif [[ ! -f "$ROOT/apps/browser-extension/dist/manifest.json" ]]; then
    echo "  · 跳过：扩展还没有构建（先运行 scripts/build-extension.sh）"
  else
    node "$ROOT/apps/browser-extension/test/packaged.mjs" "$APP" "$APP_SRC/.build/release/keevo-smoke" >"$WORK/browser.log" 2>&1 \
      || { cat "$WORK/browser.log"; fail "真实浏览器链路测试失败"; }
    grep '✓' "$WORK/browser.log" | sed 's/^ *✓ /  ✓ /'
  fi
fi

if [[ "$LAUNCH" == 1 ]]; then
  echo "启动检查"
  "$APP/Contents/MacOS/Keevo" >/dev/null 2>&1 &
  PID=$!
  sleep 4
  kill -0 "$PID" 2>/dev/null || fail "应用启动后退出了"
  kill "$PID"
  wait "$PID" 2>/dev/null || true
  pass "应用正常启动并运行 4 秒"
fi

echo "完成：$APP"
