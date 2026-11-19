#!/usr/bin/env bash
# 核实一个浏览器的代码签名，供维护 native host 的浏览器白名单（crates/keevo-macos 的 KNOWN_BROWSERS，
# 流程见 docs/browser-allowlist.md）。
#
# 用法：scripts/verify-browser.sh "/Applications/Google Chrome.app"
#
# 输出签名标识、Team ID 与证书链，并用与 native host 相同的签名要求做一次校验；通过时给出可以加入白名单的条目。
# 只读，不改动任何文件。
set -euo pipefail

APP="${1:?用法：scripts/verify-browser.sh <浏览器.app>}"
[[ -d "$APP" ]] || { echo "✗ 找不到 $APP" >&2; exit 1; }

INFO="$(codesign -dvvv "$APP" 2>&1)" || { echo "✗ 读取签名失败：$INFO" >&2; exit 1; }
IDENTIFIER="$(sed -n 's/^Identifier=//p' <<<"$INFO")"
TEAM="$(sed -n 's/^TeamIdentifier=//p' <<<"$INFO")"
BUNDLE="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$APP/Contents/Info.plist")"
VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Contents/Info.plist" 2>/dev/null || echo '?')"

echo "浏览器：${APP}（版本 ${VERSION}）"
echo "  Bundle ID：$BUNDLE"
echo "  签名标识：$IDENTIFIER"
echo "  Team ID：$TEAM"
grep '^Authority=' <<<"$INFO" | sed 's/^Authority=/  证书链：/'

[[ "$TEAM" =~ ^[A-Z0-9]{10}$ ]] || { echo "✗ 没有 Team ID：临时签名或 Apple 平台二进制，不能加入白名单" >&2; exit 1; }
[[ "$IDENTIFIER" == "$BUNDLE" ]] || echo "  ! 签名标识与 Bundle ID 不同，白名单按签名标识（native host 检查的是父进程的代码签名）"

# 完整性：代码与资源未被改动（必须通过）
codesign --verify --deep "$APP" 2>/dev/null || { echo "✗ codesign --verify --deep 未通过：应用包被改动过" >&2; exit 1; }
echo "  ✓ 代码与资源完整（codesign --verify --deep）"
# 严格模式还拒绝附加属性（如更新程序留下的 com.apple.FinderInfo）。这类属性不改变代码，只提示
if STRICT="$(codesign --verify --deep --strict "$APP" 2>&1)"; then
  echo "  ✓ 严格校验通过（--strict）"
else
  echo "  ! 严格校验未通过（代码完整，只是有附加属性）：$(tail -1 <<<"$STRICT")"
fi

# 与 KNOWN_BROWSERS 相同形式的签名要求
REQ="anchor apple generic and identifier \"$IDENTIFIER\" and certificate leaf[subject.OU] = \"$TEAM\""
codesign --verify -R="$REQ" "$APP" 2>/dev/null || { echo "✗ 不满足签名要求：$REQ" >&2; exit 1; }
echo "  ✓ 满足签名要求：$REQ"

# 公证（Gatekeeper 评估）：从官方渠道下载的正式版本应当通过
if spctl --assess --type execute "$APP" 2>/dev/null; then
  echo "  ✓ Gatekeeper 评估通过（已公证的 Developer ID 应用）"
else
  echo "  ! Gatekeeper 评估未通过：确认安装包来自官方渠道后再继续"
fi

cat <<EOF

核对：把上面的 Team ID 与至少一个独立来源比对（浏览器官网的说明、Apple 公证信息或其他已知安装包）。
一致后，在 crates/keevo-macos/src/lib.rs 的 KNOWN_BROWSERS 中加入：

    ("$IDENTIFIER", r#"$REQ"#),

并在其上方的表格中加一行：

    /// | <浏览器名> | \`$IDENTIFIER\` | \`$TEAM\` | $(date +%Y-%m-%d) |
EOF
