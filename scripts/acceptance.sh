#!/usr/bin/env bash
# M1 验收中能自动化的检查（docs/roadmap.md §3.8）：
#   性能预算（1 万条目）、kill -9、秘密泄露检测、导入字段零丢失、全部模糊测试目标、扩展的真实浏览器测试。
# 可用性测试、真实网站登录页快照与内部安全评审需要人工进行，不在这里。
#
# 用法：scripts/acceptance.sh [每个模糊测试目标的秒数，默认 60]
#   正式的 24 小时模糊测试改用 scripts/fuzz-soak.sh（分批并行，每个目标运行更久）。
# 每一步都有时间上限：卡住时报告超时并失败，而不是一直等下去。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FUZZ_SECONDS="${1:-60}"
cd "$ROOT"

pass() { echo "✓ $*"; }
fail() { echo "✗ $*" >&2; exit 1; }
# limit <秒> <命令…>：超时由 SIGALRM 结束（macOS 没有 timeout 命令）
limit() {
  local seconds="$1"
  shift
  perl -e 'alarm shift; exec @ARGV' "$seconds" "$@"
}

echo "== 性能预算（docs/product.md §6.1，release 构建）"
limit 900 cargo test -p keevo-ffi --release --locked -- --ignored performance_budget --nocapture 2>&1 \
  | grep -E "列表可用|搜索 |安全检查|test result" || fail "性能预算"
pass "列表可用 < 300 ms，每次按键的搜索 < 16 ms"

echo "== kill -9（反复强行结束写入进程，数据零损坏）"
limit 900 cargo test -p keevo-core --release --locked --test acceptance -- --ignored kill_nine_never_corrupts --nocapture 2>&1 \
  | grep -E "第 .* 轮|test result" | tail -3 || fail "kill -9"
pass "kill -9：每轮数据库完整，已确认的写入都在"

echo "== 秘密泄露检测与导入字段零丢失"
limit 900 cargo test -p keevo-core --release --locked --test acceptance no_plaintext_secrets_on_disk 2>&1 | grep "test result: ok" >/dev/null \
  || fail "秘密泄露检测"
limit 900 cargo test -p keevo-core --release --locked --lib imports_lose_no_fields 2>&1 | grep "test result: ok" >/dev/null \
  || fail "导入字段零丢失"
pass "磁盘上没有明文秘密；Bitwarden 与 1Password 样例的字段全部导入"

echo "== 模糊测试（每个目标 ${FUZZ_SECONDS} 秒，需要 nightly 与 cargo-fuzz）"
if cargo +nightly fuzz --version >/dev/null 2>&1; then
  (
    cd fuzz
    for target in $(cargo +nightly fuzz list); do
      seeds=()
      if [ -d "seeds/$target" ]; then
        mkdir -p "corpus/$target"
        seeds=("corpus/$target" "seeds/$target")
      fi
      limit $((FUZZ_SECONDS + 600)) cargo +nightly fuzz run "$target" ${seeds[@]+"${seeds[@]}"} -- -max_total_time="$FUZZ_SECONDS" >"/tmp/keevo-fuzz-$target.log" 2>&1 \
        || { tail -30 "/tmp/keevo-fuzz-$target.log" >&2; fail "模糊测试 $target"; }
      echo "  · ${target}：$(grep -E '^Done' "/tmp/keevo-fuzz-$target.log" | tail -1)"
    done
  )
  pass "全部模糊测试目标无崩溃"
else
  echo "  ! 没有 nightly 或 cargo-fuzz，跳过（安装：在仓库根目录 cargo install --locked cargo-fuzz@0.13.1，并 rustup toolchain install nightly）"
fi

echo "== 扩展：端到端、真实浏览器与登录页语料"
scripts/build-extension.sh >/dev/null
cargo build -p keevo-native-host -p keevo-service --locked >/dev/null 2>&1
for t in e2e browser corpus; do
  limit 900 node "apps/browser-extension/test/$t.mjs" >"/tmp/keevo-ext-$t.log" 2>&1 \
    || { tail -30 "/tmp/keevo-ext-$t.log" >&2; fail "扩展测试 $t"; }
  echo "  · ${t}：$(tail -1 "/tmp/keevo-ext-$t.log")"
done
pass "扩展测试全部通过"

echo
echo "自动化验收全部通过。人工部分见 docs/roadmap.md §3.8：可用性测试、真实网站登录页快照、内部安全评审。"
