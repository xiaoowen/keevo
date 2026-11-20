#!/usr/bin/env bash
# 长时间模糊测试（docs/roadmap.md §8 第 1 项：所有解析器连续 24 小时无崩溃）。
#
# 用法：scripts/fuzz-soak.sh [总时长（秒），默认 86400] [并行数，默认 CPU 核数 − 2]
#
# - 全部目标分批并行，每批同时运行"并行数"个目标；每个目标运行 总时长 ÷ 批数 秒，合计的墙钟时间约为总时长。
#   10 核的机器默认并行 8 个：15 个目标分两批，每个目标运行 12 小时（串行时只有 96 分钟）。
# - 运行期间用 caffeinate 防止系统休眠（合上笔记本的盖子仍会休眠，请接通电源并保持打开）。
# - 结果写在 fuzz/soak/<开始时间>/：每个目标的日志、崩溃样本（<目标>/crash-…、timeout-…、oom-…）与汇总
#   summary.txt。发现崩溃时其他目标继续运行，最后列出全部崩溃并以非零状态退出。
# - 语料库沿用 fuzz/corpus/<目标>/，新发现的输入会加入其中，下次运行接着用；fuzz/seeds/<目标>/ 中入库的种子
#   （合法的密钥引用、SSH agent 消息、导出文件等）一并读入。
#
# 需要 nightly 与 cargo-fuzz（cargo +nightly install --locked cargo-fuzz）。macOS 与 Linux 都可以运行，例如放在
# 打包机上：检出同一个提交即可，本机积累的语料（fuzz/corpus/，未入库）可以一并拷过去，从更好的起点开始。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOTAL="${1:-86400}"
JOBS="${2:-$(($(getconf _NPROCESSORS_ONLN) - 2))}"
[ "$JOBS" -ge 1 ] || JOBS=1

# 防止休眠：整个脚本在 caffeinate 下重新运行一次
if [ -z "${KEEVO_SOAK_AWAKE:-}" ] && command -v caffeinate >/dev/null 2>&1; then
  export KEEVO_SOAK_AWAKE=1
  exec caffeinate -ims "$0" "$@"
fi

cd "$ROOT/fuzz"
echo "== 编译全部目标（release + ASan）"
cargo +nightly fuzz build >/dev/null 2>&1 || { cargo +nightly fuzz build; exit 1; }
HOST="$(rustc +nightly -vV | sed -n 's/^host: //p')"
BIN="$ROOT/fuzz/target/$HOST/release"
TARGETS=()
while IFS= read -r t; do TARGETS+=("$t"); done < <(cargo +nightly fuzz list)
COUNT=${#TARGETS[@]}
WAVES=$(((COUNT + JOBS - 1) / JOBS))
EACH=$((TOTAL / WAVES))
RUN="$ROOT/fuzz/soak/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RUN"

echo "== ${COUNT} 个目标，每批 ${JOBS} 个、共 ${WAVES} 批，每个目标 ${EACH} 秒；预计 $((EACH * WAVES / 3600)) 小时 $((EACH * WAVES % 3600 / 60)) 分钟结束"
echo "   结果：${RUN}"
{
  echo "开始：$(date '+%Y-%m-%d %H:%M:%S')"
  echo "提交：$(git -C "$ROOT" rev-parse --short HEAD)$(git -C "$ROOT" diff --quiet || echo '（工作区有改动）')"
  echo "参数：总时长 ${TOTAL} 秒，并行 ${JOBS}，每个目标 ${EACH} 秒"
} >"$RUN/summary.txt"

run_target() {
  local target="$1"
  mkdir -p "$RUN/$target" "$ROOT/fuzz/corpus/$target"
  local seeds=()
  [ -d "$ROOT/fuzz/seeds/$target" ] && seeds=("$ROOT/fuzz/seeds/$target")
  local status=0
  "$BIN/$target" \
    -max_total_time="$EACH" -timeout=60 -rss_limit_mb=2048 -print_final_stats=1 \
    -artifact_prefix="$RUN/$target/" "$ROOT/fuzz/corpus/$target" ${seeds[@]+"${seeds[@]}"} >"$RUN/$target.log" 2>&1 || status=$?
  echo "$status" >"$RUN/$target.status"
}

for ((wave = 0; wave < WAVES; wave++)); do
  echo "== 第 $((wave + 1)) 批（$(date '+%H:%M')）"
  for ((i = wave * JOBS; i < (wave + 1) * JOBS && i < COUNT; i++)); do
    echo "  · ${TARGETS[$i]}"
    run_target "${TARGETS[$i]}" &
  done
  wait
done

echo "结束：$(date '+%Y-%m-%d %H:%M:%S')" >>"$RUN/summary.txt"
echo >>"$RUN/summary.txt"
failed=0
for target in "${TARGETS[@]}"; do
  status="$(cat "$RUN/$target.status" 2>/dev/null || echo '?')"
  runs="$(sed -n 's/^stat::number_of_executed_units: *//p' "$RUN/$target.log" | tail -1)"
  cov="$(grep -Eo 'cov: [0-9]+ ft: [0-9]+ corp: [0-9]+' "$RUN/$target.log" | tail -1)"
  samples="$(find "$RUN/$target" -type f | wc -l | tr -d ' ')"
  if [ "$status" = "0" ] && [ "$samples" = "0" ]; then
    line="✓ ${target}：执行 ${runs:-?} 次，${cov:-?}"
  else
    failed=$((failed + 1))
    line="✗ ${target}：退出状态 ${status}，样本 ${samples} 个（${RUN}/${target}/），日志 ${RUN}/${target}.log"
  fi
  echo "$line" | tee -a "$RUN/summary.txt"
done

if [ "$failed" -gt 0 ]; then
  echo "✗ ${failed} 个目标发现问题；先修复再重新运行（docs/roadmap.md §8）" | tee -a "$RUN/summary.txt" >&2
  exit 1
fi
echo "全部 ${COUNT} 个目标无崩溃" | tee -a "$RUN/summary.txt"
