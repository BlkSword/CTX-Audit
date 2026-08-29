#!/usr/bin/env bash
# CTX-Audit Public Harness: scout pass (breadth) via DSH.
# Usage: run-scout.sh <target> [extra...]
# Env:
#   DSH_SCOUT_PROMPT_FILE   additional scout instruction file (optional)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:?usage: run-scout.sh <target> [extra...]}"
shift || true
EXTRA="${*:-}"

TASK="你是 CTX-Audit 侦察兵。目标项目：${TARGET}。执行广度初筛，不要做最终 TP/FP 判定。"
TASK="$TASK 产出三分类候选清单：明确FP / 候选 / 明确TP，宁可错杀不放过。"
if [[ -n "${EXTRA:-}" ]]; then TASK="$TASK 额外要求：$EXTRA"; fi
if [[ -n "${DSH_SCOUT_PROMPT_FILE:-}" && -f "$DSH_SCOUT_PROMPT_FILE" ]]; then
  TASK="$TASK

=== 完整侦察兵指令 ===
$(cat "$DSH_SCOUT_PROMPT_FILE")"
fi
TASK="$TASK

开工前加载 ctx-audit-auditor skill。输出 JSON。"

exec "$SCRIPT_DIR/ctx-audit-dsh" "$TASK"