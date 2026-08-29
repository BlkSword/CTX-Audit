#!/usr/bin/env bash
# CTX-Audit Public Harness: sniper pass (deep review) via DSH.
# Usage: run-sniper.sh <target> <candidates-json> [extra...]
# Env:
#   DSH_SNIPER_PROMPT_FILE   additional sniper instruction file (optional)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:?usage: run-sniper.sh <target> <candidates-json> [extra...]}"
CAND_FILE="${2:?candidates JSON file required}"
shift 2 || true
EXTRA="${*:-}"

TASK="你是 CTX-Audit 狙击手。目标项目：${TARGET}。下面只对候选清单做深审：$(cat "$CAND_FILE")"
TASK="$TASK 对每个候选做链式深审 + 判定，疑似 TP 必须实机验证或明确标注未验证。"
TASK="$TASK 输出允许文本说明，但必须包含 fenced \`\`\`json\`\`\` 块，块内含 tp_candidates/fp_families/hardening/human_gate。"
if [[ -n "${EXTRA:-}" ]]; then TASK="$TASK 额外要求：$EXTRA"; fi
if [[ -n "${DSH_SNIPER_PROMPT_FILE:-}" && -f "$DSH_SNIPER_PROMPT_FILE" ]]; then
  TASK="$TASK

=== 完整狙击手指令 ===
$(cat "$DSH_SNIPER_PROMPT_FILE")"
fi
TASK="$TASK

开工前加载 ctx-audit-auditor skill。"

exec "$SCRIPT_DIR/ctx-audit-dsh" "$TASK"