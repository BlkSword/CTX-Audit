#!/usr/bin/env bash
# CTX-Audit Public Harness: run one audit round via DSH.
# Usage: run-round.sh <target> [extra...]
# Env:
#   DSH_PROFILE          audit profile (default audit)
#   CTX_AUDIT_MCP_CMD    ctx-audit binary path
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:?usage: run-round.sh <target> [extra...]}"
shift || true
EXTRA="${*:-}"

TASK="对目标项目执行一轮安全审计：${TARGET}。"
if [[ -n "$EXTRA" ]]; then
  TASK="$TASK 额外要求：$EXTRA"
fi
TASK="$TASK 开工前加载 ctx-audit-auditor skill，最终输出结构化 JSON。"

exec "$SCRIPT_DIR/ctx-audit-dsh" "$TASK"