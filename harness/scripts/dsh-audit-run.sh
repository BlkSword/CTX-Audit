#!/usr/bin/env bash
# CTX-Audit Public Harness: one-shot scout + sniper round.
# Usage: dsh-audit-run.sh <target> [round-id]
# Env:
#   AUDIT_LOG_DIR        output dir (default ./audit-logs)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:?usage: dsh-audit-run.sh <target> [round-id]}"
ROUND="${2:-R$(date +%Y%m%d-%H%M)}"
OUT_DIR="${AUDIT_LOG_DIR:-./audit-logs}"
mkdir -p "$OUT_DIR"

SCOUT_OUT="$OUT_DIR/scout-${ROUND}.out"
FINAL_OUT="$OUT_DIR/sniper-${ROUND}.out"

echo "==> [scout] $TARGET" >&2
"$SCRIPT_DIR/../bin/run-scout.sh" "$TARGET" > "$SCOUT_OUT" 2>&1

echo "==> [sniper] $TARGET" >&2
"$SCRIPT_DIR/../bin/run-sniper.sh" "$TARGET" "$SCOUT_OUT" > "$FINAL_OUT" 2>&1

echo "SCOUT=$SCOUT_OUT"
echo "FINAL=$FINAL_OUT"