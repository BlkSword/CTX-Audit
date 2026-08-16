#!/usr/bin/env python3
"""Summarize CTX-Audit MCP tool-call metrics.

Reads `.ctx-audit/mcp_metrics.jsonl` (or `CTX_AUDIT_METRICS_PATH`) and prints:
- total calls / errors
- per-tool call counts, error counts, average/p95 duration
"""
import argparse
import json
import os
import statistics
import sys
from collections import defaultdict
from pathlib import Path

DEFAULT_PATH = Path(".ctx-audit") / "mcp_metrics.jsonl"


def p95(values):
    if not values:
        return 0.0
    sorted_values = sorted(values)
    idx = min(len(sorted_values) - 1, max(0, round(len(sorted_values) * 0.95) - 1))
    return sorted_values[idx]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "path",
        nargs="?",
        default=os.environ.get("CTX_AUDIT_METRICS_PATH", DEFAULT_PATH),
        help="Path to mcp_metrics.jsonl (default: .ctx-audit/mcp_metrics.jsonl)",
    )
    args = parser.parse_args()

    path = Path(args.path)
    if not path.exists():
        print(f"metrics file not found: {path}", file=sys.stderr)
        return 1

    calls = 0
    errors = 0
    by_tool = defaultdict(list)

    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            tool = record.get("tool", "<unknown>")
            duration = float(record.get("duration_ms", 0) or 0)
            is_error = bool(record.get("is_error", False))
            calls += 1
            if is_error:
                errors += 1
            by_tool[tool].append((duration, is_error))

    print(f"total_calls={calls}")
    print(f"error_calls={errors}")
    print(f"error_rate={errors / calls:.2%}" if calls else "error_rate=n/a")
    print()
    print("per_tool:")
    for tool in sorted(by_tool):
        durations = [d for d, _ in by_tool[tool]]
        tool_errors = sum(1 for _, e in by_tool[tool] if e)
        avg = statistics.mean(durations) if durations else 0.0
        print(
            f"  {tool:32s} calls={len(durations):5d} errors={tool_errors:4d} "
            f"avg_ms={avg:8.1f} p95_ms={p95(durations):8.1f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
