#!/usr/bin/env python3
"""Evaluate evidence completeness of a CTX-Audit JSON scan result.

Usage:
    python scripts/evidence_completeness.py <scan-output.json>
"""
import json
import sys
from pathlib import Path

FIELDS = [
    "evidence_refs",
    "source_snippet",
    "sink_snippet",
    "barriers",
    "file_role",
    "enclosing_function",
    "enclosing_function_line",
    "reasoning_hint",
]


def load_findings(path: Path):
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        # Support both {"findings": [...]} and {"total": N, "findings": [...]}
        findings = data.get("findings")
        if findings is None:
            findings = data.get("results", [])
        return data, findings
    return None, data


def main():
    if len(sys.argv) != 2:
        print(__doc__.strip())
        return 2
    path = Path(sys.argv[1])
    meta, findings = load_findings(path)
    total = len(findings)
    print(f"total_findings: {total}")
    if total == 0:
        print("no findings to evaluate")
        return 0
    for field in FIELDS:
        count = sum(
            1
            for f in findings
            if f.get(field) not in (None, [], "")
        )
        pct = count * 100.0 / total
        print(f"{field}: {count}/{total} ({pct:.1f}%)")
    return 0


if __name__ == "__main__":
    sys.exit(main())