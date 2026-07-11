#!/usr/bin/env python3
"""
CTX-Audit 真实项目基线评估脚本

不依赖 ground truth，而是关注：
- 引擎检出了多少 finding
- 有多少 finding 带上了污点链 / 调用图 / source-sink 证据
- Agent  noop 模式下对证据的判定分布
- 按 CWE 的覆盖情况

用法：
    python benchmarks/evaluate_real_project.py \
        --findings target/benchmarks/webgoat_findings.json \
        --audit-log target/benchmarks/webgoat/.ctx-audit/audit_log.json \
        --output target/benchmarks/webgoat_report.md \
        --details target/benchmarks/webgoat_details.json
"""

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional


def normalize_cwe(vuln_type: Optional[str]) -> Optional[str]:
    if not vuln_type:
        return None
    s = vuln_type.strip().lower()
    m = re.search(r"cwe[- ]?(\d+)", s)
    if m:
        return f"CWE-{m.group(1)}"
    aliases = {
        "sql injection": "CWE-89",
        "command injection": "CWE-78",
        "code injection": "CWE-94",
        "path traversal": "CWE-22",
        "directory traversal": "CWE-22",
        "cross-site scripting": "CWE-79",
        "xss": "CWE-79",
        "ssrf": "CWE-918",
        "server-side request forgery": "CWE-918",
        "ldap injection": "CWE-90",
        "xxe": "CWE-611",
        "xml external entity": "CWE-611",
        "insecure deserialization": "CWE-502",
        "unsafe deserialization": "CWE-502",
        "header injection": "CWE-113",
        "log injection": "CWE-117",
        "open redirect": "CWE-601",
        "cache poisoning": "CWE-444",
        "buffer overflow": "CWE-121",
        "format string": "CWE-134",
        "weak encryption": "CWE-327",
        "weak hash": "CWE-328",
        "insecure random": "CWE-330",
        "trust boundary": "CWE-501",
        "secure cookie": "CWE-614",
        "xpath injection": "CWE-643",
    }
    for k, v in aliases.items():
        if k in s:
            return v
    return s[:40]


def load_json(path: Optional[str]) -> Any:
    if not path or not Path(path).exists():
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_findings(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("findings", []) or []
    return []


def has_source_sink_path(finding: Dict[str, Any]) -> bool:
    refs = finding.get("evidence_refs") or {}
    return bool(refs.get("source_sink_path"))


def has_call_path(finding: Dict[str, Any]) -> bool:
    refs = finding.get("evidence_refs") or {}
    return bool(refs.get("graph_snapshot") or refs.get("source_sink_path"))


def has_taint_steps(finding: Dict[str, Any]) -> bool:
    refs = finding.get("evidence_refs") or {}
    if not isinstance(refs, dict):
        return False
    if refs.get("taint_steps"):
        return True
    ss = refs.get("source_sink_path")
    if isinstance(ss, dict) and ss.get("path_steps"):
        return True
    return False


def has_code_context(finding: Dict[str, Any]) -> bool:
    return bool(finding.get("code_snippet") or finding.get("sink_snippet"))


def analyze_findings(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(findings)
    by_cwe = defaultdict(int)
    by_cwe_with_source_sink = defaultdict(int)
    by_cwe_with_taint_steps = defaultdict(int)
    by_severity = defaultdict(int)
    with_code_context = 0
    with_source_sink = 0
    with_call_path = 0
    with_taint_steps = 0
    path_lengths = []
    files_by_count = defaultdict(int)

    for f in findings:
        cwe = normalize_cwe(f.get("vuln_type"))
        cwe_key = cwe or "unknown"
        by_cwe[cwe_key] += 1
        by_severity[f.get("severity", "unknown").lower()] += 1
        files_by_count[f.get("file_path", "unknown")] += 1

        has_ss = has_source_sink_path(f)
        has_ts = has_taint_steps(f)
        if has_ss:
            with_source_sink += 1
            by_cwe_with_source_sink[cwe_key] += 1
            refs = f.get("evidence_refs") or {}
            ss = refs.get("source_sink_path")
            if isinstance(ss, dict):
                path_steps = ss.get("path_steps") or []
                if path_steps:
                    path_lengths.append(len(path_steps))
        if has_call_path(f):
            with_call_path += 1
        if has_ts:
            with_taint_steps += 1
            by_cwe_with_taint_steps[cwe_key] += 1
        if has_code_context(f):
            with_code_context += 1

    avg_path_length = sum(path_lengths) / len(path_lengths) if path_lengths else 0.0
    max_path_length = max(path_lengths) if path_lengths else 0

    return {
        "total": total,
        "by_cwe": dict(sorted(by_cwe.items(), key=lambda x: -x[1])),
        "by_cwe_with_source_sink": dict(sorted(by_cwe_with_source_sink.items(), key=lambda x: -x[1])),
        "by_cwe_with_taint_steps": dict(sorted(by_cwe_with_taint_steps.items(), key=lambda x: -x[1])),
        "by_severity": dict(sorted(by_severity.items(), key=lambda x: -x[1])),
        "with_code_context": with_code_context,
        "with_source_sink_path": with_source_sink,
        "with_call_path": with_call_path,
        "with_taint_steps": with_taint_steps,
        "avg_path_length": avg_path_length,
        "max_path_length": max_path_length,
        "top_files": dict(sorted(files_by_count.items(), key=lambda x: -x[1])[:10]),
    }


def analyze_audit_log(audit_log: Optional[List[Dict[str, Any]]]) -> Dict[str, Any]:
    if not audit_log:
        return {
            "total_investigated": 0,
            "by_verdict": {},
            "by_cwe_verdict": {},
            "avg_investigation_steps": 0.0,
            "max_investigation_steps": 0,
            "with_investigation_steps": 0,
            "with_specialist_result": 0,
            "with_taint_walk_sanitizer_check": 0,
        }

    by_verdict = defaultdict(int)
    by_cwe = defaultdict(lambda: defaultdict(int))
    step_counts = []
    specialist_hits = 0
    taint_walk_hits = 0
    investigation_hits = 0

    for entry in audit_log:
        verdict = entry.get("verdict", "unknown")
        by_verdict[verdict] += 1
        cwe = normalize_cwe(entry.get("vulnerability_type"))
        by_cwe[cwe or "unknown"][verdict] += 1

        steps = entry.get("investigation_steps") or []
        step_counts.append(len(steps))
        if steps:
            investigation_hits += 1
            if any(s.get("tool_name") == "check_sanitizer" for s in steps):
                taint_walk_hits += 1

        if entry.get("specialist_result"):
            specialist_hits += 1

    return {
        "total_investigated": len(audit_log),
        "by_verdict": dict(sorted(by_verdict.items(), key=lambda x: -x[1])),
        "by_cwe_verdict": {k: dict(v) for k, v in sorted(by_cwe.items(), key=lambda x: -sum(x[1].values()))},
        "avg_investigation_steps": sum(step_counts) / len(step_counts) if step_counts else 0,
        "max_investigation_steps": max(step_counts) if step_counts else 0,
        "with_investigation_steps": investigation_hits,
        "with_specialist_result": specialist_hits,
        "with_taint_walk_sanitizer_check": taint_walk_hits,
    }


def render_markdown(findings_stats: Dict[str, Any], audit_stats: Dict[str, Any]) -> str:
    lines = [
        "# CTX-Audit 真实项目基线报告",
        "",
        "## 扫描结果（引擎输出）",
        "",
        f"- 总 findings: **{findings_stats['total']}**",
        f"- 带代码上下文: {findings_stats['with_code_context']} ({pct(findings_stats['with_code_context'], findings_stats['total'])})",
        f"- 带 source→sink 路径: {findings_stats['with_source_sink_path']} ({pct(findings_stats['with_source_sink_path'], findings_stats['total'])})",
        f"- 带调用图路径: {findings_stats['with_call_path']} ({pct(findings_stats['with_call_path'], findings_stats['total'])})",
        f"- 带污点步骤: {findings_stats['with_taint_steps']} ({pct(findings_stats['with_taint_steps'], findings_stats['total'])})",
        f"- 平均污点路径长度: {findings_stats['avg_path_length']:.2f}",
        f"- 最大污点路径长度: {findings_stats['max_path_length']}",
        "",
        "### 按 CWE 分布",
        "",
        "| CWE | Count | 带 source→sink | 带污点步骤 |",
        "|-----|-------|----------------|------------|",
    ]
    for cwe, count in findings_stats["by_cwe"].items():
        ss = findings_stats["by_cwe_with_source_sink"].get(cwe, 0)
        ts = findings_stats["by_cwe_with_taint_steps"].get(cwe, 0)
        lines.append(f"| {cwe} | {count} | {ss} | {ts} |")

    lines.extend([
        "",
        "### Top 10 文件（按 finding 数）",
        "",
        "| 文件 | Count |",
        "|------|-------|",
    ])
    for file_path, count in findings_stats["top_files"].items():
        lines.append(f"| {file_path} | {count} |")

    lines.extend([
        "",
        "## Agent 审计结果（noop 模式）",
        "",
        f"- 已调查 findings: **{audit_stats['total_investigated']}**",
        f"- 平均调查步数: {audit_stats['avg_investigation_steps']:.2f}",
        f"- 最大调查步数: {audit_stats['max_investigation_steps']}",
        f"- 有 Specialist 参与: {audit_stats['with_specialist_result']}",
        f"- 有 TaintWalk sanitizer 检查: {audit_stats['with_taint_walk_sanitizer_check']}",
        "",
        "### 判定分布",
        "",
        "| Verdict | Count |",
        "|---------|-------|",
    ])
    for verdict, count in audit_stats.get("by_verdict", {}).items():
        lines.append(f"| {verdict} | {count} |")

    lines.append("")
    return "\n".join(lines)


def pct(part: int, total: int) -> str:
    if total == 0:
        return "0.0%"
    return f"{part / total * 100:.1f}%"


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    parser = argparse.ArgumentParser(description="评估 CTX-Audit 在真实项目上的基线表现")
    parser.add_argument("--findings", required=True, help="scan 输出的 findings JSON")
    parser.add_argument("--audit-log", help="项目 .ctx-audit/audit_log.json")
    parser.add_argument("--output", required=True, help="Markdown 报告输出路径")
    parser.add_argument("--details", help="JSON 明细输出路径")
    args = parser.parse_args()

    findings_data = load_json(args.findings)
    findings = get_findings(findings_data)

    audit_log = load_json(args.audit_log) or []

    findings_stats = analyze_findings(findings)
    audit_stats = analyze_audit_log(audit_log)

    report = render_markdown(findings_stats, audit_stats)
    Path(args.output).write_text(report, encoding="utf-8")
    print(f"Report written: {args.output}")

    if args.details:
        details = {
            "findings": findings_stats,
            "audit": audit_stats,
        }
        Path(args.details).write_text(json.dumps(details, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Details written: {args.details}")


if __name__ == "__main__":
    main()
