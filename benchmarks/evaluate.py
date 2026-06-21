#!/usr/bin/env python3
"""
CTX-Audit 基准测试结果评估脚本
支持 OWASP Benchmark Java 与 NIST Juliet C/C++ 真值文件
"""

import argparse
import csv
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# 归一化 CTX-Audit vuln_type → CWE 数字
VULN_TYPE_TO_CWE = {
    "sql injection": 89,
    "command injection": 78,
    "code injection": 94,
    "path traversal": 22,
    "directory traversal": 22,
    "cross-site scripting": 79,
    "xss": 79,
    "ssrf": 918,
    "server-side request forgery": 918,
    "ldap injection": 90,
    "xxe": 611,
    "xml external entity": 611,
    "insecure deserialization": 502,
    "unsafe deserialization": 502,
    "header injection": 113,
    "http response splitting": 113,
    "log injection": 117,
    "log forging": 117,
    "open redirect": 601,
    "unsafe redirect": 601,
    "cache poisoning": 444,
    "buffer overflow": 121,
    "format string": 134,
    "weak encryption": 327,
    "insecure random": 330,
    "hard-coded password": 798,
    "sensitive log data": 532,
    "debug info leak": 200,
    "information exposure": 200,
}

OWASP_CATEGORY_TO_CWE = {
    "cmdi": 78,
    "sqli": 89,
    "ldapi": 90,
    "header": 113,
    "securecookie": 614,
    "pathtraver": 22,
    "crypto": 327,
    "hash": 328,
    "weakrand": 330,
    "xss": 79,
    "trustbound": 501,
    "cmd": 78,
}


def normalize_cwe(vuln_type: Optional[str]) -> Optional[int]:
    if not vuln_type:
        return None
    s = vuln_type.strip().lower()
    # 直接 CWE-xxx
    m = re.search(r"cwe-?(\d+)", s)
    if m:
        return int(m.group(1))
    # 常见别名
    if s in VULN_TYPE_TO_CWE:
        return VULN_TYPE_TO_CWE[s]
    # 子串匹配
    for k, v in VULN_TYPE_TO_CWE.items():
        if k in s:
            return v
    return None


def load_owasp_ground_truth(csv_path: str) -> Dict[str, dict]:
    """返回 {test_name: {cwe, vulnerable}}"""
    gt = {}
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            if len(row) < 4:
                continue
            name, category, vuln, cwe = row[0], row[1], row[2], row[3]
            cwe_num = int(cwe) if cwe.isdigit() else OWASP_CATEGORY_TO_CWE.get(category.lower())
            gt[name] = {
                "cwe": cwe_num,
                "vulnerable": vuln.strip().lower() == "true",
                "category": category,
            }
    return gt


def load_juliet_ground_truth(manifest_path: str) -> Dict[str, List[dict]]:
    """返回 {basename: [{cwe, line}]}"""
    gt = defaultdict(list)
    tree = ET.parse(manifest_path)
    ns = {"": tree.getroot().tag.split("}")[0].strip("{")} if "}" in tree.getroot().tag else {}
    for testcase in tree.findall(".//testcase", ns):
        # 查找 flaw 标签
        flaws = testcase.findall(".//flaw", ns)
        files = testcase.findall(".//file", ns)
        for file_elem in files:
            path = file_elem.get("path") or ""
            basename = Path(path).name
            if not flaws:
                # 无 flaw 表示该文件为 good/non-vulnerable
                if not any(gt[basename]):
                    gt[basename] = []
            else:
                for flaw in flaws:
                    line = flaw.get("line")
                    name = flaw.get("name") or ""
                    cwe_match = re.search(r"CWE-(\d+)", name)
                    cwe = int(cwe_match.group(1)) if cwe_match else None
                    gt[basename].append({"cwe": cwe, "line": int(line) if line and line.isdigit() else None})
    return gt


def load_findings(json_path: str) -> List[dict]:
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    # 支持对象内嵌 findings 数组或直接数组
    if isinstance(data, dict):
        return data.get("findings", [])
    return data


def evaluate_owasp(gt: Dict[str, dict], findings: List[dict], line_tol: int = 0) -> Tuple[dict, dict]:
    # 按文件聚合发现
    by_file: Dict[str, List[dict]] = defaultdict(list)
    for f in findings:
        basename = Path(f.get("file_path", "")).stem
        by_file[basename].append(f)

    per_cwe = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tp_files": set(), "fp_files": set(), "fn_files": set()})
    details = []

    for name, truth in gt.items():
        cwe = truth["cwe"]
        if cwe is None:
            continue
        bucket = per_cwe[cwe]
        f_list = by_file.get(name, [])
        detected = False
        matched_finding = None
        for f in f_list:
            f_cwe = normalize_cwe(f.get("vuln_type"))
            if f_cwe == cwe:
                detected = True
                matched_finding = f
                break
        if truth["vulnerable"]:
            if detected:
                bucket["tp"] += 1
                bucket["tp_files"].add(name)
                details.append(("TP", name, cwe, matched_finding))
            else:
                bucket["fn"] += 1
                bucket["fn_files"].add(name)
                details.append(("FN", name, cwe, None))
        else:
            # 非漏洞文件上的任何发现都视为 FP（按发现计数）
            for f in f_list:
                bucket["fp"] += 1
                bucket["fp_files"].add(name)
                details.append(("FP", name, cwe, f))

    return dict(per_cwe), {"details": details, "by_file": dict(by_file)}


def evaluate_juliet(gt: Dict[str, List[dict]], findings: List[dict], line_tol: int = 3) -> Tuple[dict, dict]:
    by_file: Dict[str, List[dict]] = defaultdict(list)
    for f in findings:
        basename = Path(f.get("file_path", "")).name
        by_file[basename].append(f)

    per_cwe = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tp_flaws": set(), "fp_files": set(), "fn_flaws": set()})
    details = []

    # 统计每个文件的 flaw
    for basename, flaws in gt.items():
        f_list = by_file.get(basename, [])
        if not flaws:
            # 无 flaw 文件：所有发现都是 FP
            for f in f_list:
                cwe = normalize_cwe(f.get("vuln_type"))
                bucket = per_cwe[cwe if cwe else -1]
                bucket["fp"] += 1
                bucket["fp_files"].add(basename)
                details.append(("FP", basename, cwe, f))
            continue

        # 按 CWE 分组 flaw
        flaws_by_cwe: Dict[Optional[int], List[dict]] = defaultdict(list)
        for fl in flaws:
            flaws_by_cwe[fl["cwe"]].append(fl)

        matched_flaw_ids = set()
        for f in f_list:
            f_cwe = normalize_cwe(f.get("vuln_type"))
            f_line = f.get("line_start")
            # 优先匹配同 CWE 的 flaw；CWE-787（越界写）可匹配 CWE-121/122 的 buffer overflow flaw
            candidate_flaws = []
            if f_cwe == 787:
                candidate_flaws = flaws_by_cwe.get(121, []) + flaws_by_cwe.get(122, [])
            elif f_cwe:
                candidate_flaws = flaws_by_cwe.get(f_cwe, [])
            if not candidate_flaws:
                # 退而匹配任意 flaw
                candidate_flaws = [fl for fl in flaws]
            best = None
            best_dist = None
            for fl in candidate_flaws:
                if fl["line"] is None or f_line is None:
                    continue
                dist = abs(fl["line"] - f_line)
                if dist <= line_tol and (best_dist is None or dist < best_dist):
                    best = fl
                    best_dist = dist
            if best:
                key = (basename, best["line"], best["cwe"])
                if key not in matched_flaw_ids:
                    bucket = per_cwe[best["cwe"] if best["cwe"] else -1]
                    bucket["tp"] += 1
                    bucket["tp_flaws"].add(key)
                    matched_flaw_ids.add(key)
                    details.append(("TP", basename, best["cwe"], f))
                else:
                    # 同一 flaw 的重复发现：不重复计 TP，也不计 FP
                    details.append(("DUP", basename, best["cwe"], f))
            else:
                # 未匹配到任何 flaw
                bucket = per_cwe[f_cwe if f_cwe else -1]
                bucket["fp"] += 1
                bucket["fp_files"].add(basename)
                details.append(("FP", basename, f_cwe, f))

        # 统计未检出的 flaw
        for fl in flaws:
            key = (basename, fl["line"], fl["cwe"])
            if key not in matched_flaw_ids:
                bucket = per_cwe[fl["cwe"] if fl["cwe"] else -1]
                bucket["fn"] += 1
                bucket["fn_flaws"].add(key)
                details.append(("FN", basename, fl["cwe"], None))

    return dict(per_cwe), {"details": details, "by_file": dict(by_file)}


def compute_metrics(tp: int, fp: int, fn: int) -> dict:
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def format_report(per_cwe: dict, dataset_name: str, mode: str) -> str:
    lines = []
    lines.append(f"# CTX-Audit Benchmark Report: {dataset_name} ({mode})")
    lines.append("")
    lines.append("| CWE  | TP | FP | FN | Precision | Recall | F1   |")
    lines.append("|------|----|----|----|-----------|--------|------|")

    total_tp = total_fp = total_fn = 0
    rows = []
    for cwe, vals in sorted(per_cwe.items(), key=lambda x: (x[0] if isinstance(x[0], int) else 9999)):
        tp, fp, fn = vals["tp"], vals["fp"], vals["fn"]
        total_tp += tp
        total_fp += fp
        total_fn += fn
        m = compute_metrics(tp, fp, fn)
        cwe_label = f"CWE-{cwe}" if isinstance(cwe, int) else str(cwe)
        rows.append((cwe_label, tp, fp, fn, m["precision"], m["recall"], m["f1"]))

    for r in rows:
        lines.append(f"| {r[0]:<4} | {r[1]:>2} | {r[2]:>2} | {r[3]:>2} | {r[4]:.3f}     | {r[5]:.3f}  | {r[6]:.3f} |")

    total_m = compute_metrics(total_tp, total_fp, total_fn)
    lines.append("|------|----|----|----|-----------|--------|------|")
    lines.append(f"| Total| {total_tp:>2} | {total_fp:>2} | {total_fn:>2} | {total_m['precision']:.3f}     | {total_m['recall']:.3f}  | {total_m['f1']:.3f} |")
    lines.append("")
    lines.append(f"- Total findings: {total_tp + total_fp}")
    lines.append(f"- True Positives: {total_tp}")
    lines.append(f"- False Positives: {total_fp}")
    lines.append(f"- False Negatives: {total_fn}")
    lines.append(f"- Precision: {total_m['precision']:.3f}")
    lines.append(f"- Recall: {total_m['recall']:.3f}")
    lines.append(f"- F1: {total_m['f1']:.3f}")
    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Evaluate CTX-Audit benchmark results")
    parser.add_argument("--dataset", choices=["owasp-java", "juliet-cpp"], required=True)
    parser.add_argument("--ground-truth", required=True, help="Path to expectedresults.csv or manifest.xml")
    parser.add_argument("--findings", required=True, help="Path to CTX-Audit JSON findings")
    parser.add_argument("--mode", default="default", help="Scan mode label (default/taint/deep)")
    parser.add_argument("--line-tol", type=int, default=3, help="Line tolerance for Juliet flaw matching")
    parser.add_argument("--output", help="Output markdown report path")
    parser.add_argument("--details", help="Output detailed JSON with per-finding labels")
    parser.add_argument("--cwe-filter", help="Comma-separated CWE numbers to include in metrics (e.g. 121,122,134)")
    args = parser.parse_args()

    cwe_filter = set(int(x.strip()) for x in args.cwe_filter.split(",") if x.strip().isdigit()) if args.cwe_filter else None

    if args.dataset == "owasp-java":
        gt = load_owasp_ground_truth(args.ground_truth)
        if cwe_filter:
            gt = {k: v for k, v in gt.items() if v.get("cwe") in cwe_filter}
        per_cwe, meta = evaluate_owasp(gt, load_findings(args.findings))
    else:
        gt = load_juliet_ground_truth(args.ground_truth)
        if cwe_filter:
            gt = {k: [fl for fl in v if fl.get("cwe") in cwe_filter] for k, v in gt.items()}
        per_cwe, meta = evaluate_juliet(gt, load_findings(args.findings), line_tol=args.line_tol)
        if cwe_filter:
            per_cwe = {cwe: vals for cwe, vals in per_cwe.items() if cwe in cwe_filter}

    report = format_report(per_cwe, args.dataset, args.mode)
    print(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"\nReport written to {args.output}")

    if args.details:
        with open(args.details, "w", encoding="utf-8") as f:
            json.dump({
                "dataset": args.dataset,
                "mode": args.mode,
                "per_cwe": {str(k): v for k, v in per_cwe.items()},
                "details": [{"label": d[0], "file": d[1], "cwe": d[2], "finding": d[3]} for d in meta["details"]],
            }, f, indent=2, default=str)
        print(f"Details written to {args.details}")


if __name__ == "__main__":
    main()
