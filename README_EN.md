# CTX-Audit

<div align="center">

**SAST Engine + LLM Collaborative Audit**

**Data Flow Tracking · Cross-File Analysis · MCP Protocol · Evidence-Driven Verdicts**

Traces complete data paths from entry points to dangerous functions. Outputs structured evidence chains. Connects Claude/LLM via MCP to query call graphs, read code, and make evidence-based vulnerability assessments.

[![Rust](https://img.shields.io/badge/Rust-2021-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=flat-square)](LICENSE)

[中文文档](README.md)

</div>

---

## Why CTX-Audit?

Traditional SAST tools often fail at three points:

- **A rule hit is not a vulnerability**: results rarely answer whether the data is truly attacker-controlled.
- **Cross-file chains are broken**: the dangerous call is in file A while the entry point is in file B.
- **LLMs tend to hallucinate**: dumping raw scan output to an LLM without call graphs, data-flow evidence, or middleware context produces unreliable verdicts.

CTX-Audit solves this by:

1. **Building the graph first**: parse ASTs, construct call graphs, compute function summaries, and make cross-file relationships queryable.
2. **Providing evidence chains**: high-severity findings carry `enclosing_function`, `evidence_refs`, source/sink snippets, and taint paths where available.
3. **Exposing investigation tools to LLMs**: via MCP, an LLM can query callers, trace variable flows, inspect middleware and sanitizers, then make evidence-based TP/FP decisions.

> **Positioning: the deterministic engine supplies evidence; the LLM makes semantic judgments.**

---

## Quick Start

```bash
git clone https://github.com/BlkSword/CTX-Audit.git
cd CTX-Audit
cargo build --release

# Rule-based scan
ctx-audit scan ./myproject

# Deep scan: rules + AST taint + cross-file analysis
ctx-audit scan ./myproject --deep -o report.json

# MCP Server for LLM collaboration (recommended)
ctx-audit mcp

# Daemon-backed incremental scanning
ctx-audit daemon start
ctx-audit scan ./myproject --daemon
ctx-audit daemon stop
```

Optionally install locally:

```bash
cargo install --path cli --locked
```

## Commands

### `scan` — Project Scan

```bash
ctx-audit scan <PATH> [OPTIONS]
  --deep                 Rules + AST taint + cross-file analysis
  --taint                Single-file source→sink taint analysis
  --cross-file           Cross-file call graph + taint (implies --taint)
  --sca                  OSV dependency vulnerability scan
  --min-severity <level> critical / high / medium / low
  --min-confidence <n>   Confidence threshold (0.0 - 1.0)
  -o, --output <file>    json / sarif / llm / markdown
  --graph-output <path>  Export call graph for LLM/MCP use
  --query-mode           Build call graph only, skip rule scan
  --daemon               Reuse daemon incremental caches
```

**Engines**: RuleScanner (default) → AstTaintScanner (`--taint`) → CrossFileTaintAnalyzer (`--cross-file`).

### Other commands

```bash
ctx-audit analyze ./src/main.py --symbols     # Single-file symbol analysis
ctx-audit watch ./myproject                   # Continuous monitoring
ctx-audit daemon status                       # Daemon status
ctx-audit findings list                       # Finding database
ctx-audit findings export report.json --format json
ctx-audit rules list                          # List loaded rules
ctx-audit rules validate                      # Validate YAML rules
ctx-audit config set scan.threads 8           # Configuration
ctx-audit completion bash                     # Shell completion
```

## LLM Collaboration via MCP

`ctx-audit mcp` exposes **57 tools** to MCP clients (Claude Code, Cursor, etc.), covering:

| Capability | Example tools |
|------------|---------------|
| Project & attack surface | `get_project_info`, `get_attack_surface`, `analyze_risk_patterns` |
| Scanning & findings | `security_scan`, `scan_file`, `list_rules`, `validate_finding` |
| Call graph queries | `query_callers`, `query_callees`, `find_call_path`, `get_call_graph` |
| Data-flow tracing | `trace_taint`, `trace_variable_flow`, `get_data_flow`, `get_taint_path` |
| Code retrieval | `read_file`, `list_files`, `search_code`, `get_code_context` |
| Security semantics | `check_sanitizer`, `query_middleware_chain`, `list_sources`, `list_sinks` |
| Audit sessions | `start_audit_session`, `start_investigation`, `conclude_investigation`, `audit_finalize_report` |

### Claude Code configuration

`.claude/settings.json`:

```json
{
  "mcpServers": {
    "ctx-audit": {
      "command": "ctx-audit",
      "args": ["mcp"]
    }
  }
}
```

## Detection Coverage

| Type | CWE | Method |
|------|-----|--------|
| SQL Injection | CWE-89 | AST taint + MyBatis XML `${}` + rules |
| Command Injection | CWE-78 | AST taint + multi-language rules |
| Code Injection | CWE-94 | AST taint + template injection (SSTI) |
| Path Traversal | CWE-22 | AST taint + multi-language rules |
| XSS | CWE-79 | AST taint + sanitizer detection |
| SSRF | CWE-918 | Cross-file tracking + Host Header rules |
| Insecure Deserialization | CWE-502 | Rules + method param source + caller chain |
| XXE / Log Injection / Open Redirect / Secrets / Weak Hash | Various | YAML sinks + cross-file + patterns |

**Rule assets**: 80+ pattern rules with 200+ language patterns, 50+ taint sources, 100+ taint sinks, 180+ sanitizers, and framework rules for Spring, Java, Django, Flask, Express, React/Next.js, Go, PHP, C/C++, Rust, Gradio, and more.

**Cross-file analysis**: import-aware alias resolution, callback registration, receiver tracking, type-hierarchy virtual dispatch, middleware modeling, cross-file BFS source→sink paths, and CPG with AccessPath matching.

**Language support**: 12 AST grammars (Java, Python, JavaScript, TypeScript, Go, Rust, C, C++, PHP, HTML, CSS, JSON) plus Ruby rule coverage; 19 file extensions.

## Project Status & Achievements

CTX-Audit has evolved from a rule scanner into a **real-project-driven hybrid auditing platform**.

- **160+ real-world audit rounds** across Java, Python, Go, JavaScript/TypeScript, PHP, Rust, and C/C++ ecosystems.
- **49 confirmed real-world vulnerabilities (TP)** in audited projects; **40 previously undisclosed 0-days** and **17 CVEs independently verified**.
- **Engine feedback loop**: real findings and false positives are continuously converted into YAML rules, source/sink definitions, sanitizer-window semantics, and AST/CPG fixes.
- **MCP collaboration**: 57 tools let LLM analysts investigate call graphs, taint paths, and middleware context instead of guessing.
- **Honest boundaries**: the engine is an evidence provider and noise compressor; logic, authorization, and business-logic vulnerabilities still require LLM deep review and manual verification.

## License

Apache License 2.0
