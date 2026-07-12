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

## Quick Start

```bash
git clone https://github.com/BlkSword/CTX-Audit.git
cd CTX-Audit
cargo build --release

# Scan
ctx-audit scan ./myproject                    # Rule-based scan
ctx-audit scan ./myproject --deep             # Rules + AST taint + cross-file
ctx-audit scan ./myproject --deep -o report.json

# MCP Server (LLM collaboration — recommended)
ctx-audit mcp

# Daemon (incremental caching)
ctx-audit daemon start
ctx-audit scan ./myproject --daemon
ctx-audit daemon stop
```

## Commands

### `scan` — Project Scan

```bash
ctx-audit scan ./project [OPTIONS]
  --deep                 AST taint + cross-file analysis
  --min-severity <level> Minimum severity (critical/high/medium/low)
  -o, --output <file>    Output file (llm/json/sarif/markdown)
  --daemon               Execute via daemon
  --sca                  Enable SCA dependency scanning
```

**Engines**: RuleScanner (default) → AstTaintScanner (`--taint`, single-file source→sink) → CrossFileTaintAnalyzer (`--cross-file`, inter-procedural call graph + function summaries).

### `mcp` — LLM Collaboration (Recommended)

```bash
ctx-audit mcp    # Start MCP Server (stdio JSON-RPC)
```

Exposes 32+ tools via MCP for Claude Code / Cursor / any MCP Agent. LLM can autonomously drive: project understanding → scan → call graph queries → code review → evidence-based verdicts.

Claude Code config (`.claude/settings.json`):

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

### `audit` — Scan + Rule Audit

```bash
ctx-audit audit ./project                   # Scan + rule audit (no LLM)
ctx-audit audit ./project --agent           # [DEPRECATED] Internal agent mode
```

> **2026-07**: Internal `--agent` mode is deprecated. Specialist/Investigator/TaintWalk components underperformed in benchmarks (TaintWalk 0% source discovery, Specialist 28/28 "unable to determine"). Code retained, `llm_mode` defaults to `noop`. Use MCP mode instead.

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
| XXE / Log Injection / Open Redirect / Hardcoded Secret / Weak Hash | Various | YAML sinks + cross-file + patterns |

**Cross-file analysis**: Call graph + import-aware aliasing + callback registration + receiver tracking + type hierarchy virtual dispatch + middleware modeling. 68 YAML sinks, 101 sanitizers, 7 languages + framework-aware rules.

## Benchmarks

| Language | Project | Files | Findings | Evidence |
|----------|---------|-------|----------|----------|
| Java | WebGoat | 404 | 231 | 14% |
| Java | Shiro 1.2.4 | 619 | 57 | 61% — ✅ CVE-2016-4437 confirmed |
| Java | RuoYi 4.7.3 | 266 | 355 | 4% — ⚠️ MyBatis XML hits |
| Java | Fastjson 1.2.24 | 2035 | 10 | 70% |
| Python | pygoat | 80 | 104 | 49% |
| Go | govwa | 20 | 5 | 60% |
| JS | NodeGoat | 50 | 57 | 19% |

## Project Status

| Dimension | Status |
|-----------|--------|
| Cross-file analysis | Call graph + import aliasing + callback + receiver + type hierarchy + virtual dispatch + middleware |
| Language coverage | Java/Python/JS/TS/Go/Rust/C/C++/PHP — 12 AST, 7 taint rulesets |
| YAML rules | 68 sinks + 101 sanitizers (Spring/React/Django/Express) |
| MCP tools | 32+ (scan/call graph query/code search/taint trace/audit session) |
| Evidence quality | enclosing_function 97%, evidence_refs 4-70% (project-dependent) |
| Agent mode | Deprecated. MCP collaboration is the recommended path |
| Tests | 239 passed, 0 failed |
| Benchmarks | 7 projects, 819 findings verified |
| Known CVE detection | ✅ CVE-2016-4437 (Shiro), ⚠️ CVE-2017-18349 (Fastjson) |

## License

Apache License 2.0
