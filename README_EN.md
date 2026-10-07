# CTX-Audit

<div align="center">

**Code Intelligence & Forensic Infrastructure for LLMs · Verification-Layer Driven**

**Symbol Jump · Call Hierarchy · Backward Slicing · Framework Context · High-Level MCP Surface**

CTX-Audit does not compete with industrial SAST on soundness, and it is not another rule stack: the engine emits **deterministic code-topology facts** (who calls whom, how arguments flow, which guards sit on the path) and marks everything it could not resolve with an explicit `uncertainty` section. Vulnerability semantics are decided by the LLM and human review; the rule corpus only serves as **candidate seeds and a regression baseline**, not a truth path.

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
2. **Providing evidence chains**: findings carry `enclosing_function`, `evidence_refs`, source/sink snippets, and taint paths where available.
3. **Exposing investigation tools to LLMs**: the default MCP surface exposes **9 high-level capabilities** plus 4 basic tools (`read_file` / `list_files` / `report_finding` / `finish_analysis`), and every response carries `provenance` (file, line, resolver, index version) and `uncertainty`. Legacy fine-grained tools remain implemented but off by default (`--legacy-tools`).

> **Positioning: the deterministic engine supplies evidence; the LLM makes semantic judgments.**

---

## Quick Start

```bash
git clone https://github.com/BlkSword/CTX-Audit.git
cd CTX-Audit
cargo build --release

# Recommended main line: start the MCP server so the LLM can pull evidence
# directly (no prior scan needed). The project root is the current directory
# of the server process, so cd into the target project first.
cd /path/to/myproject
ctx-audit mcp

# Reach for a scan only when you want candidate seeds (candidates, not verdicts)
ctx-audit scan ./myproject                  # fast rule-based scan
ctx-audit scan ./myproject --deep -o report.json

# Daemon-backed incremental scanning
ctx-audit daemon start
ctx-audit scan ./myproject --daemon
ctx-audit daemon stop
```

Optionally install locally:

```bash
cargo install --path cli --locked
```

## LLM Collaboration via MCP

`ctx-audit mcp` is the evidence-supply main line. It exposes **13 tools = 9 high-level capabilities + 4 basic tools** by default, so the model does not have to pick between dozens of fine-grained node operations:

| High-level capability | Semantics | Main payload |
|-----------------------|-----------|--------------|
| `get_project_index` | Index status and language distribution | file/language stats, `build_id`, cache hit & limits |
| `get_symbol_definition` | Cross-file symbol definition (hybrid precision) | location + `resolver` + confidence |
| `get_symbol_references` | Symbol references (import aliases resolved) | location list + resolution kind |
| `get_call_hierarchy` | Upstream/downstream call topology | structured call tree + unresolved edge count |
| `slice_backward` | Slice backwards from a sink or variable | ≤ N relevant lines + path |
| `get_dataflow_path` | source→sink path and the guards on it | path steps + barriers |
| `get_sanitizer_guards` | Conditional branches / checks on the path | guard list |
| `get_framework_context` | Middleware/interceptor chain before a route handler | chain + unrecognised parts |
| `get_incremental_status` | Index state, cache freshness, SLO slots | status + cache metrics |

Basic tools: `read_file` / `list_files` / `report_finding` / `finish_analysis`.

### Fastest path: evidence without a scan

Evidence tools build their own index on demand — **no prior `scan` is required**:

1. Point the server at the project by setting its **working directory** to the project root (there is no `--project` flag; every `file` argument is relative to that root).
2. Call the evidence tools directly. The first call builds the index synchronously: `index.hit_source` reports `miss` (built now) or `ttl` (cache hit), along with `build_ms` and `files_indexed`. The index is persisted and reused across processes.
3. Pass `refresh: true` to force a rebuild after code changes.

This fits situations where you already know where to look (a patch, a review lead, a suspicious line). Go back to `scan` only when you need a candidate set.

### Investigation order

```text
get_project_index                                  → health check: files / language capability / limits
get_symbol_definition   {symbol}                   → where the definition is
get_symbol_references   {symbol}                   → who references it
slice_backward          {file, line, depth: 40}    → enclosing function + backward prefix slice
read_file               {file_path, start_line, end_line}  → fill in the context after the target line
get_call_hierarchy      {function, direction}      → callers / callees
get_sanitizer_guards    {file, line}               → guards on the path
report_finding / finish_analysis                   → write the verdict back
```

> Two easy traps: `slice_backward` is a **backward prefix** slice — `window.end_line` stops at the target line, while bounds checks and dangerous operations often sit **after** it, so pair it with `read_file`; and `read_file` takes `file_path` (not `path`).

Every response is `{data, provenance, uncertainty}`: `provenance` records which file, line, and resolver produced a conclusion (`tree-sitter` / `file-heuristic` / later `lsp`/`engine`), and `uncertainty` records what could not be resolved (`dynamic_dispatch_not_resolved`, `name_based_edges`, …). Dynamic dispatch, dependency injection, implicit interfaces, and same-name collisions are reported honestly instead of being papered over.

### Legacy surface

Legacy fine-grained tools are still implemented but off by default: start the server with `--legacy-tools` (or `CTX_AUDIT_LEGACY_TOOLS=1`) to expose them (`security_scan`, `query_callers`, `get_code_context`, …). Calls outside the default surface return a migration hint rather than silently executing.

### Claude Code configuration

`.claude/settings.json`:

```json
{
  "mcpServers": {
    "ctx-audit": {
      "command": "ctx-audit",
      "args": ["mcp"],
      "cwd": "/path/to/myproject"
    }
  }
}
```

`cwd` selects the analysed project (otherwise the process working directory is used).

## Commands

### `mcp` — evidence-supply main line

```bash
ctx-audit mcp                 # default surface: 9 high-level capabilities + 4 basic tools = 13
ctx-audit mcp --legacy-tools  # also register the legacy fine-grained surface
```

stdio JSON-RPC (one request per line); the project root is the process working directory.

### `scan` — project scan (candidate seeds)

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

## Custom Rules

Two kinds of YAML rules are supported:

1. **Pattern rules** — regex / tree-sitter query matching, placed in `rules/` or `.ctx-audit/rules/`.
2. **Taint rules** — source / sink / sanitizer definitions driving AST taint and cross-file tracking.

Rule directory precedence: `--rules` > `.ctx-audit/rules/` > built-in `rules/`.

```bash
mkdir -p .ctx-audit/rules
ctx-audit rules validate --rules .ctx-audit/rules
ctx-audit scan ./myproject --rules .ctx-audit/rules --deep
```

Full field tables and worked examples: **[rules/CUSTOM-RULES.md](rules/CUSTOM-RULES.md)** (Chinese). The role and freeze policy of the built-in corpus: [rules/README.md](rules/README.md).

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
- **MCP collaboration**: a high-level tool surface (9 capabilities + 4 basic tools = 13) returns code slices with `provenance` and `uncertainty`, so LLM analysts investigate call graphs, taint paths, and middleware context instead of guessing.
- **Rule corpus role**: rules and taint definitions are candidate seeds and a regression baseline — not a truth path; verdicts come from LLM/human review plus reproducible validation.
- **Honest boundaries**: the engine is an evidence provider and noise compressor; logic, authorization, and business-logic vulnerabilities still require LLM deep review and manual verification.

## License

Apache License 2.0
