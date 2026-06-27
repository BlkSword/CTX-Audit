# CTX-Audit

<div align="center">

**LLM-Native Code Security Analysis Engine**

**Data Flow Tracking · Cross-File Analysis · LLM-Ready Structured Output**

Not just regex matching — traces every data path from user input to dangerous functions. Outputs structured JSON with code context, taint chains, and confidence scores for LLM-based vulnerability assessment. Also connects Claude Code via MCP for AI-driven 0-day discovery.

[![Rust](https://img.shields.io/badge/Rust-2021-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=flat-square)](LICENSE)

[中文文档](README.md)

</div>

---

## Table of Contents

| Section | |
|---------|----|
| [What is CTX-Audit](#what-is-ctx-audit) | [LLM-Assisted Autonomous Auditing](#llm-assisted-autonomous-auditing) |
| [Quick Start](#quick-start) | [Incremental Scanning](#incremental-scanning) |
| [Commands](#commands) | [Architecture](#architecture) |
| [Configuration File](#configuration-file) | [LLM Audit Skill Guide](LLM-AUDIT-SKILL.md) |
| [Detection Capabilities](#detection-capabilities) | |
| [Custom Rules](#custom-rules) | |

---

## What is CTX-Audit

CTX-Audit is a code security analysis engine designed for LLM-assisted auditing. It doesn't just tell you "where dangerous functions are used" — it traces the **full path** of data from user input to dangerous operations, and outputs structured evidence chains that let LLMs make vulnerability verdicts based on facts.

**Core Capabilities**:

- **Multi-engine layered scanning**: Rule scanning (40 YAML rules, 6 languages) → AST taint analysis (`--taint`, single-file source→sink) → Cross-file tracking (`--cross-file`, call graph + function summaries), each engine independently controllable
- **Data flow tracking**: Powered by CPG (Code Property Graph) engine — fuses CFG + AST metadata + alias maps into a unified structure. Supports path-sensitive analysis (conditional sanitization detection), AccessPath prefix matching (`req.body` → `req.body.name`), destructuring, Promise chain support for dynamic languages — traces full taint chains like `req.body.name → eval(data)`
- **LLM autonomous audit loop**: Exposes 31 tools (including call graph query + audit session tools) via MCP protocol. LLMs can autonomously execute the full audit workflow: "project understanding → attack surface mapping → scanning → evidence collection → investigative verification → TP/FP verdict → rule generation → re-validation"
- **Local Agent mode**: `ctx-audit audit --agent` runs the full scan → hypothesize → verify → judge loop without an external MCP host, producing an evidence-backed audit log
- **False positive control**: File role classification (production/test/build/vendor), security barrier detection (shell:false, array args, require.resolve, etc.), rule-level sanitizer mechanism (skip findings when `setSecure`/`escape`/`encodeForHtml` etc. appears before the match), confidence scoring, multi-engine corroboration, baseline suppression
- **Incremental scanning**: Daemon stays resident in memory, content-hash change detection, ~1ms return for unchanged code
- **Structured output**: Default LLM-oriented JSON (with code context, taint chains, barrier info, file roles), also supports SARIF, Markdown, etc.

**Coverage**: 20+ vulnerability types (injection, XSS, SSRF, deserialization, path traversal...), AST analysis for 12 languages (JS/TS/Python/Java/Rust/Go/C/C++...), file scanning for 18 extensions, built-in framework-aware rules for Next.js, React, Django, Spring, Express, Laravel, Rails.

```
┌───────────────────┐     IPC (TCP)     ┌──────────────────────────────┐
│   ctx-audit CLI   │ ◀──────────────▶ │   ctx-audit-daemon          │
│   scan/analyze/   │                   │                              │
│   watch/findings  │                   │   AST Index (tree-sitter)    │
├───────────────────┤                   │   Taint Analysis (Source→Sink)│
│   IDE Plugin (future) │               │   Cross-file Taint Tracking  │
├───────────────────┤                   │   Pattern Matching (Regex)   │
│   AI Agent (MCP)  │                   │   SCA Scanner (OSV API)      │
│   Claude Code     │                   │   Incremental Cache (hash)   │
└───────────────────┘                   └──────────────────────────────┘
```

## Quick Start

```bash
git clone https://github.com/BlkSword/CTX-Audit.git
cd CTX-Audit
cargo build --release

# Direct usage (no daemon required)
ctx-audit scan ./myproject                    # Quick scan
ctx-audit scan ./myproject --taint            # Rules + AST taint analysis
ctx-audit scan ./myproject --cross-file       # Rules + taint + cross-file tracking
ctx-audit scan ./myproject --deep             # Same as above (backward compat shorthand)
ctx-audit scan ./myproject --taint --rules ./my-rules/  # Custom rules + taint analysis
ctx-audit analyze ./src/main.rs --symbols     # Single file analysis
ctx-audit watch ./myproject                   # Continuous monitoring
ctx-audit audit --agent ./myproject           # Local agent audit loop

# With daemon (incremental cache, 40x+ performance boost)
ctx-audit daemon start                        # Start the daemon
ctx-audit scan ./myproject --daemon           # Scan via daemon (first run: full)
ctx-audit scan ./myproject --daemon           # Scan again (incremental, ~1ms)
ctx-audit analyze ./src/main.rs --daemon      # Analyze via daemon
ctx-audit daemon stop                         # Stop the daemon

# AI Agent integration (MCP Server)
ctx-audit mcp                                 # Start MCP Server (stdio JSON-RPC)
```

## Commands

### `scan` — Project Scan

```bash
ctx-audit scan ./project [OPTIONS]

OPTIONS:
  -s, --severity <level>         Filter by severity (critical, high, medium, low, info)
  -p, --pattern <pattern>        Filter by file pattern (e.g. *.py)
  -r, --rules <dir>              Custom rules directory
  -o, --output <file>            Output file path or format name (llm/sarif/json/markdown)
  -t, --threads <N>              Number of parallel threads (default: 4)
  -e, --exclude <patterns>       Append exclusions (comma-separated, e.g. bench,*.min.js)
      --min-severity <level>     Override config file's minimum severity threshold
      --taint                    Enable AST taint analysis (single-file source→sink tracking)
      --cross-file               Enable cross-file taint tracking (implies --taint)
      --deep                     Shorthand for --taint --cross-file
      --daemon                   Execute via daemon (incremental cache)
      --sca                      Enable SCA dependency scanning
      --graph-output <file>     Export call graph as JSON (for LLM queries)
      --query-mode              Build call graph only, print stats (for use with MCP tools)
```

**Scan Engines**:

| Engine | Description | How to Enable |
|--------|-------------|---------------|
| RuleScanner | Language-aware regex rules (YAML, multi-language patterns, 40 built-in rules) | Always on |
| SCAScanner | Dependency vulnerability detection (OSV API, disabled by default, `--sca` or config to enable) | `--sca` |
| AstTaintScanner | AST taint analysis (single-file source→sink tracking) | `--taint` |
| CrossFileTaintAnalyzer | Cross-file / interprocedural taint tracking | `--cross-file` |

**Output Formats**:

Default output is `llm` (LLM-oriented structured JSON) with code context, taint chains, and confidence scores. Other formats are also supported:

```bash
ctx-audit scan ./project -o llm                     # Auto-generates ctx-audit-llm-2026-05-24.json
ctx-audit scan ./project -o sarif                   # Auto-generates ctx-audit-sarif-2026-05-24.sarif
ctx-audit scan ./project -o json                    # Auto-generates ctx-audit-json-2026-05-24.json
ctx-audit scan ./project -o report.json             # Uses specified filename report.json
ctx-audit scan ./project -o /tmp/results.sarif      # Uses full path
```

**LLM Output Structure** (default format):

```json
{
  "scan_summary": {
    "generated_at": "2026-05-17T01:19:18Z",
    "total_findings": 229,
    "by_severity": {"critical": 6, "high": 126, "medium": 97},
    "by_detector": {"RegexRule: ssrf-host-header": 1, "AstTaintScanner": 45, ...},
    "by_file_role": {"production": 229, "test": 2771, "build": 11}
  },
  "findings": [
    {
      "id": "uuid",
      "severity": "high",
      "vulnerability_type": "CWE-918",
      "detector": "RegexRule: ssrf-host-header",
      "file": "packages/next/src/server/api-utils/node/api-resolver.ts",
      "line": 302,
      "end_line": 302,
      "description": "SSRF via Host header used directly in URL construction ...",
      "file_role": "production",
      "barriers": [],
      "reasoning_hint": "Matched ssrf-host-header pattern in production context",
      "code_context": ">> 302 |       const res = await fetch(`https://${req.headers.host}${urlPath}`)",
      "source_snippet": "req.headers.host",
      "sink_snippet": "fetch(`https://${host}...`)",
      "taint_chain": ["Source:34 - req.headers.host", "Assignment:35 - ...", "Sink:36 - fetch(url)"],
      "confidence": "0.88",
      "corroboration_count": 3
    },
    {
      "id": "uuid",
      "severity": "medium",
      "vulnerability_type": "CWE-78",
      "detector": "RegexRule: command-injection",
      "file": "packages/next/src/server/lib/launch-editor.ts",
      "line": 45,
      "file_role": "production",
      "barriers": ["spawn_default_no_shell", "array_args"],
      "reasoning_hint": "Matched command-injection pattern in production context"
    }
  ]
}
```

Key fields: `file_role` identifies production/test/build code; `barriers` lists detected security mitigations; `reasoning_hint` explains why the tool flagged this; `>>` in `code_context` marks the matched line (±3 lines context); `taint_chain` and `source_snippet`/`sink_snippet` are included only for `--taint` findings.

### `analyze` — Single File Analysis

```bash
ctx-audit analyze ./src/main.py [OPTIONS]

OPTIONS:
  -s, --start_line <N>   Start line (default: 1)
  -e, --end_line <N>     End line
      --ast              Show AST information
      --symbols          Show symbols and call information
      --daemon           Execute via daemon
```

Output includes: language detection, code snippet, function calls, taint flows.

### `watch` — Continuous Monitoring

```bash
ctx-audit watch ./project [OPTIONS]

OPTIONS:
  -s, --severity <level>       Filter by severity
      --output_path <file>     SARIF output path (default: .ctx-audit.sarif)
      --ignore <patterns>      Directories to ignore, comma-separated
      --daemon                 Execute via daemon (recommended)
```

Monitors file changes, performs incremental scans, continuously updates the SARIF file. `--daemon` mode leverages the daemon's cache — each poll only scans changed files.

### `daemon` — Daemon Management

```bash
ctx-audit daemon start [--project <path>]    # Start the daemon
ctx-audit daemon status                      # Query status
ctx-audit daemon stop                        # Stop
```

Daemon features:
- **Incremental cache**: content-hash change detection, 1ms for unchanged code
- **Heartbeat**: periodic heartbeat file, CLI auto-detects liveness
- **Auto-reconnect**: exponential backoff, auto-recovery after daemon crash
- **Graceful degradation**: `--daemon` falls back to local scan on connection failure
- **Process lock**: PID file + port probe, prevents multiple instances
- **Panic recovery**: panic hook auto-restarts the daemon

### `mcp` — AI Agent Integration

```bash
ctx-audit mcp    # Start MCP Server (stdio JSON-RPC)
```

Exposes security analysis capabilities to AI agents (e.g. Claude Code) via MCP protocol. Provides **31 tools**:

**Coarse-grained tools**:

| Tool | Description |
|------|-------------|
| `security_scan` | Scan project, supports deep/severity/file_role_filter/min_severity filtering |
| `scan_file` | Analyze single file, returns language/symbols/taint flows |
| `daemon_status` | Query daemon status |

**Fine-grained tools (atomic interfaces)**:

| Tool | Description |
|------|-------------|
| `get_taint_path` | Get full taint propagation path from source to sink |
| `get_data_flow` | Trace variable definitions, uses, and propagation |
| `check_sanitizer` | Check if a function matches known sanitizer patterns |
| `list_sources` | List all taint sources in a file |
| `list_sinks` | List all taint sinks in a file |
| `cross_file_analysis` | Run cross-file taint analysis (call graph + function summaries) |
| `get_call_graph` | Get project function call graph |

**LLM Collaboration tools (0-day discovery support)**:

| Tool | Description |
|------|-------------|
| `get_attack_surface` | Map project attack surface (entry points, risk scores, trust boundaries, framework detection) |
| `analyze_risk_patterns` | Analyze architectural risk patterns (unvalidated input→deserialization, unauthenticated→privileged ops, etc.) |
| `add_custom_rule` | Dynamically inject custom rules (LLM-generated YAML rules take effect immediately) |

**LLM Autonomous Audit tools**:

| Tool | Description |
|------|-------------|
| `get_code_context` | Read source code context around a specific line (for verifying findings) |
| `get_project_info` | Project overview: language distribution, frameworks, directory structure, entry point stats |
| `validate_finding` | Record audit verdict (TP/FP + reasoning), auto-suppresses FPs |
| `list_rules` | View all currently loaded security rules |

**Call Graph Query Tools (Deterministic Evidence)**:

| Tool | Description |
|------|-------------|
| `get_graph_stats` | Get cross-file call graph statistics: nodes/edges/cross-file edges/sources/sinks/types/middleware |
| `list_file_functions` | List all functions indexed in the call graph for a file (with source/sink/callback markers) |
| `query_callers` | Find all functions that call a given function (with receiver info) — backward trace from sink to entry points |
| `query_callees` | Find all functions called by a given function — forward trace from entry point to sinks |
| `find_call_path` | Find the exact call path from source to sink in the cross-file call graph — deterministic reachability evidence |
| `resolve_method_call` | Resolve `obj.method()` to actual implementations (import aliases + receiver tracking + type hierarchy) |
| `query_type_hierarchy` | Get class inheritance hierarchy: parents/children/interface implementations/all methods (including inherited) |
| `query_middleware_chain` | Get Express app.use() / Django MIDDLEWARE registrations and which routes they affect |
| `trace_variable_flow` | Trace a tainted variable through the cross-file call graph to find all reachable sinks |

These tools return data based on AST-parsed **deterministic call graphs** — function call relationships do not depend on any LLM inference. LLMs use these tools to obtain evidence chains rather than guessing code behavior.

**Audit Session Tools (Investigative Collaboration)**:

| Tool | Description |
|------|-------------|
| `start_audit_session` | Create an audit session, returns session_uuid for linking subsequent investigations |
| `start_investigation` | Start a deep investigation on a finding, returns deterministic evidence + suggested follow-up tools |
| `log_investigation_step` | Record an investigation step (tool call + finding + reasoning), building a complete audit trail |
| `conclude_investigation` | Conclude investigation with verdict (TP/FP/needs_review), auto-writes audit_log and baseline |
| `conclude_audit_session` | Conclude the entire audit session, returns TP/FP/review summary statistics |

These 5 tools implement **stateful investigation** — instead of a one-shot "scan → judge", the LLM
establishes investigation context for each finding, progressively collects evidence, records reasoning
chains, and renders a final verdict. See the full workflow in [LLM Audit Skill Guide](LLM-AUDIT-SKILL.md).

Claude Code configuration example (`.claude/settings.json`):

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

### `rules` — Rule Management

```bash
ctx-audit rules list                          # List all loaded rules
ctx-audit rules list --rules ./my-rules/      # List rules in specific directory
ctx-audit rules validate                      # Validate rule file format
ctx-audit rules validate --rules ./my-rules/  # Validate specific directory
```

### `findings` — Vulnerability Management

```bash
ctx-audit findings list [-s critical] [--json]
ctx-audit findings view <ID>
ctx-audit findings update <ID> --status fixed
ctx-audit findings export -o report.json
```

### `config` — Configuration Management

```bash
ctx-audit config show                    # Show current config
ctx-audit config show sca.enabled        # Show single key
ctx-audit config set sca.enabled true    # Set config value
ctx-audit config remove scan.severity    # Reset to default
ctx-audit config list                    # List all config keys
ctx-audit config validate                # Validate config
ctx-audit config reset --confirm         # Reset to defaults
```

## Configuration File

The configuration file is located in the system config directory:

| Platform | Path |
|----------|------|
| Windows | `%APPDATA%\ctx-audit\config.toml` |
| macOS | `~/Library/Application Support/ctx-audit/config.toml` |
| Linux | `~/.config/ctx-audit/config.toml` |

No need to create the file manually — running `ctx-audit config set` will auto-generate it.

**Full configuration example** (`config.toml`):

```toml
[scan]
threads = 4                        # Parallel thread count
include_tests = false              # Include test files
max_file_size_mb = 10              # Max file size to scan (MB)
memory_budget_mb = 500             # Scan memory budget (MB)
batch_size = 100                   # Parallel batch size
line_tolerance = 3                 # Dedup line tolerance (±N lines merged)
severity = "medium"                # Exact severity filter (optional)
min_severity = "medium"            # Minimum severity threshold (filters low/info)
context_lines = 3                  # Code context lines (±N lines)
deep = false                       # Enable deep scan by default
# Deep scan taint limits
taint_max_candidate_files = 5000   # Max files to inspect when resolving sources across the repo
taint_max_file_kb = 500            # Skip individual source files larger than N KB during deep taint resolution

# Exclude dirs/file patterns (fully config-driven, defaults generated on first run)
exclude_patterns = [
  "node_modules", ".git", "target", "build", "dist", "vendor",
  "__pycache__", ".gradle", ".idea", ".vscode", ".cache",
  "bower_components", ".next", ".nuxt", "coverage",
  "test", "tests", "__tests__", "spec", "fixtures", "e2e",
  "examples", "example", "scripts",
  "*.min.js", "*.min.css", "*.bundle.js", "*.chunk.js",
  "*.map", ".env.*", "*.test.*", "*.spec.*",
]
exclude_extra = []                 # Additional exclusions (appended to exclude_patterns)

[output]
format = "llm"                     # Output format (llm/json/sarif/markdown/text)
color = true                       # Show colors
verbose = false                    # Verbose output

[advanced]
enable_cache = true                # Enable caching
log_level = "info"                 # Log level (trace/debug/info/warn/error)

[sca]
enabled = false                    # Enable SCA dependency scanning
dev_dependencies = true            # Include devDependencies
severity_threshold = "low"         # Minimum severity to report
cache_ttl_hours = 24               # Cache TTL (hours)
osv_timeout_sec = 30               # OSV API timeout (seconds)
fail_offline = false               # Error on network failure
ignore_vulns = []                  # Ignored vuln IDs, e.g. ["CVE-2024-1234"]
ignore_packages = []               # Ignored packages, e.g. ["lodash@4.17.21"]
ignore_ecosystems = []             # Skipped ecosystems, e.g. ["Go"]

[sca.severity_mapping]
critical = 9.0                     # CVSS >= 9.0 → critical
high = 7.0                         # CVSS >= 7.0 → high
medium = 4.0                       # CVSS >= 4.0 → medium

[daemon]
listen_addr = "127.0.0.1:19527"    # Listen address
rules_reload_interval_secs = 30    # Rule hot-reload interval (seconds)
ast_idle_secs = 3600               # AST Engine idle timeout (seconds)
ast_max_memory_mb = 512            # AST Engine max total memory (MB)
scan_cache_idle_secs = 7200        # Scan Cache idle timeout (seconds)
heartbeat_interval_secs = 5        # Heartbeat interval (seconds)
reconnect_max_retries = 3          # Max reconnect retries
reconnect_base_delay_ms = 200      # Reconnect base delay (milliseconds)
```

### Baseline Suppression

Suppress confirmed false positives via `.ctx-audit/baseline.json`:

```json
{
  "ignored": {
    "src/utils.ts:10:CWE-79": "False positive: parameter is escaped",
    "src/api.ts:45:CWE-89": "Confirmed: uses parameterized query"
  }
}
```

The key format is `file_path:line_number:vuln_type`, value is the suppression reason. Findings matching the baseline are automatically skipped during scans.

### Project-Level Configuration

Each project can place project-level files in the `.ctx-audit/` directory:

| File | Purpose |
|------|---------|
| `.ctx-audit/rules/` | Project-level custom rules (YAML), takes priority over built-in rules |
| `.ctx-audit/baseline.json` | Baseline suppression file |
| `.ctx-audit/cache/` | Cache directory (AST, SCA, etc.) |

## Detection Capabilities

### Code Vulnerabilities

| Vulnerability | Severity | CWE | Detection Method |
|--------------|----------|-----|-----------------|
| SQL Injection | Critical | CWE-89 | AST taint analysis |
| Command Injection | Critical | CWE-78 | Multi-lang rules + taint analysis |
| Code Injection | Critical | CWE-94 | Multi-lang rules + taint analysis |
| Path Traversal | High | CWE-22 | Multi-lang rules + taint analysis |
| XSS (Reflected/Stored) | High | CWE-79 | Taint analysis |
| SSRF | High | CWE-918 | Taint analysis + Host Header rules |
| Unsafe Deserialization | Critical | CWE-502 | Multi-lang rules |
| Host Header SSRF | High | CWE-918 | Semantic rules |
| Prototype Pollution | High | CWE-1321 | Semantic rules |
| Unbounded Stream Read (DoS) | High | CWE-400 | Semantic rules |
| Cache Poisoning | Medium | CWE-444 | Semantic rules |
| Header Injection | Medium | CWE-639 | Semantic rules |
| JWT Security Issues | High | — | Rule matching |
| ReDoS | Medium | CWE-1333 | Rule matching |
| XXE | High | CWE-611 | Rule matching |
| Open Redirect | Medium | CWE-601 | Rule matching |
| Hardcoded Credentials | High | CWE-259 | Pattern matching |
| Sensitive Info Exposure | High | CWE-200 | Pattern matching |
| Buffer Overflow | Critical | CWE-120 | C/C++ rules |
| Format String | High | CWE-134 | C/C++ rules |

### Cross-File Taint Tracking

`--cross-file` (or `--deep`) enables cross-file, interprocedural analysis:

- **Call graph construction**: Auto-extracts function nodes and call relationships, supports anonymous callback registration (arrow functions/function expressions) and independent HTTP response callback body analysis
- **Cross-file resolution**: Two-phase call resolution — Phase 1 via Import/Require alias exact matching to target file and export name, Phase 2 global name fallback + receiver narrowing
- **Method call tracking**: `CallTarget` preserves `obj.method()` receiver info, supports both `property` and `field` AST field names (JS/Java compatible)
- **Function summaries**: Bottom-up computation of each function's taint propagation signature; summaries now include `param_to_calls` to track downstream call arguments reached by each parameter, enabling multi-hop propagation through renames/field accesses
- **Path tracing**: BFS search for source→sink cross-file call paths, with sink detection in Return nodes and return-value LHS back-propagation to the caller
- **Context assembly**: Identifies callers, callees, and trust boundaries
- **CPG auto-summaries**: FunctionCPG cache from Stage B is passed to Stage C, auto-generating precise function summaries (replacing heuristic guesses) with accurate sink line numbers and param→return propagation
- **Path-sensitive analysis**: Branch-aware taint propagation — `if (isSafe(x))` True branch auto-marks sanitized, reducing false positives under conditional guards
- **Property path tracking**: Taint state keyed by AccessPath with prefix matching — `req.body` taint detected at `req.body.name`; `req.body.name` taint does NOT affect `req.body.email`
- **Type hierarchy**: Class/Interface/Struct inheritance DAG + virtual method dispatch (Java/TypeScript/Python)
- **Framework middleware**: Express `app.use()` middleware virtual edge injection, Django MIDDLEWARE detection
- **Constructor FP filtering**: Auto-demotes outer constructor functions when inner Method nodes are the actual sources/sinks
- **Language wildcard**: YAML rule language field supports wildcard matching, preventing cross-language rule failures

Supports 12 languages: JavaScript/JSX, TypeScript/TSX, Python, Java, Rust, Go, C, C++, HTML, CSS, JSON.

### Dynamic Language Smart Tracking

Taint tracking enhancements for Python, JavaScript, and TypeScript that solve "taint chain breaks" in dynamic languages:

| Feature | Description |
|---------|-------------|
| AccessPath | Tracks variables as dotted paths (e.g., `req.body.name`) instead of flat strings |
| AliasMap | Resolves variable aliases: `const y = x` inherits x's taint state |
| Destructuring | `const { body } = req` → body inherits req.body's taint |
| Property Access | `const x = obj.prop` → x aliases obj.prop |
| await Expression | `const data = await resp.json()` → taint propagation continues |
| Promise Chains | `.then(data => eval(data))` → data inherits chain's taint |
| Callback Hints | `.forEach(item => ...)` and `.map(x => ...)` → parameter inherits taint |
| HTTP Callback Hints | `needle.get(url, (err, resp, body) => ...)` → body marked as second-order taint source (external response) |
| TypeScript Types | `(req: HttpRequest)` → auto-identifies req as taint source |
| Module Exports | `module.exports.handler = fn` and `exports.processData = fn` detection |
| CommonJS Destructuring | `const { body } = require('express')` → named symbol extraction |

### Dependency Vulnerabilities (SCA)

Queries known vulnerable dependencies via OSV API: npm (`package.json`), PyPI (`requirements.txt`), crates.io (`Cargo.lock`), Go (`go.sum`).

> **Note**: SCA scanning is disabled by default. The first scan sends network requests to `osv.dev`; projects with many dependencies (e.g., large Cargo.lock) may add several to tens of seconds. Subsequent scans are accelerated via local cache (default 24h TTL).

**Enable SCA** (choose one):

```bash
# Option 1: enable for a single scan
ctx-audit scan ./project --sca

# Option 2: persist in config
ctx-audit config set sca.enabled true
```

**Configuration example** (`config.toml` `[sca]` section):

```toml
[sca]
enabled = true
severity_threshold = "medium"      # only report medium and above
dev_dependencies = false           # skip devDependencies
cache_ttl_hours = 48               # cache for 48 hours
osv_timeout_sec = 60               # API timeout 60 seconds
fail_offline = false               # silently skip on network failure
ignore_vulns = ["CVE-2024-1234"]   # ignore specific vulnerability IDs
ignore_packages = ["lodash@4.17.21"]  # ignore specific packages
ignore_ecosystems = ["Go"]         # skip specific ecosystems

[sca.severity_mapping]
critical = 9.0                     # CVSS >= 9.0 → critical
high = 7.0                         # CVSS >= 7.0 → high
medium = 4.0                       # CVSS >= 4.0 → medium (below → low)
```

**Offline usage**:

SCA scanning relies on `api.osv.dev` online queries. For offline environments:
1. Use local cache: after the first online scan, the cache file (`.ctx-audit/cache/sca_cache.json`) works offline within TTL
2. Pre-download OSV database: OSV provides a public GCS bucket (`gs://osv-vulnerabilities/`) with full vulnerability data per ecosystem. See https://osv.dev/docs/#data-access

### False Positive Control

| Mechanism | Description |
|-----------|-------------|
| Same-line dedup | Multiple scanner hits on same file:line auto-merged, highest severity kept |
| File role classification | Auto-tags production/test/build/vendor, adjusts severity by role |
| Security barrier detection | Detects shell:false, array args, require.resolve etc., auto-downgrades |
| Test directory filter | Attack surface findings in test/tests/spec dirs auto-skipped |
| Config-driven exclusions | All exclusions via `scan.exclude_patterns` in config file, `--exclude` CLI flag appends |
| Confidence scoring | Each finding includes confidence (0.0-1.0), boosted to 0.9 on multi-engine corroboration |
| Sanitizer recognition | 30+ sanitizer patterns reduce confidence on sanitized paths |
| Parameterized query detection | Distinguishes string-concatenated SQL from parameterized queries |
| Baseline suppression | `.ctx-audit/baseline.json` records confirmed/ignored findings |
| Context-awareness | Reduced confidence for matches in test files and config dirs |
| Path-sensitive sanitization | `if (isSafe(x))` True branch auto-marks sanitized, confidence drops to 0.3; partial sanitization paths get confidence 0.5 |
| Property path isolation | `req.body.name` taint does NOT affect `req.body.email` (AccessPath prefix matching, different properties don't cross-contaminate) |

**Config-driven exclusions**: All exclusion patterns are controlled via `scan.exclude_patterns` in `config.toml`. First run uses code defaults; modify anytime via `config set`. The `--exclude` CLI flag appends (does not replace) config values.

```bash
# View current exclusion list
ctx-audit config show scan.exclude_patterns

# Modify exclusion list (full replacement)
ctx-audit config set scan.exclude_patterns '["node_modules",".git","target","test","*.min.js"]'

# Append exclusions (no replacement)
ctx-audit config set scan.exclude_extra '["scripts","bench"]'

# CLI temporary append
ctx-audit scan ./project --exclude "temp,vendor"
```

### Framework-Aware Rules

| Framework | Sources | Sinks |
|-----------|---------|-------|
| React/Next.js | formData, cookies, headers, searchParams, params, useSearchParams, req.headers.host, x-forwarded-host | dangerouslySetInnerHTML, eval, parseModel, redirect, setHeader, revalidatePath, revalidateTag, NextResponse.redirect |
| Django | request.GET/POST/args | raw(), extra() |
| Spring | @RequestParam | JdbcTemplate, Runtime.exec |
| Express/Node | req.body/query/params | eval, child_process.exec |
| Laravel | Request::input, $request->get | DB::raw, DB::select |
| Rails | params[], request.env | eval, system, send_file |

## Custom Rules

CTX-Audit supports user-written custom YAML rules, placed in `.ctx-audit/rules/`.

**Two rule types**:

1. **Pattern Rules** — Regex-based code pattern matching (e.g. `rules/command-injection.yaml`), with optional `sanitizers` list for pre-match sanitization detection
2. **Taint Rules** — Define taint sources, sinks, and sanitizers (e.g. `rules/taint/generic-taint.yaml`), where each sink can declare `sanitizers`

**Rule priority**: `--rules` flag > `.ctx-audit/rules/` > built-in `rules/`

**Daemon hot-reload**: The daemon checks rule directories every 30 seconds and auto-reloads changes.

For detailed writing guides, see [`docs/custom-rules-en.md`](docs/custom-rules-en.md) | [`docs/custom-rules.md`](docs/custom-rules.md) (中文).

## LLM-Assisted Autonomous Auditing

CTX-Audit exposes **31 tools** (including 9 call graph query + 5 audit session tools) via the MCP protocol, enabling LLMs (Claude Code / Cursor / any MCP-compatible agent) to fully autonomously drive the security audit process — from project understanding, scanning, evidence collection, investigative verification to audit conclusions — with zero manual intervention.

### Setup

Add the following to your Claude Code configuration (`.claude/settings.json`):

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

### Autonomous Audit Workflow

CTX-Audit uses an **investigative collaboration** model — the LLM is not just a judge of scan results, but an active investigator. Each finding goes through: "establish investigation → collect evidence → record reasoning → reach verdict."

```
1. get_project_info         → Understand the project: languages, frameworks, structure, entry points
2. get_attack_surface       → Map attack surface: high-risk entry points, trust boundaries, unauthenticated routes
3. get_graph_stats          → Understand call graph scale: nodes, edges, source/sink distribution
4. security_scan(deep=true) → Full scan, returns findings with evidence_refs pointers
5. start_audit_session      → Create audit session, get session_uuid ★
6. For each high/critical finding:
   ├─ start_investigation   → Start investigation, get evidence_map + suggested_tools ★
   ├─ get_code_context      → Read source code around the finding
   ├─ query_callers         → Backward trace: what entry points reach this sink?
   ├─ query_callees         → Forward trace: what sensitive operations does this call?
   ├─ find_call_path        → Exact source→sink path (deterministic reachability evidence)
   ├─ query_middleware_chain → Does middleware cover this route? (auth bypass detection)
   ├─ resolve_method_call   → Resolve ambiguous method calls to implementations
   ├─ log_investigation_step → Record each tool call + finding + reasoning ★
   └─ conclude_investigation → Reach verdict (TP/FP/needs_review), auto-record audit_log ★
7. add_custom_rule          → Dynamically generate rules for discovered 0-day patterns
8. security_scan            → Re-scan with new rules to validate
9. conclude_audit_session   → Output full audit summary (TP/FP/review counts) ★
```

★ = New investigative collaboration steps. See [LLM-AUDIT-SKILL.md](LLM-AUDIT-SKILL.md) for detailed workflow and examples.

### MCP Tool Reference

#### Scanning & Detection

| Tool | Description |
|------|-------------|
| `security_scan` | Project scan with deep/severity/file_role_filter/min_severity filtering |
| `scan_file` | Single file analysis: language detection, symbol extraction, taint flows |
| `get_project_info` | Project overview: language distribution, framework detection, directory structure, entry point stats |
| `list_rules` | View all loaded security rules (including custom rules) |

#### Taint Analysis & Data Flow

| Tool | Description |
|------|-------------|
| `get_taint_path` | Get full source→sink taint propagation path (with code snippets at each step) |
| `get_data_flow` | Trace variable definitions, uses, propagation, and taint status |
| `check_sanitizer` | Check if a function matches known sanitizer patterns |
| `list_sources` | List all taint sources (user input points) in a file |
| `list_sinks` | List all taint sinks (dangerous function calls) in a file |
| `cross_file_analysis` | Cross-file taint tracking (call graph + function summaries + path finding) |
| `get_call_graph` | Get project function call graph |

#### Attack Surface & Risk Patterns

| Tool | Description |
|------|-------------|
| `get_attack_surface` | Map attack surface: entry points, risk scores, trust boundaries, framework detection |
| `analyze_risk_patterns` | Detect architectural risk patterns (unvalidated input→deserialization, etc.) |

#### LLM Audit Loop

| Tool | Description |
|------|-------------|
| `get_code_context` | Read source code context around a specific line (for verifying findings) |
| `validate_finding` | Record audit verdict: TP/FP + reasoning, auto-writes to baseline for FP suppression |
| `add_custom_rule` | Dynamically inject custom rules (YAML format, takes effect immediately) |
| `daemon_status` | Query daemon process status |

#### Call Graph Query (Deterministic Evidence)

| Tool | Description |
|------|-------------|
| `get_graph_stats` | Call graph statistics: nodes/edges/sources/sinks/types/middleware |
| `list_file_functions` | List all indexed functions in a file |
| `query_callers` | Backward trace: who calls this function? |
| `query_callees` | Forward trace: what does this function call? |
| `find_call_path` | Exact call path: is source→sink reachable? |
| `resolve_method_call` | Resolve obj.method() → actual implementation |
| `query_type_hierarchy` | Class inheritance chain + virtual method dispatch |
| `query_middleware_chain` | Middleware registrations and affected routes |
| `trace_variable_flow` | Cross-file taint variable propagation paths |

#### Audit Session (Investigative Collaboration)

| Tool | Description |
|------|-------------|
| `start_audit_session` | Create audit session, get session_uuid |
| `start_investigation` | Start investigation on a finding, get evidence + suggested tools |
| `log_investigation_step` | Record investigation step (tool + finding + reasoning) |
| `conclude_investigation` | Conclude with verdict, auto-write audit_log/baseline |
| `conclude_audit_session` | End session, output TP/FP/review summary |

### System Prompt for Autonomous Auditing

The complete LLM audit guidance system is at **[LLM-AUDIT-SKILL.md](LLM-AUDIT-SKILL.md)** —
a structured Skill file containing:
- Audit philosophy (investigative collaboration vs scan→judge)
- Complete 4-phase audit workflow
- Usage scenarios and parameters for every MCP tool
- Evidence-driven TP/FP verdict framework
- Example audit dialogs

Usage with Claude Code:
```bash
# Copy the skill file to your project
cp LLM-AUDIT-SKILL.md .claude/agents/ctx-auditor.md
# Or reference directly in conversation
@LLM-AUDIT-SKILL.md Please audit this project for security vulnerabilities
```

### Example Audit Output

```
## Security Audit Report

### Project Overview
- **Project**: next.js (TypeScript/JavaScript)
- **Source files**: 22,000+
- **Frameworks**: Next.js, React
- **Attack surface**: 156 entry points (23 unauthenticated)

### Scan Results
- **Scan mode**: deep (AST taint analysis + cross-file tracking)
- **Total findings**: 3014 → filtered: 229 production code findings
- **Critical**: 6 | **High**: 126 | **Medium**: 97

### Critical Finding Audit

#### 1. [TP] SSRF via Host Header — `api-resolver.ts:302`
- **Data flow**: req.headers.host → `https://${host}/api/...` → fetch()
- **Code context**:
  ```typescript
  >> 302 | const res = await fetch(`https://${req.headers.host}${urlPath}`)
  ```
- **Reasoning**: Host header is fully client-controlled, directly interpolated into fetch URL with no validation
- **Barriers**: None (barriers field is empty)
- **Recommendation**: Validate Host header against whitelist, or check allowed domain list before using it

#### 2. [FP] Command Injection — `launch-editor.ts:45`
- **Data flow**: editorPath → spawn(args)
- **Barriers**: spawn_default_no_shell + array_args
- **Reasoning**: Node.js spawn() defaults to shell:false, and args are an array — attacker cannot inject extra commands
- **Conclusion**: Auto-downgraded to medium, confirmed as FP

### Custom Rules Generated
- `llm-generated-nextjs-host-ssrf.yaml` — Detects Next.js Host Header SSRF variants
```

## Incremental Scanning

The daemon implements incremental scanning via content-hash caching:

```
First scan:  Full scan → cache per-file findings + content hash
Next scan:   Detect changed files → scan only changes → merge with cache
No changes:  Return cached results directly (~1ms)
```

Performance benchmarks:

| Scenario | Time | Notes |
|----------|------|-------|
| First scan (full) | ~50ms | Scans all files |
| Re-scan (no changes) | ~1ms | Cache hit |
| Scan after file change | ~5ms | Only scans changed files |

## Architecture

```
daemon/                   # Daemon process
├── src/protocol.rs       # IPC protocol (NDJSON over TCP)
├── src/server.rs         # TCP server, heartbeat, multi-client concurrency
├── src/engine.rs         # Analysis engine coordination + incremental cache + cross-file
├── src/state.rs          # Project state management
├── src/client.rs         # IPC client (exponential backoff reconnect)
├── src/lib.rs            # Library entry (public interface exports)
└── src/main.rs           # Daemon entry (PID lock + panic recovery)

core/                     # Deterministic analysis engine
├── lib.rs                # Library entry (layered exports: scanning/taint/ast_api/attack_surface)
├── ast/                  # AST engine (tree-sitter, 12 languages, 18 extensions, incremental mtime index)
├── diff/                 # Diff engine
│   ├── engine.rs         # DiffEngine (code diff computation)
│   ├── git_integration.rs # Git integration (diff/commit parsing)
│   └── types.rs          # Diff type definitions
├── analysis/             # Analysis modules
│   ├── taint.rs          # Taint analysis core (Source/Sink/Flow types)
│   ├── ast_taint.rs      # AST taint analyzer (CFG + worklist + CPG path-sensitive algorithm)
│   ├── cross_file.rs     # Cross-file analysis (call graph + function summaries + CPG cache)
│   ├── enhanced_dataflow.rs  # Enhanced data flow analysis (CFG + edge types)
│   ├── enhanced_taint.rs # Enhanced taint analyzer
│   ├── dataflow.rs       # Basic data flow analysis
│   ├── alias.rs          # AccessPath + AliasMap (dynamic language tracking)
│   ├── async_flow.rs     # Promise chain + callback taint hints
│   ├── attack_surface.rs # Attack surface mapping
│   ├── risk_patterns.rs  # Architectural risk pattern detection
│   ├── cache.rs          # Analysis cache (AST/Taint/Analysis cache management)
│   ├── cpg/              # Code Property Graph engine
│   │   ├── mod.rs        # FunctionCPG, CPGNodeMeta, ConditionInfo, FunctionSignature
│   │   ├── builder.rs    # CPGBuilder (AST→CPG construction + condition extraction + alias building)
│   │   ├── query.rs      # CodePropertyGraph unified query API
│   │   ├── path_taint.rs # PathSensitiveState + AccessPath prefix matching + branch merging
│   │   └── summary.rs    # CPG auto function summary generation
│   ├── imports.rs        # Import resolution
│   ├── type_hierarchy.rs # Type hierarchy (extends/implements DAG)
│   ├── middleware.rs     # Framework middleware modeling (Express app.use)
│   └── query.rs          # Call graph query engine (LLM evidence chain)
├── scanner/              # Scanners
│   ├── regex_scanner.rs  # Regex scanner
│   ├── sca_scanner.rs    # SCA scanner (OSV API + local cache)
│   └── manager.rs        # Scanner manager
├── rules/                # YAML rule system
│   ├── model.rs          # Rule/RuleSet data model
│   ├── taint_model.rs    # TaintRuleSet data model
│   ├── loader.rs         # Rule loader
│   ├── taint_loader.rs   # Taint rule loader
│   └── scanner.rs        # RuleScanner
├── sarif/                # SARIF 2.1.0 output
├── watcher/              # File watching + change detection
└── indexing/             # Code indexing

tools/                    # MCP tool suite
├── lib.rs                # Module entry (tool category definitions)
├── registry.rs           # Tool registry
├── executor.rs           # Tool execution engine
├── bridge.rs             # Built-in tool implementations
├── external.rs           # External tool adapters (Semgrep/Bandit/Gitleaks)
├── ast_tools.rs          # AST query tools
├── taint_tools.rs        # Taint analysis tools
├── pattern_tools.rs      # Pattern detection tools
├── call_graph_tools.rs   # Call graph query tools (9 LLM evidence queries)
└── search_tools.rs       # Code search tools

cli/                      # Command-line client
├── main.rs               # CLI entry point
├── config.rs             # Configuration management (TOML read/write + path resolution)
├── output.rs             # Output formatting (LLM/SARIF/JSON/Markdown/Text)
├── terminal.rs           # Terminal UI (progress bar + colorized output)
├── index.rs              # File indexing
├── commands/             # Command implementations
│   ├── scan.rs           # Scan command (with progress callback + incremental mode)
│   ├── analyze.rs        # Single file analysis command
│   ├── watch.rs          # Continuous monitoring command
│   ├── daemon.rs         # Daemon management command
│   ├── mcp.rs            # MCP Server (17 tools)
│   ├── rules.rs          # Rule management command
│   ├── config.rs         # Configuration management command
│   └── findings.rs       # Vulnerability management command
├── database/             # Vulnerability database
│   ├── schema.rs         # SQLite schema definitions
│   ├── models.rs         # Data models
│   ├── queries.rs        # Query interface
│   └── migrations.rs     # Database migrations
└── report/               # Report export
    └── exporter.rs       # Multi-format report export

rules/                    # Built-in rules (40 pattern + 5 taint)
├── *.yaml                # Pattern rules (including Next.js semantic rules)
└── taint/                # Taint rules
    ├── generic-taint.yaml          # Generic taint rules
    └── frameworks/                 # Framework-specific rules
        ├── react-nextjs.yaml
        ├── django.yaml
        ├── spring.yaml
        └── express-node.yaml

docs/                     # Documentation
├── custom-rules.md       # Custom rules guide (Chinese)
└── custom-rules-en.md    # Custom Rules Guide (English)
```

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/security-scan.yml
name: CTX-Audit Security Scan
on: [push, pull_request]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - run: cargo build --release
      - run: ./target/release/ctx-audit -o sarif scan . --deep -o results.sarif   # SARIF for GitHub
      # Default -o llm outputs LLM format for downstream AI analysis
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### Custom Rules Integration

```bash
# Project-level custom rules
mkdir -p .ctx-audit/rules/
cp my-custom-rule.yaml .ctx-audit/rules/

# Auto-loaded during scan
ctx-audit scan ./myproject --deep    # Automatically loads .ctx-audit/rules/
```

## Performance

Benchmarks based on the [Next.js](https://github.com/vercel/next.js) repository (~22,000 source files, 243MB), excluding test/bench/docs directories, release build, Windows 10.

| Mode | Time | Notes |
|------|------|-------|
| Quick scan | **~10s** | Rule scanning + attack surface mapping (single-pass) |
| `--taint` | **~1m** | Rules + AST taint analysis (single-file source→sink) |
| `--deep` / `--cross-file` | **~2.5m** | Rules + taint + cross-file tracking (22K-file large project) |
| Quick scan + SCA | **~35s** | Includes OSV API network queries (first run); cached runs approach quick scan time |
| Daemon first scan | **~41s** | Full scan + result caching |
| Daemon incremental (no changes) | **~9s** | Cache hit, only file change detection |

**Performance tips**:
- Quick scan merges attack surface mapping and rule scanning into a single file pass — no extra overhead
- Deep scan on large projects limits candidate files via `scan.taint_max_candidate_files` and file size via `scan.taint_max_file_kb` to prevent OOM
- Daemon mode uses content-hash caching — unchanged files are skipped in incremental scans
- SCA first-run is slower (network requests); subsequent runs use a 24h local cache
- Use `--exclude` to append exclusions for irrelevant directories and reduce scan file count

## Development

```bash
cargo build --release        # Build (ctx-audit + ctx-audit-daemon)
cargo test --workspace       # Run tests (210+ tests)
cargo fmt                    # Format
cargo clippy                 # Lint
```

## Project Status

| Dimension | Status |
|-----------|--------|
| CPG Analysis Engine | CFG + AST metadata + alias map fusion, path-sensitive taint propagation, AccessPath property tracking, 12 languages AST, 30+ sanitizers |
| Dynamic Language Tracking | AccessPath + AliasMap + destructuring + property access + await + Promise chains |
| Cross-file Tracking | Call graph + Import-Aware alias resolution + Callback registration + CallTarget receiver tracking + Type hierarchy virtual dispatch + Framework middleware virtual edges + CPG auto-summaries + BFS path finding + Constructor FP filtering + Callback body analysis |
| TypeScript Integration | Type annotation → auto taint source (HttpRequest, Request, etc.) |
| Pattern Matching | 40 pattern rules + 5 taint rules, covering 6 languages + 6 frameworks |
| False Positive Control | File role classification + security barrier detection + multi-engine confidence fusion + baseline suppression |
| SCA Scanner | OSV API, 4 ecosystems, local cache, configurable (disabled by default) |
| MCP Integration | 31 tools (3 scanning + 7 taint + 3 risk patterns + 4 autonomous audit + 9 call graph query + 5 audit session) |
| Local Agent Mode | `ctx-audit audit --agent` runs SURVEY→HYPOTHESIZE→VERIFY→JUDGE and writes `.ctx-audit/audit_log.json` |
| LLM Output | Structured JSON: code context + taint chains + file role + barriers + confidence |
| Custom Rules | YAML format, daemon hot-reload |
| Daemon | Incremental cache + heartbeat + auto-reconnect + panic recovery |
| Config-driven | All exclusions, severity thresholds, and engine toggles via config.toml |
| Test Coverage | 210+ tests |
| NodeGoat Benchmark | 7/7 ground truth hits (eval/redirect/ReDoS/IDOR/NoSQL/SSRF/XSS), 25+ findings |
| WebGoat Real-Project Validation | `--deep` scan detects CWE-502 XStream deserialization, CWE-259 hardcoded password, CWE-22 path traversal, etc.; CWE-614 false positives reduced from 7 to 3 via the sanitizer mechanism |

## License

Apache License 2.0
