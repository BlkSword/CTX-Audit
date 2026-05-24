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

## What is CTX-Audit

One command to scan 30+ vulnerability types across 12 languages and major frameworks (Next.js, React, Spring, Express, Django, and more).

**How?** Not keyword matching — CTX-Audit parses your code with AST, traces the full data path from user input (source) to dangerous functions (sink), across files and function boundaries. The engine stays resident in memory with incremental caching — unchanged code returns in **~1ms**. Default output is LLM-oriented structured JSON with code context, taint chains, and confidence scores, ready for LLM-based vulnerability triage.

**AI Collaboration:** Connect Claude Code (or any LLM) via MCP protocol. The AI reads your attack surface, analyzes data flows, discovers risk patterns that rules miss, and even generates targeted rules on the fly — evolving from "detect known vulnerabilities" to "discover unknown ones".

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
ctx-audit scan ./myproject --deep             # Deep scan (AST taint analysis)
ctx-audit scan ./myproject --deep --rules ./my-rules/  # Custom rules
ctx-audit analyze ./src/main.rs --symbols     # Single file analysis
ctx-audit watch ./myproject                   # Continuous monitoring

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
  -o, --output <file>            Output file path
  -t, --threads <N>              Number of parallel threads (default: 4)
  -e, --exclude <patterns>       Append exclusions (comma-separated, e.g. bench,*.min.js)
      --min-severity <level>     Override config file's minimum severity threshold
      --deep                     Enable deep scan (AST taint + cross-file analysis)
      --daemon                   Execute via daemon (incremental cache)
      --sca                      Enable SCA dependency scanning
```

**Scan Engines**:

| Engine | Description |
|--------|-------------|
| RuleScanner | Language-aware regex rules (YAML, multi-language patterns, 39 built-in rules) |
| SCAScanner | Dependency vulnerability detection (OSV API, disabled by default, `--sca` or config to enable) |
| AstTaintScanner | AST taint analysis (`--deep` mode) |
| CrossFileTaintAnalyzer | Cross-file / interprocedural taint tracking (`--deep` mode) |

**Output Formats**:

Default output is `llm` (LLM-oriented structured JSON) with code context, taint chains, and confidence scores. Other formats are also supported:

```bash
ctx-audit scan ./project -o report.json              # Default llm format JSON
ctx-audit -o sarif scan ./project -o report.sarif    # SARIF 2.1.0
ctx-audit -o json scan ./project -o results.json     # Raw JSON
ctx-audit -o markdown scan ./project -o report.md    # Markdown
```

**LLM Output Structure** (default format):

```json
{
  "scan_summary": {
    "generated_at": "2026-05-17T01:19:18Z",
    "total_findings": 8,
    "by_severity": {"critical": 1, "high": 2, "medium": 5},
    "by_detector": {"RegexRule: ssrf-host-header": 1, ...}
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
      "code_context": ">> 302 |       const res = await fetch(`https://${req.headers.host}${urlPath}`)",
      "source_snippet": "req.headers.host",
      "sink_snippet": "fetch(`https://${host}...`)",
      "taint_chain": ["Source:34 - req.headers.host", "Assignment:35 - ...", "Sink:36 - fetch(url)"],
      "confidence": "0.88",
      "corroboration_count": 3
    }
  ]
}
```

`>>` marks the matched line in `code_context` with `±3` lines of context. `source_snippet` / `sink_snippet` are included only for AST taint analysis findings.

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

Exposes security analysis capabilities to AI agents (e.g. Claude Code) via MCP protocol. Provides **17 tools**:

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

`--deep` mode enables cross-file, interprocedural analysis:

- **Call graph construction**: Auto-extracts function nodes and call relationships
- **Cross-file resolution**: Matches bare function names to global functions, builds cross-file call edges
- **Function summaries**: Bottom-up computation of each function's taint propagation signature
- **Path tracing**: DFS search for source→sink cross-file call paths
- **Context assembly**: Identifies callers, callees, and trust boundaries

Supports 12 languages: Python, JavaScript, TypeScript, Java, Rust, Go, C, C++, PHP, Ruby, JSX, TSX.

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
| Test directory filter | Attack surface findings in test/tests/spec dirs auto-skipped |
| Config-driven exclusions | All exclusions via `scan.exclude_patterns` in config file, `--exclude` CLI flag appends |
| Confidence scoring | Each finding includes confidence (0.0-1.0) |
| Sanitizer recognition | 30+ sanitizer patterns reduce confidence on sanitized paths |
| Parameterized query detection | Distinguishes string-concatenated SQL from parameterized queries |
| Baseline suppression | `.ctx-audit/baseline.json` records confirmed/ignored findings |
| Context-awareness | Reduced confidence for matches in test files and config dirs |

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

1. **Pattern Rules** — Regex-based code pattern matching (e.g. `rules/command-injection.yaml`)
2. **Taint Rules** — Define taint sources, sinks, and sanitizers (e.g. `rules/taint/generic-taint.yaml`)

**Rule priority**: `--rules` flag > `.ctx-audit/rules/` > built-in `rules/`

**Daemon hot-reload**: The daemon checks rule directories every 30 seconds and auto-reloads changes.

For detailed writing guides, see [`docs/custom-rules-en.md`](docs/custom-rules-en.md) | [`docs/custom-rules.md`](docs/custom-rules.md) (中文).

## LLM-Assisted Autonomous Auditing

CTX-Audit exposes **17 tools** via the MCP protocol, enabling LLMs (Claude Code / Cursor / any MCP-compatible agent) to fully autonomously drive the security audit process — from project understanding, scanning, taint tracing, code review to audit conclusions — with zero manual intervention.

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

```
1. get_project_info      → Understand the project: languages, frameworks, structure, entry points
2. get_attack_surface    → Map attack surface: high-risk entry points, trust boundaries, unauthenticated routes
3. security_scan         → Full scan: rule matching + AST taint analysis (--deep)
4. Filter results        → file_role_filter="production", min_severity="high"
5. Audit each finding:
   ├─ get_code_context   → Read source code around the finding
   ├─ get_taint_path     → Trace full source→sink data flow
   ├─ check_sanitizer    → Verify if sanitization functions exist
   ├─ list_sources/sinks → View all taint sources and sinks in the file
   └─ validate_finding   → Record audit verdict (TP/FP) with reasoning
6. add_custom_rule       → Dynamically generate rules for discovered 0-day patterns
7. security_scan         → Re-scan with new rules to validate
```

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

### System Prompt for Autonomous Auditing

Once MCP is configured in Claude Code, use this system prompt to drive fully autonomous auditing:

```
You are a security audit expert responsible for performing a fully autonomous security audit of the target project.
You have access to CTX-Audit tools for scanning and analysis.

## Audit Process

### Phase 1: Project Understanding
1. Call `get_project_info` to understand the tech stack and structure
2. Call `get_attack_surface` to map the attack surface and identify high-risk entry points
3. Call `list_rules` to confirm available detection rules

### Phase 2: Deep Scanning
4. Call `security_scan` with `deep: true`, `file_role_filter: "production"`,
   `min_severity: "high"` for production code deep scan
5. For each critical finding:
   - Call `get_code_context` to read surrounding code and understand full context
   - Call `get_taint_path` to trace the full data flow (source→sink)
   - Call `check_sanitizer` to verify if sanitization functions exist
   - Make a comprehensive judgment: true positive (TP) or false positive (FP)
   - Call `validate_finding` to record the audit verdict

### Phase 3: 0-day Exploration
6. Call `analyze_risk_patterns` to detect architectural risk patterns
7. For high-risk patterns, call `cross_file_analysis` for cross-file tracking
8. If you discover new vulnerability patterns not covered by rules, call `add_custom_rule`
9. Re-scan with new rules to validate

### Phase 4: Audit Report
10. Summarize all TP findings, sorted by priority
11. Provide fix recommendations for each TP
12. FPs are automatically recorded to baseline (via validate_finding)

## Output Requirements
- Each TP/FP verdict must include detailed reasoning
- Reference specific code line numbers and data flow steps
- Consider framework built-in security mechanisms (e.g., Next.js auto-escaping)
- The `barriers` field indicates detected security barriers — verify their effectiveness
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
└── src/main.rs           # Daemon entry (PID lock + panic recovery)

core/                     # Deterministic analysis engine
├── ast/                  # AST engine (tree-sitter, 12+ languages, incremental mtime index)
├── analysis/             # Analysis modules
│   ├── taint.rs          # Taint analysis core (Source/Sink/Flow types)
│   ├── ast_taint.rs      # AST taint analyzer (CFG + worklist algorithm)
│   ├── cross_file.rs     # Cross-file analysis (call graph + function summaries)
│   ├── enhanced_dataflow.rs  # Enhanced data flow analysis
│   ├── alias.rs          # AccessPath + AliasMap (dynamic language tracking)
│   ├── async_flow.rs     # Promise chain + callback taint hints
│   ├── attack_surface.rs # Attack surface mapping
│   └── imports.rs        # Import resolution
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

tools/                    # Tool suite
├── ast_tools.rs          # AST query tools
├── taint_tools.rs        # Taint analysis tools
├── pattern_tools.rs      # Pattern detection tools
└── search_tools.rs       # Code search tools

cli/                      # Command-line client
├── commands/scan.rs      # Scan command
├── commands/analyze.rs   # Analyze command
├── commands/watch.rs     # Watch command
├── commands/daemon.rs    # Daemon management
├── commands/mcp.rs       # MCP Server (17 tools)
├── commands/rules.rs     # Rule management
└── commands/findings.rs  # Vulnerability management

rules/                    # Built-in rules (45+ YAML files)
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
| Quick scan + SCA | **~35s** | Includes OSV API network queries (first run); cached runs approach quick scan time |
| Daemon first scan | **~41s** | Full scan + result caching |
| Daemon incremental (no changes) | **~9s** | Cache hit, only file change detection |
| Deep scan (`--deep`) | **~2.5m** | AST taint analysis + cross-file tracking (22K-file large project) |

**Performance tips**:
- Quick scan merges attack surface mapping and rule scanning into a single file pass — no extra overhead
- Deep scan on large projects automatically limits candidate files (top 200 by severity) and processes in batches to prevent OOM
- Daemon mode uses content-hash caching — unchanged files are skipped in incremental scans
- SCA first-run is slower (network requests); subsequent runs use a 24h local cache
- Use `--exclude` to append exclusions for irrelevant directories and reduce scan file count

## Development

```bash
cargo build --release        # Build (ctx-audit + ctx-audit-daemon)
cargo test --workspace       # Run tests (162 tests)
cargo fmt                    # Format
cargo clippy                 # Lint
```

## Project Status

| Dimension | Status |
|-----------|--------|
| AST Taint Analysis | CFG + worklist algorithm, 12 languages, 30+ sanitizers |
| Dynamic Language Tracking | AccessPath + AliasMap + destructuring + property access + await + Promise chains |
| Cross-file Tracking | Call graph + function summaries + DFS path finding |
| TypeScript Integration | Type annotation → auto taint source (HttpRequest, Request, etc.) |
| Pattern Matching | 45+ YAML rules covering 7 injection types + 6 languages + Next.js semantic rules |
| SCA Scanner | OSV API, 4 ecosystems, local cache, configurable (disabled by default) |
| MCP Integration | 17 tools (3 coarse-grained + 7 fine-grained + 3 LLM collaboration + 4 autonomous audit) |
| LLM Output | Structured JSON with code context, taint chains, source/sink snippets, confidence |
| Custom Rules | YAML format, daemon hot-reload |
| Daemon | Incremental cache + heartbeat + auto-reconnect + panic recovery |
| Config-driven | All exclusions, severity thresholds, and context settings via config file |
| Test Coverage | 162 tests |

## License

Apache License 2.0
