# CTX-Audit

<div align="center">

**Security Analysis Daemon**

**Rust Deterministic Analysis Engine — AST Taint Tracking + Pattern Matching + SCA**

[![Rust](https://img.shields.io/badge/Rust-2021-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=flat-square)](LICENSE)

[中文文档](README.md)

</div>

---

## What is CTX-Audit

CTX-Audit is a Rust-based code security analysis daemon. It runs a deterministic analysis engine (AST taint analysis, cross-file tracking, pattern matching, SCA) as a persistent background service, providing high-performance security analysis capabilities to consumers such as CLI, IDE, and AI agents via IPC.

**Core Design**: The engine stays resident in memory, with AST indexes and scan results cached and reused. Repeated scans use content-hash incremental detection — unchanged code returns results in **~1ms**.

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
  -s, --severity <level>    Filter by severity (critical, high, medium, low, info)
  -p, --pattern <pattern>   Filter by file pattern (e.g. *.py)
  -r, --rules <dir>         Custom rules directory
  -o, --output <file>       Output file path
  -t, --threads <N>         Number of parallel threads (default: 4)
      --deep                Enable deep scan (AST taint + cross-file analysis)
      --daemon              Execute via daemon (incremental cache)
```

**Scan Engines**:

| Engine | Description |
|--------|-------------|
| RuleScanner | Language-aware regex rules (YAML, multi-language patterns) |
| RegexScanner | Hardcoded pattern detection (passwords, keys, etc.) |
| SCAScanner | Dependency vulnerability detection (OSV API, 24h local cache) |
| AstTaintScanner | AST taint analysis (`--deep` mode) |
| CrossFileTaintAnalyzer | Cross-file / interprocedural taint tracking (`--deep` mode) |

**Output Formats**:

```bash
ctx-audit -o sarif scan ./project -o report.sarif     # SARIF 2.1.0
ctx-audit -o json scan ./project -o results.json       # JSON
ctx-audit -o markdown scan ./project -o report.md      # Markdown
```

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

Exposes security analysis capabilities to AI agents (e.g. Claude Code) via MCP protocol. Provides **11 tools**:

**Coarse-grained tools**:

| Tool | Description |
|------|-------------|
| `security_scan` | Scan project, supports deep/severity/pattern filtering |
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
ctx-audit config show
ctx-audit config set scan.threads 8
ctx-audit config list
```

## Detection Capabilities

### Code Vulnerabilities

| Vulnerability | Severity | CWE | Detection Method |
|--------------|----------|-----|-----------------|
| SQL Injection | Critical | CWE-89 | AST taint analysis |
| Command Injection | Critical | CWE-78 | Multi-lang rules + taint analysis |
| Code Injection | Critical | CWE-94 | Multi-lang rules + taint analysis |
| Path Traversal | High | CWE-22 | Multi-lang rules + taint analysis |
| XSS (Reflected/Stored) | High | CWE-79 | Taint analysis |
| SSRF | High | CWE-918 | Taint analysis |
| Unsafe Deserialization | Critical | CWE-502 | Multi-lang rules |
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

### Dependency Vulnerabilities (SCA)

Queries known vulnerable dependencies via OSV API: npm (`package.json`), PyPI (`requirements.txt`), crates.io (`Cargo.lock`), Go (`go.sum`). Results cached locally for 24h to reduce network requests.

### False Positive Control

| Mechanism | Description |
|-----------|-------------|
| Confidence scoring | Each finding includes confidence (0.0-1.0) |
| Sanitizer recognition | 30+ sanitizer patterns reduce confidence on sanitized paths |
| Parameterized query detection | Distinguishes string-concatenated SQL from parameterized queries |
| Baseline suppression | `.ctx-audit/baseline.json` records confirmed/ignored findings |
| Context-awareness | Reduced confidence for matches in test files and config dirs |

### Framework-Aware Rules

| Framework | Sources | Sinks |
|-----------|---------|-------|
| React/Next.js | formData, cookies, headers, searchParams | dangerouslySetInnerHTML, eval, parseModel |
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
├── commands/mcp.rs       # MCP Server (11 tools)
├── commands/rules.rs     # Rule management
└── commands/findings.rs  # Vulnerability management

rules/                    # Built-in rules (37 YAML files)
├── *.yaml                # Pattern rules (25 files)
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
      - run: ./target/release/ctx-audit -o sarif scan . --deep -o results.sarif
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

## Development

```bash
cargo build --release        # Build (ctx-audit + ctx-audit-daemon)
cargo test --workspace       # Run tests (123 tests)
cargo fmt                    # Format
cargo clippy                 # Lint
```

## Project Status

| Dimension | Status |
|-----------|--------|
| AST Taint Analysis | CFG + worklist algorithm, 12 languages, 30+ sanitizers |
| Cross-file Tracking | Call graph + function summaries + DFS path finding |
| Pattern Matching | 37 YAML rules covering 7 injection types + 6 languages |
| SCA Scanner | OSV API, 4 ecosystems, local cache |
| MCP Integration | 11 tools (3 coarse-grained + 7 fine-grained + 1 status) |
| Custom Rules | YAML format, daemon hot-reload |
| Daemon | Incremental cache + heartbeat + auto-reconnect + panic recovery |
| Test Coverage | 123 tests |

## License

Apache License 2.0
