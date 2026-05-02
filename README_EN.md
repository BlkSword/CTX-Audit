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

CTX-Audit is a Rust-based code security analysis daemon. It runs a deterministic analysis engine (AST taint analysis, pattern matching, SCA) as a persistent background service, providing high-performance security analysis capabilities to consumers such as CLI, IDE, and AI agents via IPC.

**Core Design**: The engine stays resident in memory, with AST indexes and scan results cached and reused. Repeated scans use content-hash incremental detection — unchanged code returns results in **~1ms**.

```
┌───────────────────┐     IPC (TCP)     ┌──────────────────────────────┐
│   ctx-audit CLI   │ ◀──────────────▶ │   ctx-audit-daemon          │
│   scan/analyze/   │                   │                              │
│   watch/findings  │                   │   AST Index (tree-sitter)    │
├───────────────────┤                   │   Taint Analysis (Source→Sink)│
│   IDE Plugin (future) │               │   Pattern Matching (Regex)   │
├───────────────────┤                   │   SCA Scanner (OSV API)      │
│   AI Agent (future)  │                │   Incremental Cache (hash)   │
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
ctx-audit analyze ./src/main.rs --symbols     # Single file analysis
ctx-audit watch ./myproject                   # Continuous monitoring

# With daemon (incremental cache, 40x+ performance boost)
ctx-audit daemon start                        # Start the daemon
ctx-audit scan ./myproject --daemon           # Scan via daemon (first run: full)
ctx-audit scan ./myproject --daemon           # Scan again (incremental, ~1ms)
ctx-audit analyze ./src/main.rs --daemon      # Analyze via daemon
ctx-audit daemon stop                         # Stop the daemon
```

## Commands

### `scan` — Project Scan

```bash
ctx-audit scan ./project [OPTIONS]

OPTIONS:
  -s, --severity <level>    Filter by severity (critical, high, medium, low, info)
  -p, --pattern <pattern>   Filter by file pattern (e.g. *.py)
  -o, --output <file>       Output file path
  -t, --threads <N>         Number of parallel threads (default: 4)
      --deep                Enable deep scan (AST taint analysis)
      --daemon              Execute via daemon (incremental cache)
```

**Scan Engines**:

| Engine | Description |
|--------|-------------|
| RuleScanner | Language-aware regex rules (YAML, multi-language patterns) |
| RegexScanner | Hardcoded pattern detection (passwords, keys, etc.) |
| SCAScanner | Dependency vulnerability detection (OSV API) |
| AstTaintScanner | AST taint analysis (`--deep` mode) |

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

The daemon runs persistently in the background, maintaining AST indexes and scan caches. It communicates with the CLI via TCP IPC (127.0.0.1:19527).

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
| XSS | High | CWE-79 | Taint analysis |
| SSRF | High | CWE-918 | Taint analysis |
| Unsafe Deserialization | Critical | CWE-502 | Multi-lang rules |
| Hardcoded Credentials | High | CWE-259 | Pattern matching |
| Sensitive Info Exposure | High | CWE-200 | Pattern matching |

### Dependency Vulnerabilities (SCA)

Queries known vulnerable dependencies via OSV API: npm (`package.json`), PyPI (`requirements.txt`), crates.io (`Cargo.lock`), Go (`go.sum`).

### Framework-Aware Rules

| Framework | Sources | Sinks |
|-----------|---------|-------|
| React/Next.js | formData, cookies, headers | dangerouslySetInnerHTML, eval |
| Django | request.GET/POST | raw(), extra() |
| Spring | @RequestParam | JdbcTemplate, Runtime.exec |
| Express/Node | req.body/query | eval, child_process.exec |

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
├── src/server.rs         # TCP server, multi-client concurrency
├── src/engine.rs         # Analysis engine coordination + incremental cache
├── src/state.rs          # Project state management
└── src/client.rs         # IPC client

core/                     # Deterministic analysis engine
├── ast/                  # AST engine (tree-sitter, 12+ languages)
├── analysis/             # Taint analysis (AST taint, cross-file, data flow)
├── scanner/              # Scanners (regex, rules, SCA)
├── rules/                # YAML rule system
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
└── commands/findings.rs  # Vulnerability management
```

## CI/CD Integration

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

## Development

```bash
cargo build --release        # Build (ctx-audit + ctx-audit-daemon)
cargo test --workspace       # Run tests
cargo fmt                    # Format
cargo clippy                 # Lint
```

## License

Apache License 2.0
