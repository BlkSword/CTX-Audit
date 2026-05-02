# CTX-Audit

<div align="center">

**安全分析守护进程**

**Rust 确定性分析引擎 — AST 污点追踪 + 模式匹配 + SCA**

[![Rust](https://img.shields.io/badge/Rust-2021-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=flat-square)](LICENSE)

</div>

---

## CTX-Audit 是什么

CTX-Audit 是一个基于 Rust 的代码安全分析守护进程。它将确定性分析引擎（AST 污点分析、模式匹配、SCA）以常驻后台服务的形式运行，通过 IPC 为 CLI、IDE、AI agent 等消费者提供高性能安全分析能力。

**核心设计**：引擎常驻内存，AST 索引和扫描结果缓存复用。重复扫描利用 content-hash 增量检测，无变更时 **1ms** 返回结果。

```
┌───────────────────┐     IPC (TCP)     ┌──────────────────────────────┐
│   ctx-audit CLI   │ ◀──────────────▶ │   ctx-audit-daemon          │
│   scan/analyze/   │                   │                              │
│   watch/findings  │                   │   AST 索引 (tree-sitter)     │
├───────────────────┤                   │   污点分析 (Source→Sink)     │
│   IDE 插件 (未来)  │                   │   模式匹配 (Regex + Rules)  │
├───────────────────┤                   │   SCA 扫描 (OSV API)        │
│   AI Agent (未来)  │                   │   增量缓存 (content hash)   │
└───────────────────┘                   └──────────────────────────────┘
```

## 快速开始

```bash
git clone https://github.com/BlkSword/CTX-Audit.git
cd CTX-Audit
cargo build --release

# 直接使用（无需守护进程）
ctx-audit scan ./myproject                    # 快速扫描
ctx-audit scan ./myproject --deep             # 深度扫描（AST 污点分析）
ctx-audit analyze ./src/main.rs --symbols     # 单文件分析
ctx-audit watch ./myproject                   # 持续监控

# 使用守护进程（增量缓存，性能提升 40x+）
ctx-audit daemon start                        # 启动守护进程
ctx-audit scan ./myproject --daemon           # 通过守护进程扫描（首次全量）
ctx-audit scan ./myproject --daemon           # 再次扫描（增量，1ms 返回）
ctx-audit analyze ./src/main.rs --daemon      # 通过守护进程分析
ctx-audit daemon stop                         # 停止守护进程
```

## 命令

### `scan` — 项目扫描

```bash
ctx-audit scan ./project [OPTIONS]

OPTIONS:
  -s, --severity <级别>     按严重程度过滤 (critical, high, medium, low, info)
  -p, --pattern <模式>      按文件模式过滤 (如 *.py)
  -o, --output <文件>       输出文件路径
  -t, --threads <N>         并行线程数 (默认: 4)
      --deep                启用深度扫描 (AST 污点分析)
      --daemon              通过守护进程执行（增量缓存）
```

**扫描引擎**：

| 引擎 | 说明 |
|------|------|
| RuleScanner | 语言感知正则规则（YAML，多语言模式） |
| RegexScanner | 硬编码模式检测（密码、密钥等） |
| SCAScanner | 依赖漏洞检测（OSV API） |
| AstTaintScanner | AST 污点分析（`--deep` 模式） |

**输出格式**：

```bash
ctx-audit -o sarif scan ./project -o report.sarif     # SARIF 2.1.0
ctx-audit -o json scan ./project -o results.json       # JSON
ctx-audit -o markdown scan ./project -o report.md      # Markdown
```

### `analyze` — 单文件分析

```bash
ctx-audit analyze ./src/main.py [OPTIONS]

OPTIONS:
  -s, --start_line <N>   起始行号 (默认: 1)
  -e, --end_line <N>     结束行号
      --ast              显示 AST 信息
      --symbols          显示符号和调用信息
      --daemon           通过守护进程执行
```

输出包含：语言检测、代码片段、函数调用、污点流。

### `watch` — 持续监控

```bash
ctx-audit watch ./project [OPTIONS]

OPTIONS:
  -s, --severity <级别>        按严重程度过滤
      --output_path <文件>     SARIF 输出路径 (默认: .ctx-audit.sarif)
      --ignore <模式>          忽略的目录，逗号分隔
      --daemon                 通过守护进程执行（推荐）
```

监听文件变更，增量扫描，持续更新 SARIF 文件。`--daemon` 模式利用守护进程缓存，每次轮询仅扫描变更文件。

### `daemon` — 守护进程管理

```bash
ctx-audit daemon start [--project <路径>]    # 启动守护进程
ctx-audit daemon status                      # 查询状态
ctx-audit daemon stop                        # 停止
```

守护进程启动后常驻后台，维护 AST 索引和扫描缓存。通过 TCP IPC（127.0.0.1:19527）与 CLI 通信。

### `findings` — 漏洞管理

```bash
ctx-audit findings list [-s critical] [--json]
ctx-audit findings view <ID>
ctx-audit findings update <ID> --status fixed
ctx-audit findings export -o report.json
```

### `config` — 配置管理

```bash
ctx-audit config show
ctx-audit config set scan.threads 8
ctx-audit config list
```

## 检测能力

### 代码漏洞

| 漏洞类型 | 严重程度 | CWE | 检测方式 |
|----------|----------|-----|----------|
| SQL 注入 | Critical | CWE-89 | AST 污点分析 |
| 命令注入 | Critical | CWE-78 | 多语言规则 + 污点分析 |
| 代码注入 | Critical | CWE-94 | 多语言规则 + 污点分析 |
| 路径遍历 | High | CWE-22 | 多语言规则 + 污点分析 |
| XSS | High | CWE-79 | 污点分析 |
| SSRF | High | CWE-918 | 污点分析 |
| 不安全反序列化 | Critical | CWE-502 | 多语言规则 |
| 硬编码密码 | High | CWE-259 | 模式匹配 |
| 敏感信息泄露 | High | CWE-200 | 模式匹配 |

### 依赖漏洞 (SCA)

通过 OSV API 查询已知漏洞依赖：npm (`package.json`)、PyPI (`requirements.txt`)、crates.io (`Cargo.lock`)、Go (`go.sum`)。

### 框架感知规则

| 框架 | Sources | Sinks |
|------|---------|-------|
| React/Next.js | formData, cookies, headers | dangerouslySetInnerHTML, eval |
| Django | request.GET/POST | raw(), extra() |
| Spring | @RequestParam | JdbcTemplate, Runtime.exec |
| Express/Node | req.body/query | eval, child_process.exec |

## 增量扫描原理

守护进程通过 content-hash 缓存实现增量扫描：

```
第一次扫描: 全量扫描 → 缓存 per-file findings + content hash
第二次扫描: 检测变更文件 → 只扫描变更部分 → 合并缓存
无变更时: 直接返回缓存结果（~1ms）
```

实测性能：

| 场景 | 耗时 | 说明 |
|------|------|------|
| 首次扫描（全量） | ~50ms | 扫描所有文件 |
| 再次扫描（无变更） | ~1ms | 缓存命中 |
| 文件变更后扫描 | ~5ms | 只扫描变更文件 |

## 架构

```
daemon/                   # 守护进程
├── src/protocol.rs       # IPC 协议 (NDJSON over TCP)
├── src/server.rs         # TCP 服务器，多客户端并发
├── src/engine.rs         # 分析引擎协调 + 增量缓存
├── src/state.rs          # 项目状态管理
└── src/client.rs         # IPC 客户端

core/                     # 确定性分析引擎
├── ast/                  # AST 引擎 (tree-sitter, 12+ 语言)
├── analysis/             # 污点分析 (AST taint, cross-file, data flow)
├── scanner/              # 扫描器 (regex, rules, SCA)
├── rules/                # YAML 规则系统
├── sarif/                # SARIF 2.1.0 输出
├── watcher/              # 文件监听 + 变更检测
└── indexing/             # 代码索引

tools/                    # 工具集
├── ast_tools.rs          # AST 查询工具
├── taint_tools.rs        # 污点分析工具
├── pattern_tools.rs      # 模式检测工具
└── search_tools.rs       # 代码搜索工具

cli/                      # 命令行客户端
├── commands/scan.rs       # 扫描命令
├── commands/analyze.rs    # 分析命令
├── commands/watch.rs      # 监控命令
├── commands/daemon.rs     # 守护进程管理
└── commands/findings.rs   # 漏洞管理
```

## CI/CD 集成

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

## 开发

```bash
cargo build --release        # 构建（ctx-audit + ctx-audit-daemon）
cargo test --workspace       # 运行测试
cargo fmt                    # 格式化
cargo clippy                 # 代码检查
```

## 许可证

Apache License 2.0
