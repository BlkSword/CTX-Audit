# CTX-Audit

<div align="center">

**安全分析守护进程**

**Rust 确定性分析引擎 — AST 污点追踪 + 模式匹配 + SCA**

[![Rust](https://img.shields.io/badge/Rust-2021-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=flat-square)](LICENSE)

[English](README_EN.md)

</div>

---

## CTX-Audit 是什么

CTX-Audit 是一个基于 Rust 的代码安全分析守护进程。它将确定性分析引擎（AST 污点分析、跨文件追踪、模式匹配、SCA）以常驻后台服务的形式运行，通过 IPC 为 CLI、IDE、AI agent 等消费者提供高性能安全分析能力。

**核心设计**：引擎常驻内存，AST 索引和扫描结果缓存复用。重复扫描利用 content-hash 增量检测，无变更时 **1ms** 返回结果。

```
┌───────────────────┐     IPC (TCP)     ┌──────────────────────────────┐
│   ctx-audit CLI   │ ◀──────────────▶ │   ctx-audit-daemon          │
│   scan/analyze/   │                   │                              │
│   watch/findings  │                   │   AST 索引 (tree-sitter)     │
├───────────────────┤                   │   污点分析 (Source→Sink)     │
│   IDE 插件 (未来)  │                   │   跨文件污点追踪             │
├───────────────────┤                   │   模式匹配 (Regex + Rules)  │
│   AI Agent (MCP)  │                   │   SCA 扫描 (OSV API)        │
│   Claude Code     │                   │   增量缓存 (content hash)   │
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
ctx-audit scan ./myproject --deep --rules ./my-rules/  # 自定义规则
ctx-audit analyze ./src/main.rs --symbols     # 单文件分析
ctx-audit watch ./myproject                   # 持续监控

# 使用守护进程（增量缓存，性能提升 40x+）
ctx-audit daemon start                        # 启动守护进程
ctx-audit scan ./myproject --daemon           # 通过守护进程扫描（首次全量）
ctx-audit scan ./myproject --daemon           # 再次扫描（增量，1ms 返回）
ctx-audit analyze ./src/main.rs --daemon      # 通过守护进程分析
ctx-audit daemon stop                         # 停止守护进程

# AI Agent 集成（MCP Server）
ctx-audit mcp                                 # 启动 MCP Server（stdio JSON-RPC）
```

## 命令

### `scan` — 项目扫描

```bash
ctx-audit scan ./project [OPTIONS]

OPTIONS:
  -s, --severity <级别>     按严重程度过滤 (critical, high, medium, low, info)
  -p, --pattern <模式>      按文件模式过滤 (如 *.py)
  -r, --rules <目录>        自定义规则目录
  -o, --output <文件>       输出文件路径
  -t, --threads <N>         并行线程数 (默认: 4)
  -e, --exclude <模式>      排除目录或文件（逗号分隔，如 test,*.min.js,.json）
      --deep                启用深度扫描 (AST 污点分析 + 跨文件追踪)
      --daemon              通过守护进程执行（增量缓存）
```

**扫描引擎**：

| 引擎 | 说明 |
|------|------|
| RuleScanner | 语言感知正则规则（YAML，多语言模式，33 条内置规则） |
| SCAScanner | 依赖漏洞检测（OSV API，本地缓存 24h） |
| AstTaintScanner | AST 污点分析（`--deep` 模式） |
| CrossFileTaintAnalyzer | 跨文件/跨过程污点追踪（`--deep` 模式） |

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

守护进程特性：
- **增量缓存**：content-hash 变更检测，无变更时 1ms 返回
- **心跳检测**：定期写入心跳文件，CLI 自动检测存活状态
- **自动重连**：CLI 指数退避重连，daemon 崩溃后自动恢复
- **优雅降级**：`--daemon` 连接失败时自动 fallback 到本地扫描
- **进程锁**：PID 文件 + 端口探测，防止多实例
- **Panic 自恢复**：panic hook 自动重启

### `mcp` — AI Agent 集成

```bash
ctx-audit mcp    # 启动 MCP Server（stdio JSON-RPC）
```

通过 MCP 协议暴露安全分析能力给 AI agent（如 Claude Code）。提供 **10 个工具**：

**粗粒度工具**：

| 工具 | 说明 |
|------|------|
| `security_scan` | 扫描项目，支持 deep/severity/pattern 过滤 |
| `scan_file` | 分析单个文件，返回语言/符号/污点流 |
| `daemon_status` | 查询守护进程状态 |

**细粒度工具（原子化接口）**：

| 工具 | 说明 |
|------|------|
| `get_taint_path` | 获取 source→sink 的完整污点传播路径 |
| `get_data_flow` | 追踪指定变量的定义、使用和传播 |
| `check_sanitizer` | 检查函数是否匹配已知净化器模式 |
| `list_sources` | 列出文件中所有污点源 |
| `list_sinks` | 列出文件中所有污点汇 |
| `cross_file_analysis` | 运行跨文件污点分析（调用图 + 函数摘要） |
| `get_call_graph` | 获取项目函数调用图 |

Claude Code 配置示例（`.claude/settings.json`）：

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

### `rules` — 规则管理

```bash
ctx-audit rules list                          # 列出所有已加载的规则
ctx-audit rules list --rules ./my-rules/      # 列出指定目录的规则
ctx-audit rules validate                      # 验证规则文件格式
ctx-audit rules validate --rules ./my-rules/  # 验证指定目录
```

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
| XSS（反射型/存储型） | High | CWE-79 | 污点分析 |
| SSRF | High | CWE-918 | 污点分析 |
| 不安全反序列化 | Critical | CWE-502 | 多语言规则 |
| JWT 安全问题 | High | — | 规则匹配 |
| ReDoS（正则 DoS） | Medium | CWE-1333 | 规则匹配 |
| XXE | High | CWE-611 | 规则匹配 |
| 开放重定向 | Medium | CWE-601 | 规则匹配 |
| 硬编码密码 | High | CWE-259 | 模式匹配 |
| 敏感信息泄露 | High | CWE-200 | 模式匹配 |
| 缓冲区溢出 | Critical | CWE-120 | C/C++ 规则 |
| 格式化字符串 | High | CWE-134 | C/C++ 规则 |

### 跨文件污点追踪

`--deep` 模式启用跨文件、跨过程分析：

- **调用图构建**：自动提取项目函数节点和调用关系
- **跨文件解析**：将裸函数名匹配到全局函数，建立跨文件调用边
- **函数摘要**：自底向上计算每个函数的污点传播签名
- **路径追踪**：DFS 查找 source→sink 的跨文件调用路径
- **上下文组装**：识别 callers、callees、信任边界

支持 12 种语言：Python, JavaScript, TypeScript, Java, Rust, Go, C, C++, PHP, Ruby, JSX, TSX。

### 动态语言智能追踪

针对 Python、JavaScript、TypeScript 的污点追踪增强，解决动态语言的"污点断链"问题：

| 特性 | 说明 |
|------|------|
| AccessPath | 将变量追踪为属性链路径（如 `req.body.name`），而非扁平字符串 |
| AliasMap | 解析变量别名：`const y = x` 自动继承 x 的污点状态 |
| 解构赋值 | `const { body } = req` → body 继承 req.body 的污点 |
| 属性访问 | `const x = obj.prop` → x 别名 obj.prop |
| await 表达式 | `const data = await resp.json()` → 污点传播不中断 |
| Promise 链 | `.then(data => eval(data))` → data 继承链路污点 |
| 回调提示 | `.forEach(item => ...)` 和 `.map(x => ...)` → 参数继承污点 |
| TypeScript 类型 | `(req: HttpRequest)` → 自动识别 req 为污点源 |
| 模块导出 | `module.exports.handler = fn` 和 `exports.processData = fn` 检测 |
| CommonJS 解构 | `const { body } = require('express')` → 命名符号提取 |

### 依赖漏洞 (SCA)

通过 OSV API 查询已知漏洞依赖：npm (`package.json`)、PyPI (`requirements.txt`)、crates.io (`Cargo.lock`)、Go (`go.sum`)。查询结果本地缓存 24h，减少网络请求。

### 误报控制

| 机制 | 说明 |
|------|------|
| 同行去重 | 同一 file:line 的多个扫描器发现自动合并，取最高 severity |
| 测试目录过滤 | 自动跳过 test/tests/spec 目录的攻击面发现 |
| 黑名单排除 | `--exclude` 支持目录名、文件模式 (`*.min.js`)、后缀 (`.json`) |
| 置信度评分 | 每条 finding 附带 confidence (0.0-1.0) |
| Sanitizer 识别 | 30+ 净化函数模式，降低已净化路径置信度 |
| 参数化查询检测 | 区分字符串拼接 SQL vs 参数化查询 |
| 基线抑制 | `.ctx-audit/baseline.json` 记录已确认/已忽略的 finding |
| 上下文感知 | 测试文件和配置目录中的匹配自动降低置信度 |

**默认排除列表**：`node_modules`, `.git`, `target`, `build`, `dist`, `vendor`, `*.min.js`, `*.min.css`, `*.map` 等。

```bash
# 排除示例
ctx-audit scan ./project --exclude "test,example"           # 排除目录
ctx-audit scan ./project --exclude "*.test.ts,*.spec.js"    # 排除文件模式
ctx-audit scan ./project --exclude ".json,.lock"            # 排除后缀
ctx-audit scan ./project --exclude "test,*.min.js,.env.*"   # 混合使用
```

### 框架感知规则

| 框架 | Sources | Sinks |
|------|---------|-------|
| React/Next.js | formData, cookies, headers, searchParams | dangerouslySetInnerHTML, eval, parseModel |
| Django | request.GET/POST/args | raw(), extra() |
| Spring | @RequestParam | JdbcTemplate, Runtime.exec |
| Express/Node | req.body/query/params | eval, child_process.exec |
| Laravel | Request::input, $request->get | DB::raw, DB::select |
| Rails | params[], request.env | eval, system, send_file |

## 自定义规则

CTX-Audit 支持用户编写自定义 YAML 规则，放置在 `.ctx-audit/rules/` 目录中。

**两种规则类型**：

1. **Pattern Rules** — 基于正则的代码模式匹配（如 `rules/command-injection.yaml`）
2. **Taint Rules** — 定义污点源、汇和净化函数（如 `rules/taint/generic-taint.yaml`）

**规则优先级**：`--rules` 参数 > `.ctx-audit/rules/` > 内置 `rules/`

**Daemon 热加载**：守护进程每 30 秒检测规则目录变更，自动重新加载。

详细编写指南见 [`docs/custom-rules.md`](docs/custom-rules.md) | [`docs/custom-rules-en.md`](docs/custom-rules-en.md)。

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
├── src/server.rs         # TCP 服务器，心跳检测，多客户端并发
├── src/engine.rs         # 分析引擎协调 + 增量缓存 + 跨文件分析
├── src/state.rs          # 项目状态管理
├── src/client.rs         # IPC 客户端（指数退避重连）
└── src/main.rs           # 守护进程入口（PID 锁 + panic 自恢复）

core/                     # 确定性分析引擎
├── ast/                  # AST 引擎 (tree-sitter, 12+ 语言, 增量 mtime 索引)
├── analysis/             # 分析模块
│   ├── taint.rs          # 污点分析核心（Source/Sink/Flow 类型）
│   ├── ast_taint.rs      # AST 污点分析器（CFG + worklist 算法）
│   ├── cross_file.rs     # 跨文件分析（调用图 + 函数摘要 + 上下文组装）
│   ├── enhanced_dataflow.rs  # 增强数据流分析
│   ├── alias.rs          # AccessPath + AliasMap（动态语言追踪）
│   ├── async_flow.rs     # Promise 链 + 回调污点提示
│   ├── attack_surface.rs # 攻击面映射
│   └── imports.rs        # 导入解析
├── scanner/              # 扫描器
│   ├── regex_scanner.rs  # 正则扫描
│   ├── sca_scanner.rs    # SCA 扫描（OSV API + 本地缓存）
│   └── manager.rs        # 扫描器管理
├── rules/                # YAML 规则系统
│   ├── model.rs          # Rule/RuleSet 数据模型
│   ├── taint_model.rs    # TaintRuleSet 数据模型
│   ├── loader.rs         # 规则加载器
│   ├── taint_loader.rs   # 污点规则加载器
│   └── scanner.rs        # RuleScanner
├── sarif/                # SARIF 2.1.0 输出
├── watcher/              # 文件监听 + 变更检测
└── indexing/             # 代码索引

tools/                    # 工具集
├── ast_tools.rs          # AST 查询工具
├── taint_tools.rs        # 污点分析工具
├── pattern_tools.rs      # 模式检测工具
└── search_tools.rs       # 代码搜索工具

cli/                      # 命令行客户端
├── commands/scan.rs      # 扫描命令
├── commands/analyze.rs   # 分析命令
├── commands/watch.rs     # 监控命令
├── commands/daemon.rs    # 守护进程管理
├── commands/mcp.rs       # MCP Server（11 个工具）
├── commands/rules.rs     # 规则管理
└── commands/findings.rs  # 漏洞管理

rules/                    # 内置规则（38 个 YAML 文件）
├── *.yaml                # 模式规则（26 个）
└── taint/                # 污点规则
    ├── generic-taint.yaml          # 通用污点规则
    └── frameworks/                 # 框架特定规则
        ├── react-nextjs.yaml
        ├── django.yaml
        ├── spring.yaml
        └── express-node.yaml

docs/                     # 文档
├── custom-rules.md       # 自定义规则编写指南（中文）
└── custom-rules-en.md    # Custom Rules Guide (English)
```

## CI/CD 集成

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

### 自定义规则集成

```bash
# 项目级自定义规则
mkdir -p .ctx-audit/rules/
cp my-custom-rule.yaml .ctx-audit/rules/

# 扫描时自动加载
ctx-audit scan ./myproject --deep    # 自动加载 .ctx-audit/rules/
```

## 开发

```bash
cargo build --release        # 构建（ctx-audit + ctx-audit-daemon）
cargo test --workspace       # 运行测试（155 个测试）
cargo fmt                    # 格式化
cargo clippy                 # 代码检查
```

## 项目状态

| 维度 | 状态 |
|------|------|
| AST 污点分析 | CFG + worklist 算法，12 语言，30+ sanitizer |
| 动态语言追踪 | AccessPath + AliasMap + 解构 + 属性访问 + await + Promise 链 |
| 跨文件追踪 | 调用图 + 函数摘要 + DFS 路径查找 |
| TypeScript 集成 | 类型注解 → 自动污点源识别（HttpRequest, Request 等） |
| 模式匹配规则 | 38 个 YAML 规则，覆盖 7 类注入 + 6 语言 |
| SCA 扫描 | OSV API，4 个生态，本地缓存 |
| MCP 集成 | 10 个工具（3 粗粒度 + 7 细粒度 + 1 状态查询） |
| 自定义规则 | YAML 格式，daemon 热加载 |
| 守护进程 | 增量缓存 + 心跳 + 自动重连 + panic 自恢复 |
| 测试覆盖 | 155 个测试 |

## 许可证

Apache License 2.0
