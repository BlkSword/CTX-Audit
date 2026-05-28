# CTX-Audit

<div align="center">

**LLM 原生代码安全分析引擎**

**数据流追踪 · 跨文件分析 · LLM 协作发现未知漏洞**

不靠规则堆砌——追踪每一行数据从入口到危险函数的完整路径，输出含代码上下文和污点链的结构化 JSON，直接喂给 LLM 做最终判定。也可接入 Claude Code，让 AI 读取攻击面、分析数据流、发现规则扫不到的风险。

[![Rust](https://img.shields.io/badge/Rust-2021-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=flat-square)](LICENSE)

[English](README_EN.md)

</div>

---

## CTX-Audit 是什么

CTX-Audit 是一个面向 LLM 协作审计的代码安全分析引擎。它不只是告诉你"哪里用了危险函数"——而是追踪数据从用户输入到危险操作的**完整路径**，并输出结构化的证据链，让 LLM 基于事实做漏洞判定。

**核心能力**：

- **多引擎分层扫描**：规则扫描（40 条 YAML 规则，6 语言）→ AST 污点分析（`--taint`，单文件 source→sink）→ 跨文件追踪（`--cross-file`，调用图 + 函数摘要），每个引擎可独立启用
- **数据流追踪**：基于 CPG（代码属性图）引擎，融合 CFG + AST 元数据 + 别名映射，支持路径敏感分析（条件净化检测）、属性路径前缀匹配（`req.body` → `req.body.name`）、AccessPath、AliasMap、解构赋值、Promise 链等动态语言特性，追踪 `req.body.name → eval(data)` 这样的完整污点链
- **LLM 自主审计闭环**：通过 MCP 协议暴露 17 个工具，LLM 可自主完成"项目理解 → 攻击面映射 → 扫描 → 污点追踪 → 代码审查 → TP/FP 判定 → 规则生成 → 重新验证"的完整审计流程
- **误报控制**：文件角色标签（production/test/build/vendor）、安全屏障检测（shell:false、数组参数、require.resolve 等）、置信度评分、多引擎交叉确认、基线抑制
- **增量扫描**：守护进程常驻内存，content-hash 变更检测，无变更时 ~1ms 返回
- **结构化输出**：默认输出 LLM 面向的 JSON（含代码上下文、污点链、屏障信息、文件角色），也支持 SARIF、Markdown 等

**覆盖范围**：20+ 漏洞类型（注入、XSS、SSRF、反序列化、路径遍历...），AST 分析支持 12 种语言（JS/TS/Python/Java/Rust/Go/C/C++...），文件扫描覆盖 18 种扩展名，内置 Next.js、React、Django、Spring、Express、Laravel、Rails 框架感知规则。

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
ctx-audit scan ./myproject --taint            # 规则 + AST 污点分析
ctx-audit scan ./myproject --cross-file       # 规则 + 污点 + 跨文件追踪
ctx-audit scan ./myproject --deep             # 同上（向后兼容简写）
ctx-audit scan ./myproject --taint --rules ./my-rules/  # 自定义规则 + 污点分析
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
  -s, --severity <级别>         按严重程度过滤 (critical, high, medium, low, info)
  -p, --pattern <模式>          按文件模式过滤 (如 *.py)
  -r, --rules <目录>            自定义规则目录
  -o, --output <文件>           输出文件路径或格式名 (llm/sarif/json/markdown)
  -t, --threads <N>             并行线程数 (默认: 4)
  -e, --exclude <模式>          追加排除目录或文件（逗号分隔，如 bench,*.min.js）
      --min-severity <级别>     覆盖配置文件的最低严重程度阈值
      --taint                   启用 AST 污点分析 (单文件 source→sink 追踪)
      --cross-file              启用跨文件污点追踪 (隐含 --taint)
      --deep                    等同于 --taint --cross-file
      --daemon                  通过守护进程执行（增量缓存）
      --sca                     启用 SCA 依赖漏洞扫描
```

**扫描引擎**：

| 引擎 | 说明 | 启用方式 |
|------|------|----------|
| RuleScanner | 语言感知正则规则（YAML，多语言模式，40 条内置规则） | 默认启用 |
| SCAScanner | 依赖漏洞检测（OSV API，默认关闭，`--sca` 或配置启用） | `--sca` |
| AstTaintScanner | AST 污点分析（单文件 source→sink 追踪） | `--taint` |
| CrossFileTaintAnalyzer | 跨文件/跨过程污点追踪 | `--cross-file` |

**输出格式**：

默认输出为 `llm`（面向 LLM 的结构化 JSON），包含代码上下文、污点链、置信度等完整信息。也支持其他格式：

```bash
ctx-audit scan ./project -o llm                     # 自动生成 ctx-audit-llm-2026-05-24.json
ctx-audit scan ./project -o sarif                   # 自动生成 ctx-audit-sarif-2026-05-24.sarif
ctx-audit scan ./project -o json                    # 自动生成 ctx-audit-json-2026-05-24.json
ctx-audit scan ./project -o report.json             # 指定文件名 report.json
ctx-audit scan ./project -o /tmp/results.sarif      # 指定完整路径
```

**LLM 输出结构**（默认格式）：

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
      "description": "检测 Host header 直接用于 URL 构造导致的 SSRF ...",
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
      "file": "packages/next/src/server/lib.launch-editor.ts",
      "line": 45,
      "file_role": "production",
      "barriers": ["spawn_default_no_shell", "array_args"],
      "reasoning_hint": "Matched command-injection pattern in production context"
    }
  ]
}
```

关键字段：`file_role` 标识生产/测试/构建代码；`barriers` 列出检测到的安全屏障；`reasoning_hint` 说明标记原因；`code_context` 中 `>>` 标识匹配行（±3 行上下文）；`taint_chain` 和 `source_snippet`/`sink_snippet` 仅 `--taint` 发现包含。

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

通过 MCP 协议暴露安全分析能力给 AI agent（如 Claude Code）。提供 **17 个工具**：

**粗粒度工具**：

| 工具 | 说明 |
|------|------|
| `security_scan` | 扫描项目，支持 deep/severity/file_role_filter/min_severity 过滤 |
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

**LLM 协作工具（0-day 发现支持）**：

| 工具 | 说明 |
|------|------|
| `get_attack_surface` | 映射项目攻击面（入口点、风险评分、信任边界、框架检测） |
| `analyze_risk_patterns` | 分析架构级风险模式（未验证输入→反序列化、未认证→特权操作等） |
| `add_custom_rule` | 动态注入自定义规则（LLM 生成 YAML 规则实时生效） |

**LLM 自主审计工具**：

| 工具 | 说明 |
|------|------|
| `get_code_context` | 读取源代码指定行周围上下文（验证发现） |
| `get_project_info` | 项目概览：语言分布、框架、目录结构、入口点统计 |
| `validate_finding` | 记录审计结论（TP/FP + 推理原因），自动抑制 FP |
| `list_rules` | 查看当前加载的所有安全规则 |

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
ctx-audit config show                    # 显示当前配置
ctx-audit config show sca.enabled        # 查看单个配置
ctx-audit config set sca.enabled true    # 设置配置
ctx-audit config remove scan.severity    # 恢复默认值
ctx-audit config list                    # 列出所有配置键
ctx-audit config validate                # 验证配置
ctx-audit config reset --confirm         # 重置为默认
```

## 配置文件

配置文件位于系统配置目录：

| 系统 | 路径 |
|------|------|
| Windows | `%APPDATA%\ctx-audit\config.toml` |
| macOS | `~/Library/Application Support/ctx-audit/config.toml` |
| Linux | `~/.config/ctx-audit/config.toml` |

首次使用不需要手动创建配置文件——运行 `ctx-audit config set` 时会自动生成。

**完整配置示例**（`config.toml`）：

```toml
[scan]
threads = 4                        # 并行线程数
include_tests = false              # 是否包含测试文件
max_file_size_mb = 10              # 单文件最大扫描大小 (MB)
memory_budget_mb = 500             # 扫描内存预算 (MB)
batch_size = 100                   # 并行批次大小
line_tolerance = 3                 # 去重行容差 (±N 行内合并)
severity = "medium"                # 精确严重程度过滤 (可选)
min_severity = "medium"            # 最低严重程度阈值 (过滤 low/info)
context_lines = 3                  # 代码上下文行数 (±N 行)
deep = false                       # 是否默认启用深度扫描

# 排除目录/文件模式（完全由配置文件控制，首次运行生成默认值）
exclude_patterns = [
  "node_modules", ".git", "target", "build", "dist", "vendor",
  "__pycache__", ".gradle", ".idea", ".vscode", ".cache",
  "bower_components", ".next", ".nuxt", "coverage",
  "test", "tests", "__tests__", "spec", "fixtures", "e2e",
  "examples", "example", "scripts",
  "*.min.js", "*.min.css", "*.bundle.js", "*.chunk.js",
  "*.map", ".env.*", "*.test.*", "*.spec.*",
]
exclude_extra = []                 # 额外排除项（追加到 exclude_patterns）

[output]
format = "llm"                     # 输出格式 (llm/json/sarif/markdown/text)
color = true                       # 是否显示颜色
verbose = false                    # 是否显示详细输出

[advanced]
enable_cache = true                # 是否启用缓存
log_level = "info"                 # 日志级别 (trace/debug/info/warn/error)

[sca]
enabled = false                    # 是否启用 SCA 依赖扫描
dev_dependencies = true            # 是否包含 devDependencies
severity_threshold = "low"         # 最低报告严重程度
cache_ttl_hours = 24               # 缓存 TTL (小时)
osv_timeout_sec = 30               # OSV API 超时 (秒)
fail_offline = false               # 离线时是否报错
ignore_vulns = []                  # 忽略的漏洞 ID，如 ["CVE-2024-1234"]
ignore_packages = []               # 忽略的包，如 ["lodash@4.17.21"]
ignore_ecosystems = []             # 跳过的生态，如 ["Go"]

[sca.severity_mapping]
critical = 9.0                     # CVSS ≥ 9.0 → critical
high = 7.0                         # CVSS ≥ 7.0 → high
medium = 4.0                       # CVSS ≥ 4.0 → medium

[daemon]
listen_addr = "127.0.0.1:19527"    # 监听地址
rules_reload_interval_secs = 30    # 规则热重载间隔 (秒)
ast_idle_secs = 3600               # AST Engine 空闲超时 (秒)
ast_max_memory_mb = 512            # AST Engine 最大总内存 (MB)
scan_cache_idle_secs = 7200        # Scan Cache 空闲超时 (秒)
heartbeat_interval_secs = 5        # 心跳间隔 (秒)
reconnect_max_retries = 3          # 最大重连重试次数
reconnect_base_delay_ms = 200      # 重连基础延迟 (毫秒)
```

### 基线抑制

通过 `.ctx-audit/baseline.json` 文件忽略已确认的误报：

```json
{
  "ignored": {
    "src/utils.ts:10:CWE-79": "误报：参数已转义",
    "src/api.ts:45:CWE-89": "已确认：使用参数化查询"
  }
}
```

key 格式为 `文件路径:行号:漏洞类型`，value 为忽略原因。扫描时会自动跳过基线中记录的发现。

### 项目级配置

每个项目可在 `.ctx-audit/` 目录下放置项目级文件：

| 文件 | 用途 |
|------|------|
| `.ctx-audit/rules/` | 项目级自定义规则（YAML），优先于内置规则 |
| `.ctx-audit/baseline.json` | 基线抑制文件 |
| `.ctx-audit/cache/` | 缓存目录（AST、SCA 等） |

## 检测能力

### 代码漏洞

| 漏洞类型 | 严重程度 | CWE | 检测方式 |
|----------|----------|-----|----------|
| SQL 注入 | Critical | CWE-89 | AST 污点分析 |
| 命令注入 | Critical | CWE-78 | 多语言规则 + 污点分析 |
| 代码注入 | Critical | CWE-94 | 多语言规则 + 污点分析 |
| 路径遍历 | High | CWE-22 | 多语言规则 + 污点分析 |
| XSS（反射型/存储型） | High | CWE-79 | 污点分析 |
| SSRF | High | CWE-918 | 污点分析 + Host Header 规则 |
| 不安全反序列化 | Critical | CWE-502 | 多语言规则 |
| Host Header SSRF | High | CWE-918 | 语义规则 |
| 原型链污染 | High | CWE-1321 | 语义规则 |
| 无边界流读取 (DoS) | High | CWE-400 | 语义规则 |
| 缓存投毒 | Medium | CWE-444 | 语义规则 |
| Header 注入 | Medium | CWE-639 | 语义规则 |
| JWT 安全问题 | High | — | 规则匹配 |
| ReDoS（正则 DoS） | Medium | CWE-1333 | 规则匹配 |
| XXE | High | CWE-611 | 规则匹配 |
| 开放重定向 | Medium | CWE-601 | 规则匹配 |
| 硬编码密码 | High | CWE-259 | 模式匹配 |
| 敏感信息泄露 | High | CWE-200 | 模式匹配 |
| 缓冲区溢出 | Critical | CWE-120 | C/C++ 规则 |
| 格式化字符串 | High | CWE-134 | C/C++ 规则 |

### 跨文件污点追踪

`--cross-file`（或 `--deep`）启用跨文件、跨过程分析：

- **调用图构建**：自动提取项目函数节点和调用关系
- **跨文件解析**：将裸函数名匹配到全局函数，建立跨文件调用边
- **函数摘要**：自底向上计算每个函数的污点传播签名
- **路径追踪**：DFS 查找 source→sink 的跨文件调用路径
- **上下文组装**：识别 callers、callees、信任边界
- **CPG 自动摘要**：Stage B 构建的 FunctionCPG 缓存传递给 Stage C，自动生成精确函数摘要（替代启发式猜测），提供准确的 sink 行号和参数→返回值传播信息
- **路径敏感分析**：条件分支感知的污点传播，`if (isSafe(x))` 的 True 分支自动标记净化，减少条件保护下的误报
- **属性路径追踪**：污点状态以 AccessPath 为 key，支持前缀匹配——`req.body` 被污染时 `req.body.name` 自动检出，`req.body.name` 不影响 `req.body.email`

支持 12 种语言：JavaScript/JSX, TypeScript/TSX, Python, Java, Rust, Go, C, C++, HTML, CSS, JSON。

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

通过 OSV API 查询已知漏洞依赖：npm (`package.json`)、PyPI (`requirements.txt`)、crates.io (`Cargo.lock`)、Go (`go.sum`)。

> **注意**：SCA 扫描默认关闭。首次扫描需要向 `osv.dev` 发送网络请求，依赖较多的项目（如大型 Cargo.lock）可能增加数秒到数十秒的扫描时间。后续扫描通过本地缓存（默认 24h TTL）加速。

**启用方式**（二选一）：

```bash
# 方式 1：单次扫描启用
ctx-audit scan ./project --sca

# 方式 2：配置文件持久启用
ctx-audit config set sca.enabled true
```

**配置示例**（`config.toml` 中的 `[sca]` 段）：

```toml
[sca]
enabled = true
severity_threshold = "medium"      # 只报告 medium 及以上
dev_dependencies = false           # 不扫描 devDependencies
cache_ttl_hours = 48               # 缓存 48 小时
osv_timeout_sec = 60               # API 超时 60 秒
fail_offline = false               # 网络失败静默跳过
ignore_vulns = ["CVE-2024-1234"]   # 忽略指定漏洞 ID
ignore_packages = ["lodash@4.17.21"]  # 忽略指定包
ignore_ecosystems = ["Go"]         # 跳过指定生态

[sca.severity_mapping]
critical = 9.0                     # CVSS ≥ 9.0 → critical
high = 7.0                         # CVSS ≥ 7.0 → high
medium = 4.0                       # CVSS ≥ 4.0 → medium（低于此值 → low）
```

**离线方案**：

SCA 扫描依赖 `api.osv.dev` 在线查询。离线环境下可：
1. 利用本地缓存：首次联网扫描后，缓存文件（`.ctx-audit/cache/sca_cache.json`）在 TTL 内可离线使用
2. 预下载 OSV 数据库：OSV 提供公开 GCS bucket（`gs://osv-vulnerabilities/`），可按生态下载全量漏洞数据并定期同步。详见 https://osv.dev/docs/#data-access

### 误报控制

| 机制 | 说明 |
|------|------|
| 同行去重 | 同一 file:line 的多个扫描器发现自动合并，取最高 severity |
| 文件角色分类 | 自动标记 production/test/build/vendor，按角色调整严重程度 |
| 安全屏障检测 | 检测 shell:false、数组参数、require.resolve 等屏障，自动降级 |
| 测试目录过滤 | 自动跳过 test/tests/spec 目录的攻击面发现 |
| 黑名单排除 | `--exclude` 支持目录名、文件模式 (`*.min.js`)、后缀 (`.json`) |
| 置信度评分 | 每条 finding 附带 confidence (0.0-1.0)，多引擎交叉确认时提升至 0.9 |
| Sanitizer 识别 | 30+ 净化函数模式，降低已净化路径置信度 |
| 参数化查询检测 | 区分字符串拼接 SQL vs 参数化查询 |
| 基线抑制 | `.ctx-audit/baseline.json` 记录已确认/已忽略的 finding |
| 上下文感知 | 测试文件和配置目录中的匹配自动降低置信度 |
| 路径敏感净化 | `if (isSafe(x))` 条件保护下的 True 分支自动标记净化，置信度降至 0.3；部分净化路径置信度 0.5 |
| 属性路径隔离 | `req.body.name` 的污点不影响 `req.body.email`（AccessPath 前缀匹配，不同属性不交叉） |

**配置驱动的排除**：所有排除项通过 `config.toml` 中的 `scan.exclude_patterns` 控制，首次运行使用代码默认值，用户可随时修改。`--exclude` CLI 参数为追加（不替换配置文件）。

```bash
# 查看当前排除列表
ctx-audit config show scan.exclude_patterns

# 修改排除列表（完全替换）
ctx-audit config set scan.exclude_patterns '["node_modules",".git","target","test","*.min.js"]'

# 追加排除（不替换）
ctx-audit config set scan.exclude_extra '["scripts","bench"]'

# CLI 临时追加
ctx-audit scan ./project --exclude "temp,vendor"
```

### 框架感知规则

| 框架 | Sources | Sinks |
|------|---------|-------|
| React/Next.js | formData, cookies, headers, searchParams, params, useSearchParams, req.headers.host, x-forwarded-host | dangerouslySetInnerHTML, eval, parseModel, redirect, setHeader, revalidatePath, revalidateTag, NextResponse.redirect |
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

## LLM 协作审计

CTX-Audit 通过 MCP 协议暴露 **17 个工具**，让 LLM（Claude Code / Cursor / 任何支持 MCP 的 Agent）完全自主驱动安全审计流程——从项目理解、扫描、污点追踪、代码审查到审计结论，全程无需人工干预。

### 接入方式

在 Claude Code 的配置文件（`.claude/settings.json`）中添加：

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

### 自主审计工作流

```
1. get_project_info      → 了解项目：语言、框架、文件结构、入口点数量
2. get_attack_surface    → 映射攻击面：高风险入口点、信任边界、未认证路由
3. security_scan         → 全量扫描：规则匹配 + AST 污点分析（--deep）
4. 过滤筛选              → file_role_filter="production", min_severity="high"
5. 逐条审计:
   ├─ get_code_context   → 阅读发现点周围的源代码
   ├─ get_taint_path     → 追踪 source→sink 完整数据流
   ├─ check_sanitizer    → 验证是否存在有效的净化函数
   ├─ list_sources/sinks → 查看文件中所有污点源和汇
   └─ validate_finding   → 记录审计结论（TP/FP）及推理过程
6. add_custom_rule       → 针对发现的 0-day 模式动态生成规则
7. security_scan         → 使用新规则重新扫描验证
```

### MCP 工具清单

#### 扫描与检测

| 工具 | 说明 |
|------|------|
| `security_scan` | 项目扫描，支持 deep/severity/file_role_filter/min_severity 过滤 |
| `scan_file` | 单文件分析：语言检测、符号提取、污点流 |
| `get_project_info` | 项目概览：语言分布、框架检测、目录结构、入口点统计 |
| `list_rules` | 查看当前加载的所有安全规则（含自定义规则） |

#### 污点分析与数据流

| 工具 | 说明 |
|------|------|
| `get_taint_path` | 获取 source→sink 完整污点传播路径（含每步代码片段） |
| `get_data_flow` | 追踪指定变量的定义、使用、传播和污点状态 |
| `check_sanitizer` | 检查函数是否匹配已知净化器模式 |
| `list_sources` | 列出文件中所有污点源（用户输入点） |
| `list_sinks` | 列出文件中所有污点汇（危险函数调用） |
| `cross_file_analysis` | 跨文件污点追踪（调用图 + 函数摘要 + 路径查找） |
| `get_call_graph` | 获取项目函数调用图 |

#### 攻击面与风险模式

| 工具 | 说明 |
|------|------|
| `get_attack_surface` | 映射攻击面：入口点、风险评分、信任边界、框架检测 |
| `analyze_risk_patterns` | 检测架构级风险模式（未验证输入→反序列化等） |

#### LLM 审计闭环

| 工具 | 说明 |
|------|------|
| `get_code_context` | 读取源代码指定行周围上下文（用于验证发现） |
| `validate_finding` | 记录审计结论：TP/FP + 推理原因，自动写入 baseline 抑制 FP |
| `add_custom_rule` | 动态注入自定义规则（YAML 格式，实时生效） |
| `daemon_status` | 查询守护进程状态 |

### 提示词示例

在 Claude Code 中配置 MCP 后，可直接使用以下系统提示词驱动自主审计：

```
你是一名安全审计专家，负责对目标项目进行完全自主的安全审计。
你可以使用 CTX-Audit 工具进行扫描和分析。

## 审计流程

### 第一阶段：项目理解
1. 调用 `get_project_info` 了解项目的技术栈和结构
2. 调用 `get_attack_surface` 映射攻击面，识别高风险入口点
3. 调用 `list_rules` 确认可用的检测规则

### 第二阶段：深度扫描
4. 调用 `security_scan` 并设置 `deep: true`, `file_role_filter: "production"`,
   `min_severity: "high"` 进行生产代码深度扫描
5. 对每个 critical 发现：
   - 调用 `get_code_context` 阅读周围代码，理解完整上下文
   - 调用 `get_taint_path` 追踪完整数据流（source→sink）
   - 调用 `check_sanitizer` 验证是否存在净化函数
   - 综合判断是否为真实漏洞（TP）或误报（FP）
   - 调用 `validate_finding` 记录审计结论

### 第三阶段：0-day 探索
6. 调用 `analyze_risk_patterns` 检测架构级风险模式
7. 对高风险模式调用 `cross_file_analysis` 进行跨文件追踪
8. 如果发现规则未覆盖的新漏洞模式，调用 `add_custom_rule` 创建规则
9. 使用新规则重新扫描验证

### 第四阶段：审计报告
10. 汇总所有 TP 发现，按优先级排序
11. 为每个 TP 提供修复建议
12. 将 FP 记录到 baseline（validate_finding 自动处理）

## 输出要求
- 每条发现的 TP/FP 判定必须附上详细推理过程
- 引用具体的代码行号和数据流步骤
- 考虑框架自带的安全机制（如 Next.js 的自动转义）
- barriers 字段表示检测到的安全屏障，需验证其有效性
```

### 审计输出示例

```
## 安全审计报告

### 项目概况
- **项目**: next.js (TypeScript/JavaScript)
- **源文件**: 22,000+
- **框架**: Next.js, React
- **攻击面**: 156 个入口点 (23 个未认证)

### 扫描结果
- **扫描模式**: deep (AST 污点分析 + 跨文件追踪)
- **总发现**: 3014 → 过滤后: 229 条生产代码发现
- **Critical**: 6 | **High**: 126 | **Medium**: 97

### Critical 发现审计

#### 1. [TP] SSRF via Host Header — `api-resolver.ts:302`
- **数据流**: req.headers.host → `https://${host}/api/...` → fetch()
- **代码上下文**:
  ```typescript
  >> 302 | const res = await fetch(`https://${req.headers.host}${urlPath}`)
  ```
- **推理**: Host header 完全由客户端控制，直接拼接进 fetch URL，无验证
- **屏障**: 无（barriers 为空）
- **建议**: 使用白名单验证 Host header，或使用 `req.headers.host` 之前检查允许的域名列表

#### 2. [FP] Command Injection — `launch-editor.ts:45`
- **数据流**: editorPath → spawn(args)
- **屏障**: spawn_default_no_shell + array_args
- **推理**: Node.js spawn() 默认 shell:false，且参数为数组，攻击者无法注入额外命令
- **结论**: 已自动降级为 medium，确认为 FP

### 已生成自定义规则
- `llm-generated-nextjs-host-ssrf.yaml` — 检测 Next.js 中的 Host Header SSRF 变体
```

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
├── src/lib.rs            # 库入口（公共接口导出）
└── src/main.rs           # 守护进程入口（PID 锁 + panic 自恢复）

core/                     # 确定性分析引擎
├── lib.rs                # 库入口（分层导出: scanning/taint/ast_api/attack_surface）
├── ast/                  # AST 引擎 (tree-sitter, 12 语言, 18 种扩展名, 增量 mtime 索引)
├── diff/                 # 差异引擎
│   ├── engine.rs         # DiffEngine（代码差异计算）
│   ├── git_integration.rs # Git 集成（diff/commit 解析）
│   └── types.rs          # 差异类型定义
├── analysis/             # 分析模块
│   ├── taint.rs          # 污点分析核心（Source/Sink/Flow 类型）
│   ├── ast_taint.rs      # AST 污点分析器（CFG + worklist + CPG 路径敏感算法）
│   ├── cross_file.rs     # 跨文件分析（调用图 + 函数摘要 + CPG 缓存）
│   ├── enhanced_dataflow.rs  # 增强数据流分析（CFG + 边类型）
│   ├── enhanced_taint.rs # 增强污点分析器
│   ├── dataflow.rs       # 基础数据流分析
│   ├── alias.rs          # AccessPath + AliasMap（动态语言追踪）
│   ├── async_flow.rs     # Promise 链 + 回调污点提示
│   ├── attack_surface.rs # 攻击面映射
│   ├── risk_patterns.rs  # 架构级风险模式检测
│   ├── cache.rs          # 分析缓存（AST/Taint/Analysis 缓存管理）
│   ├── cpg/              # 代码属性图引擎 (CPG)
│   │   ├── mod.rs        # FunctionCPG, CPGNodeMeta, ConditionInfo, FunctionSignature
│   │   ├── builder.rs    # CPGBuilder (AST→CPG 构建 + 条件提取 + 别名构建)
│   │   ├── query.rs      # CodePropertyGraph 统一查询 API
│   │   ├── path_taint.rs # PathSensitiveState + AccessPath 前缀匹配 + 分支合并
│   │   └── summary.rs    # CPG 自动函数摘要生成
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

tools/                    # MCP 工具集
├── lib.rs                # 模块入口（工具类别定义）
├── registry.rs           # 工具注册中心
├── executor.rs           # 工具执行引擎
├── bridge.rs             # 内置工具实现
├── external.rs           # 外部工具适配（Semgrep/Bandit/Gitleaks）
├── ast_tools.rs          # AST 查询工具
├── taint_tools.rs        # 污点分析工具
├── pattern_tools.rs      # 模式检测工具
└── search_tools.rs       # 代码搜索工具

cli/                      # 命令行客户端
├── main.rs               # CLI 入口
├── config.rs             # 配置管理（TOML 读写 + 路径解析）
├── output.rs             # 输出格式化（LLM/SARIF/JSON/Markdown/Text）
├── terminal.rs           # 终端 UI（进度条 + 彩色输出）
├── index.rs              # 文件索引
├── commands/             # 命令实现
│   ├── scan.rs           # 扫描命令（含进度回调 + 增量模式）
│   ├── analyze.rs        # 单文件分析命令
│   ├── watch.rs          # 持续监控命令
│   ├── daemon.rs         # 守护进程管理命令
│   ├── mcp.rs            # MCP Server（17 个工具）
│   ├── rules.rs          # 规则管理命令
│   ├── config.rs         # 配置管理命令
│   └── findings.rs       # 漏洞管理命令
├── database/             # 漏洞数据库
│   ├── schema.rs         # SQLite schema 定义
│   ├── models.rs         # 数据模型
│   ├── queries.rs        # 查询接口
│   └── migrations.rs     # 数据库迁移
└── report/               # 报告导出
    └── exporter.rs       # 多格式报告导出

rules/                    # 内置规则（40 模式 + 5 污点）
├── *.yaml                # 模式规则（含 Next.js 语义规则）
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
      - run: ./target/release/ctx-audit -o sarif scan . --deep -o results.sarif   # SARIF for GitHub
      # 默认 -o llm 可直接输出 LLM 格式给后续 AI 分析
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

## 性能

以下基准基于 [Next.js](https://github.com/vercel/next.js) 仓库（~22,000 源文件，243MB），排除 test/bench/docs 目录，release 构建，Windows 10。

| 模式 | 耗时 | 说明 |
|------|------|------|
| 快速扫描 | **~10s** | 规则扫描 + 攻击面映射（单次文件遍历） |
| `--taint` | **~1m** | 规则 + AST 污点分析（单文件 source→sink） |
| `--deep` / `--cross-file` | **~2.5m** | 规则 + 污点 + 跨文件追踪（22K 文件超大项目） |
| 快速扫描 + SCA | **~35s** | 含 OSV API 网络查询（首次），缓存后接近快速扫描 |
| Daemon 首次扫描 | **~41s** | 全量扫描 + 结果缓存 |
| Daemon 增量扫描（无变更） | **~9s** | 命中缓存，仅做文件变更检测 |

**性能提示**：
- 快速扫描已合并攻击面映射与规则扫描为单次文件遍历，无需额外开销
- 大型项目深度扫描自动限制候选文件数（top 200 by severity），分批处理避免 OOM
- 守护进程模式下增量扫描利用 content-hash 缓存，无变更文件跳过扫描
- SCA 首次扫描较慢（网络请求），后续使用 24h 本地缓存
- `--exclude` 排除不关心的目录可显著减少扫描文件数

## 开发

```bash
cargo build --release        # 构建（ctx-audit + ctx-audit-daemon）
cargo test --workspace       # 运行测试（184 个测试）
cargo fmt                    # 格式化
cargo clippy                 # 代码检查
```

## 项目状态

| 维度 | 状态 |
|------|------|
| CPG 分析引擎 | CFG + AST 元数据 + 别名映射融合，路径敏感污点传播，AccessPath 属性路径追踪，12 语言 AST，30+ sanitizer |
| 动态语言追踪 | AccessPath + AliasMap + 解构 + 属性访问 + await + Promise 链 |
| 跨文件追踪 | 调用图 + 函数摘要 + DFS 路径查找（`--cross-file`） + CPG 自动函数摘要（精确 sink 行号，替代启发式） |
| TypeScript 集成 | 类型注解 → 自动污点源识别（HttpRequest, Request 等） |
| 模式匹配规则 | 40 条模式规则 + 5 条污点规则，覆盖 6 语言 + 6 框架 |
| 误报控制 | 文件角色分类 + 安全屏障检测 + 多引擎置信度融合 + 基线抑制 |
| SCA 扫描 | OSV API，4 个生态，本地缓存，可配置（默认关闭） |
| MCP 集成 | 17 个工具（3 扫描 + 7 污点 + 3 风险模式 + 4 自主审计） |
| LLM 输出 | 结构化 JSON：代码上下文 + 污点链 + 文件角色 + 屏障 + 置信度 |
| 自定义规则 | YAML 格式，daemon 热加载 |
| 守护进程 | 增量缓存 + 心跳 + 自动重连 + panic 自恢复 |
| 配置驱动 | 所有排除项、严重程度阈值、引擎开关均可通过 config.toml 控制 |
| 测试覆盖 | 184 个测试 |

## 许可证

Apache License 2.0
