# CTX-Audit

<div align="center">

**SAST 引擎 + LLM 协作审计**

**数据流追踪 · 跨文件分析 · MCP 协议 · 证据驱动判定**

不靠规则堆砌——追踪数据从入口到危险函数的完整路径，输出结构化证据链。通过 MCP 协议让 LLM 读取攻击面、查询调用图、基于确定性证据做漏洞判定。

[![Rust](https://img.shields.io/badge/Rust-2021-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=flat-square)](LICENSE)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-blue?style=flat-square)](.github/workflows/ci.yml)

[English](README_EN.md)

</div>

---

## 为什么选择 CTX-Audit？

传统 SAST 的主要痛点：

- **规则命中不等于漏洞**：大量规则扫描结果无法回答“这条数据是否真的外部可控”。
- **跨文件链路断裂**：危险函数在 A 文件，入口参数在 B 文件，单文件扫描只能看到局部。
- **LLM 容易“脑补”**：直接把扫描结果丢给 LLM 判定，它没有可验证的调用图、数据流和中间件上下文，容易把 FP 当 TP。

CTX-Audit 的解法：

1. **先建图，再扫描**：解析 AST、构建调用图、计算函数摘要，把跨文件调用关系变成可查询的结构化数据。
2. **用证据链说话**：每个高危 finding 携带 `enclosing_function`、`evidence_refs`、source/sink 代码片段，必要时附带污点传播路径。
3. **把分析能力交给 LLM**：通过 MCP 暴露 57 个工具，LLM 可以像安全工程师一样查询调用者、追踪变量、检查中间件和 sanitizer，最后基于确定性证据给出 TP / FP / Needs Review 判定。

> **核心定位：确定性引擎负责“证据供给”，LLM 负责“语义判定”。**

---

## 目录

- [快速开始](#快速开始)
- [命令总览](#命令总览)
- [LLM 协作审计（推荐）](#llm-协作审计推荐)
- [配置文件](#配置文件)
- [检测能力](#检测能力)
- [自定义规则](#自定义规则)
- [报告与输出](#报告与输出)
- [架构](#架构)
- [项目现状与成就](#项目现状与成就)
- [开发与测试](#开发与测试)
- [许可证](#许可证)

---

## 快速开始

```bash
# 获取与构建
git clone https://github.com/BlkSword/CTX-Audit.git
cd CTX-Audit
cargo build --release

# 规则扫描：秒级批处理
ctx-audit scan ./myproject

# 深度扫描：规则 + AST 污点 + 跨文件追踪
ctx-audit scan ./myproject --deep

# 输出结构化报告
ctx-audit scan ./myproject --deep -o report.json

# 启动 MCP Server，让 LLM 参与审计（推荐）
ctx-audit mcp

# 启动增量缓存守护进程
ctx-audit daemon start
ctx-audit scan ./myproject --daemon
ctx-audit daemon stop
```

也可以安装到本机：

```bash
cargo install --path cli --locked
```

然后直接使用 `ctx-audit` 命令。

---

## 命令总览

### `scan` — 项目扫描

```
ctx-audit scan <PATH> [OPTIONS]
```

| 选项 | 说明 |
|------|------|
| `--deep` | 启用 AST 污点 + 跨文件追踪（等价 `--taint --cross-file`） |
| `--taint` | 仅启用单文件 AST 污点分析（source→sink） |
| `--cross-file` | 启用跨文件调用图 + 跨文件污点追踪（隐含 `--taint`） |
| `--sca` | 启用 SCA 依赖漏洞扫描（OSV 数据源） |
| `--min-severity <级别>` | 最低严重程度：critical / high / medium / low |
| `--min-confidence <0.0-1.0>` | 最低置信度阈值，过滤低置信度发现 |
| `-o, --output <文件>` | 输出到文件，支持 `json` / `sarif` / `llm` / `markdown` |
| `-t, --threads <N>` | 并行线程数 |
| `-r, --rules <目录>` | 自定义规则目录 |
| `-e, --exclude <模式>` | 追加排除目录，逗号分隔 |
| `--graph-output <路径>` | 单独导出调用图（供 MCP / LLM 查询） |
| `--query-mode` | 只构建调用图，不跑规则扫描 |
| `--daemon` | 通过守护进程执行，复用增量缓存 |

扫描引擎按需叠加：

```
RuleScanner（默认，快速批处理）
  → AstTaintScanner（--taint，单文件 source→sink）
    → CrossFileTaintAnalyzer（--cross-file，跨文件调用图 + 函数摘要）
      → SCA 依赖扫描（--sca）
```

### `analyze` — 单文件分析

```bash
ctx-audit analyze ./src/main.py --symbols   # 符号信息
ctx-audit analyze ./src/main.py --ast       # AST 结构
ctx-audit analyze ./src/main.py --daemon    # 复用守护进程缓存
```

### `watch` — 持续监控

```bash
ctx-audit watch ./myproject
ctx-audit watch ./myproject --output sarif --output-path .ctx-audit.sarif
```

监听文件变更，自动增量扫描并输出 SARIF 报告，适合集成到 CI 或本地持续检测流程。

### `daemon` — 增量缓存守护进程

```bash
ctx-audit daemon start
ctx-audit daemon status
ctx-audit daemon stop
```

守护进程维护 AST / 调用图 / 扫描缓存，让重复扫描和 `watch` 模式更快；`scan --daemon` 可复用同一份缓存。

### `findings` — 漏洞记录管理

```bash
ctx-audit findings list                     # 列出记录
ctx-audit findings view <id>                # 查看详情
ctx-audit findings update <id> --status fixed --note "..."
ctx-audit findings export report.json --format json
```

扫描结果可落库，便于团队跟踪状态、复现和治理。

### `rules` — 规则管理

```bash
ctx-audit rules list                        # 列出已加载规则
ctx-audit rules validate                    # 校验规则目录 YAML 合法性
```

### `config` — 配置管理

```bash
ctx-audit config show
ctx-audit config set scan.threads 8
ctx-audit config list
ctx-audit config validate
ctx-audit config reset --confirm
```

### `completion` — Shell 自动补全

```bash
ctx-audit completion bash
ctx-audit completion zsh
ctx-audit completion fish
ctx-audit completion powershell
```

### `mcp` — LLM 协作服务

```bash
ctx-audit mcp
```

启动 MCP Server（stdio JSON-RPC），由 Claude Code / Cursor / 任意 MCP 客户端管理生命周期。

> 说明：仓库中的 `agent` 子命令是通用 LLM Agent / Pipeline 框架，可用 `agent.native_pipeline.file` 或 `CTX_AUDIT_PIPELINE_FILE` 定制审计流程；日常单轮审计仍推荐 `ctx-audit mcp` 配合外部 LLM 客户端完成协作审计。

---

## LLM 协作审计（推荐）

CTX-Audit 不是“把扫描报告丢给 LLM 猜”，而是通过 MCP 协议为 LLM 提供一整套 **代码安全取证工具**：

| 能力 | 代表工具 |
|------|---------|
| 项目与攻击面 | `get_project_info`、`get_attack_surface`、`analyze_risk_patterns` |
| 扫描与发现 | `security_scan`、`scan_file`、`list_rules`、`validate_finding` |
| 调用图查询 | `query_callers`、`query_callees`、`find_call_path`、`get_call_graph` |
| 数据流追踪 | `trace_taint`、`trace_variable_flow`、`get_data_flow`、`get_taint_path` |
| 代码检索 | `read_file`、`list_files`、`search_code`、`get_code_context` |
| 安全语义 | `check_sanitizer`、`query_middleware_chain`、`list_sources`、`list_sinks` |
| 审计会话 | `start_audit_session`、`start_investigation`、`conclude_investigation`、`audit_finalize_report` |

当前 MCP Server 默认合并暴露 **57 个工具**，覆盖扫描、代码理解、调用链、污点路径、中间件、规则管理和审计会话。

### 典型工作流

```
1. security_scan → 获取 findings（含 enclosing_function + evidence_refs）
2. 对每个 high/critical finding:
   a. get_code_context → 理解代码
   b. query_callers / find_call_path → 追踪数据来源
   c. search_code → 搜索相关模式
   d. check_sanitizer / query_middleware_chain → 排除误报
   e. 判定 → TP / FP / Needs Review
3. 输出报告（证据链完整、可追溯）
```

### Claude Code 集成

`.claude/settings.json`：

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

在 Claude Code 中即可直接用自然语言驱动完整审计流程。

---

## 配置文件

配置文件位置：

- Linux：`~/.config/ctx-audit/config.toml`
- macOS：`~/Library/Application Support/ctx-audit/config.toml`
- Windows：`%APPDATA%\ctx-audit\config.toml`

首次执行 `ctx-audit config set` 时自动生成。

**常用配置**：

```toml
[scan]
threads = 4
min_severity = "medium"
exclude_patterns = ["node_modules", ".git", "target", "build", "dist", "vendor", "test", "tests"]
taint_max_candidate_files = 1000
taint_max_file_kb = 256

[daemon]
listen_addr = "127.0.0.1:19527"

[sca]
enabled = false
dev_dependencies = false
severity_threshold = "high"
```

SCA 支持 OSV 漏洞库查询、依赖忽略列表、缓存 TTL、离线失败策略等配置；所有配置键可通过 `ctx-audit config list` 查看。

---

## Agent / Pipeline 框架

`agent/` 目录提供通用 LLM Agent 基础设施和可配置审计流水线：

- 通用：LLM provider、消息驱动主循环、JSONL 会话、工具注册/白名单、子 Agent、预算/熔断、cron。
- 可配置：通过 `agent.native_pipeline.file` 或 `CTX_AUDIT_PIPELINE_FILE` 指定 Pipeline YAML。
- 输出契约可定制：TP 候选路径、verdict 字段、接受值均可配置。
- 私有方法论可保留在本地，通过 `triage.prompt_path`、`deep_review.prompt_path` 或 `judge_prompt_path` 指向私有 prompt。
- DSH 公共 `harness/` 默认使用极简模式；审计专用 `ctx-audit-auditor` preset 通过私有 overlay 提供。

```bash
# 使用自定义 Pipeline
export CTX_AUDIT_PIPELINE_FILE=templates/pipelines/custom-example.yaml
ctx-audit agent round run --target ./project
```

公共模板见 `templates/`，公开 DSH harness 即 `harness/`（脱敏、可安装、可运行、默认极简模式；私有内容通过本地 overlay 注入）。

---

## 检测能力

### 漏洞覆盖

| 类型 | CWE | 检测方式 |
|------|-----|---------|
| SQL 注入 | CWE-89 | AST 污点 + MyBatis XML `${}` + 规则 |
| 命令注入 | CWE-78 | AST 污点 + 多语言规则 |
| 代码注入 | CWE-94 | AST 污点 + 模板注入（SSTI） |
| 路径遍历 | CWE-22 | AST 污点 + 多语言规则 |
| XSS | CWE-79 | AST 污点 + sanitizer 检测 |
| SSRF | CWE-918 | 跨文件追踪 + Host Header 规则 + 重定向作用域检查 |
| 不安全反序列化 | CWE-502 | 规则 + 方法参数 source + 调用者链 |
| XXE | CWE-611 | YAML sink 规则 |
| 日志注入 | CWE-117 | 跨文件追踪 + logger sink |
| 开放重定向 | CWE-601 | 规则 + sendRedirect 检测 |
| 硬编码密码 / 密钥 | CWE-259 / CWE-798 | 模式匹配 |
| 弱哈希 | CWE-328 | YAML sink 规则 |
| 不安全 Cookie | CWE-614 | 规则 + sanitizer 检测 |
| 信任边界 | CWE-501 | 跨文件追踪 |

### 规则资产

- **80+ 条模式规则**，包含 200+ 多语言模式
- **50+ 污点 source 定义**
- **100+ 污点 sink 定义**
- **180+ sanitizer 定义**
- 框架规则覆盖 Spring / Java / Django / Flask / Express / React-Next.js / Go / PHP / C-C++ / Gradio / LLM-App / Rust 等
- 14 个审计包（audit-packs）沉淀 CWE 家族判定判据

### 跨文件追踪

- **调用图构建**：Import-Aware 别名解析 + Callback 注册 + receiver 追踪 + 类型层次虚方法分发
- **函数摘要**：自底向上计算污点签名，`param_to_calls` 多跳传播，返回值 LHS 回传
- **路径追踪**：BFS source→sink 跨文件路径查找
- **中间件建模**：Express `app.use()` / Django `MIDDLEWARE` 虚拟边
- **CPG 引擎**：路径敏感分析 + AccessPath 前缀匹配 + sanitizer 净化检测

### 误报控制

- 文件角色标签（production / test / build / vendor）
- Sanitizer 净化检测（前缀窗口 + 后向窗口 + 文件级豁免）
- 安全屏障检测（shell:false、数组参数等）
- 构造函数 FP 过滤
- 基线抑制（`.ctx-audit/baseline.json`）
- 置信度评分 + 多引擎交叉确认
- YAML 规则 schema 校验失败告警

### 语言支持

- **AST 深度分析**：Java / Python / JavaScript / TypeScript / Go / Rust / C / C++ / PHP / HTML / CSS / JSON
- **规则 / 污点扫描**：覆盖上述语言及 Ruby，文件类型覆盖 19 种扩展名

---

## 自定义规则

CTX-Audit 支持两类 YAML 自定义规则：

1. **Pattern Rules**：正则 / tree-sitter query 模式匹配，适合快速识别固定风险模式。
2. **Taint Rules**：定义 source / sink / sanitizer，驱动 AST 污点分析与跨文件追踪。

规则目录优先级：

```text
--rules 参数 > .ctx-audit/rules/ > 内置 rules/
```

示例：

```bash
# 在项目级规则目录加入自定义规则
mkdir -p .ctx-audit/rules

# 校验规则文件
ctx-audit rules validate --rules .ctx-audit/rules

# 使用自定义规则扫描
ctx-audit scan ./myproject --rules .ctx-audit/rules --deep
```

内置规则均位于 `rules/`，可直接作为编写参考。

---

## 报告与输出

| 格式 | 用途 |
|------|------|
| `json` | 机器可读，便于二次分析 / 入库 |
| `sarif` | GitHub Code Scanning / 通用 SARIF 工具链 |
| `markdown` | 人工阅读报告 |
| `llm` | 面向 LLM 的 JSON，包含 `enclosing_function`、`evidence_refs`、`taint_chain`、`confidence` 等结构化判定素材 |

`llm` 格式专门为协作审计设计：把引擎的判断依据、代码上下文和置信度一并交给 LLM，减少无依据的猜测。

---

## 架构

```
CTX-Audit
├── core/                         # 确定性分析引擎
│   ├── analysis/                 # 污点/数据流/CPG/调用图/攻击面/风险模式
│   ├── scanner/                  # 扫描器 + source/sink pattern
│   ├── rules/                    # YAML 规则引擎 + 审计包
│   ├── ast/                      # tree-sitter AST（12 语言）
│   ├── sarif/                    # SARIF 导出
│   └── scan_cache.rs             # 扫描缓存
│
├── tools/                        # MCP 工具集
│   ├── bridge.rs                 # 内置工具
│   ├── registry.rs / executor.rs # 工具注册与执行
│   ├── ast_tools.rs              # AST / 符号工具
│   ├── call_graph_tools.rs       # 调用图查询工具
│   ├── search_tools.rs           # 文本 / 正则搜索
│   ├── taint_tools.rs            # 污点追踪工具
│   └── pattern_tools.rs          # 漏洞模式工具
│
├── cli/                          # CLI 客户端
│   ├── commands/                 # scan/analyze/watch/daemon/mcp/config/...
│   ├── database/                 # findings SQLite 存储
│   └── report/                   # 报告导出
│
├── daemon/                       # 守护进程（增量缓存 / 状态服务）
│
├── rules/                        # YAML 模式规则 + taint 框架规则 + audit-packs
│
└── agent/                        # 通用 Agent / Pipeline 框架（可配置定制审计流程）
```

---

## 项目现状与成就

CTX-Audit 已从“规则扫描工具”逐步演进为一套 **真实项目驱动的混合审计能力平台**：

### 已验证的能力

- **真实项目审计轮次**：累计完成 160+ 轮真实项目定向审计，覆盖 Java / Python / Go / JavaScript / TypeScript / PHP / Rust / C/C++ 等生态。
- **漏洞验证产出**：在真实项目中确认 49 个真实漏洞（TP），其中 40 个为此前未公开的 0day，17 个 CVE 已通过复现/分析验证。
- **引擎反哺闭环**：多个真实项目的漏洞与误报直接反哺为新增规则、YAML source/sink、sanitizer 窗口语义和 AST/CPG 修复，形成“真实项目 → 引擎改进 → 回归验证”的闭环。
- **多语言确定性分析**：12 种 AST 语言、19 种扩展名、100+ sink、180+ sanitizer，支撑从 Web 应用到 C/C++ 系统软件的扫描。
- **MCP 协作审计**：默认暴露 57 个 MCP 工具，支持 LLM 在调用图、污点路径和中间件上下文上做证据驱动的漏洞判定。

### 诚实边界

- 引擎定位是 **证据供给与噪声压缩**，逻辑漏洞、授权漏洞、业务漏洞等仍高度依赖 LLM 深审与人工验证。
- 持续使用真实项目验证召回与误报，而不是只用人工构造的基准集“刷分”。
- 高置信成果均以 **实机验证 / 双向版本对照** 的方式确认。

---

## 开发与测试

```bash
cargo build --workspace --release
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

CI 会在 GitHub Actions 上自动执行构建、测试、CLI smoke 测试与 Clippy。

---

## 许可证

Apache License 2.0
