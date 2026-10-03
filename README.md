# CTX-Audit

<div align="center">

**面向 LLM 的代码智能与取证基础设施 · 验证层驱动**

**符号跳转 · 调用层级 · 反向切片 · 框架上下文 · 高阶 MCP 工具面**

不与工业级 SAST 比拼健全性，也不做规则堆砌：引擎输出**确定性的代码拓扑事实**（谁调用谁、参数如何传递、路径上有哪些守卫），并把"没解析出来/靠猜"的部分用 `uncertainty` 显式标注；漏洞语义判定交给 LLM 与人工复核。规则语料只作为**候选种子与回归基线**，不承担真值判定。

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
3. **把分析能力交给 LLM**：MCP 默认只暴露 **9 个高阶语义能力**（符号定义/引用、调用层级、反向切片、数据流路径、sanitizer 守卫、框架上下文、项目索引、增量状态等）+ 4 个基础工具（`read_file` / `list_files` / `report_finding` / `finish_analysis`），每个响应都携带 `provenance`（文件/行/解析方式/索引版本）与 `uncertainty`（不确定度与原因）。LLM 不必在几十个细粒度工具之间做选择；遗留的细粒度工具面保留实现，用 `--legacy-tools` 显式打开。

> **核心定位：引擎负责“确定性证据供给”，LLM 负责“语义判定”，可复现验证负责“坐实”。**



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
- [能力边界与验证方法](#能力边界与验证方法)
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
ctx-audit mcp                 # 默认：高阶工具面（9 高阶能力 + read_file/list_files/finish_analysis）
ctx-audit mcp --legacy-tools  # 兼容：额外注册遗留的细粒度工具面
```

启动 MCP Server（stdio JSON-RPC），由 Claude Code / Cursor / 任意 MCP 客户端管理生命周期。
默认工具面之外的调用会返回迁移提示而不是静默执行；也可用环境变量 `CTX_AUDIT_LEGACY_TOOLS=1` 打开遗留面。

> 说明：仓库中的 `agent` 子命令是通用 LLM Agent / Pipeline 框架，可用 `agent.native_pipeline.file` 或 `CTX_AUDIT_PIPELINE_FILE` 定制审计流程；日常单轮审计仍推荐 `ctx-audit mcp` 配合外部 LLM 客户端完成协作审计。

---

## LLM 协作审计（推荐）

CTX-Audit 不是“把扫描报告丢给 LLM 猜”，而是通过 MCP 协议为 LLM 提供**外科手术式的代码切片**：模型不必读完整仓库，也不必自己拼调用关系。

默认工具面（13 个 = 9 高阶能力 + 3 基础工具 + `report_finding`）：

| 高阶能力 | 语义 | 主要返回 |
|---------|------|---------|
| `get_project_index` | 项目索引状态与语言分布 | 文件/语言统计、`build_id`、缓存命中与限额 |
| `get_symbol_definition` | 符号定义（跨文件跳转，混合精度） | 位置 + `resolver` + 置信度 |
| `get_symbol_references` | 符号引用（含 import 别名解析） | 位置列表 + 解析方式 |
| `get_call_hierarchy` | 函数上下游调用拓扑 | 结构化调用树 + 未解析边计数 |
| `slice_backward` | 从 sink/变量向前切片 | ≤ N 行相关代码 + 路径 |
| `get_dataflow_path` | source→sink 路径与经过的守卫 | 路径步骤 + barriers |
| `get_sanitizer_guards` | 变量路径上的条件分支/校验逻辑 | guard 列表 |
| `get_framework_context` | 路由 handler 的前置中间件/拦截器链 | 中间件链 + 未识别部分 |
| `get_incremental_status` | 索引状态、缓存新鲜度与 SLO 位 | 状态 + 缓存指标 |

> 每个响应都是 `{data, provenance, uncertainty}`：`provenance` 说明这条结论从哪个文件、哪一行、用哪种解析方式得出（`tree-sitter` / `file-heuristic` / 未来的 `lsp`/`engine`），`uncertainty` 说明哪里没解析出来（例如 `dynamic_dispatch_not_resolved`、`name_based_edges`）。**不假装健全**——动态派发、DI、隐式接口、同符号名歧义都会如实标注。

### 典型工作流

```
1. ctx-audit scan --deep → 规则 + AST 污点 + 跨文件候选（候选，不是结论）
2. 对每个 high/critical 候选:
   a. get_symbol_definition / get_symbol_references → 定位真实定义与消费点
   b. get_call_hierarchy / get_dataflow_path → 追数据来源与路径
   c. get_sanitizer_guards / get_framework_context → 找守卫与中间件拦截
   d. slice_backward → 只取判定需要的几十行（含 provenance/uncertainty）
   e. 判定 → TP / FP / Needs Review（证据链可追溯）
3. 候选被坐实/证伪后回写：report_finding（供后续回归使用）
```

> 规则/污点语料是**候选种子 + 回归基线**：`scan` 的输出是"值得看的候选"，不是"漏洞结论"；认定由 LLM/人 + 可复现验证给出。

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
- **定位说明**：以上规则/污点语料是**候选种子与回归基线**，用于召回可疑点与防止回归；
  漏洞认定不在引擎内完成，而是由 LLM/人 + 可复现验证给出。

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
├── core/                              # 确定性分析引擎（deepaudit-core）
│   ├── analysis/                      # 污点 / 数据流 / CPG / 调用图 / 攻击面 / 风险模式
│   ├── scanner/                       # 扫描编排、文件角色与严重度调整
│   ├── rules/                         # YAML 规则引擎（pattern → finding，含行号换算）
│   ├── ast/                           # tree-sitter AST（12 语言）与符号提取
│   ├── sarif/                         # SARIF 2.1.0 导出
│   └── indexing/                      # 代码索引
│
├── tools/                             # MCP 工具集（ctx-audit-tools）
│   ├── code_intel_tools.rs            # 高阶代码智能面（9 能力 + envelope）
│   ├── symbol_index.rs                # 符号/标识符倒排索引（定义、引用、落盘持久化）
│   ├── index_cache.rs                 # 项目索引缓存（TTL + 显式 refresh）
│   ├── text_scan.rs                   # 代码段语义（注释/字符串剥离、标识符边界）
│   ├── bridge.rs / registry.rs / executor.rs   # 工具注册与执行
│   └── ast_tools.rs / call_graph_tools.rs / search_tools.rs /
│       taint_tools.rs / pattern_tools.rs       # 细粒度工具面（Cargo feature 门控）
│
├── cli/                               # CLI 客户端（二进制 ctx-audit）
│   ├── commands/                      # scan / analyze / watch / daemon / mcp / rules / config …
│   ├── database/                      # findings SQLite 存储
│   └── report/                        # 报告导出（json / llm / sarif / markdown）
│
├── daemon/                            # 守护进程（增量缓存、状态服务、agent host）
│
├── agent/                             # Agent / Pipeline 框架（LLM provider、轮次、子代理、回放）
│
├── rules/                             # YAML 模式规则 + taint 框架规则 + audit-packs
│
└── harness/                           # 公共 DSH 编排框架（可安装；私有内容经本地 overlay 注入）
```

---

## 能力边界与验证方法

CTX-Audit 的定位是**面向 LLM 的确定性代码智能与取证基础设施**：引擎负责把代码拓扑与数据流变成可查询、可复核的结构化事实，判定由 LLM 与人工在证据之上完成。

### 引擎提供什么

- **符号与引用**：基于标识符的符号索引（定义、引用），按代码段语义（剥离注释与字符串）匹配，避免子串误配。
- **调用层级**：函数上下游调用拓扑，callee 通过标识符精确解析，并区分函数作用域内的调用点。
- **函数作用域切片**：反向切片以所在函数为界，保证包含函数头，便于阅读与引用。
- **跨文件数据流**：调用图 + 函数摘要 + 跨文件路径查找，配合 sanitizer 守卫识别。
- **框架上下文**：路由到处理函数的绑定、装饰器链、鉴权判据，以及各框架的中间件运行时顺序。
- **响应契约**：每个响应携带 `provenance`（文件 / 行 / 解析方式 / 索引版本）与 `uncertainty`（不确定度与原因）；任何结果上限都会显式上报 `total_hits` / `limit` / `truncated_at_limit`，不静默截断。

### 引擎不做什么

- **不承担漏洞真值判定**：规则与污点命中输出的是**候选与证据**，`findings` 在 JSON / LLM 报告中标记为 `candidate`。漏洞认定由 LLM / 人工结合上下文与可复现验证给出。
- **不承诺健全性**：不与工业级 SAST 比拼完备性；能力的意义在于“把可验证的事实供给判定者”，而不是替代判定。
- **能力随语言分层**：项目索引会报告每种语言的分析能力（主分析语言与启发式语言的差别，以及 `analysis_backed` 标志），不具备完整分析能力的语言会在响应中显式标注不确定度。

### 如何验证

- **夹具回归**：仓库内提供可重复的 ground-truth 夹具与基线，比较工具输出（定义、引用、调用图、切片覆盖）是否回退。
- **双向版本对照**：以“漏洞版本命中、修复版本豁免”的方式检验检测语义，而不是只看单侧命中数。
- **边界显式化**：索引的规模与单文件上限、结果条数上限均可在索引元数据与响应中读到，超出即上报。
- **不刷分**：优先使用真实代码库与可复现的对照，而非只针对人工构造样本调参。

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
