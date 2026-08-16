# CTX-Audit

<div align="center">

**SAST 引擎 + LLM 协作审计**

**数据流追踪 · 跨文件分析 · MCP 协议 · 证据驱动判定**

不靠规则堆砌——追踪数据从入口到危险函数的完整路径，输出结构化证据链。通过 MCP 协议让 Claude/LLM 读取攻击面、查询调用图、基于确定性证据做漏洞判定。

[![Rust](https://img.shields.io/badge/Rust-2021-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=flat-square)](LICENSE)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-blue?style=flat-square)](.github/workflows/ci.yml)

[English](README_EN.md)

</div>

---

## 目录

- [快速开始](#快速开始)
- [命令](#命令)
- [LLM 协作审计](#llm-协作审计推荐方式)
- [配置文件](#配置文件)
- [检测能力](#检测能力)
- [架构](#架构)
- [基准测试](#基准测试)
- [项目状态](#项目状态)

---

## 快速开始

```bash
git clone https://github.com/BlkSword/CTX-Audit.git
cd CTX-Audit
cargo build --release

# 扫描
ctx-audit scan ./myproject                    # 规则扫描
ctx-audit scan ./myproject --deep             # 规则 + AST 污点 + 跨文件追踪
ctx-audit scan ./myproject --deep -o report.json

# 单文件分析
ctx-audit analyze ./src/main.rs --symbols

# 持续监控
ctx-audit watch ./myproject

# MCP Server（LLM 协作）
ctx-audit mcp

# 守护进程（增量缓存）
ctx-audit daemon start
ctx-audit scan ./myproject --daemon
ctx-audit daemon stop
```

## 命令

### `scan` — 项目扫描

```bash
ctx-audit scan ./project [OPTIONS]

OPTIONS:
  --deep                 启用 AST 污点 + 跨文件追踪
  --taint                 仅启用 AST 污点分析
  --cross-file            仅启用跨文件追踪
  --min-severity <级别>    最低严重程度 (critical/high/medium/low)
  -o, --output <文件>      输出文件 (llm/json/sarif/markdown)
  -t, --threads <N>        并行线程数
  -r, --rules <目录>        自定义规则目录
  -e, --exclude <模式>      追加排除
  --daemon                 通过守护进程执行
  --sca                    启用 SCA 依赖扫描
```

**扫描引擎**: RuleScanner（默认）→ AstTaintScanner（`--taint`，单文件 source→sink）→ CrossFileTaintAnalyzer（`--cross-file`，跨文件调用图 + 函数摘要）。每个引擎可独立启用。

### `analyze` / `watch` / `daemon`

```bash
ctx-audit analyze ./src/main.py --symbols   # 单文件分析
ctx-audit watch ./myproject                 # 持续监控
ctx-audit daemon start                      # 启动守护进程
ctx-audit daemon status                     # 查询状态
ctx-audit daemon stop                       # 停止
```

### `mcp` — LLM 协作（推荐）

```bash
ctx-audit mcp    # 启动 MCP Server（stdio JSON-RPC）
```

通过 MCP 协议暴露 32+ 工具给 Claude Code / Cursor / 任何 MCP Agent，让 LLM 自主驱动安全审计流程。详见 [LLM-AUDIT-SKILL.md](LLM-AUDIT-SKILL.md)。

MCP 集成配置（`.claude/settings.json`）：

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

### `audit` — 扫描 + 规则审计

```bash
ctx-audit audit ./project                   # 扫描 + 规则审计（无 LLM 调用）
ctx-audit audit ./project --agent           # [已搁置] 内部 Agent 模式
```

> **2026-07**: 内部 `--agent` 模式已搁置。其 Specialist/Investigator/TaintWalk 组件在基准测试中效果未达预期，建议使用 MCP 模式。代码保留但 `llm_mode` 默认 `noop`。

### `config` — 配置管理

```bash
ctx-audit config show            # 显示当前配置
ctx-audit config set <key> <val> # 设置配置
ctx-audit config list            # 列出所有配置键
```

## LLM 协作审计（推荐方式）

CTX-Audit 通过 MCP 协议让外部 LLM 自主完成安全审计。核心差异：**不是让 LLM 看扫描结果猜 TP/FP，而是给 LLM 32+ 个工具去查调用图、读代码、追踪数据流，基于确定性证据做判定。**

### 工作流

```
1. security_scan → 获取 findings（含 enclosing_function + evidence_refs）
2. 对每个 high/critical finding:
   a. get_code_context → 理解代码
   b. query_callers / find_call_path → 追踪数据来源
   c. search_code → 搜索相关模式
   d. check_sanitizer / query_middleware_chain → 排除误报
   e. 判定 → TP / FP / Needs Review
3. 输出审计报告（证据链完整、可追溯）
```

### 已验证的审计效率

| 项目 | 审计方式 | 耗时 | 产出 |
|------|---------|------|------|
| Shiro 1.2.4 | MCP 协作 | ~15min | 确认 CVE-2016-4437 + gadget chain |
| Shiro 1.2.4 | 纯手工 | ~2h | 同上 |
| RuoYi 4.7.3 | 扫描 | ~5s | 355 findings，含 6 个 MyBatis SQL 注入 |

完整指南和示例见 **[LLM-AUDIT-SKILL.md](LLM-AUDIT-SKILL.md)** 和 **[docs/MCP-AUDIT-EXAMPLE.md](docs/MCP-AUDIT-EXAMPLE.md)**。

## 配置文件

配置文件位于 `~/.config/ctx-audit/config.toml`（Linux）/ `~/Library/Application Support/ctx-audit/config.toml`（macOS）/ `%APPDATA%\ctx-audit\config.toml`（Windows）。

首次运行 `ctx-audit config set` 时自动生成。

**常用配置**：

```toml
[scan]
threads = 4
min_severity = "medium"
exclude_patterns = ["node_modules", ".git", "target", "build", "dist", "vendor", "test", "tests"]

[agent]
llm_mode = "noop"               # noop / http（MCP 模式不需配置此项）

[agent.llm]
provider = "openai"
model = "deepseek-chat"
endpoint = "https://api.deepseek.com/v1/chat/completions"

[daemon]
listen_addr = "127.0.0.1:19527"
```

## 检测能力

### 漏洞覆盖

| 类型 | CWE | 检测方式 |
|------|-----|---------|
| SQL 注入 | CWE-89 | AST 污点 + MyBatis XML `${}` + 规则 |
| 命令注入 | CWE-78 | AST 污点 + 多语言规则 |
| 代码注入 | CWE-94 | AST 污点 + 模板注入（SSTI） |
| 路径遍历 | CWE-22 | AST 污点 + 多语言规则 |
| XSS | CWE-79 | AST 污点 + sanitizer 检测 |
| SSRF | CWE-918 | 跨文件追踪 + Host Header 规则 |
| 不安全反序列化 | CWE-502 | 规则 + 方法参数 source + 调用者链 |
| XXE | CWE-611 | YAML sink 规则 |
| 日志注入 | CWE-117 | 跨文件追踪 + logger sink |
| 开放重定向 | CWE-601 | 规则 + sendRedirect 检测 |
| 硬编码密码 | CWE-259 | 模式匹配 |
| 弱哈希 | CWE-328 | YAML sink 规则 |
| 不安全 Cookie | CWE-614 | 规则 + sanitizer 检测 |
| 信任边界 | CWE-501 | 跨文件追踪 |

### 跨文件追踪

- **调用图构建**：Import-Aware 别名解析 + Callback 注册 + receiver 追踪 + 类型层次虚方法分发
- **函数摘要**：自底向上计算污点签名，`param_to_calls` 多跳传播，返回值 LHS 回传
- **路径追踪**：BFS source→sink 跨文件路径查找
- **中间件建模**：Express app.use() / Django MIDDLEWARE 虚拟边
- **CPG 引擎**：路径敏感分析 + AccessPath 前缀匹配 + sanitizer 净化检测
- **YAML 规则**: 68 sinks + 101 sanitizers，覆盖 7 语言 + 框架（Spring/React/Django/Express）

### 误报控制

- 文件角色标签（production/test/build/vendor）
- Sanitizer 净化检测（101 个模式）
- 安全屏障检测（shell:false、数组参数等）
- 构造函数 FP 过滤
- 基线抑制（`.ctx-audit/baseline.json`）
- 置信度评分 + 多引擎交叉确认

### 语言支持

Java / Python / JavaScript / TypeScript / Go / Rust / C / C++ / PHP — AST 分析 12 种语言，文件扫描 18 种扩展名。

## 架构

```
CTX-Audit
├── core/                         # 确定性分析引擎
│   ├── analysis/
│   │   ├── taint.rs              # 污点分析核心（Source/Sink/Flow/Sanitizer）
│   │   ├── ast_taint.rs          # AST 污点分析器（CFG + CPG 路径敏感）
│   │   ├── cross_file.rs         # 跨文件分析（调用图 + 函数摘要 + BFS）
│   │   ├── cpg/                  # 代码属性图引擎（构建/查询/摘要）
│   │   ├── query.rs              # 调用图查询引擎（LLM 证据 API）
│   │   ├── framework_detector.rs # 安全框架检测（pom.xml/gradle）
│   │   ├── imports.rs / type_hierarchy.rs / middleware.rs
│   │   └── attack_surface.rs / risk_patterns.rs
│   ├── scanner/
│   │   ├── mod.rs                # 扫描管道 + Finding + 证据富化
│   │   ├── source_sink_patterns.rs # 本地 source→sink 模式匹配
│   │   └── sca_scanner.rs        # SCA 依赖扫描
│   ├── rules/                    # YAML 规则引擎
│   └── ast/                      # AST 引擎（tree-sitter，12 语言）
│
├── tools/                        # MCP 工具集
│   ├── bridge.rs                 # 内置工具（read_file/list_files/search）
│   └── registry.rs / executor.rs
│
├── cli/                          # CLI 客户端
│   ├── commands/
│   │   ├── scan.rs / analyze.rs / watch.rs
│   │   ├── mcp.rs                # MCP Server（32+ 工具）
│   │   └── daemon.rs / config.rs / rules.rs
│   ├── agent/                    # 内部 Agent（已搁置）
│   │   ├── supervisor.rs         # 并发调度器
│   │   ├── investigator/         # ReAct 调查器 + TaintWalk
│   │   ├── specialist/           # CWE Specialist
│   │   └── prompts.rs / evidence.rs / llm_client.rs
│   └── config.rs
│
├── daemon/                       # 守护进程
│   └── src/{protocol,server,engine,state,client}.rs
│
├── rules/                        # YAML 规则（68 sinks, 101 sanitizers）
│   ├── *.yaml                    # 模式规则
│   └── taint/frameworks/         # 框架污点规则（7 语言）
│
└── docs/                         # 文档
    ├── MCP-AUDIT-EXAMPLE.md      # MCP 审计实战（Shiro CVE-2016-4437）
    ├── MCP-INTEGRATION.md        # MCP 集成配置指南
    └── research/                 # 研究报告 + 基准汇总
```

## 基准测试

### 7 项目跨语言基准

| 语言 | 项目 | 文件 | Findings | Critical 检出 | Evidence | 已知命中 |
|------|------|------|----------|-------------|----------|---------|
| Java | WebGoat | 404 | 231 | 9 | 14% | 教学项目 |
| Java | Shiro 1.2.4 | 619 | 57 | 9 CWE-502 | 61% | ✅ CVE-2016-4437 |
| Java | RuoYi 4.7.3 | 266 | 355 | 6 CWE-89 | 4% | ⚠️ MyBatis XML |
| Java | Fastjson 1.2.24 | 2035 | 10 | 7 CWE-502 | 70% | ⚠️ 入口待关联 |
| Python | pygoat | 80 | 104 | 23 | 49% | 教学项目 |
| Go | govwa | 20 | 5 | 1 | 60% | 教学项目 |
| JS | NodeGoat | 50 | 57 | 4 | 19% | 教学项目 |

## 项目状态

| 维度 | 状态 |
|------|------|
| 跨文件分析 | 调用图 + Import 别名 + Callback + receiver + 类型层次 + 虚方法 + 中间件 |
| 语言覆盖 | Java/Python/JS/TS/Go/Rust/C/C++/PHP — 12 种 AST，7 种污点规则 |
| YAML 规则 | 68 sinks + 101 sanitizers（Spring/React/Django/Express 框架感知） |
| MCP 工具 | 35+（扫描/调用图查询/代码搜索/污点追踪/审计会话） |
| 证据质量 | enclosing_function 97%，evidence_refs 4-70%（项目类型决定） |
| Agent 模式 | 已搁置（`llm_mode=noop`）。MCP 协作是推荐方向 |
| 测试 | 由 `.github/workflows/ci.yml` 统一执行，不维护单一静态计数 |
| 基准 | 7 项目，819 findings 验证 |
| 已知 CVE 检出 | ✅ CVE-2016-4437（Shiro），⚠️ CVE-2017-18349（Fastjson），CVE-2023-27025（RuoYi 部分） |

### 关于 0-day 发现

工具**能发现 0-day 的组件和模式**（如反序列化 sink、MyBatis 动态 SQL、库 API 危险入口），但**不能自动确认为 0-day**。需要安全研究员或 MCP LLM 逐 finding 追踪调用者链、确认外部可达性、判定可利用性。在合适的场景（未审计的 Java 库/框架），效率提升约 8-10x（vs 全文阅读）。

0-day 发现依赖安全研究员或 MCP LLM 逐 finding 追踪调用者链、确认外部可达性。

## 许可证

Apache License 2.0
