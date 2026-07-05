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

## 目录

| 章节 | |
|------|----|
| [CTX-Audit 是什么](#ctx-audit-是什么) | [LLM 协作审计](#llm-协作审计) |
| [快速开始](#快速开始) | [增量扫描原理](#增量扫描原理) |
| [命令](#命令) | [架构](#架构) |
| [配置文件](#配置文件) | [LLM 审计 Skill 指南](LLM-AUDIT-SKILL.md) |
| [检测能力](#检测能力) | |
| [自定义规则](#自定义规则) | |

---

## CTX-Audit 是什么

CTX-Audit 是一个面向 LLM 协作审计的代码安全分析引擎。它不只是告诉你"哪里用了危险函数"——而是追踪数据从用户输入到危险操作的**完整路径**，并输出结构化的证据链，让 LLM 基于事实做漏洞判定。

**核心能力**：

- **多引擎分层扫描**：规则扫描（40 条 YAML 规则，6 语言）→ AST 污点分析（`--taint`，单文件 source→sink）→ 跨文件追踪（`--cross-file`，调用图 + 函数摘要），每个引擎可独立启用
- **数据流追踪**：基于 CPG（代码属性图）引擎，融合 CFG + AST 元数据 + 别名映射，支持路径敏感分析（条件净化检测）、属性路径前缀匹配（`req.body` → `req.body.name`）、AccessPath、AliasMap、解构赋值、Promise 链等动态语言特性，追踪 `req.body.name → eval(data)` 这样的完整污点链
- **LLM 自主审计闭环**：通过 MCP 协议暴露 31 个工具（含调用图查询 + 审计会话），LLM 可自主完成"项目理解 → 攻击面映射 → 扫描 → 污点追踪 → 代码审查 → 调查式验证 → TP/FP 判定 → 规则生成 → 重新验证"的完整审计流程
- **本地 Agent 模式**：`ctx-audit audit --agent` 无需外部 MCP 宿主即可自动执行扫描 → 假设 → 验证 → 判定闭环；内置 Supervisor 并发调度、CWE Specialist（SQLi/XSS）深度判定、Reviewer 复核/辩论、基于 `ToolRegistry` 的调用图/污点工具证据，以及 **Phase 7 完整体 Agent 能力**：`EnvironmentModel` 全局环境感知、`StrategyPlanner` 自动目标生成、`PlanExecutor` 行动选择（入口点探索、假设验证、定向重扫描）、`ReAct 调查器（`--investigate`）`让 LLM 动态选工具迭代取证，输出带证据链的审计日志
- **误报控制**：文件角色标签（production/test/build/vendor）、安全屏障检测（shell:false、数组参数、require.resolve 等）、规则级 sanitizer 机制（命中前存在 `setSecure`/`escape`/`encodeForHtml` 等净化代码即跳过）、置信度评分、多引擎交叉确认、基线抑制
- **增量扫描**：守护进程常驻内存，content-hash 变更检测，无变更时 ~1ms 返回
- **结构化输出**：默认输出 LLM 面向的 JSON（含代码上下文、污点链、屏障信息、文件角色），也支持 SARIF、Markdown 等

**覆盖范围**：20+ 漏洞类型（注入、XSS、SSRF、反序列化、路径遍历...），AST 分析支持 12 种语言（JavaScript/JSX、TypeScript/TSX、Python、Java、Rust、Go、C、C++、HTML、CSS、JSON），文件扫描覆盖 18 种扩展名，内置 Next.js、React、Django、Spring、Express、Laravel、Rails 框架感知规则。

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
ctx-audit audit --agent ./myproject           # 本地 Agent 自动审计闭环
ctx-audit audit --agent ./myproject --specialist --review-mode debate   # 启用 Specialist + Reviewer 辩论模式
ctx-audit audit --agent ./myproject                                      # 默认启用自动目标生成（Phase 7）
ctx-audit audit --agent ./myproject --investigate --max-investigation-steps 5  # 启用 ReAct 调查器，LLM 动态选工具验证
ctx-audit audit --agent ./myproject --no-auto-goal                         # 关闭自动目标生成，回退到传统行为

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
      --graph-output <文件>    导出调用图为 JSON（供 LLM 查询）
      --query-mode             仅构建调用图，输出统计信息（配合 MCP 工具使用）
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

通过 MCP 协议暴露安全分析能力给 AI agent（如 Claude Code）。提供 **31 个工具**：

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

**调用图查询工具（确定性证据）**：

| 工具 | 说明 |
|------|------|
| `get_graph_stats` | 获取跨文件调用图统计概览：节点/边/跨文件边/source/sink/类型/中间件数量 |
| `list_file_functions` | 列出文件中所有被调用图索引的函数（含 source/sink/callback 标记） |
| `query_callers` | 查询谁调用了指定函数（含 receiver 信息）——反向追踪 sink 到入口点 |
| `query_callees` | 查询指定函数调用了谁——正向追踪入口点到 sink |
| `find_call_path` | 在跨文件调用图中查找 source→sink 的精确调用路径（确定性可达性证据） |
| `resolve_method_call` | 解析 `obj.method()` 到实际函数实现（import 别名 + receiver 追踪 + 类型层次） |
| `query_type_hierarchy` | 获取类的继承层次：父类/子类/接口实现/所有方法（含继承） |
| `query_middleware_chain` | 获取 Express app.use() / Django MIDDLEWARE 中间件及其影响的路由 |
| `trace_variable_flow` | 从 source 函数出发，找出所有可达的 sink 及完整调用路径 |

这些工具返回的数据基于 AST 解析的**确定性调用图**——函数调用关系不依赖任何 LLM 推断。
LLM 审计时使用这些工具获取证据链，而非猜测代码行为。

**审计会话工具（调查式协作）**：

| 工具 | 说明 |
|------|------|
| `start_audit_session` | 创建审计会话，返回 session_uuid 用于关联后续调查 |
| `start_investigation` | 对单个 finding 启动深度调查，返回确定性证据 + 建议的后续查询工具 |
| `log_investigation_step` | 记录调查步骤（工具调用 + 发现 + 推理），构建完整审计轨迹 |
| `conclude_investigation` | 结束调查并下结论（TP/FP/needs_review），自动写入 audit_log 和 baseline |
| `conclude_audit_session` | 结束审计会话，返回 TP/FP/review 统计摘要 |

这 5 个工具实现**状态化调查**——LLM 不再是一次性"扫描→判断"，而是可以
对每个 finding 建立调查上下文、逐步收集证据、记录推理链、最终下结论。
完整调查流程见 [LLM 审计 Skill 指南](LLM-AUDIT-SKILL.md)。

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

### `audit` — 本地 Agent 自动审计

```bash
ctx-audit audit ./project [OPTIONS]

OPTIONS:
      --agent                 启用本地 Agent 自动审计闭环（默认即启用）
      --deep                  启用跨文件调用图分析（默认启用）
      --specialist                  启用 CWE Specialist（SQLi / XSS）深度判定
      --review-mode <MODE>          Reviewer 模式：off / debate / single
      --investigate                 启用 ReAct 调查器（需配置 LLM 才执行真实工具循环）
      --max-investigation-steps <N> 最大调查步数（默认 5）
      --no-auto-goal                禁用 Phase 7 自动目标生成，回退到传统 Supervisor
      --strategy <MODE>             策略模式：auto / rule / llm（默认 auto）
      --max-goals <N>               最大审计目标数
      --max-exploration-actions <N> 每个目标最大探索行动数
      --min-severity <级别>         最低严重程度阈值
      --max-findings <N>            最多调查的 finding 数量
  -o, --output <文件>               输出报告路径
```

Agent 工作流：

1. **Survey** — 全量扫描并收集 evidence_refs、代码上下文、调用图证据
2. **Environment** — 构建 `EnvironmentModel`：整合攻击面、架构风险模式、调用图统计、历史 Blackboard、基线
3. **Strategy** — `StrategyPlanner` 根据环境模型自动生成审计目标（如“验证未认证入口可达的注入漏洞”），并基于风险评分与历史收敛状态排序
4. **Plan** — `RuleBasedPlanner` / `LlmBasedPlanner` 把目标展开为 `Action` 序列：`InvestigateFinding`、`ExploreEntryPoint`、`VerifyHypothesis`、`ReScanWithRule`
5. **Execute** — `PlanExecutor` 批量派发 finding 调查、主动探索入口点、组合工具验证假设；若启用 `--investigate`，ReAct 调查器会让 LLM 每轮动态选择工具并记录完整调查轨迹
6. **Judge & Learn** — 综合各层意见输出 TP/FP/needs_review，写入 `.ctx-audit/audit_log.json`；更新 Blackboard 信息素与收敛状态，用于下一次审计

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
taint_max_candidate_files = 5000   # 深度扫描 AST 候选文件上限
taint_max_file_kb = 500            # 深度扫描单文件大小上限 (KB)

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

[agent]
enabled = true                     # 是否启用本地 Agent
triage_concurrency = 4             # 并发 triage 任务数
llm_mode = "noop"                  # LLM 模式：noop / http / mcp_relay
review_mode = "off"                # Reviewer 模式：off / debate / single
max_llm_calls = 0                  # 最大 LLM 调用次数，0 表示不限制
specialist_enabled = false         # 是否启用 CWE Specialist
investigator_enabled = false       # 是否启用 ReAct 调查器
max_investigation_steps = 5        # 调查器每 finding 最大工具调用步数

[agent.llm]
provider = "openai"                # openai / anthropic / ollama
model = "gpt-4o-mini"              # 模型名
api_key = ""                       # API 密钥（也可通过环境变量设置）
endpoint = ""                      # 自定义 endpoint（可选）
timeout_sec = 60                   # 请求超时
max_tokens = 2048                  # 最大 token 数

[agent.planner]
strategy = "auto"                  # auto / rule / llm
max_goals = 10                     # 最大审计目标数
max_exploration_actions = 5        # 每个目标最大探索行动数
enable_proactive_scan = false      # 是否允许 Agent 动态生成规则并重扫描
enable_reflection = true           # 是否启用反思/重规划
convergence_threshold = 5.0        # 信息素收敛阈值

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

- **调用图构建**：自动提取项目函数节点和调用关系，支持匿名回调注册（箭头函数/函数表达式）和 HTTP 响应回调体独立分析
- **跨文件解析**：两阶段调用解析——Phase 1 通过 Import/Require 别名精确匹配目标文件和导出名，Phase 2 全局名称回退 + receiver 缩小范围
- **方法调用追踪**：`CallTarget` 保留 `obj.method()` 的 receiver 信息，支持 `property` 和 `field` AST 字段名（JS/Java 兼容）
- **函数摘要**：自底向上计算每个函数的污点传播签名；摘要新增 `param_to_calls`，记录参数通过数据流到达的下游调用参数，支持中间函数重命名/字段访问后的多跳传播
- **路径追踪**：BFS 查找 source→sink 的跨文件调用路径，支持 Return 节点中的 sink 检测，并支持 callee 返回值赋值给 caller LHS 变量的回传
- **上下文组装**：识别 callers、callees、信任边界
- **CPG 自动摘要**：Stage B 构建的 FunctionCPG 缓存传递给 Stage C，自动生成精确函数摘要
- **路径敏感分析**：条件分支感知的污点传播，`if (isSafe(x))` 的 True 分支自动标记净化
- **属性路径追踪**：AccessPath 前缀匹配——`req.body` 污染时 `req.body.name` 自动检出
- **类型层次**：Class/Interface/Struct 继承 DAG + 虚方法分发（Java/TypeScript/Python）
- **框架中间件**：Express `app.use()` 中间件虚拟边注入，Django MIDDLEWARE 检测
- **构造函数 FP 过滤**：自动降级外层构造函数误标，内层 Method 节点为实际 source/sink
- **语言过滤**：YAML 规则中的 language 字段支持通配符，避免跨语言规则失效

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
| HTTP 回调提示 | `needle.get(url, (err, resp, body) => ...)` → body 标记为二阶污点源（外部响应体） |
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

1. **Pattern Rules** — 基于正则的代码模式匹配（如 `rules/command-injection.yaml`），支持可选 `sanitizers` 列表用于命中前净化检测
2. **Taint Rules** — 定义污点源、汇和净化函数（如 `rules/taint/generic-taint.yaml`），每个 sink 可声明 `sanitizers`

**规则优先级**：`--rules` 参数 > `.ctx-audit/rules/` > 内置 `rules/`

**Daemon 热加载**：守护进程每 30 秒检测规则目录变更，自动重新加载。

详细编写指南见 [`docs/custom-rules.md`](docs/custom-rules.md) | [`docs/custom-rules-en.md`](docs/custom-rules-en.md)。

## LLM 协作审计

CTX-Audit 通过 MCP 协议暴露 **31 个工具**（含 9 个调用图查询 + 5 个审计会话工具），让 LLM（Claude Code / Cursor / 任何支持 MCP 的 Agent）完全自主驱动安全审计流程——从项目理解、扫描、证据收集、调查式验证到审计结论，全程无需人工干预。

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

CTX-Audit 采用**调查式协作**模式——LLM 不仅是扫描结果的评判者，更是主动的调查者。
每个 finding 都经过"建立调查 → 收集证据 → 记录推理 → 下结论"的完整流程。

```
1. get_project_info         → 了解项目：语言、框架、文件结构、入口点数量
2. get_attack_surface       → 映射攻击面：高风险入口点、信任边界、未认证路由
3. get_graph_stats          → 了解调用图规模：节点数、边数、source/sink 分布
4. security_scan(deep=true) → 全量扫描，返回 findings（含 evidence_refs 证据指针）
5. start_audit_session      → 创建审计会话，获得 session_uuid ★
6. 对每个 high/critical finding:
   ├─ start_investigation   → 启动调查，获得 evidence_map + suggested_tools ★
   ├─ get_code_context      → 阅读发现点周围的源代码
   ├─ query_callers         → 反向追踪：哪些入口点可达这个 sink？
   ├─ query_callees         → 正向追踪：这个函数调用了哪些敏感操作？
   ├─ find_call_path        → source→sink 精确路径（确定性可达性证据）
   ├─ query_middleware_chain → 中间件是否覆盖此路由？（认证绕过检测）
   ├─ resolve_method_call   → 解析模糊方法调用到实际实现
   ├─ log_investigation_step → 记录每一步的工具调用 + 发现 + 推理 ★
   └─ conclude_investigation → 下结论（TP/FP/needs_review），自动记录 audit_log ★
7. add_custom_rule          → 针对发现的 0-day 模式动态生成规则
8. security_scan            → 使用新规则重新扫描验证
9. conclude_audit_session   → 输出完整审计摘要（TP/FP/review 统计）★
```

★ = 调查式协作新增步骤。详细流程和示例见 [LLM-AUDIT-SKILL.md](LLM-AUDIT-SKILL.md)。

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

#### 调用图查询（确定性证据）

| 工具 | 说明 |
|------|------|
| `get_graph_stats` | 调用图统计：节点/边/source/sink/类型/中间件 |
| `list_file_functions` | 列出文件中所有已索引的函数 |
| `query_callers` | 反向追踪：谁调用了这个函数？ |
| `query_callees` | 正向追踪：这个函数调用了谁？ |
| `find_call_path` | 精确调用路径：source 到 sink 可达？ |
| `resolve_method_call` | 解析 obj.method() → 实际实现 |
| `query_type_hierarchy` | 类继承层次 + 虚方法分发 |
| `query_middleware_chain` | 中间件及其影响的路由 |
| `trace_variable_flow` | 污点变量跨文件传播路径 |

#### 审计会话（调查式协作）

| 工具 | 说明 |
|------|------|
| `start_audit_session` | 创建审计会话，获得 session_uuid |
| `start_investigation` | 对 finding 启动调查，返回证据 + 建议工具 |
| `log_investigation_step` | 记录调查步骤（工具 + 发现 + 推理） |
| `conclude_investigation` | 结束调查，下结论（TP/FP），自动记录 audit_log |
| `conclude_audit_session` | 结束会话，输出 TP/FP/review 统计 |

### 提示词示例

完整的 LLM 审计引导系统见 **[LLM-AUDIT-SKILL.md](LLM-AUDIT-SKILL.md)**——
这是一个结构化的 Skill 文件，包含：
- 审计哲学（调查式协作 vs 扫描→判断）
- 完整的 4 阶段审计工作流
- 每个 MCP 工具的使用场景和参数
- 证据驱动的 TP/FP 判定框架
- 实际审计对话示例

在 Claude Code 中使用：
```bash
# 将 skill 文件复制到项目目录
cp LLM-AUDIT-SKILL.md .claude/agents/ctx-auditor.md
# 或在对话中直接引用
@LLM-AUDIT-SKILL.md 请对当前项目进行安全审计
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
│   ├── imports.rs        # 导入解析
│   ├── type_hierarchy.rs # 类型层次结构（extends/implements DAG）
│   ├── middleware.rs     # 框架中间件建模（Express app.use）
│   └── query.rs          # 调用图查询引擎（LLM 证据链）
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
├── call_graph_tools.rs   # 调用图查询工具（9 个 LLM 证据查询）
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
│   ├── mcp.rs            # MCP Server（31 个工具）
│   ├── rules.rs          # 规则管理命令
│   ├── config.rs         # 配置管理命令
│   └── findings.rs       # 漏洞管理命令
├── database/             # 漏洞数据库
│   ├── schema.rs         # SQLite schema 定义
│   ├── models.rs         # 数据模型
│   ├── queries.rs        # 查询接口
│   └── migrations.rs     # 数据库迁移
├── report/               # 报告导出
│   └── exporter.rs       # 多格式报告导出
└── agent/                # 本地审计 Agent（Phase 1-7）
    ├── mod.rs            # Agent 入口：扫描 → 环境模型 → 策略/计划 → 执行 → 报告
    ├── environment.rs    # EnvironmentModel：攻击面 + 风险模式 + 调用图 + 历史 Blackboard
    ├── planner/          # Phase 7 目标导向与行动选择
    │   ├── mod.rs        # AuditGoal / Action / Plan / Planner trait
    │   ├── strategy.rs   # StrategyPlanner：自动生成审计目标与优先级
    │   ├── rule_based.rs # RuleBasedPlanner：确定性计划生成
    │   └── executor.rs   # PlanExecutor：调度 Supervisor / ToolRegistry 执行 Action
    ├── supervisor.rs     # Supervisor：并发 Semaphore + Triage Actor
    ├── blackboard.rs     # 共享 Blackboard + ACO 信息素/收敛状态/证据图谱
    ├── heuristics.rs     # 规则化初审判定与置信度评分
    ├── llm_client.rs     # LLM 客户端抽象（含受控调用/Noop 模式）
    ├── llm.rs            # LLM triage 判定实现
    ├── prompts.rs        # Prompt 模板
    ├── evidence.rs       # 调用图/污点/代码上下文证据收集
    ├── tools.rs          # Agent 工具层：包装 ToolRegistry + 缓存 CallGraphQueryEngine
    ├── investigator/     # ReAct 自主调查器（Phase 6）
    │   └── mod.rs        # 每轮 LLM 选工具、执行、观察、下结论
    ├── specialist/       # CWE Specialist Agent
    │   ├── mod.rs        # Specialist 框架与上下文
    │   ├── sqli.rs       # SQL 注入 Specialist
    │   └── xss.rs        # XSS Specialist
    ├── reviewer/         # Reviewer / Debate Agent
    │   └── mod.rs        # 基于规则的复核器（可借助工具验证攻击面）
    └── report.rs         # Agent 审计报告输出

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
      - run: ./target/release/ctx-audit scan . --deep -o results.sarif   # SARIF for GitHub
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

### v2.1.0 扫描性能优化

v2.1.0 对深度扫描的 **Stage B（AST 污点分析）** 进行了并行化重构：

- 移除批次（batch）串行等待，所有 AST 候选文件一次性进入并行处理。
- 文件内部按**函数粒度**并行构建 CPG 并执行污点分析。
- 污点规则（sources / sinks / sanitizers）通过 `Arc` 在并行任务间共享，避免每文件/每函数重复克隆。
- `AstTaintAnalyzer` 不再持有非线程安全的 `tree-sitter::Parser`，分析器本身可 `Arc` 共享；解析需求下沉到线程本地 parser。
- 函数级任务通过 `parse_fragment` 对函数体文本重新解析局部 AST，保持 AST-based CFG 精度，避免回退到较慢的 text-based CFG。

### 基准

#### WebGoat-new（真实漏洞验证项目）

基于 [WebGoat](https://github.com/WebGoat/WebGoat)（Java + 少量前端 JS，~400 个 AST 候选文件），release 构建，Windows 11，清空缓存：

| 模式 | 耗时 | findings | 说明 |
|------|------|----------|------|
| `audit --agent --deep --no-auto-goal --max-findings 10 --min-severity high` | **~52s** | 249 total / 10 investigated | 含规则扫描 + AST 污点 + 跨文件追踪（83,058 条跨文件污点流） |

#### Next.js（超大型项目）

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
- 大型项目深度扫描通过 `scan.taint_max_candidate_files` / `scan.taint_max_file_kb` 限制候选文件数和文件大小，避免 OOM
- 守护进程模式下增量扫描利用 content-hash 缓存，无变更文件跳过扫描
- SCA 首次扫描较慢（网络请求），后续使用 24h 本地缓存
- `--exclude` 排除不关心的目录可显著减少扫描文件数

## 开发

```bash
cargo build --release        # 构建（ctx-audit + ctx-audit-daemon）
cargo test --workspace       # 运行测试（210+ 个测试）
cargo fmt                    # 格式化
cargo clippy                 # 代码检查
```

## 项目状态

| 维度 | 状态 |
|------|------|
| CPG 分析引擎 | CFG + AST 元数据 + 别名映射融合，路径敏感污点传播，AccessPath 属性路径追踪，12 语言 AST，30+ sanitizer |
| 动态语言追踪 | AccessPath + AliasMap + 解构 + 属性访问 + await + Promise 链 |
| 跨文件追踪 | 调用图 + Import-Aware 别名解析 + Callback 注册 + CallTarget receiver 追踪 + 类型层次虚方法分发 + 框架中间件虚拟边 + CPG 自动摘要 + `param_to_calls` 多跳传播 + 返回值 LHS 回传 + BFS 路径查找 + 构造函数 FP 过滤 + 回调体独立分析 |
| TypeScript 集成 | 类型注解 → 自动污点源识别（HttpRequest, Request 等） |
| 模式匹配规则 | 40 条模式规则 + 5 条污点规则，覆盖 6 语言 + 6 框架 |
| 误报控制 | 文件角色分类 + 安全屏障检测 + 多引擎置信度融合 + 基线抑制 |
| SCA 扫描 | OSV API，4 个生态，本地缓存，可配置（默认关闭） |
| MCP 集成 | 31 个工具（3 扫描 + 7 污点 + 3 风险模式 + 4 自主审计 + 9 调用图查询 + 5 审计会话） |
| 本地 Agent 模式 | `ctx-audit audit --agent` 自动执行 SURVEY→HYPOTHESIZE→VERIFY→JUDGE；Phase 5 已接入 `ToolRegistry`， Specialist / Reviewer 可调用调用图/污点工具获取确定性证据 |
| LLM 输出 | 结构化 JSON：代码上下文 + 污点链 + 文件角色 + 屏障 + 置信度 |
| 自定义规则 | YAML 格式，daemon 热加载 |
| 守护进程 | 增量缓存 + 心跳 + 自动重连 + panic 自恢复 |
| 配置驱动 | 所有排除项、严重程度阈值、引擎开关均可通过 config.toml 控制 |
| 测试覆盖 | 210+ 个测试 |
| NodeGoat Benchmark | 7/7 ground truth 命中（eval/重定向/ReDoS/IDOR/NoSQL/SSRF/XSS），25+ findings |
| WebGoat 真实项目验证 | `--deep` 扫描检出 CWE-502 XStream 反序列化、CWE-259 硬编码密码、CWE-22 路径遍历等；CWE-614 误报经 sanitizer 机制从 7 降至 3 |

## 许可证

Apache License 2.0
