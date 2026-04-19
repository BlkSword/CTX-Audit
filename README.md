# CTX-Audit

<div align="center">

**AI 驱动的代码安全审计工具**

**神经符号引擎：Rust 静态分析 + LLM 语义验证**

[![Rust](https://img.shields.io/badge/Rust-2021-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=flat-square)](LICENSE)

[中文](#中文) | [English](#english)

</div>

---

## 中文

### CTX-Audit 是什么

CTX-Audit 是一款将 **Rust 确定性静态分析** 与 **LLM 语义验证** 相结合的代码安全审计工具。Rust 引擎找出从 source 到 sink 的所有物理数据流路径，LLM 作为语义判断器，判定中间的 sanitizer 是否可被绕过。

**设计原则**：不让 LLM "找漏洞"，而是让它"判断漏洞"——确定性引擎负责发现，LLM 负责定性。这是学术界和工业界公认的最优解。

```
Rust 引擎：找出所有物理路径 (source → sink)
     │
     ▼
污点切片：提取路径上的代码上下文
     │
     ▼
LLM 引擎："在这个具体上下文中，这段过滤逻辑能被绕过吗？"
     │
     ▼
SARIF 报告：含 codeFlows 污点路径 + fix 修复建议
```

### 快速开始

```bash
# 从源码构建
git clone https://github.com/BlkSword/CTX-Audit.git
cd CTX-Audit
cargo build --release

# 配置 LLM（深度审计需要）
ctx-audit config set llm.api_key your-api-key

# 快速规则扫描（不需要 LLM）
ctx-audit scan ./myproject

# 深度 AI 审计（Rust 静态分析 + LLM 验证）
ctx-audit audit ./myproject --verbose

# 守护模式：持续监听，输出 SARIF
ctx-audit watch ./myproject
```

### 命令详解

#### `scan` — 快速规则扫描

基于正则模式匹配的快速扫描，不需要 LLM，完全本地运行。

```bash
ctx-audit scan ./project [OPTIONS]

OPTIONS:
  -s, --severity <级别>     按严重程度过滤 (critical, high, medium, low, info)
  -p, --pattern <模式>      按文件模式过滤 (如 *.py)
  -o, --output <文件>       输出文件路径
  -t, --threads <N>         并行扫描线程数 (默认: 4)
  -r, --rules <目录>        自定义规则目录
```

#### `audit` — 深度 AI 审计

五阶段专业审计：初始化 → 确定性扫描 → 深度分析 → 验证 → 报告。

```bash
ctx-audit audit ./project [OPTIONS]

OPTIONS:
  -t, --audit_type <类型>   审计类型: full, quick, incremental (默认: full)
  -i, --max_iterations <N>  最大 LLM 迭代次数
  -o, --output <文件>       输出文件路径
  -v, --verbose             显示 LLM 思考过程、工具调用和观察结果
      --skip-verification   跳过验证阶段
```

#### `watch` — 守护模式

监听文件变更，增量扫描，持续更新 SARIF 文件。专为 IDE 集成设计。

```bash
ctx-audit watch ./project [OPTIONS]

OPTIONS:
  -s, --severity <级别>        按严重程度过滤
      --output_path <文件>     SARIF 输出路径 (默认: .ctx-audit.sarif)
      --ignore <模式>          忽略的目录，逗号分隔

默认值:
  输出路径: .ctx-audit.sarif
  忽略目录: node_modules,.git,target,build,dist,__pycache__,vendor
```

#### `chat` — REPL 对话模式

与 AI 安全分析师的交互式对话。

```bash
ctx-audit chat [PATH]       # 可选项目路径，提供上下文
```

#### `analyze` — 单文件分析

对单个文件进行深度分析，支持 AST 和符号检查。

```bash
ctx-audit analyze ./src/main.py [OPTIONS]

OPTIONS:
  -s, --start_line <N>   起始行号 (默认: 1)
  -e, --end_line <N>     结束行号
      --ast              显示 AST 信息
      --symbols          显示符号信息
```

#### `findings` — 漏洞管理

查看、更新和导出已发现的漏洞。

```bash
ctx-audit findings list [-s critical] [-f open] [--json]
ctx-audit findings view <ID>
ctx-audit findings update <ID> -s fixed --note "已在 commit abc 中修复"
ctx-audit findings delete <ID> --confirm
ctx-audit findings export -o report.json -f sarif
```

#### `ui` — 终端界面

基于 ratatui 的交互式终端界面。

```bash
ctx-audit ui ./project [--audit]
```

#### 其他命令

```bash
ctx-audit config show                # 查看配置
ctx-audit config set llm.api_key     # 设置 API 密钥
ctx-audit config validate --test-llm # 测试 LLM 连接
ctx-audit completion bash            # 生成 Shell 补全脚本
```

### SARIF 输出

CTX-Audit 生成符合 **SARIF 2.1.0** 标准的输出，可被以下工具直接消费：

| 消费方 | 方式 |
|--------|------|
| **VS Code / Cursor** | 安装 SARIF Viewer 扩展，打开 `.sarif` 文件 |
| **GitHub Code Scanning** | 通过 `github/codeql-action/upload-sarif@v3` 上传 |
| **Claude Code** | 读取 SARIF 文件，辅助一键修复 |
| **任何 SARIF 兼容工具** | 标准交换格式 |

#### SARIF 特性

- **`codeFlows`**：完整的污点传播路径可视化（source → 传播步骤 → sink）
- **`fixes`**：结构化修复建议（old_code → new_code 替换）
- **`rules`**：内置 CWE 规则元数据（CWE-89, CWE-78, CWE-22, CWE-79, CWE-918, CWE-94）
- **`properties`**：置信度分数、发现来源、验证状态
- **`invocations`**：运行元数据与时间戳

#### 示例：生成 SARIF

```bash
# 扫描 → SARIF
ctx-audit scan ./project --output report.sarif

# 审计 → SARIF（含污点路径和修复建议）
ctx-audit audit ./project --output report.sarif

# 守护模式 → 持续更新 SARIF
ctx-audit watch ./project --output_path .ctx-audit.sarif
```

### CI/CD 集成

#### GitHub Actions

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
      - name: Install CTX-Audit
        run: cargo install ctx-audit
      - name: Run Scan
        run: ctx-audit scan . --output results.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: ctx-audit
```

GitHub 会在 PR 代码审查界面自动显示漏洞标注。

### 系统架构

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI (clap)                           │
│  audit | scan | watch | chat | ui | analyze | findings      │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                    Agent Engine                              │
│                                                              │
│  Coordinator ──► SharedTaskList ──► Specialists              │
│       │                                      │               │
│       └── Mailbox (P2P 消息) ──────────────┘               │
│                                                              │
│  PhaseAwareExecutor:                                         │
│    初始化 → 确定性扫描 → 深度分析 → 验证 → 报告              │
│                                                              │
│  SecurityAuditChain (假设驱动审计)                            │
│  ReAct Loop (推理-行动循环)                                   │
│  ToolRecommender (阶段感知工具推荐)                           │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                    Core Library                              │
│                                                              │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │ SARIF 引擎   │  │ 污点引擎      │  │ AST 引擎          │  │
│  │ (2.1.0 完整) │  │ (Source→Sink) │  │ (tree-sitter 12+) │  │
│  └─────────────┘  └──────────────┘  └───────────────────┘  │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │ FileWatcher  │  │ Scanner       │  │ Rule Engine       │  │
│  │ (守护进程)   │  │ (正则/模式)    │  │ (YAML 规则)       │  │
│  └─────────────┘  └──────────────┘  └───────────────────┘  │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                    LLM Integration                           │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │  Anthropic   │  │   OpenAI      │  │    Ollama         │  │
│  │  (Claude)    │  │   (GPT-4)     │  │   (本地模型)      │  │
│  └─────────────┘  └──────────────┘  └───────────────────┘  │
│  兼容: 智谱、DeepSeek、vLLM、任何 OpenAI 兼容接口             │
└─────────────────────────────────────────────────────────────┘
```

### 审计流程

```
┌──────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────┐   ┌──────────┐
│  初始化  │──▶│ 确定性扫描   │──▶│  深度分析    │──▶│   验证   │──▶│   报告   │
│          │   │              │   │              │   │          │   │          │
│ 项目信息 │   │ 污点路径     │   │ Multi-Agent  │   │ 双重     │   │ SARIF    │
│ 技术栈   │   │ 模式检测     │   │ 语义理解     │   │ 交叉     │   │ JSON     │
│ 攻击面   │   │              │   │              │   │ LLM      │   │ Markdown │
│          │   │     ▼        │   │              │   │ 最终判断 │   │ 修复建议 │
│          │   │ codeFlows    │   │              │   │          │   │          │
│          │   │ 富化         │   │              │   │          │   │          │
└──────────┘   └──────────────┘   └──────────────┘   └──────────┘   └──────────┘
```

### 支持的漏洞类型

| 漏洞类型 | 严重程度 | CWE | 检测方式 |
|----------|----------|-----|----------|
| SQL 注入 | Critical | CWE-89 | 污点分析 + LLM |
| 命令注入 | Critical | CWE-78 | 污点分析 + LLM |
| 代码注入 | Critical | CWE-94 | 污点分析 + LLM |
| 路径遍历 | High | CWE-22 | 污点分析 + LLM |
| XSS | High | CWE-79 | 污点分析 + LLM |
| SSRF | High | CWE-918 | 污点分析 + LLM |
| 不安全反序列化 | High | CWE-502 | 模式匹配 + LLM |
| LDAP 注入 | Medium | CWE-90 | 模式匹配 |
| 日志注入 | Medium | CWE-93 | 模式匹配 |
| 开放重定向 | Medium | CWE-601 | 模式匹配 |

### 项目结构

```
CTX-Audit/
├── cli/                         # CLI 二进制 (ctx-audit)
│   └── src/
│       ├── commands/            # 命令实现
│       │   ├── audit.rs         # 深度 AI 审计
│       │   ├── scan.rs          # 快速规则扫描
│       │   ├── watch.rs         # 守护模式
│       │   ├── chat.rs          # REPL 对话
│       │   └── ...
│       ├── tui/                 # 终端 UI (ratatui)
│       ├── output.rs            # 统一输出格式化
│       └── config.rs            # 配置管理
│
├── core/                        # 核心分析库
│   └── src/
│       ├── sarif/               # SARIF 2.1.0 引擎
│       │   ├── types.rs         # 完整 SARIF 类型定义
│       │   ├── converter.rs     # FindingData/TaintFlow → SARIF
│       │   └── rules.rs         # 内置 CWE 规则注册表
│       ├── watcher/             # 文件监听与增量扫描
│       │   ├── mod.rs           # FileWatcher
│       │   └── delta.rs         # Content Hash 变更检测
│       ├── analysis/            # 污点分析、数据流
│       ├── ast/                 # AST 引擎 (tree-sitter)
│       ├── scanner/             # 模式扫描器
│       └── indexing/            # 代码索引 & RAG
│
├── agent-engine/                # 多 Agent 编排
│   └── src/
│       ├── multi_agent/         # Coordinator-Specialist 系统
│       ├── audit_prompts.rs     # LLM 提示词模板
│       ├── phase_executor.rs    # 五阶段审计执行器
│       └── react/               # ReAct 推理循环
│
├── llm/                         # LLM 客户端抽象
│   └── src/
│       ├── providers.rs         # Anthropic, OpenAI, Ollama
│       └── factory.rs           # Provider 工厂
│
├── tools/                       # 工具系统
│   └── src/
│       ├── bridge.rs            # FindingData 模型、内置工具
│       ├── taint_tools.rs       # 污点分析工具
│       ├── ast_tools.rs         # AST 查询工具
│       └── pattern_tools.rs     # 模式检测工具
│
└── .github/workflows/           # CI/CD 模板
    └── ctx-audit.yml            # GitHub Actions SARIF 上传
```

### 配置

配置文件位置：
- Windows: `%APPDATA%\ctx-audit\config.toml`
- macOS/Linux: `~/.config/ctx-audit/config.toml`

```toml
[llm]
provider = "anthropic"            # anthropic, openai, ollama
api_key = "sk-ant-..."
model = "claude-sonnet-4-20250514"
base_url = ""                     # 自定义端点 (兼容接口)
timeout_secs = 120

[scan]
max_threads = 4
exclude_patterns = ["node_modules", "target", "vendor", ".git"]
```

**支持的 LLM 提供商：**

| 提供商 | provider 值 | 说明 |
|--------|-------------|------|
| Anthropic | `anthropic` | Claude 模型，推荐 |
| OpenAI | `openai` | GPT-4 / GPT-4o |
| 智谱 | `openai` + `base_url` | GLM 模型 |
| DeepSeek | `openai` + `base_url` | DeepSeek 模型 |
| Ollama | `ollama` | 本地模型 (Llama, Qwen 等) |

### 全局选项

```bash
ctx-audit [全局选项] <命令>

全局选项:
  -v, --verbose            详细输出
  -d, --debug              调试输出
      --log-level <级别>    日志级别 (trace, debug, info, warn, error)
  -o, --output <格式>      输出格式: text, json, markdown, sarif
  -c, --config <路径>      配置文件路径
```

### 开发

```bash
cargo build                    # 开发构建
cargo build --release          # Release 构建
cargo test                     # 运行测试
cargo clippy                   # 代码检查
cargo fmt                      # 格式化

# 调试日志 (PowerShell)
$env:RUST_LOG="ctx_audit=debug"
cargo run -- audit ./project --verbose

# 调试日志 (bash)
RUST_LOG="ctx_audit=debug" cargo run -- audit ./project --verbose
```

### 许可证

Apache License 2.0

---

## English

### What is CTX-Audit

CTX-Audit is a code security audit tool that combines **Rust-based deterministic static analysis** with **LLM-powered semantic verification**. The Rust engine finds all physical data flow paths from source to sink; the LLM acts as a semantic judge to determine if sanitizers can be bypassed.

**Design principle**: Don't let LLMs "find bugs" — let them "judge bugs" that the deterministic engine discovers. This is the recognized optimal approach in both academia and industry.

### Quick Start

```bash
git clone https://github.com/BlkSword/CTX-Audit.git
cd CTX-Audit
cargo build --release

ctx-audit config set llm.api_key your-api-key    # Required for deep audit
ctx-audit scan ./myproject                         # Quick scan (no LLM)
ctx-audit audit ./myproject --verbose              # Deep AI audit
ctx-audit watch ./myproject                        # Continuous monitoring
```

### Commands

| Command | Description |
|---------|-------------|
| `scan <path>` | Quick pattern-based scan (no LLM needed) |
| `audit <path>` | Deep AI audit (5 phases, Rust + LLM) |
| `watch <path>` | Continuous monitoring with SARIF output |
| `chat [path]` | Interactive REPL with AI analyst |
| `analyze <file>` | Single file deep analysis |
| `findings <action>` | Vulnerability management (list/view/update/export) |
| `ui [path]` | Terminal UI (ratatui) |
| `config <action>` | Configuration management |

### SARIF Output

CTX-Audit generates **SARIF 2.1.0** compliant output with:
- **`codeFlows`**: Taint propagation path (source → steps → sink)
- **`fixes`**: Structured fix suggestions (old_code → new_code)
- **`rules`**: Built-in CWE metadata (CWE-89, 78, 22, 79, 918, 94)
- **`properties`**: Confidence, discovery source, verification status

Consumable by VS Code, Cursor, GitHub Code Scanning, Claude Code, and any SARIF-compatible tool.

### CI/CD Integration

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
      - run: cargo install ctx-audit
      - run: ctx-audit scan . --output results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### Configuration

```toml
[llm]
provider = "anthropic"      # anthropic, openai, ollama
api_key = "sk-ant-..."
model = "claude-sonnet-4-20250514"
base_url = ""               # Custom endpoint for compatible providers
timeout_secs = 120
```

**Supported Providers**: Anthropic (Claude), OpenAI (GPT-4), 智谱 (GLM), DeepSeek, Ollama (local models).

### License

Apache License 2.0
