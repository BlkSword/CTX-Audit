# CTX-Audit

<div align="center">

**AI-Powered Professional Code Security Audit Terminal Tool**

[![Rust](https://img.shields.io/badge/Rust-2021-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/Version-2.0.0-green?style=flat-square)](Cargo.toml)

[English](#english) | [中文](#中文)

</div>

---

## 中文

### 简介

CTX-Audit 是一个用 Rust 实现的专业代码安全审计终端工具，融合了**传统静态分析**与**AI 智能分析**的能力。与通用 AI 助手不同，它提供确定性、可重复、专业级的安全审计：

```bash
# 一键深度审计
ctx-audit audit ./myproject
```

### 核心特性

| 特性 | 描述 |
|------|------|
| **确定性污点分析** | 基于变量追踪的精确数据流分析，而非简单的行号比较 |
| **假设驱动审计** | 专业安全审计思维链：Hypothesis → Evidence → Verification → Conclusion |
| **跨文件分析** | 函数调用图构建，支持过程间污点传播 |
| **智能工具推荐** | 根据审计阶段和上下文自动推荐最佳分析工具 |
| **多 Agent 协作** | Orchestrator、Recon、Analysis、Verification 四类 Agent 协同工作 |
| **RAG 上下文增强** | 基于向量存储的代码检索增强生成 |
| **自动修复 & PoC** | 自动生成漏洞修复建议和概念验证代码 |
| **多语言支持** | 通过 tree-sitter 支持 Python、JavaScript、TypeScript、Java、Rust、Go 等 10+ 种语言 |

### 快速开始

```bash
# 从源码构建
git clone https://github.com/ctx-audit/ctx-audit.git
cd ctx-audit
cargo build --release

# 安装到系统
cargo install --path cli

# 配置 LLM API 密钥
ctx-audit config set llm.api_key your-api-key

# 运行审计
ctx-audit audit ./myproject
```

### 使用方法

```bash
# AI 驱动的深度审计
ctx-audit audit ./myproject

# 快速规则扫描
ctx-audit scan ./myproject

# 启动交互式 TUI 界面
ctx-audit ui ./myproject

# REPL 对话模式
ctx-audit chat

# 分析单个文件
ctx-audit analyze ./src/main.py

# 管理漏洞发现
ctx-audit findings list
ctx-audit findings export --format json

# 配置管理
ctx-audit config show
ctx-audit config set llm.api_key your-api-key
ctx-audit config validate --test-llm
```

### CLI 子命令

| 命令 | 功能 | 说明 |
|------|------|------|
| `audit <path>` | AI 深度审计 | 多 Agent 协作，假设驱动审计 |
| `scan <path>` | 规则快速扫描 | 批处理，高性能 |
| `chat [path]` | REPL 对话模式 | 交互式代码问答 |
| `ui [path]` | TUI 界面 | 终端图形界面 |
| `analyze <file>` | 单文件分析 | 显示 AST 和符号信息 |
| `findings <action>` | 漏洞管理 | 查看、更新、导出漏洞 |
| `config <action>` | 配置管理 | LLM 配置、规则配置 |
| `completion <shell>` | Shell 补全 | bash/zsh/fish/powershell |

### 系统架构

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CLI (clap)                                   │
│    ctx-audit audit │ ctx-audit scan │ ctx-audit ui │ ctx-audit chat │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────┐
│                        Agent Engine                                  │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐  │
│  │ SecurityAudit   │  │ ToolRecommender │  │   PhaseExecutor     │  │
│  │ Chain           │  │                 │  │                     │  │
│  │ (假设驱动审计)   │  │ (智能工具推荐)   │  │ (五阶段审计执行)    │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────────┘  │
│                                                                      │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐  │
│  │ ReAct Loop      │  │ RAG Retriever   │  │ Fix & PoC Generator │  │
│  │ (推理-行动循环)  │  │ (上下文增强)     │  │ (修复与验证生成)    │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────────┘  │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────┐
│                      Tools System                                    │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌───────────────┐  │
│  │ Taint Tools │ │ AST Tools   │ │ Search Tools│ │ Write Tools   │  │
│  └─────────────┘ └─────────────┘ └─────────────┘ └───────────────┘  │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────┐
│                     Core Library                                     │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐  │
│  │ EnhancedTaint   │  │ CrossFileTaint  │  │   CacheManager      │  │
│  │ Analyzer        │  │ Analyzer        │  │                     │  │
│  │ (变量级污点追踪) │  │ (调用图+跨文件)  │  │ (AST/分析缓存)      │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────────┘  │
│                                                                      │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐  │
│  │ AST Engine      │  │ Rule Engine     │  │ Vector Store        │  │
│  │ (tree-sitter)   │  │ (YAML 规则)     │  │ (语义搜索)          │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────────┘  │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────┐
│                    LLM Integration                                   │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐  │
│  │ Anthropic       │  │ OpenAI          │  │ Ollama              │  │
│  │ (Claude 3.5)    │  │ (GPT-4)         │  │ (本地模型)          │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

### 审计流程

CTX-Audit 采用专业的五阶段审计流程：

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   初始化     │ ──▶│ 确定性扫描   │ ──▶│  深度分析    │ ──▶│   验证       │ ──▶│   报告       │
│              │    │              │    │              │    │              │    │              │
│ 项目信息收集 │    │ 污点分析     │    │ LLM 分析     │    │ 交叉验证     │    │ 结构化报告   │
│ 技术栈识别   │    │ 模式检测     │    │ 工具验证     │    │ 置信度评估   │    │ 修复建议     │
│ 攻击面评估   │    │ 规则匹配     │    │ 假设验证     │    │ PoC 生成     │    │ 导出功能     │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
```

### 内置专业工具

#### 分析工具
| 工具 | 功能 |
|------|------|
| `trace_taint` | 执行污点分析，追踪数据流（变量级） |
| `detect_vulnerability_patterns` | 检测常见漏洞模式 |
| `global_taint_analysis` | 跨文件污点分析 |
| `batch_pattern_scan` | 批量模式扫描 |

#### 文件与搜索工具
| 工具 | 功能 |
|------|------|
| `read_file` | 读取文件内容 |
| `list_files` | 列出目录文件 |
| `search_symbol` | 搜索符号定义 |
| `get_ast_context` | 获取 AST 上下文 |
| `text_search` | 文本搜索 |

#### 输出工具
| 工具 | 功能 |
|------|------|
| `report_finding` | 报告漏洞发现 |
| `write_file` | 写入文件（自动修复） |
| `execute_shell` | 执行 Shell 命令 |

### 智能工具推荐

根据审计阶段自动推荐最佳工具：

| 阶段 | 推荐工具 | 用途 |
|------|----------|------|
| 初始化 | `list_files`, `get_file_structure` | 项目结构分析 |
| 确定性扫描 | `global_taint_analysis`, `batch_pattern_scan` | 批量漏洞检测 |
| 深度分析 | `trace_taint`, `detect_vulnerability_patterns` | 精确漏洞追踪 |
| 验证 | `detect_vulnerability_patterns`（交叉验证） | 确认漏洞有效性 |

### 支持的漏洞类型

18+ 种漏洞类型，完整 CWE 映射：

| 漏洞类型 | 严重程度 | CWE |
|----------|----------|-----|
| SQL 注入 | Critical | CWE-89 |
| 命令注入 | Critical | CWE-78 |
| 代码注入 | Critical | CWE-94 |
| 认证绕过 | Critical | CWE-287 |
| 路径遍历 | High | CWE-22 |
| XSS | High | CWE-79 |
| SSRF | High | CWE-918 |
| XXE | High | CWE-611 |
| 不安全反序列化 | High | CWE-502 |
| 硬编码密钥 | High | CWE-798 |
| 开放重定向 | Medium | CWE-601 |
| LDAP 注入 | Medium | CWE-90 |
| 日志注入 | Medium | CWE-93 |
| 不安全 Cookie | Medium | CWE-614 |
| 弱加密 | Medium | CWE-327 |
| 不安全随机数 | Medium | CWE-338 |
| 敏感信息泄露 | High | CWE-200 |
| 调试信息泄露 | Low | CWE-209 |

### TUI 界面

基于 **ratatui** 的终端用户界面：

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Files         │  Code View                                    │ Findings │
│ ┌────────────┐ │ ┌────────────────────────────────────────────┐ │ ┌──────┐ │
│ │ ▸ src/     │ │ │  1 │ def process_input(user_data):         │ │ │ HIGH │ │
│ │   main.py  │ │ │  2 │     # 污点源: 用户输入                 │ │ │ SQLi │ │
│ │   utils.py │ │ │  3 │     query = f"SELECT * FROM users     │ │ │ CMDi │ │
│ │   auth.py  │ │ │  4 │               WHERE id = {user_data}" │ │ │ XSS  │ │
│ │ ▸ tests/   │ │ │  5 │     # 危险函数: SQL 执行               │ │ │ ...  │ │
│ └────────────┘ │ └────────────────────────────────────────────┘ │ └──────┘ │
├────────────────┴────────────────────────────────────────────────┴──────────┤
│  Agent Status                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │ [Analysis Agent] 正在执行污点分析...                    ████████░░ 80% │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
├───────────────────────────────────────────────────────────────────────────┤
│  Chat                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │ > 检查这个文件是否存在 SQL 注入漏洞                                   │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────────┘
```

**快捷键**:
- `Tab` / `Shift+Tab` - 切换面板
- `Enter` - 发送消息
- `Esc` - 退出
- `Ctrl+C` - 强制退出

### 配置

配置文件位置：
- Windows: `%APPDATA%\ctx-audit\config.toml`
- macOS/Linux: `~/.config/ctx-audit/config.toml`

```toml
[llm]
provider = "anthropic"
api_key = "sk-ant-..."
model = "claude-3-5-sonnet-20241022"
max_tokens = 4096
temperature = 0.7

[scan]
rules_dir = "./rules"
max_threads = 4
exclude_patterns = ["node_modules", "target", "vendor", ".git"]

[output]
format = "terminal"  # terminal, json, sarif
color = true
verbose = false
```

### 支持的 LLM 提供商

| 提供商 | provider 值 | 推荐模型 | 说明 |
|--------|-------------|----------|------|
| Anthropic | `anthropic` | Claude 3.5 Sonnet | **推荐**，复杂分析能力最强 |
| OpenAI | `openai` | GPT-4 / GPT-4o | 通用分析 |
| OpenAI Compatible | `openai-compatible` | - | 自定义端点（如 vLLM） |
| Ollama | `ollama` | Llama 3 / Qwen | 本地模型，隐私保护 |

### 项目结构

```
CTX-Audit/
├── cli/                         # CLI 工具 (ctx-audit)
│   ├── src/
│   │   ├── commands/           # CLI 子命令实现
│   │   │   ├── audit.rs        # AI 深度审计
│   │   │   ├── scan.rs         # 规则扫描
│   │   │   ├── chat.rs         # REPL 对话
│   │   │   └── ...
│   │   ├── tui/                # 终端 UI (ratatui)
│   │   │   ├── panels/         # 面板实现
│   │   │   ├── widgets/        # 自定义组件
│   │   │   └── llm/            # 流式 LLM 响应
│   │   ├── database/           # SQLite 数据层
│   │   ├── report/             # 报告生成
│   │   └── config.rs           # 配置管理
│   └── Cargo.toml
├── core/                        # deepaudit-core 共享库
│   └── src/
│       ├── ast/                # AST 引擎 (tree-sitter)
│       ├── scanner/            # 文件扫描器
│       ├── rules/              # 规则引擎
│       ├── analysis/           # 分析模块
│       │   ├── taint.rs        # 污点分析
│       │   ├── dataflow.rs     # 数据流分析
│       │   ├── imports.rs      # 跨文件引用
│       │   └── cache.rs        # 分析缓存
│       └── indexing/           # 代码索引
├── agent-engine/               # Agent 引擎
│   └── src/
│       ├── react/              # ReAct 循环
│       ├── context/            # RAG 上下文检索
│       ├── fix/                # 自动修复生成
│       ├── poc/                # PoC 漏洞验证
│       ├── audit_chain.rs      # 审计思维链
│       ├── tool_recommender.rs # 工具推荐
│       └── phase_executor.rs   # 阶段执行器
├── llm/                        # LLM 客户端
│   └── src/
│       ├── providers/          # Anthropic, OpenAI, Ollama
│       ├── embedding.rs        # 文本嵌入
│       └── stream.rs           # 流式响应
├── tools/                      # 工具系统
│   └── src/
│       ├── ast_tools.rs        # AST 工具
│       ├── taint_tools.rs      # 污点分析工具
│       ├── pattern_tools.rs    # 模式匹配工具
│       ├── search_tools.rs     # 搜索工具
│       ├── shell_tools.rs      # Shell 工具
│       └── write_tools.rs      # 写入工具
├── rules/                      # 安全规则 YAML
│   ├── command-injection.yaml
│   ├── path-traversal.yaml
│   └── ...
├── Cargo.toml                  # Workspace 配置
└── CLAUDE.md                   # 开发指南
```

### 开发

```bash
# 开发构建
cargo build

# Release 构建
cargo build --release

# 运行测试
cargo test

# 代码检查
cargo clippy
cargo clippy --fix

# 格式化
cargo fmt
cargo fmt -- --check

# 运行（开发模式）
cargo run -- audit ./test-project --verbose

# 日志调试 (Windows PowerShell)
$env:RUST_LOG="ctx_audit=debug"
cargo run -- audit ./project

# 日志调试 (Linux/macOS)
RUST_LOG="ctx_audit=debug" cargo run -- audit ./project
```


### 数据库位置

审计数据存储在本地 SQLite 数据库：
- Windows: `%APPDATA%\ctx-audit\audit.db`
- macOS/Linux: `~/.local/share/ctx-audit/audit.db`

### License

Apache License 2.0

---

## English

### Introduction

CTX-Audit is a professional code security audit terminal tool implemented in Rust, combining **traditional static analysis** with **AI-powered intelligent analysis**. Unlike general-purpose AI assistants, it provides deterministic, reproducible, professional-grade security audits:

```bash
# One-command deep audit
ctx-audit audit ./myproject
```

### Key Features

| Feature | Description |
|---------|-------------|
| **Deterministic Taint Analysis** | Precise data flow analysis based on variable tracking, not simple line number comparison |
| **Hypothesis-Driven Audit** | Professional security audit thinking chain: Hypothesis → Evidence → Verification → Conclusion |
| **Cross-File Analysis** | Function call graph construction with interprocedural taint propagation |
| **Intelligent Tool Recommendation** | Automatically recommends the best analysis tools based on audit phase and context |
| **Multi-Agent Collaboration** | Four agent types: Orchestrator, Recon, Analysis, Verification |
| **RAG Context Enhancement** | Vector store-based retrieval-augmented generation |
| **Auto Fix & PoC** | Automatic vulnerability fix suggestions and proof-of-concept code generation |
| **Multi-Language Support** | 10+ languages via tree-sitter (Python, JavaScript, TypeScript, Java, Rust, Go, etc.) |

### Quick Start

```bash
# Build from source
git clone https://github.com/ctx-audit/ctx-audit.git
cd ctx-audit
cargo build --release

# Install to system
cargo install --path cli

# Configure LLM API key
ctx-audit config set llm.api_key your-api-key

# Run audit
ctx-audit audit ./myproject
```

### Usage

```bash
# AI-driven deep audit
ctx-audit audit ./myproject

# Quick rule scan
ctx-audit scan ./myproject

# Launch interactive TUI interface
ctx-audit ui ./myproject

# REPL chat mode
ctx-audit chat

# Analyze single file
ctx-audit analyze ./src/main.py

# Manage findings
ctx-audit findings list
ctx-audit findings export --format json

# Configuration
ctx-audit config show
ctx-audit config set llm.api_key your-api-key
ctx-audit config validate --test-llm
```

### CLI Commands

| Command | Function | Description |
|---------|----------|-------------|
| `audit <path>` | AI deep audit | Multi-agent collaboration, hypothesis-driven audit |
| `scan <path>` | Quick rule scan | Batch processing, high performance |
| `chat [path]` | REPL chat mode | Interactive code Q&A |
| `ui [path]` | TUI interface | Terminal graphical interface |
| `analyze <file>` | Single file analysis | Display AST and symbol info |
| `findings <action>` | Vulnerability management | View, update, export vulnerabilities |
| `config <action>` | Configuration | LLM config, rule config |
| `completion <shell>` | Shell completion | bash/zsh/fish/powershell |

### Audit Workflow

CTX-Audit uses a professional five-phase audit process:

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Initialize  │ ──▶│ Deterministic│ ──▶│ Deep Analysis│ ──▶│ Verification │ ──▶│   Report     │
│              │    │    Scan      │    │              │    │              │    │              │
│ Project info │    │ Taint        │    │ LLM analysis │    │ Cross-       │    │ Structured   │
│ Tech stack   │    │ Pattern      │    │ Tool         │    │ validation   │    │ Fix          │
│ Attack       │    │ detection    │    │ verification │    │ Confidence   │    │ suggestions  │
│ surface      │    │ Rule match   │    │ Hypothesis   │    │ PoC gen      │    │ Export       │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
```

### Supported Vulnerability Types

18+ vulnerability types with complete CWE mapping:

| Type | Severity | CWE |
|------|----------|-----|
| SQL Injection | Critical | CWE-89 |
| Command Injection | Critical | CWE-78 |
| Code Injection | Critical | CWE-94 |
| Auth Bypass | Critical | CWE-287 |
| Path Traversal | High | CWE-22 |
| XSS | High | CWE-79 |
| SSRF | High | CWE-918 |
| XXE | High | CWE-611 |
| Insecure Deserialization | High | CWE-502 |
| Hardcoded Secrets | High | CWE-798 |
| Open Redirect | Medium | CWE-601 |
| LDAP Injection | Medium | CWE-90 |
| Log Injection | Medium | CWE-93 |
| Insecure Cookie | Medium | CWE-614 |
| Weak Encryption | Medium | CWE-327 |
| Insecure Random | Medium | CWE-338 |
| Sensitive Data Exposure | High | CWE-200 |
| Debug Info Leak | Low | CWE-209 |

### Configuration

Config file location:
- Windows: `%APPDATA%\ctx-audit\config.toml`
- macOS/Linux: `~/.config/ctx-audit/config.toml`

```toml
[llm]
provider = "anthropic"
api_key = "sk-ant-..."
model = "claude-3-5-sonnet-20241022"
max_tokens = 4096
temperature = 0.7

[scan]
rules_dir = "./rules"
max_threads = 4
exclude_patterns = ["node_modules", "target", "vendor", ".git"]

[output]
format = "terminal"  # terminal, json, sarif
color = true
verbose = false
```

### Supported LLM Providers

| Provider | provider value | Recommended Model | Notes |
|----------|----------------|-------------------|-------|
| Anthropic | `anthropic` | Claude 3.5 Sonnet | **Recommended**, best for complex analysis |
| OpenAI | `openai` | GPT-4 / GPT-4o | General-purpose |
| OpenAI Compatible | `openai-compatible` | - | Custom endpoints (e.g., vLLM) |
| Ollama | `ollama` | Llama 3 / Qwen | Local models, privacy protection |

### Development

```bash
# Development build
cargo build

# Release build
cargo build --release

# Run tests
cargo test

# Linting
cargo clippy
cargo clippy --fix

# Format
cargo fmt
cargo fmt -- --check

# Run (dev mode)
cargo run -- audit ./test-project --verbose

# Debug logging (Windows PowerShell)
$env:RUST_LOG="ctx_audit=debug"
cargo run -- audit ./project

# Debug logging (Linux/macOS)
RUST_LOG="ctx_audit=debug" cargo run -- audit ./project
```

### License

Apache License 2.0
