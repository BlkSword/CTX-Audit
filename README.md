# CTX-Audit

<div align="center">

**AI-Powered Professional Code Security Audit Terminal Tool**

**Multi-Agent Parallel Audit System**

[![Rust](https://img.shields.io/badge/Rust-2021-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/Version-2.0.0-green?style=flat-square)](Cargo.toml)

[English](#english) | [中文](#中文)

</div>

---

## 中文

### 简介

CTX-Audit 是一款 Rust 实现的专业代码安全审计终端工具，采用 **Multi-Agent Coordinator-Specialist 并行架构**，融合了**传统静态分析**与**AI 智能分析**的能力：

```bash
# 一键深度审计（多专家并行分析）
ctx-audit audit ./myproject
```

### 核心特性

#### Multi-Agent 并行审计系统

| 特性 | 描述 |
|------|------|
| **Coordinator-Specialist 架构** | 共享任务列表 + P2P 消息系统 + 自我认领机制 |
| **专家 Agent** | SQL注入、XSS、命令注入、路径遍历、SSRF、认证、业务逻辑、加密、配置、通用分析师 |
| **结果聚合** | 位置去重、类型匹配、多专家共识验证 |
| **交叉验证** | 4 种验证策略：单一专家、多专家共识、多样性专家、高置信优先 |
| **任务依赖管理** | 支持任务间依赖关系和委派模式 |
| **动态优先级** | 根据审计进展动态调整任务优先级 |
| **文件锁定** | 防止多专家同时分析同一文件 |

#### 语义理解引擎

| 特性 | 描述 |
|------|------|
| **意图推断** | 从模式匹配升级为代码意图理解（7 种意图类型） |
| **上下文感知** | 理解框架特定语义（Django、Flask、Express、Spring） |
| **安全边界检测** | 识别显式/隐式安全机制 |

#### 业务逻辑漏洞检测

| 特性 | 描述 |
|------|------|
| **IDOR 检测** | 不安全的直接对象引用 |
| **权限绕过** | 缺失权限检查识别 |
| **状态机异常** | 竞态条件、非法状态转换 |
| **业务规则违规** | 数量/金额/时间限制检测 |

#### 全局数据流追踪

| 特性 | 描述 |
|------|------|
| **跨文件污点分析** | 基于调用图的过程间数据流追踪 |
| **DFS 路径搜索** | 从入口点到危险汇的完整路径 |
| **代码签名** | 支持可重现性验证 |

#### Git 历史"举一反三"

| 特性 | 描述 |
|------|------|
| **漏洞修复学习** | 从 Git 历史提取修复模式 |
| **相似漏洞发现** | 在未修复文件中查找相似漏洞 |
| **修复模式识别** | 参数化查询、输入转义、权限检查等 |

#### 双重验证系统

| 特性 | 描述 |
|------|------|
| **三阶段验证** | 初次判断 → 自我质疑 → 综合判断 |
| **4 种质疑策略** | 矛盾证据、假设检查、攻击者视角、遗漏保护 |
| **置信度调整** | 主动证伪，降低误报率 |

#### 确定性审计

| 特性 | 描述 |
|------|------|
| **固定种子** | 确保审计结果可重现 |
| **结果缓存** | 智能缓存策略（内存/磁盘/混合） |
| **可重现性验证** | 多次运行验证一致性 |

#### 其他核心功能

| 特性 | 描述 |
|------|------|
| **假设驱动审计** | 专业安全审计思维链：Hypothesis → Evidence → Verification → Conclusion |
| **ReAct 循环** | 推理-行动循环，工具自动选择 |
| **智能工具推荐** | 根据审计阶段自动推荐最佳分析工具 |
| **RAG 上下文增强** | 基于向量存储的代码检索增强生成 |
| **自动修复 & PoC** | 自动生成漏洞修复建议和概念验证代码 |
| **多语言支持** | 通过 tree-sitter 支持 10+ 种语言 |

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
# 多专家并行审计（默认）
ctx-audit audit ./myproject

# 指定专家类型
ctx-audit audit ./myproject --experts sql,xss,auth

# 启用确定性审计（可重现）
ctx-audit audit ./myproject --deterministic --seed 42

# Git 历史"举一反三"分析
ctx-audit audit ./myproject --git-learning

# 业务逻辑专项检测
ctx-audit audit ./myproject --business-logic

# 双重验证模式
ctx-audit audit ./myproject --dual-verification

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

| 命令 | 功能 |
|------|------|
| `audit <path>` | AI 深度审计（多专家并行） |
| `scan <path>` | 规则快速扫描 |
| `chat [path]` | REPL 对话模式 |
| `ui [path]` | TUI 界面 |
| `analyze <file>` | 单文件分析 |
| `findings <action>` | 漏洞管理 |
| `config <action>` | 配置管理 |
| `completion <shell>` | Shell 补全 |

### CLI 选项

```bash
# 审计选项
ctx-audit audit ./project [OPTIONS]

# 多 Agent 配置
--experts <types>     # 指定专家类型：sql,xss,command,path,ssrf,auth,bizlogic,crypto,config,general

# 确定性审计
--deterministic       # 启用确定性审计
--seed <value>        # 指定随机种子

# 特殊分析模式
--git-learning        # 启用 Git 历史"举一反三"分析
--business-logic      # 启用业务逻辑专项检测
--dual-verification   # 启用双重验证模式
```

### 系统架构

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CLI (clap)                                     │
│     audit │ scan │ chat │ ui │ analyze │ findings │ config                  │
└────────────────────────────────────┬────────────────────────────────────────┘
                                     │
┌────────────────────────────────────▼────────────────────────────────────────┐
│                         Agent Engine                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    Multi-Agent System                                │   │
│  │  ┌─────────────┐   ┌──────────────┐   ┌─────────────────────────┐   │   │
│  │  │Coordinator │───│SharedTaskList│───│ Result Aggregator      │   │   │
│  │  │(协调中心)   │   │(共享任务列表) │   │ (去重+共识验证)         │   │   │
│  │  └─────────────┘   └──────────────┘   └─────────────────────────┘   │   │
│  │         │                              │           │               │   │
│  │         │         ┌────────────────────┼────────────────────┐       │   │
│  │         │         ▼                    ▼                    ▼       │   │
│  │         │  ┌──────────┐         ┌──────────┐         ┌──────────┐   │   │
│  │         └─▶│SQL Expert│         │XSS Expert│         │Auth Expert│...│   │
│  │            │Specialist│         │Specialist│         │Specialist│   │   │
│  │            └──────────┘         └──────────┘         └──────────┘   │   │
│  │                   ▲                    ▲                    ▲        │   │
│  │                   └────────────────────┼────────────────────┘        │   │
│  │                                        │                            │   │
│  │                              ┌─────────┴─────────┐                   │   │
│  │                              │   Mailbox (P2P)   │                   │   │
│  │                              │  (消息传递系统)    │                   │   │
│  │                              └───────────────────┘                   │   │
│  │                                        │                            │   │
│  │                              ┌─────────▼─────────┐                   │   │
│  │                              │ CrossValidator   │                   │   │
│  │                              │ (交叉验证)        │                   │   │
│  │                              └──────────────────┘                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    Semantic Understanding                            │   │
│  │  ┌──────────────────┐  ┌──────────────────┐                        │   │
│  │  │ IntentInferencer │  │ContextAwareAnalyzer│                       │   │
│  │  │ (意图推断: 7种)  │  │ (框架语义+安全边界) │                        │   │
│  │  └──────────────────┘  └──────────────────┘                        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    Business Logic Analyzer                           │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │   │
│  │  │ IDOR Detector│  │Authz Detector│  │ StateMachine Analyzer     │  │   │
│  │  │ (IDOR检测)   │  │ (权限绕过)    │  │ (竞态条件)                │  │   │
│  │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        Core Components                                │   │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐  │   │
│  │  │ SecurityAudit   │  │ ToolRecommender │  │   PhaseExecutor     │  │   │
│  │  │ Chain           │  │                 │  │                     │  │   │
│  │  │ (假设驱动审计)   │  │ (智能工具推荐)   │  │ (五阶段审计执行)    │  │   │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────────┘  │   │
│  │                                                                          │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐  │   │
│  │  │ ReAct Loop      │  │ RAG Retriever   │  │ Fix & PoC Generator │  │   │
│  │  │ (推理-行动循环)  │  │ (上下文增强)     │  │ (修复与验证生成)    │  │   │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────┬────────────────────────────────────────┘
                                     │
┌────────────────────────────────────▼────────────────────────────────────────┐
│                              Analysis Layer                                 │
│  ┌──────────────────────┐  ┌──────────────────────┐  ┌─────────────────┐  │
│  │  GlobalFlowGraph     │  │ GitHistoryAnalyzer   │  │ DualVerification│  │
│  │  (跨文件数据流追踪)   │  │ ("举一反三"学习)       │  │ (双重验证系统)   │  │
│  └──────────────────────┘  └──────────────────────┘  └─────────────────┘  │
└────────────────────────────────────┬────────────────────────────────────────┘
                                     │
┌────────────────────────────────────▼────────────────────────────────────────┐
│                              Tools System                                   │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌───────────────┐       │
│  │ Taint Tools │ │ AST Tools   │ │ Search Tools│ │ Write Tools   │       │
│  └─────────────┘ └─────────────┘ └─────────────┘ └───────────────┘       │
└────────────────────────────────────┬────────────────────────────────────────┘
                                     │
┌────────────────────────────────────▼────────────────────────────────────────┐
│                              Core Library                                   │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐       │
│  │ EnhancedTaint   │  │ CrossFileTaint  │  │   CacheManager      │       │
│  │ Analyzer        │  │ Analyzer        │  │                     │       │
│  └─────────────────┘  └─────────────────┘  └─────────────────────┘       │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐       │
│  │ AST Engine      │  │ Rule Engine     │  │ Vector Store        │       │
│  │ (tree-sitter)   │  │ (YAML 规则)     │  │ (语义搜索)          │       │
│  └─────────────────┘  └─────────────────┘  └─────────────────────┘       │
└────────────────────────────────────┬────────────────────────────────────────┘
                                     │
┌────────────────────────────────────▼────────────────────────────────────────┐
│                              LLM Integration                                │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐       │
│  │ Anthropic       │  │ OpenAI          │  │ Ollama              │       │
│  │ (Claude 3.5)    │  │ (GPT-4)         │  │ (本地模型)          │       │
│  └─────────────────┘  └─────────────────┘  └─────────────────────┘       │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 审计流程

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   初始化     │ ──▶│ 确定性扫描   │ ──▶│  深度分析    │ ──▶│   验证       │ ──▶│   报告       │
│              │    │              │    │              │    │              │    │              │
│ 项目信息收集 │    │ 污点分析     │    │ Multi-Agent  │    │ 双重验证     │    │ 结构化报告   │
│ 技术栈识别   │    │ 模式检测     │    │ 语义理解     │    │ 交叉验证     │    │ 修复建议     │
│ 攻击面评估   │    │ 规则匹配     │    │ 业务逻辑     │    │ 置信度评估   │    │ 导出功能     │
│              │    │              │    │ Git学习      │    │ PoC 生成     │    │              │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
```

### 专家 Agent 类型

| 专家 | 专长领域 | 典型漏洞 |
|------|----------|----------|
| **SQL Expert** | SQL 注入检测 | SQLi、NoSQL 注入 |
| **XSS Expert** | 跨站脚本攻击 | Reflected XSS、Stored XSS、DOM XSS |
| **Command Expert** | 命令注入检测 | OS 命令注入、代码注入 |
| **Path Expert** | 路径遍历检测 | 路径遍历、文件包含 |
| **SSRF Expert** | 请求伪造检测 | SSRF、XXE |
| **Auth Expert** | 认证授权检测 | 认证绕过、会话管理 |
| **BizLogic Expert** | 业务逻辑漏洞 | IDOR、支付绕过、竞态条件 |
| **Crypto Expert** | 加密安全检测 | 弱加密、硬编码密钥 |
| **Config Expert** | 配置安全检测 | 不安全配置、CORS/CSP |
| **General Analyst** | 通用分析 | 综合安全评估 |

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
| IDOR | High | CWE-639 |
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
│  │ [Multi-Agent] SQL Expert: ████████░░ 80% | XSS Expert: ████████░░ 75%│ │
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

[multi_agent]
enabled = true
max_parallel_workers = 5
default_experts = ["sql", "xss", "auth", "bizlogic"]

[deterministic]
enabled = false
seed = 42
cache_strategy = "smart"  # disabled, memory_only, persistent, smart

[git_learning]
enabled = false
max_commits = 100
similarity_threshold = 0.5

[dual_verification]
enabled = true
question_rounds = 2
min_confidence_threshold = 0.6

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
| Anthropic | `anthropic` | Claude 3.5 Sonnet | 推荐，复杂分析能力最强 |
| OpenAI | `openai` | GPT-4 / GPT-4o | 通用分析 |
| OpenAI Compatible | `openai-compatible` | - | 自定义端点（如 vLLM） |
| Ollama | `ollama` | Llama 3 / Qwen | 本地模型，隐私保护 |

### 项目结构

```
CTX-Audit/
├── cli/                         # CLI 工具 (ctx-audit)
│   ├── src/
│   │   ├── commands/           # CLI 子命令实现
│   │   ├── tui/                # 终端 UI (ratatui)
│   │   ├── database/           # SQLite 数据层
│   │   └── config.rs           # 配置管理
│   └── Cargo.toml
├── core/                        # deepaudit-core 共享库
│   └── src/
│       ├── ast/                # AST 引擎 (tree-sitter)
│       ├── scanner/            # 文件扫描器
│       ├── rules/              # 规则引擎
│       ├── analysis/           # 分析模块
│       └── indexing/           # 代码索引
├── agent-engine/               # Agent 引擎
│   └── src/
│       ├── multi_agent/        # Multi-Agent 系统 (Coordinator-Specialist)
│       │   ├── system.rs       # 统一系统接口 (UnifiedMultiAgentSystem)
│       │   ├── coordinator/    # Coordinator-Specialist 架构
│       │   │   ├── mod.rs      # AuditTeamSystem
│       │   │   ├── coordinator.rs  # Coordinator 协调器
│       │   │   ├── specialist.rs    # Specialist 专家
│       │   │   ├── shared_task_list.rs  # 共享任务列表
│       │   │   ├── mailbox.rs     # P2P 消息系统
│       │   │   ├── dynamic_priority.rs  # 动态优先级
│       │   │   └── cross_validation.rs  # 交叉验证
│       │   ├── task.rs         # AuditTask 任务定义
│       │   ├── aggregator.rs   # ResultAggregator 聚合器
│       │   ├── validator.rs    # CrossValidator 交叉验证
│       │   ├── prompts.rs      # 专家提示词模板
│       │   └── helpers.rs      # 辅助函数
│       ├── semantic/           # 语义理解引擎
│       │   ├── mod.rs          # SemanticUnderstandingEngine
│       │   ├── intent_inferencer.rs  # IntentInferencer
│       │   └── context_analyzer.rs   # ContextAwareAnalyzer
│       ├── analysis/           # 高级分析模块
│       │   ├── business_logic.rs     # BusinessLogicAnalyzer
│       │   ├── global_flow.rs        # GlobalFlowGraph
│       │   └── git_history.rs        # GitHistoryAnalyzer
│       ├── verification/       # 双重验证系统
│       │   ├── dual_verification.rs  # DualVerificationSystem
│       │   └── self_questioner.rs    # SelfQuestioner
│       ├── deterministic/      # 确定性审计
│       │   ├── config.rs       # DeterministicConfig
│       │   ├── cache.rs        # AuditCache
│       │   └── executor.rs     # DeterministicExecutor
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
├── docs/                       # 文档
│   └── OPTIMIZATION_PLAN.md    # 优化计划
├── Cargo.toml                  # Workspace 配置
├── CLAUDE.md                   # 开发指南
└── README.md                   # 本文件
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

CTX-Audit is a professional code security audit terminal tool implemented in Rust, featuring a **Multi-Agent Coordinator-Specialist Parallel Architecture** that combines **traditional static analysis** with **AI-powered intelligent analysis**:

```bash
# One-command deep audit (multi-expert parallel analysis)
ctx-audit audit ./myproject
```

### Key Features

#### Multi-Agent Parallel Audit System

| Feature | Description |
|---------|-------------|
| **Coordinator-Specialist Architecture** | Shared task list + P2P messaging + Self-claim mechanism |
| **Expert Agents** | SQLi, XSS, Command Injection, Path Traversal, SSRF, Auth, BizLogic, Crypto, Config, General |
| **Result Aggregation** | Location deduplication, type matching, multi-expert consensus |
| **Cross Validation** | 4 strategies: SingleExpert, MultiExpertConsensus, DiverseExpertise, HighConfidenceFirst |
| **Task Dependency** | Support for task dependencies and delegation mode |
| **Dynamic Priority** | Dynamic task priority adjustment based on audit progress |
| **File Locking** | Prevent multiple specialists from analyzing the same file |

#### Semantic Understanding Engine

| Feature | Description |
|---------|-------------|
| **Intent Inference** | From pattern matching to code intent understanding (7 intent types) |
| **Context Aware** | Framework-specific semantics (Django, Flask, Express, Spring) |
| **Security Boundary** | Identify explicit/implicit security mechanisms |

#### Business Logic Vulnerability Detection

| Feature | Description |
|---------|-------------|
| **IDOR Detection** | Insecure Direct Object Reference |
| **Authorization Bypass** | Missing authorization checks |
| **State Machine Anomalies** | Race conditions, invalid transitions |
| **Business Rule Violations** | Quantity/amount/time limits |

#### Global Data Flow Tracking

| Feature | Description |
|---------|-------------|
| **Cross-File Taint** | Call graph-based inter-procedural analysis |
| **DFS Path Search** | Complete paths from entry points to sinks |
| **Code Signature** | Reproducibility verification |

#### Git History "Learn from Fixes"

| Feature | Description |
|---------|-------------|
| **Fix Pattern Learning** | Extract fix patterns from Git history |
| **Similar Vulnerability Discovery** | Find similar unfixed vulnerabilities |
| **Fix Pattern Recognition** | Parameterized queries, input escaping, permission checks |

#### Dual Verification System

| Feature | Description |
|---------|-------------|
| **Three-Stage Verification** | Primary judgment → Self-questioning → Final conclusion |
| **4 Questioning Strategies** | Contradiction evidence, assumption check, attacker perspective, missed protection |
| **Confidence Adjustment** | Active falsification, reduce false positives |

#### Deterministic Audit

| Feature | Description |
|---------|-------------|
| **Fixed Seed** | Ensures reproducible audit results |
| **Result Caching** | Smart caching strategies (memory/disk/hybrid) |
| **Reproducibility Verification** | Multi-run consistency verification |

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
# Multi-expert parallel audit (default)
ctx-audit audit ./myproject

# Specify expert types
ctx-audit audit ./myproject --experts sql,xss,auth

# Enable deterministic audit (reproducible)
ctx-audit audit ./myproject --deterministic --seed 42

# Git history "learn from fixes" analysis
ctx-audit audit ./myproject --git-learning

# Business logic focused detection
ctx-audit audit ./myproject --business-logic

# Dual verification mode
ctx-audit audit ./myproject --dual-verification

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

| Command | Function |
|---------|----------|
| `audit <path>` | AI deep audit (multi-expert parallel) |
| `scan <path>` | Quick rule scan |
| `chat [path]` | REPL chat mode |
| `ui [path]` | TUI interface |
| `analyze <file>` | Single file analysis |
| `findings <action>` | Vulnerability management |
| `config <action>` | Configuration |
| `completion <shell>` | Shell completion |

### CLI Options

```bash
# Audit options
ctx-audit audit ./project [OPTIONS]

# Multi-Agent configuration
--experts <types>     # Specify expert types: sql,xss,command,path,ssrf,auth,bizlogic,crypto,config,general

# Deterministic audit
--deterministic       # Enable deterministic audit
--seed <value>        # Specify random seed

# Special analysis modes
--git-learning        # Enable Git history "learn from fixes" analysis
--business-logic      # Enable business logic focused detection
--dual-verification   # Enable dual verification mode
```

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

[multi_agent]
enabled = true
max_parallel_workers = 5
default_experts = ["sql", "xss", "auth", "bizlogic"]

[deterministic]
enabled = false
seed = 42
cache_strategy = "smart"

[git_learning]
enabled = false
max_commits = 100
similarity_threshold = 0.5

[dual_verification]
enabled = true
question_rounds = 2
min_confidence_threshold = 0.6
```

### Supported LLM Providers

| Provider | provider value | Recommended Model | Notes |
|----------|----------------|-------------------|-------|
| Anthropic | `anthropic` | Claude 3.5 Sonnet | Recommended, best for complex analysis |
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
