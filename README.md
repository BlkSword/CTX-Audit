# CTX-Audit

<div align="center">

**AI 驱动的代码安全审计工具**

**神经符号引擎：Rust 静态分析 + LLM 语义验证**

[![Rust](https://img.shields.io/badge/Rust-2021-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-227%20passed-brightgreen?style=flat-square)]()

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

# 深度扫描（加入 AST 污点分析 + 置信度评分）
ctx-audit scan ./myproject --deep

# 深度 AI 审计（Rust 静态分析 + LLM 验证）
ctx-audit audit ./myproject --verbose

# 守护模式：持续监听，输出 SARIF
ctx-audit watch ./myproject
```

### 命令详解

#### `scan` — 快速规则扫描

多引擎并行扫描：语言感知正则规则 + SCA 依赖漏洞检测 + 可选 AST 污点分析。

```bash
ctx-audit scan ./project [OPTIONS]

OPTIONS:
  -s, --severity <级别>     按严重程度过滤 (critical, high, medium, low, info)
  -p, --pattern <模式>      按文件模式过滤 (如 *.py)
  -o, --output <文件>       输出文件路径
  -t, --threads <N>         并行扫描线程数 (默认: 4)
  -r, --rules <目录>        自定义规则目录
      --deep                启用深度扫描 (AST 污点分析 + 置信度评分 + 去重)
```

**扫描引擎**：

| 引擎 | 说明 | 速度 |
|------|------|------|
| RuleScanner | 语言感知正则规则（YAML，多语言模式） | 快 |
| RegexScanner | 硬编码模式检测 | 快 |
| SCAScanner | 依赖漏洞检测（OSV API） | 中 |
| AstTaintScanner | AST 污点分析（`--deep` 模式） | 慢 |

**输出格式**（全局 `-o` 参数）：

```bash
ctx-audit -o json scan ./project -o results.json      # JSON
ctx-audit -o sarif scan ./project -o results.sarif     # SARIF 2.1.0
ctx-audit -o markdown scan ./project -o report.md      # Markdown
ctx-audit -o text scan ./project -o report.txt          # 纯文本 (默认)
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
ctx-audit -o sarif scan ./project -o report.sarif

# 深度扫描 → SARIF（含 AST 污点路径和置信度）
ctx-audit -o sarif scan ./project --deep -o report.sarif

# 审计 → SARIF（含 LLM 验证和修复建议）
ctx-audit -o sarif audit ./project -o report.sarif

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
        run: ctx-audit -o sarif scan . --deep -o results.sarif
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
│  DualVerification (LLM + 确定性引擎交叉验证)                  │
│  ContextAwareAnalyzer (框架感知语义分析)                      │
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
│  │ SCA 扫描器   │  │ Scanner       │  │ Rule Engine       │  │
│  │ (OSV API)   │  │ (多语言正则)  │  │ (YAML 多语言规则)  │  │
│  └─────────────┘  └──────────────┘  └───────────────────┘  │
│  ┌─────────────┐  ┌──────────────┐                          │
│  │ FileWatcher  │  │ 去重+评分     │                          │
│  │ (增量扫描)   │  │ (置信度系统)  │                          │
│  └─────────────┘  └──────────────┘                          │
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
│ 项目信息 │   │ AST 污点分析 │   │ Multi-Agent  │   │ 双重     │   │ SARIF    │
│ 技术栈   │   │ 语言感知规则 │   │ 语义理解     │   │ 交叉     │   │ JSON     │
│ 攻击面   │   │ SCA 依赖检测 │   │              │   │ LLM+Det  │   │ Markdown │
│          │   │ 置信度评分   │   │              │   │ 最终判断 │   │ 修复建议 │
│          │   │ 去重合并     │   │              │   │          │   │          │
└──────────┘   └──────────────┘   └──────────────┘   └──────────┘   └──────────┘
```

### 检测能力

#### 代码漏洞检测

| 漏洞类型 | 严重程度 | CWE | 检测方式 |
|----------|----------|-----|----------|
| SQL 注入 | Critical | CWE-89 | AST 污点分析 + LLM |
| 命令注入 | Critical | CWE-78 | 多语言规则 + 污点分析 |
| 代码注入 | Critical | CWE-94 | 多语言规则 + 污点分析 |
| 路径遍历 | High | CWE-22 | 多语言规则 + 污点分析 |
| XSS | High | CWE-79 | 污点分析 + LLM |
| SSRF | High | CWE-918 | 污点分析 + LLM |
| 不安全反序列化 | Critical | CWE-502 | 多语言规则 (Java/Python/PHP) |
| CSRF | Medium | CWE-352 | Spring 注解检测 |
| XXE | Critical | CWE-611 | Java XML 解析器检测 |
| 开放重定向 | Medium | CWE-601 | 多语言规则 |
| 弱加密 | High | CWE-327 | Java 加密 API 检测 |
| 不安全 Cookie | Medium | CWE-614 | HTTP Set-Cookie 检测 |
| 硬编码密码 | High | CWE-259 | 通用模式匹配 |
| 敏感信息泄露 | High | CWE-200 | 通用模式匹配 |
| 日志注入 | Medium | CWE-117 | 多语言规则 |
| 调试信息泄露 | Info | CWE-215 | 多语言规则 |

#### 依赖漏洞检测 (SCA)

通过 OSV API (osv.dev) 查询已知漏洞依赖，支持：

| 生态 | 文件 | 说明 |
|------|------|------|
| npm | `package.json` | Node.js 依赖 |
| PyPI | `requirements.txt` | Python 依赖 |
| crates.io | `Cargo.lock` | Rust 依赖 |
| Go | `go.sum` | Go 模块依赖 |

#### 框架感知规则

| 框架 | Sources | Sinks | Sanitizers |
|------|---------|-------|------------|
| React/Next.js | formData, cookies, headers, searchParams | dangerouslySetInnerHTML, eval | DOMPurify, sanitizeHtml |
| Django | request.GET/POST/META, get_object_or_404 | raw(), extra(), mark_safe | bleach.clean, strip_tags |
| Spring | @RequestParam, @PathVariable, @RequestBody | JdbcTemplate, Runtime.exec | PreparedStatement |
| Express/Node | req.body/query/params/headers | eval, child_process.exec | validator.escape |

### 真实项目验证

对 Halo (Java/Spring Boot 博客平台, 1233 Java 文件) 的扫描结果：

| 指标 | 值 |
|------|-----|
| 扫描耗时 | ~4 秒 |
| 总发现 | 94 个 |
| SCA 依赖漏洞 | 22 个 (axios, dompurify, lodash 等) |
| 代码漏洞 | 72 个 (反序列化、CSRF、硬编码密码等) |
| 误报率 | ~20% |
| 输出格式 | JSON / SARIF 2.1.0 / Markdown / Text |

### 规则系统

规则以 YAML 文件定义，支持单语言和多语言模式：

```yaml
# 单语言规则
id: ldap-injection
language: java
pattern: (?i)(DirContext|InitialDirContext).*filter
severity: high

# 多语言规则
id: code-injection
language: all
patterns:
  - language: java
    pattern: (?i)(ScriptEngineManager|GroovyShell|Runtime\.getRuntime)
  - language: javascript
    pattern: (?i)(eval\s*\(|new\s+Function\s*\(|vm\.runIn)
  - language: python
    pattern: (?i)(eval\s*\(|exec\s*\(|__import__)
severity: critical
```

**规则元数据**：

```yaml
id: sql-injection
owasp: "A03:2021-Injection"
remediation: "使用参数化查询，避免字符串拼接 SQL"
references:
  - "https://owasp.org/www-community/attacks/SQL_Injection"
  - "https://cwe.mitre.org/data/definitions/89.html"
```

### 项目结构

```
CTX-Audit/
├── cli/                         # CLI 二进制 (ctx-audit)
│   └── src/
│       ├── commands/            # 命令实现
│       │   ├── audit.rs         # 深度 AI 审计
│       │   ├── scan.rs          # 快速规则扫描 + --deep 模式
│       │   ├── watch.rs         # 守护模式（增量扫描）
│       │   ├── chat.rs          # REPL 对话
│       │   └── ...
│       ├── tui/                 # 终端 UI (ratatui)
│       ├── output.rs            # 统一输出格式化
│       └── config.rs            # 配置管理
│
├── core/                        # 核心分析库
│   └── src/
│       ├── sarif/               # SARIF 2.1.0 引擎
│       ├── watcher/             # 文件监听与增量扫描
│       │   ├── mod.rs           # FileWatcher + 增量 AST 污点分析
│       │   └── delta.rs         # Content Hash 变更检测
│       ├── analysis/            # 污点分析
│       │   ├── ast_taint.rs     # AST 污点分析器 (核心引擎)
│       │   ├── taint.rs         # Source/Sink/Flow 数据结构
│       │   ├── enhanced_taint.rs # 增强污点分析
│       │   ├── cross_file.rs    # 跨文件污点分析
│       │   └── data_flow.rs     # 数据流分析
│       ├── ast/                 # AST 引擎 (tree-sitter 12+ 语言)
│       ├── scanner/             # 扫描器
│       │   ├── mod.rs           # scan_directory + scan_directory_deep + 去重
│       │   ├── regex_scanner.rs # 硬编码正则扫描
│       │   ├── sca_scanner.rs   # SCA 依赖扫描 (OSV API)
│       │   └── manager.rs       # 扫描器管理
│       ├── rules/               # 规则系统
│       │   ├── model.rs         # Rule + LanguagePattern 数据模型
│       │   ├── scanner.rs       # 语言感知规则扫描器
│       │   ├── loader.rs        # YAML 规则加载
│       │   ├── taint_model.rs   # 污点规则 YAML 模型
│       │   └── taint_loader.rs  # 污点规则加载
│       └── indexing/            # 代码索引 & RAG
│
├── agent-engine/                # 多 Agent 编排
│   └── src/
│       ├── multi_agent/         # Coordinator-Specialist 系统
│       ├── verification/        # 双重交叉验证 (LLM + 确定性)
│       ├── semantic/            # 框架感知语义分析
│       ├── audit_chain.rs       # 假设驱动审计链
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
├── rules/                       # YAML 规则文件
│   ├── *.yaml                   # 17 条检测规则 (多语言模式)
│   └── taint/                   # 污点分析规则
│       ├── generic-taint.yaml   # 通用污点规则
│       └── frameworks/          # 框架特定规则
│           ├── react-nextjs.yaml
│           ├── django.yaml
│           ├── spring.yaml
│           └── express-node.yaml
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
cargo test --workspace --lib   # 运行测试 (227 tests)
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
ctx-audit scan ./myproject --deep                  # Deep scan (AST taint analysis)
ctx-audit audit ./myproject --verbose              # Deep AI audit
ctx-audit watch ./myproject                        # Continuous monitoring
```

### Commands

| Command | Description |
|---------|-------------|
| `scan <path>` | Multi-engine scan: language-aware rules + SCA + optional AST taint (`--deep`) |
| `audit <path>` | Deep AI audit (5 phases, Rust + LLM dual verification) |
| `watch <path>` | Continuous monitoring with incremental SARIF output |
| `chat [path]` | Interactive REPL with AI analyst |
| `analyze <file>` | Single file deep analysis |
| `findings <action>` | Vulnerability management (list/view/update/export) |
| `ui [path]` | Terminal UI (ratatui) |
| `config <action>` | Configuration management |

### Detection Capabilities

| Category | CWE | Method |
|----------|-----|--------|
| Code/Command/SQL Injection | CWE-94/78/89 | Multi-lang rules + AST taint analysis |
| Path Traversal | CWE-22 | Multi-lang rules + taint source matching |
| Deserialization | CWE-502 | Multi-lang rules (Java/Python/PHP) |
| CSRF, XXE | CWE-352/611 | Framework-aware detection |
| SCA (Dependency Vulns) | - | OSV API (npm/PyPI/crates.io/Go) |
| Hardcoded Secrets | CWE-259/200 | Pattern matching |
| XSS, SSRF | CWE-79/918 | AST taint analysis + LLM |

### SARIF Output

SARIF 2.1.0 compliant with `codeFlows`, `fixes`, `rules`, and confidence scores. Consumable by VS Code, GitHub Code Scanning, and any SARIF tool.

### Validation

Scanned **Halo** (Java/Spring Boot, 1233 files): 94 findings in ~4s, ~20% FP rate, 22 real SCA vulnerabilities detected.

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
      - run: ctx-audit -o sarif scan . --deep -o results.sarif
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
