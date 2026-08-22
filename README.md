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

## 目录

- [快速开始](#快速开始)
- [命令](#命令)
- [LLM 协作审计](#llm-协作审计推荐方式)
- [配置文件](#配置文件)
- [检测能力](#检测能力)
- [架构](#架构)
- [基准测试](#基准测试)
- [许可证](#许可证)

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

### `mcp` — LLM 协作

```bash
ctx-audit mcp    # 启动 MCP Server（stdio JSON-RPC）
```

通过 MCP 协议暴露 30+ 工具给 Claude Code / Cursor / 任何 MCP 客户端，让 LLM 自主驱动代码安全分析流程。核心思路：LLM 不直接“猜”，而是通过工具读取调用图、代码上下文、污点传播路径，基于确定性证据做判定。

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

### `config` — 配置管理

```bash
ctx-audit config show            # 显示当前配置
ctx-audit config set <key> <val> # 设置配置
ctx-audit config list            # 列出所有配置键
```

## LLM 协作审计（推荐方式）

CTX-Audit 通过 MCP 协议让外部 LLM 参与代码安全分析。核心差异：**不是让 LLM 看扫描结果猜 TP/FP，而是给 LLM 30+ 个工具去查调用图、读代码、追踪数据流，基于确定性证据做判定。**

### 工作流

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

## 配置文件

配置文件位于 `~/.config/ctx-audit/config.toml`（Linux）/ `~/Library/Application Support/ctx-audit/config.toml`（macOS）/ `%APPDATA%\ctx-audit\config.toml`（Windows）。

首次运行 `ctx-audit config set` 时自动生成。

**常用配置**：

```toml
[scan]
threads = 4
min_severity = "medium"
exclude_patterns = ["node_modules", ".git", "target", "build", "dist", "vendor", "test", "tests"]

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
| SSRF | CWE-918 | 跨文件追踪 + Host Header 规则 + 重定向作用域检查 |
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
- **YAML 规则**: 70+ sinks / 100+ sanitizers，覆盖多语言与常见框架

### 误报控制

- 文件角色标签（production/test/build/vendor）
- Sanitizer 净化检测
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
│   ├── analysis/                 # 污点/数据流/CPG/攻击面/风险模式
│   ├── scanner/                  # 扫描器 + source/sink pattern
│   ├── rules/                    # YAML 规则引擎
│   └── ast/                      # tree-sitter AST（12 语言）
│
├── tools/                        # MCP 工具集
│   ├── bridge.rs                 # 内置工具
│   └── registry.rs / executor.rs
│
├── cli/                          # CLI 客户端
│   ├── commands/                 # scan/analyze/watch/daemon/mcp/config
│   ├── database/                 # findings SQLite
│   └── report/                   # 报告导出
│
├── daemon/                       # 守护进程（增量缓存）
│
├── rules/                        # YAML 模式规则 + taint 框架规则 + audit-packs
│
└── docs/                         # 文档与研究报告
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

## 许可证

Apache License 2.0
