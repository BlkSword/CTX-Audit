# DeepAudit

支持 MCP 协议的高级代码审计工具，集成了AST 引擎、规则引擎、代码图谱等工具，可以进一步激发LLM审计能力

## 🚀 核心架构

DeepAudit 采用双引擎混合架构，兼顾性能与扩展性：

- **Rust 核心 (Tauri 2.x)**: 负责高性能文件 IO、并发扫描、AST 解析、Git 差异计算及 SQLite 数据持久化。
- **Python Sidecar (FastMCP)**: 提供高级语义分析、知识图谱生成及 LLM 辅助验证。

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   前端 (React)   │◄──►│  Tauri (Rust)    │◄──►│ Python Sidecar  │
│ • React 19      │    │ • 高效文件扫描    │    │ • FastMCP 服务   │
│ • Tailwind CSS  │    │ • SQLite 存储     │    │ • AST 语义分析   │
│ • Monaco Editor │    │ • Git 深度对比    │    │ • 知识图谱生成   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

##  关键功能

- **双引擎扫描**: 结合 Rust 的毫秒级正则扫描与 Python 的深度 AST 语法分析。
- **智能规则系统**: 统一的 YAML 规则定义，支持 Regex 模式与 Tree-sitter 语法查询。
- **Git 版本对比**: 支持任意 Git 引用（分支/提交/标签）的深度差异分析，内置重命名检测。
- **代码图谱可视化**: 交互式展示项目文件、类与函数间的依赖关系。
- **快速全局搜索**: 基于 `ignore` 库的高性能文件内容搜索，支持大中型项目。
- **发现管理**: 使用 SQLite 持久化存储审计发现，支持漏洞状态跟踪与详情查看。

##  MCP 工具集

DeepAudit 提供 10+ 个核心 MCP 工具：

| 类别 | 工具名称 | 描述 |
| :--- | :--- | :--- |
| **分析** | `build_ast_index` | 构建 AST 索引，项目分析的首要步骤 |
| | `run_security_scan` | 运行多语言安全扫描，支持自定义过滤 |
| | `get_knowledge_graph` | 获取项目代码结构知识图谱 |
| **导航** | `search_symbol` | 全局 AST 符号搜索（类、函数、方法） |
| | `get_call_graph` | 生成函数调用链图谱 |
| | `get_code_structure` | 解析特定文件的语法结构 |
| **文件** | `read_file` / `list_files` | 基础文件操作与内容读取 |
| | `search_files` | 高性能正则内容搜索 |

##  快速开始

### 依赖要求
- **Node.js** (v18+) / **Rust** (Stable) / **Python 3.8+**

### 安装与运行
1. **安装前端**: `npm install`
2. **安装 Python**: `cd python-sidecar && pip install -r requirements.txt`
3. **启动开发模式**: `npm run tauri dev`

##  项目结构

- `src/`: React 前端源码（UI 组件、图谱、对比视图）
- `src-tauri/`: Rust 后端核心（扫描器、AST 引擎、Git 逻辑）
- `python-sidecar/`: Python MCP 服务（FastMCP 工具实现）
- `rules/`: YAML 规则库（内置 20+ 种常见漏洞检测规则）

##  规则定义示例

```yaml
id: "no-hardcoded-secrets"
name: "硬编码密钥检测"
severity: "critical"
language: "python"
query: "(assignment left: (identifier) @var right: (string) @val)" # AST 查询
```
