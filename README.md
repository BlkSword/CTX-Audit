# DeepAudit

支持 MCP 协议的高级大语言模型（LLM）代码审计工具，集成了 Rust AST 引擎和 Python MCP 服务器。

## 架构概览

DeepAudit 采用混合架构设计，结合了 Rust 的性能优势和 Python 的生态丰富性：

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   前端 (React)   │◄──►│  Tauri (Rust)    │◄──►│ Python Sidecar  │
│                 │    │                  │    │                 │
│ • React 19      │    │ • AST 引擎       │    │ • MCP 服务器     │
│ • TypeScript    │    │ • 文件系统操作   │    │ • 安全扫描       │
│ • Vite          │    │ • 对话框管理     │    │ • 报告生成       │
│ • Tailwind CSS  │    │ • SQL 数据库      │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### 核心组件

- **前端**：React 19 + TypeScript + Vite + Tailwind CSS
- **后端**：Rust (Tauri 2.x) + SQLx (SQLite)
- **AST 引擎**：Rust (tree-sitter) 支持多语言解析
- **MCP 服务**：Python FastMCP 服务器，提供高级分析工具
- **UI 框架**：Radix UI + Lucide React + Framer Motion

## 前置依赖

### 必需依赖
- **Node.js** (推荐 v18+) 
- **Rust** (最新稳定版)
- **Python 3.8+**
- **Tauri CLI** 
  ```bash
  npm install -g @tauri-apps/cli
  ```

## 安装步骤

### 1. 克隆项目
```bash
git clone <repository-url>
cd DeepAudit
```

### 2. 安装前端依赖
```bash
npm install
```

### 3. 安装 Python 依赖
```bash
cd python-sidecar
pip install -r requirements.txt
cd ..
```

### 4. 安装 Rust 依赖
```bash
cd src-tauri
cargo fetch
cd ..
```

## 运行方式

### 开发模式
```bash
npm run tauri dev
```

### 生产构建
```bash
npm run tauri build
```

### 仅前端开发
```bash
npm run dev
```

## 📋 使用指南

### 基本工作流

1. **启动应用**：运行 `npm run tauri dev`
2. **打开项目**：点击 "打开项目..." 按钮选择代码目录
3. **构建索引**：使用 `build_ast_index` 工具构建 AST 索引
4. **执行分析**：运行安全扫描或代码结构分析
5. **查看结果**：在日志面板或漏洞列表查看分析结果
6. **验证漏洞**：使用 LLM 验证功能减少误报
7. **可视分析**：通过代码图谱了解项目结构

### 进阶功能

#### 添加自定义规则
1. 切换到 "规则" 面板
2. 点击 "+" 按钮打开规则编辑器
3. 填写规则信息（ID、名称、严重性、语言等）
4. 提供 Regex 模式或 Tree-sitter 查询
5. 保存并立即生效

#### 代码对比
- **项目对比**：打开项目后，使用 "比较项目..." 功能
- **Git 对比**：在 MCP 工具中调用 `compare_git_versions`
- **调优参数**：支持忽略空白、大小写、重命名检测等选项

#### 知识图谱探索
1. 切换到 "代码图谱" 视图
2. 系统自动显示当前项目的代码结构图
3. 使用搜索框高亮特定节点
4. 拖拽和缩放探索代码依赖关系

### 快捷操作

- **项目文件树**：自动显示项目结构，支持文件搜索
- **实时日志**：分批显示 Rust 和 Python 日志，支持分类查看
- **工具描述**：在 MCP 工具面板查看每个工具的详细说明
- **一键清理**：清除日志和缓存
- **快速搜索**：全局文件内容搜索，支持结果高亮

## 🔧 MCP 工具集

DeepAudit 提供 14+ 个 MCP 工具，分为以下类别：

### 核心分析工具

| 工具名称 | 参数 | 描述 |
| :--- | :--- | :--- |
| **build_ast_index** | `directory` | 构建 AST 索引，支持多语言代码解析。初始化项目的必需步骤 |
| **run_security_scan** | `directory`, `custom_rules`, `include_dirs`, `exclude_dirs` | 使用自定义规则运行安全扫描，支持目录过滤 |
| **get_analysis_report** | `directory` | 获取缓存的详细分析报告（JSON 格式） |
| **get_knowledge_graph** | `limit` | 获取项目的代码知识图谱（节点与关系） |
| **verify_finding** | `file`, `line`, `description`, `vuln_type`, `code` | 使用 LLM 验证安全漏洞的真实性 |
| **analyze_code_with_llm** | `code`, `context` | 使用 LLM 分析代码片段的逻辑或缺陷 |

### 文件操作工具

| 工具名称 | 参数 | 描述 |
| :--- | :--- | :--- |
| **list_files** | `directory` | 列出目录内容（非递归） |
| **read_file** | `file_path` | 读取文件完整内容 |
| **search_files** | `directory`, `pattern` | 正则表达式搜索文件内容 |
| **get_code_structure** | `file_path` | 解析文件结构（类、函数、方法） |

### 代码导航工具

| 工具名称 | 参数 | 描述 |
| :--- | :--- | :--- |
| **search_symbol** | `query` | 在全局 AST 索引中搜索符号定义 |
| **find_call_sites** | `directory`, `symbol` | 查找函数/方法的所有调用位置 |
| **get_call_graph** | `directory`, `entry`, `max_depth` | 生成函数调用关系图 |
| **get_class_hierarchy** | `directory`, `class_name` | 获取类的继承关系 |

### 代码对比工具

| 工具名称 | 参数 | 描述 |
| :--- | :--- | :--- |
| **compare_files_or_directories** | `source_a`, `source_b`, 多种对比选项 | 对比文件或目录的内容差异 |
| **compare_git_versions** | `repository_path`, `left_ref`, `right_ref` | 对比 Git 仓库的两个版本 |

## 🎯 核心功能

### 智能代码分析
- **多语言 AST 解析**：支持 14 种编程语言的语法树分析
- **安全漏洞扫描**：内置规则 + 自定义规则，支持 Regex 和 Tree-sitter 查询
- **知识图谱可视化**：使用 ReactFlow 展示代码结构和依赖关系
- **漏洞验证**：集成 LLM 进行智能误报判断

### 代码对比与版本控制
- **文件/目录对比**：支持 side-by-side、unified、compact 三种视图
- **Git 集成**：对比任意两个 Git 引用（分支、标签、提交）
- **重命名检测**：智能识别文件移动和重命名操作
- **语法高亮**：使用 Monaco Editor 显示对比结果

### 规则管理与自定义
- **规则编辑器**：可视化界面添加自定义扫描规则
- **多语言支持**：为不同语言设置特定的检测规则
- **CWE 映射**：支持 Common Weakness Enumeration 标准
- **严重程度分级**：Critical、High、Medium、Low、Info 五级分类

### 现代化用户界面
- **Monaco Editor**：VS Code 同款编辑器，支持语法高亮和智能提示
- **响应式布局**：可调整大小的面板，支持垂直/水平分割
- **多标签页**：系统日志、MCP 日志、漏洞列表、终端面板
- **代码图谱**：交互式代码结构可视化，支持搜索和高亮

## 支持的编程语言

Rust AST 引擎支持以下语言的解析：

- **Web**: JavaScript, TypeScript, HTML, CSS, JSON
- **后端**: Python, Java, Rust, Go, C/C++
- **扩展性**: 可通过 tree-sitter 添加新语言支持

## 💾 缓存机制

### 缓存位置
- **AST 索引**: `.deepaudit_cache/<repo_hash>/ast_index.bin`<br>
- **分析报告**: `.deepaudit_cache/<repo_hash>/analysis_report.json`

### 缓存策略
- **智能失效**: 文件修改时间变化时自动重建
- **跨会话持久**: 关闭应用后缓存保留
- **内存优化**: 大型项目分批处理，避免内存溢出
- **并发安全**: 支持多线程扫描，使用通道进行数据传输


## ⚙️ 开发指南

### 项目结构

```
DeepAudit/
├── src/                            # React 前端源码
│   ├── App.tsx                      # 主应用组件
│   ├── components/                  # UI 组件
│   │   ├── ui/                      # Radix UI 基础组件
│   │   ├── diff/                    # 对比视图组件
│   │   ├── file-explorer/           # 文件树组件
│   │   ├── search/                  # 搜索面板组件
│   │   ├── log/                     # 日志面板组件
│   │   └── graph/                   # 代码图谱节点组件
│   └── lib/                         # 工具函数（图谱布局等）
├── src-tauri/                       # Rust 后端源码
│   ├── src/
│   │   ├── lib.rs                   # Tauri 命令和主入口
│   │   ├── ast/                     # AST 引擎（解析、缓存、查询）
│   │   ├── diff/                    # 对比引擎（文件对比、Git 集成）
│   │   ├── mcp/                     # MCP 服务集成
│   │   ├── rules/                   # 规则系统（加载、扫描）
│   │   └── scanners/                # 扫描器管理器和实现
│   └── Cargo.toml                   # Rust 依赖
├── python-sidecar/                  # Python MCP 服务
│   ├── agent.py                     # MCP 工具定义和实现
│   ├── ast_engine.py                # Python AST 处理引擎
│   ├── llm_engine.py                # LLM 集成引擎
│   └── requirements.txt             # Python 依赖
├── rules/                           # 扫描规则目录
│   ├── no_hardcoded_passwords.yaml  # 示例规则
│   └── ast_rules.yaml               # AST 查询规则
└── dist/                            # 构建输出（自动生成）
```

### 技术栈详情

- **前端框架**: React 19 + TypeScript + Vite
- **UI 组件**: Radix UI  + Tailwind CSS 样式
- **状态管理**: Zustand
- **编辑器**: Monaco Editor
- **图谱可视化**: ReactFlow
- **Rust 后端**: Tauri 2.x + Tokio 
- **数据库**: SQLite
- **Python 服务**: FastMCP + Uvicorn + Starlette
- **AST 解析**: tree-sitter（多语言支持）

### 添加新的 MCP 工具

1. **Python 端**：在 `python-sidecar/agent.py` 中添加 `@mcp.tool()` 装饰的函数
2. **前端端**：在 `src/App.tsx` 的 `MCP_TOOL_DESCRIPTIONS` 中添加工具描述
3. **Rust 端**：在 `src-tauri/src/lib.rs` 的 `invoke_handler` 中注册命令
4. **类型安全**：确保参数和返回值的 JSON 序列化兼容性

### 添加自定义规则

规则使用 YAML 格式定义，支持两种类型：

**正则规则**（适用于简单模式匹配）：
```yaml
id: "no-eval"
name: "No eval() Usage"
description: "Detects usage of eval() function"
severity: "high"
language: "javascript"
pattern: "eval\s*\("
cwe: "CWE-95"
category: "Security"
```

**AST 查询规则**（适用于精确语法匹配）：
```yaml
id: "no-hardcoded-secrets"
name: "No Hardcoded Secrets"
description: "Detects hardcoded API keys and secrets"
severity: "critical"
language: "python"
query: "(assignment left: (identifier) @var right: (string) @val)"
cwe: "CWE-798"
category: "Security"
```

### 性能优化

- **并行扫描**: 使用 Rust rayon 库实现多线程文件扫描
- **增量处理**: 文件变更时只重新扫描变更的部分
- **分批日志**: 日志采用分批刷新，避免 UI 卡顿
- **智能缓存**: AST 索引和分析报告自动缓存
- **内存管理**: 大型项目分批处理，防止内存溢出
