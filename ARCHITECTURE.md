# CTX-Audit 架构文档

## 项目概述

CTX-Audit 是一个现代化的代码安全审计平台，支持多语言代码分析、AST深度解析、AI驱动的漏洞检测等功能。

## 技术栈

### 前端
- **框架**: React 18 + TypeScript
- **构建工具**: Vite
- **状态管理**: Zustand
- **UI组件**: Radix UI + Tailwind CSS
- **路由**: React Router v6
- **代码图谱**: ReactFlow

### 后端
- **语言**: Rust
- **Web框架**: Axum 0.7
- **数据库**: SQLite
- **异步运行时**: Tokio
- **序列化**: Serde

### 核心库
- **AST引擎**: tree-sitter (多语言支持)
- **规则引擎**: 正则 + 规则匹配
- **差异对比**: Git集成

## 整体架构

```
┌─────────────────────────────────────────────────────────────────┐
│                         用户界面层                                │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌─────────┐  │
│  │  Dashboard │  │  Project   │  │  Settings  │  │  Agent  │  │
│  │  (项目列表) │  │  (项目视图) │  │  (设置页面) │  │ (审计)  │  │
│  └────────────┘  └────────────┘  └────────────┘  └─────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        前端状态层 (Zustand)                       │
│  ┌──────────────┐  ┌───────────┐  ┌──────────┐  ┌───────────┐  │
│  │ ProjectStore │  │ FileStore │  │ScanStore │  │AgentStore │  │
│  └──────────────┘  └───────────┘  └──────────┘  └───────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        API服务层                                 │
│  ┌─────────────┐  ┌───────────┐  ┌──────────┐  ┌────────────┐  │
│  │ AST Service │  │Project API│  │Scan API  │  │  File API  │  │
│  └─────────────┘  └───────────┘  └──────────┘  └────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      HTTP通信层 (REST API)                       │
│                         http://localhost:8000/api               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        后端服务层 (Axum)                         │
│  ┌─────────────┐  ┌───────────┐  ┌──────────┐  ┌────────────┐  │
│  │  AST Engine │  │ Project   │  │ Scanner  │  │File Handler│  │
│  │   (Core)    │  │  Manager  │  │  Engine  │  │            │  │
│  └─────────────┘  └───────────┘  └──────────┘  └────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        核心业务层                                 │
│  ┌──────────────┐  ┌─────────────┐  ┌──────────┐  ┌─────────┐  │
│  │ AST Parser   │  │ Rule Engine│  │ Git Diff │  │Scanner  │  │
│  │(tree-sitter) │  │  (Regex)   │  │  Engine  │  │Manager  │  │
│  └──────────────┘  └─────────────┘  └──────────┘  └─────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        数据存储层                                 │
│  ┌──────────────┐  ┌─────────────┐  ┌──────────┐  ┌─────────┐  │
│  │   SQLite DB  │  │ File System│  │AST Cache │  │Git Repo │  │
│  └──────────────┘  └─────────────┘  └──────────┘  └─────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## 前端架构

### 目录结构

```
src/
├── pages/                    # 页面组件
│   ├── Dashboard.tsx         # 仪表板 - 项目列表
│   ├── project/              # 项目相关页面
│   │   ├── ProjectLayout.tsx # 项目布局容器
│   │   ├── ProjectView.tsx   # 项目视图
│   │   ├── EditorPanel.tsx   # 代码编辑面板
│   │   ├── ScanPanel.tsx     # 扫描面板
│   │   ├── AnalysisPanel.tsx # 分析工具面板
│   │   └── GraphPanel.tsx    # 代码图谱面板
│   └── settings/             # 设置页面
│       ├── SettingsLayout.tsx
│       ├── LLMConfigPage.tsx
│       └── PromptTemplatesPage.tsx
├── components/               # 组件
│   ├── ui/                   # 基础UI组件
│   ├── audit/                # 审计组件
│   ├── diff/                 # 差异对比
│   ├── file-explorer/        # 文件浏览器
│   ├── graph/                # 图谱组件
│   ├── log/                  # 日志面板
│   └── search/               # 搜索面板
├── shared/                   # 共享代码
│   ├── api/                  # API服务层
│   │   ├── client.ts         # HTTP客户端
│   │   ├── agent-client.ts   # Agent客户端
│   │   └── services/         # 服务实现
│   ├── types/                # 类型定义
│   └── constants.ts          # 常量
└── stores/                   # 状态管理
    ├── projectStore.ts       # 项目状态
    ├── fileStore.ts          # 文件状态
    ├── scanStore.ts          # 扫描状态
    ├── agentStore.ts         # Agent状态
    └── uiStore.ts            # UI状态
```

### 路由结构

| 路径 | 组件 | 说明 |
|------|------|------|
| `/` | Dashboard | 项目列表页 |
| `/project/:id` | ProjectLayout | 项目主页 |
| `/settings` | SettingsLayout | 设置页 |
| `/settings/llm` | LLMConfigPage | LLM配置 |
| `/settings/prompts` | PromptTemplatesPage | 提示词模板 |

## 后端架构

### 目录结构

```
web-backend/src/
├── main.rs                   # 应用入口
├── state.rs                  # 应用状态管理
└── api/                      # API路由
    ├── mod.rs                # API模块导出
    ├── project.rs            # 项目API
    ├── scanner.rs            # 扫描API
    ├── ast.rs                # AST API
    └── files.rs              # 文件API

core/src/                     # 核心业务库
├── ast/                      # AST模块
│   ├── mod.rs
│   ├── engine.rs             # AST引擎
│   ├── parser.rs             # 解析器
│   ├── query.rs              # 查询引擎
│   ├── cache.rs              # 缓存管理
│   └── symbol.rs             # 符号表
├── scanner/                  # 扫描模块
│   ├── mod.rs
│   ├── manager.rs            # 扫描管理器
│   └── regex_scanner.rs      # 正则扫描器
├── rules/                    # 规则模块
│   ├── mod.rs
│   ├── loader.rs             # 规则加载器
│   ├── model.rs              # 规则模型
│   └── scanner.rs            # 规则扫描器
└── diff/                     # 差异对比模块
    ├── mod.rs
    ├── engine.rs             # 对比引擎
    ├── git_integration.rs    # Git集成
    └── types.rs              # 类型定义
```

### API路由结构

```
/api
├── /health                   # 健康检查
│
├── /project/                 # 项目管理
│   ├── POST /create          # 创建项目（路径方式）
│   ├── POST /upload          # 上传项目（ZIP方式）
│   ├── GET  /list            # 项目列表
│   ├── GET  /:id             # 项目详情
│   └── POST /:id             # 删除项目
│
├── /ast/                     # AST分析
│   ├── POST /build_index     # 构建索引
│   ├── POST /search_symbol   # 搜索符号
│   ├── POST /get_call_graph  # 调用图
│   ├── POST /get_code_structure # 代码结构
│   ├── POST /find_call_sites # 查找调用点
│   ├── POST /get_class_hierarchy # 类层次
│   └── POST /get_knowledge_graph # 知识图谱
│
├── /scanner/                 # 安全扫描
│   ├── POST /scan            # 运行扫描
│   ├── POST /upload          # 上传扫描
│   └── GET  /findings/:id    # 扫描结果
│
└── /files/                   # 文件操作
    ├── GET  /read            # 读取文件
    ├── GET  /list            # 列出目录
    └── GET  /search          # 搜索文件
```

## 前后端API对应关系

### 项目管理 API

| 前端方法 | HTTP方法 | 后端路由 | 说明 |
|---------|---------|---------|------|
| `projectService.createProject(name, path)` | POST | `/api/project/create` | 通过路径创建项目 |
| `projectService.uploadProject(name, zipFile)` | POST | `/api/project/upload` | 通过ZIP上传项目 |
| `projectService.listProjects()` | GET | `/api/project/list` | 获取项目列表 |
| `projectService.getProject(id)` | GET | `/api/project/:id` | 获取项目详情 |
| `projectService.deleteProject(id)` | POST | `/api/project/:id` | 删除项目 |

### AST分析 API

| 前端方法 | HTTP方法 | 后端路由 | 说明 |
|---------|---------|---------|------|
| `astService.buildASTIndex(path)` | POST | `/api/ast/build_index` | 构建AST索引 |
| `astService.searchSymbol(query)` | POST | `/api/ast/search_symbol` | 搜索符号 |
| `astService.getCallGraph(fn, depth)` | POST | `/api/ast/get_call_graph` | 获取调用图 |
| `astService.getCodeStructure(path)` | POST | `/api/ast/get_code_structure` | 获取代码结构 |
| `astService.findCallSites(name)` | POST | `/api/ast/find_call_sites` | 查找调用点 |
| `astService.getClassHierarchy(name)` | POST | `/api/ast/get_class_hierarchy` | 获取类层次 |
| `astService.getKnowledgeGraph(limit)` | POST | `/api/ast/get_knowledge_graph` | 获取知识图谱 |

### 扫描 API

| 前端方法 | HTTP方法 | 后端路由 | 说明 |
|---------|---------|---------|------|
| `scannerService.runScan(path, rules)` | POST | `/api/scanner/scan` | 运行扫描 |
| `scannerService.uploadAndScan(files)` | POST | `/api/scanner/upload` | 上传扫描 |
| `scannerService.getFindings(id)` | GET | `/api/scanner/findings/:id` | 获取结果 |

### 文件操作 API

| 前端方法 | HTTP方法 | 后端路由 | 说明 |
|---------|---------|---------|------|
| `fileService.readFile(path)` | GET | `/api/files/read?path=xxx` | 读取文件 |
| `fileService.listFiles(dir)` | GET | `/api/files/list?directory=xxx` | 列出目录 |
| `fileService.searchFiles(query, path)` | GET | `/api/files/search?query=xxx&path=xxx` | 搜索文件 |

## 数据库设计

### 表结构

```sql
-- 项目表
CREATE TABLE projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    path TEXT NOT NULL UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 扫描发现表
CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER,
    finding_id TEXT UNIQUE,
    file_path TEXT,
    line_start INTEGER,
    line_end INTEGER,
    detector TEXT,
    vuln_type TEXT,
    severity TEXT,
    description TEXT,
    code_snippet TEXT,
    status TEXT DEFAULT 'new',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(project_id) REFERENCES projects(id)
);

-- 扫描记录表
CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER,
    status TEXT DEFAULT 'pending',
    files_scanned INTEGER DEFAULT 0,
    findings_found INTEGER DEFAULT 0,
    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    FOREIGN KEY(project_id) REFERENCES projects(id)
);
```

## 状态管理

### Zustand Stores

| Store | 职责 |
|-------|------|
| `projectStore` | 管理项目列表、当前项目、项目CRUD操作 |
| `fileStore` | 管理文件树、当前选中文件 |
| `scanStore` | 管理扫描状态、扫描结果 |
| `agentStore` | 管理Agent任务、审计流程 |
| `uiStore` | 管理UI状态（日志、加载状态等） |

## 开发流程

### 启动开发环境

```bash
# 1. 启动基础服务（Docker）
docker-compose up -d postgres chromadb redis

# 2. 启动后端（Rust）
cd web-backend
cargo run
# 运行在 http://localhost:8000

# 3. 启动前端（Vite）
npm run dev
# 运行在 http://localhost:3002

# 4. 启动Agent服务（Python）
cd agent-service
python -m app.main
# 运行在 http://localhost:8001
```

### 端口分配

| 服务 | 端口 |
|------|------|
| 前端开发服务器 | 3002 |
| Rust后端 | 8000 |
| Agent服务 | 8001 |
| PostgreSQL | 15432 |
| ChromaDB | 8002 |
| Redis | 6379 |

## 部署

### Docker部署

```bash
# 开发环境
docker-compose up

# 生产环境
docker-compose --profile production up
```

### 目录权限

- 项目存储: `./data/projects/`
- 数据库: `./data/audit.db`
- 上传临时: `./uploads/`

## 扩展性

### 添加新的API端点

1. **后端**: 在 `web-backend/src/api/` 创建模块
2. **前端**: 在 `src/shared/api/services/` 创建服务
3. **类型**: 在 `src/shared/types/` 添加类型定义

### 添加新的页面

1. 在 `src/pages/` 创建页面组件
2. 在 `App.tsx` 添加路由
3. 更新导航组件（如需要）
