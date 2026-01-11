# CTX-Audit

> AI 驱动的代码安全审计平台
**当前项目还在开发调试过程中，还不是最终结果
基于 Rust 高性能后端和 React 现代前端的代码安全审计工具，集成 AST 引擎、规则引擎、代码图谱等核心功能，支持 LLM 辅助审计。

## 核心架构

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   前端 (React)   │◄──►│  后端 (Rust)     │◄──►│  Agent 服务     │
│ • React 18      │    │ • Axum Web 框架  │    │ • FastAPI       │
│ • TypeScript    │    │ • AST 引擎       │    │ • LLM 集成       │
│ • Monaco Editor │    │ • 高性能扫描     │    │ • RAG 支持       │
│ • ReactFlow     │    │ • SQLite 存储    │    │ • 任务编排       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │   核心库 (Core)   │
                       │ • Tree-sitter    │
                       │ • 规则引擎        │
                       │ • Git 集成        │
                       └──────────────────┘
```

## 关键功能

- **项目上传**: 支持 ZIP 文件上传并自动解压
- **AST 智能分析**: 基于 Tree-sitter 的多语言代码解析引擎
- **高性能扫描**: Rust 实现的并发文件扫描引擎
- **代码图谱可视化**: 交互式展示代码依赖关系
- **Agent 审计**: AI 驱动的智能代码审计流程
- **知识图谱**: 基于 ChromaDB 的向量存储

## 技术栈

### 前端
- **框架**: React 18 + TypeScript
- **构建工具**: Vite
- **UI 库**: Radix UI + Tailwind CSS
- **代码编辑**: Monaco Editor
- **图谱可视化**: ReactFlow
- **状态管理**: Zustand

### 后端
- **语言**: Rust
- **Web 框架**: Axum 0.7
- **数据库**: SQLite (sqlx)
- **AST 解析**: Tree-sitter
- **异步运行时**: Tokio

### Agent 服务
- **语言**: Python 3.8+
- **框架**: FastAPI
- **LLM**: Claude / OpenAI / Gemini
- **向量数据库**: ChromaDB
- **消息队列**: Redis

## 快速开始

### 开发环境

#### 1. 启动基础服务 (Docker)

```bash
# 启动 PostgreSQL, ChromaDB, Redis
docker-compose up -d postgres chromadb redis
```

#### 2. 启动后端 (Rust)

```bash
cd web-backend
cargo run
# 运行在 http://localhost:8000
```

#### 3. 启动前端 (React)

```bash
npm run dev
# 运行在 http://localhost:3002
```

#### 4. 启动 Agent 服务 (Python)

```bash
cd agent-service
pip install -r requirements.txt
python -m app.main
# 运行在 http://localhost:8001
```

### Docker 一键启动

```bash
# 启动所有服务
docker-compose up -d

# 访问前端
http://localhost:3000
```

## 端口分配

| 服务 | 端口 | 说明 |
|------|------|------|
| 前端开发服务器 | 3002 | Vite 开发服务器 |
| 前端生产服务器 | 3000 | Nginx 静态文件服务 |
| Rust 后端 | 8000 | Axum Web 服务 |
| Agent 服务 | 8001 | FastAPI 服务 |
| PostgreSQL | 15432 | Agent 状态存储 |
| ChromaDB | 8002 | 向量数据库 |
| Redis | 6379 | 消息队列 |

## 项目结构

```
ctx-audit/
├── src/                    # React 前端源码
│   ├── pages/             # 页面组件
│   │   ├── Dashboard.tsx  # 项目列表页
│   │   ├── project/       # 项目相关页面
│   │   └── settings/      # 设置页面
│   ├── components/        # UI 组件
│   │   ├── ui/           # 基础组件
│   │   ├── graph/        # 图谱组件
│   │   ├── log/          # 日志组件
│   │   └── search/       # 搜索组件
│   ├── shared/           # 共享代码
│   │   ├── api/          # API 客户端
│   │   │   ├── client.ts # HTTP 客户端
│   │   │   └── services/ # 服务层
│   │   └── types/        # 类型定义
│   └── stores/           # Zustand 状态管理
├── web-backend/          # Rust 后端
│   └── src/
│       ├── main.rs       # 后端入口
│       ├── api/          # API 路由
│       │   ├── project.rs
│       │   ├── scanner.rs
│       │   ├── ast.rs
│       │   └── files.rs
│       └── state.rs      # 应用状态
├── core/                 # 核心共享库
│   └── src/
│       ├── ast/          # AST 引擎
│       ├── scanner/      # 扫描器
│       ├── rules/        # 规则系统
│       └── diff/         # 差异对比
├── agent-service/        # Agent 服务
│   └── app/
│       ├── main.py       # FastAPI 入口
│       ├── agents/       # Agent 实现
│       ├── services/     # 服务层
│       └── prompts/      # Prompt 模板
├── docker/               # Docker 配置
├── docker-compose.yml    # Docker Compose 配置
└── ARCHITECTURE.md       # 详细架构文档
```

## API 文档

详细的 API 文档请参考 [ARCHITECTURE.md](ARCHITECTURE.md)

### 主要 API 端点

#### 项目管理
- `POST /api/project/upload` - 上传 ZIP 项目
- `GET /api/project/list` - 项目列表
- `GET /api/project/:id` - 项目详情
- `POST /api/project/:id` - 删除项目

#### AST 分析
- `POST /api/ast/build_index` - 构建 AST 索引
- `POST /api/ast/search_symbol` - 搜索符号
- `POST /api/ast/get_call_graph` - 获取调用图
- `POST /api/ast/get_knowledge_graph` - 获取知识图谱

#### 扫描
- `POST /api/scanner/scan` - 运行扫描
- `GET /api/scanner/findings/:id` - 获取结果

#### 文件操作
- `GET /api/files/read` - 读取文件
- `GET /api/files/list` - 列出目录
- `GET /api/files/search` - 搜索文件

## 配置

### 前端环境变量

创建 `.env.web` 文件：

```bash
VITE_API_BASE_URL=http://localhost:8000
VITE_AGENT_API_BASE_URL=http://localhost:8001
VITE_PLATFORM=web
```

### Agent 服务配置

创建 `agent-service/.env` 文件：

```bash
# 服务配置
AGENT_PORT=8001
LOG_LEVEL=info

# LLM 配置
LLM_PROVIDER=anthropic
LLM_MODEL=claude-3-5-sonnet-20241022
ANTHROPIC_API_KEY=your_key_here

# 数据库
DATABASE_URL=postgresql://audit_user:audit_pass@localhost:15432/audit_db
CHROMADB_HOST=localhost
CHROMADB_PORT=8002
REDIS_URL=redis://localhost:6379/0
```

## 开发指南

### 添加新的 API 端点

1. 后端：在 `web-backend/src/api/` 创建模块
2. 前端：在 `src/shared/api/services/` 创建服务类
3. 类型：在 `src/shared/types/` 添加类型定义

### 添加新的页面

1. 在 `src/pages/` 创建页面组件
2. 在 `App.tsx` 添加路由
3. 更新导航组件（如需要）

### 数据库迁移

```bash
# 查看数据库
sqlite3 data/audit.db

# 执行 SQL
sqlite3 data/audit.db "SELECT * FROM projects;"
```

## 部署

### Docker 部署

```bash
# 开发环境
docker-compose up

# 生产环境
docker-compose --profile production up
```

### 手动部署

```bash
# 前端构建
npm run build

# 后端构建
cd web-backend
cargo build --release
```

## 常见问题

### 后端编译失败

确保安装了 Rust 工具链：
```bash
rustc --version
cargo --version
```

### 前端依赖安装失败

```bash
rm -rf node_modules package-lock.json
npm install
```

### ChromaDB 连接失败

```bash
# Windows 上可能需要禁用 orjson
set CHROMA_DISABLE_INFERENCE=1
python -m app.main
```

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request！
