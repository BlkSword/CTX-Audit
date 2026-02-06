# CTX-Audit Desktop

> AI 驱动的代码安全审计桌面应用

**项目正在积极开发中(之前的项目偏离了原先的期望，现在在进行结构重构，找回正轨)**

CTX-Audit Desktop 是一个基于 Tauri 2.x 的桌面应用，提供高性能代码安全审计功能。采用 Rust 后端和 React 前端，集成 AST 引擎、规则引擎等核心功能，支持 LLM 辅助审计。

## 核心架构

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   前端 (React)   │◄──►│  Tauri (Rust)    │◄──►│  Agent 服务     │
│ • React 19      │    │ • Commands API   │    │ • FastAPI       │
│ • TypeScript    │    │ • AST 引擎       │    │ • LLM 集成       │
│ • Monaco Editor │    │ • 高性能扫描     │    │ • 任务编排       │
│ • ReactFlow     │    │ • SQLite 存储    │    │                 │
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

- **VSCode 风格界面**: 可拖拽的多面板布局
- **多语言 AST 分析**: 基于 Tree-sitter 的代码解析引擎
- **高性能扫描**: Rust 实现的并发文件扫描引擎
- **代码图谱可视化**: 交互式展示代码依赖关系
- **Agent 审计**: AI 驱动的智能代码审计流程
- **多项目支持**: 同时审计多个项目
- **本地 LLM**: 支持 Ollama 本地模型

## 技术栈

### 前端
- **框架**: React 19 + TypeScript
- **构建工具**: Vite 7.x
- **UI 库**: Radix UI + Tailwind CSS
- **代码编辑**: Monaco Editor
- **图谱可视化**: ReactFlow
- **状态管理**: Zustand
- **可拖拽面板**: react-resizable-panels

### 后端 (Tauri)
- **语言**: Rust
- **框架**: Tauri 2.x
- **数据库**: SQLite (嵌入式)
- **AST 解析**: Tree-sitter
- **异步运行时**: Tokio

### Agent 服务 (可选)
- **语言**: Python 3.8+
- **框架**: FastAPI
- **LLM**: Claude / OpenAI / Ollama

## 快速开始

### 前置要求

- Node.js 18+
- Rust 1.70+

### 安装依赖

```bash
npm install
```

### 启动开发环境

```bash
# 启动 Tauri 开发服务器 (包括前端 + 后端)
npm run tauri:dev
```

### 构建生产版本

```bash
npm run tauri:build
```

## 项目结构

```
ctx-audit/
├── src/                    # React 前端源码
│   ├── pages/              # 页面组件
│   ├── components/         # UI 组件
│   │   └── ui/             # 基础组件 (Radix UI)
│   ├── shared/             # 共享代码
│   │   └── api/            # Tauri API 客户端
│   └── stores/             # Zustand 状态管理
├── src-tauri/              # Tauri 后端 (Rust)
│   ├── src/
│   │   ├── commands/       # Tauri Commands
│   │   │   ├── project.rs  # 项目管理
│   │   │   ├── scanner.rs  # 扫描器
│   │   │   ├── files.rs    # 文件操作
│   │   │   └── agent.rs    # Agent 控制
│   │   ├── services/       # 业务服务层
│   │   │   ├── database.rs # SQLite 管理
│   │   │   └── agent_service.rs # Agent 进程管理
│   │   └── main.rs         # Tauri 入口
│   ├── Cargo.toml          # Rust 依赖
│   └── tauri.conf.json     # Tauri 配置
├── core/                   # 核心共享库
│   └── src/
│       ├── ast/            # AST 引擎
│       ├── scanner/        # 扫描器
│       ├── rules/          # 规则系统
│       └── diff/           # 差异对比
└── rules/                  # 审计规则
```

## Tauri Commands API

### 项目管理
- `list_projects()` - 获取所有项目
- `create_project(name, path)` - 创建新项目
- `delete_project(uuid)` - 删除项目

### 扫描
- `run_scan(project_path, project_id?, rules?)` - 运行扫描
- `get_findings(project_id)` - 获取扫描结果

### 文件操作
- `read_file(path)` - 读取文件内容
- `list_directory(path)` - 列出目录内容
- `select_directory()` - 打开目录选择对话框

### Agent 控制 (Rust 引擎)
- `start_audit()` - 启动 Agent 审计
- `get_audit_status()` - 获取审计状态
- `pause_audit()` - 暂停审计
- `cancel_audit()` - 取消审计
- `get_audit_events()` - 获取审计事件

## 配置

### Agent 服务配置

创建 `agent-service/.env` 文件：

```bash
# 服务配置
AGENT_PORT=8001
LOG_LEVEL=info

# LLM 配置 (支持 Ollama/Claude/OpenAI)
LLM_PROVIDER=ollama|anthropic|openai
LLM_MODEL=llama3.2|claude-3-5-sonnet-20241022
ANTHROPIC_API_KEY=your_key_here
OPENAI_API_KEY=your_key_here
OLLAMA_BASE_URL=http://localhost:11434
```

## 开发指南

### 添加新的 Tauri Command

1. 在 `src-tauri/src/commands/` 创建模块
2. 定义 `#[tauri::command]` 函数
3. 在 `main.rs` 的 `invoke_handler!` 中注册
4. 在前端 `src/shared/api/tauri-client.ts` 添加调用方法

### 添加新页面

1. 在 `src/pages/` 创建页面组件
2. 在 `App.tsx` 添加路由

### 数据库位置

SQLite 数据库位于：
- Windows: `%APPDATA%\com.ctx-audit.desktop\audit.db`
- macOS: `~/Library/Application Support/com.ctx-audit.desktop/audit.db`
- Linux: `~/.local/share/com.ctx-audit.desktop/audit.db`

## 常见问题

### Tauri 开发服务器无法启动

```bash
# 清理并重新构建
cd src-tauri
cargo clean
cd ..
npm run tauri:dev
```

### 前端依赖安装失败

```bash
rm -rf node_modules package-lock.json
npm install
```

### Agent 连接失败

检查 LLM 配置是否正确（设置 → LLM），确保 API Key 已配置。

## 桌面版改造计划

### 已完成 ✅
- [x] 阶段一：Tauri 基础框架
- [x] 移植核心 Commands
- [x] SQLite 数据库集成

### 待实施 📋
- [ ] 阶段二：Agent 服务简化
- [ ] 阶段三：VSCode 风格布局
- [ ] 阶段四：LLM 双模式支持
- [ ] 阶段五：多项目并行
- [ ] 阶段六：打包和优化

详细计划请参考 [CLAUDE.md](CLAUDE.md)

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request！
