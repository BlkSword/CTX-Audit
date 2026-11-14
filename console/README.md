# CTX-Audit Console

工作区中心化的审计控制台：每个审计项目 = 一个 workspace，包含总览、审计流、覆盖与待审、候选链、漂移闸门、报告六个视图。

## 快速开始

```bash
cd console
npm install          # 首次
npm run build        # 构建 SPA 到 dist/
npm run serve        # 启动 API + 静态服务（默认 http://127.0.0.1:4317）
```

环境变量：

| 变量 | 默认 | 说明 |
|---|---|---|
| `CTX_CONSOLE_PORT` | `4317` | 监听端口 |
| `CTX_CONSOLE_HOST` | `127.0.0.1` | 监听地址（仅回环） |
| `CTX_AUDIT_BIN` | `../target/release/ctx-audit.exe` | ctx-audit 二进制路径 |
| `CTX_CONSOLE_CLI_TIMEOUT_MS` | `90000` | 单次 CLI 调用超时 |

开发模式（Vite HMR，API 代理到 4317）：

```bash
npm run dev          # http://127.0.0.1:4318
```

## 页面

| 视图 | 数据来源 | 内容 |
|---|---|---|
| 总览 | `audit -o json` + `chain --list` | 端点/未覆盖/候选链/耗时四个指标、覆盖分布、链档分布、高风险待审 Top12 |
| 审计流 | SSE `/api/workspaces/:id/stream` | 覆盖分析 → 链扫描的逐步状态、耗时、错误 |
| 覆盖与待审 | `audit` worklist | 风险分排序的待审端点、判定徽章、信号标签 |
| 候选链 | `chain --list` + `chain --id` | 链列表 + 点击查看链档（路径步骤/守卫/断点） |
| 漂移闸门 | `gate --git` | base/head/严格模式，判决与 verdict 列表 |
| 报告 | 总览数据 | Markdown 报告预览，可一键复制 |

## API

```
GET    /api/health
GET    /api/workspaces
POST   /api/workspaces                 { path, name? }
DELETE /api/workspaces/:id
GET    /api/workspaces/:id/overview
GET    /api/workspaces/:id/worklist?limit=200
GET    /api/workspaces/:id/chains?limit=20
GET    /api/workspaces/:id/chain?id=CH-xxxx
POST   /api/workspaces/:id/gate        { base, head, strict? }
GET    /api/workspaces/:id/stream      (SSE)
```

## 安全边界

- 仅回环监听；工作区路径必须存在且为目录；
- 无 shell：CLI 以 argv 数组直接 spawn；
- 每次调用有超时与输出上限；请求体上限 256KB；
- 只读分析：不执行 payload、不修改被审计仓库。

## 设计

深色高密度界面，单一强调色（`#4f8cff`），语义色区分覆盖/风险/链档；所有指标使用等宽数字；表格粘性表头、空态与加载骨架齐备。设计令牌集中在 `src/styles.css` 的 `:root`。
