# CTX-Audit web surface（DSH 客户端插件）

把 CTX-Audit 接进 DSH 的 Web GUI：一个由插件注册的 **中心页面**、它的 **侧边栏入口**，以及 CTX-Audit 的
**MCP 服务器行**；页面数据来自本 bundle host 半区的只读端点。

## 为什么这样就够了（机制）

- Harness 里的"页面"**不是 URL 路由**，而是布局 `main` 插槽（`kind: 'keyed'`）里的一个 keyed 条目，
  由共享同一 panel id 的侧边栏条目选中（`ctx.layout.selectPanel(id)`）。
- 客户端插件是**外挂包**：`package.json` 声明 `dsh.bundle.patch`（host 侧行）与 `dsh.client`（浏览器侧），
  `exports["./client"]` 指向浏览器半区；host 把它组成 boot graph，经已挂载的 `/plugins/<id>/client.js`
  路由提供，浏览器懒加载。
- 页面不能是 host 自己出的 HTML 文档（iframe 拿不到主题 token 与 locale），所以**页面用 React 渲染在插槽里**，
  数据用本插件自己注册的 **JSON 路由**提供（`ctx.webServer.register`；宿主只拥有无人认领的路径与 fallback 座位）。
- 因此**不需要 fork `dsh-web-app` / `dsh-web-frontend`**。

## ⚠️ 必须记住的一条（实测踩到）

bundle 的 `cordis.patch.yml` **必须为自己的包插一行**：

```yaml
- insert:
    - id: ctx-audit-web
      name: '@local/ctx-audit-web'
```

`dsh-client-modules` 是**扫描"已启用的 Loader 条目"**里的 `dsh.client` 来组成浏览器 boot graph 的——
`package.json` 里写了 `dsh.client` 但**没有对应行**时，客户端半区**永远不会被提供**：页面不出现，
**且日志里没有任何报错**。官方模板隐式包含这一行，很容易漏。

## 文件

| 文件 | 作用 |
|---|---|
| `package.json` | bundle 与 client 两半的声明（`dsh.bundle.patch` + `dsh.client` + `exports["./client"]`） |
| `cordis.patch.yml` | 两行：指向本包的条目（必需，见上）+ `dsh-mcp-client` 接 `ctx-audit mcp`（stdio） |
| `index.js` | host 半区：`inject: ['webServer']` + 只读 JSON 端点 |
| `client.js` | 浏览器半区：`main` 页面 + `sidebar.panellist` 入口，纯 ESM、零构建 |
| `locale/{en,zh}.json` | 插件管理页/设置里显示的标题与描述（不激活插件即可读） |

## 数据端点

`GET /ctx-audit/api/status`（前缀 `/ctx-audit/api` 由本插件独占；未知子路径 404，非 GET/HEAD 405）

```json
{
  "mcp": { "serverName": "ctxaudit", "transport": "stdio", "command": "…ctx-audit.exe",
           "commandFound": true, "toolNamePrefix": "mcp__ctxaudit__*" },
  "workspace": "…", "artifactsDir": "….ctx-audit",
  "artifacts": [{ "name": "…", "kind": "file|dir", "bytes": 123, "mtime": "…" }],
  "artifactLimit": 30, "generatedAt": "…"
}
```

只读、有界（最多 30 项）、**不返回文件内容**；Web server 默认只绑回环（启动器拒绝 `--host 0.0.0.0`）。
`commandFound` 为 `null` 表示命令是裸名（经 PATH 解析，此处无法判定），页面据此显示为"经 PATH 解析"而不是猜。

## 部署

推荐（幂等、含自校验）：

```bash
DSH_HOME="$HOME/.dsh" ./harness/install.sh              # 已存在则跳过
FORCE=1 DSH_HOME="$HOME/.dsh" ./harness/install.sh      # 覆盖本仓库自带副本
```

脚本会把 profile 与 bundle 复制到 `$DSH_HOME/profiles/ctx-audit-web{,/node_modules/@local/ctx-audit-web}`，
然后用 `dsh --profile ctx-audit-web --dump-config` **校验两行是否都在组合树里**（失败会 WARN，不会假装成功）。

启动：

```bash
CTX_AUDIT_MCP_CMD=<abs>/ctx-audit dsh --profile ctx-audit-web --port 3081 --no-open
```

手动放置时注意：`Copy-Item`/`cp -R` 在目标目录已存在时会把源目录**嵌套**进去，要么先删目标，要么复制
`<src>/*`（bash 用 `<src>/.`）。

正式产品化应改用宿主安装通道（同时完成包安装与 bundle 选择，新装 bundle 可经 HMR 生效）：
`dsh plugin --profile ctx-audit-web add <pkg>`，或 DSH 内的 `plugin_manager.install_bundle`——
不要用 shell 复刻它的安装/选择步骤。

## 已验证 / 未验证（实测口径）

| 项 | 结果 |
|---|---|
| profile 组合 | `dsh --profile ctx-audit-web --dump-config` 1272 行，含 `ctx-audit-web` 与 `ctx-audit-mcp` 两行 |
| 客户端半区进 boot graph | index 内 `{"id":"@local/ctx-audit-web","url":"plugins/??@local/ctx-audit-web/client.js&rev=…","immediately":true}` |
| bundle 被服务 | `GET /plugins/??@local/ctx-audit-web/client.js&rev=…` → 200，内容含 `sidebar.panellist` 与端点路径 |
| 数据端点 | `GET /ctx-audit/api/status` → 200 + `application/json`；未知子路径 404；POST 405 |
| MCP 握手 | 子进程 `ctx-audit` 被拉起并驻留；`failOnStartupError: true` 时 profile 仍能启动 |
| 安装脚本 | 干净 `DSH_HOME` 跑通并自校验通过（`verified: … composes with both rows`） |
| 语法/清单 | `node --check client.js\|index.js` 通过；`package.json` 与 `locale/*.json` 均为合法 UTF-8 JSON（无 BOM） |
| 视觉渲染 | 已由使用者在真实浏览器中确认页面出现（agent 不另开浏览器截图，见官方 verification 指南） |

## 已知边界与下一步

- **未实现**：`tool.call.toolview`（把 MCP 工具结果渲染成专用卡片）。原因：该插槽组件必须在**有会话**时才能
  验证，而未经核对的插槽组件一旦抛错会**清空宿主自己的工具卡片**——宁可先不写。下一步应在有 agent 会话的
  环境里按 `cordis_inspect what:"client"` 的 slot 契约实现并验证。
- 页面数据目前**不经会话**：`main` 的非 `conversation` 键没有 Session binding。要把引擎证据（findings /
  切片 / 污点链）接进来，应走 host 投影（`wire.view`）或经 `dsh-api-remotes`，属独立一步。
- 可见文案暂未走 Client locale 服务；主题 token 用 `var(--dsw-alias-*, <fallback>)` 写法，token 名未经
  `cordis_inspect_query Theme` 核对（写错只退化为 fallback，不破坏渲染）。
- 插槽注册只能用**已挂载组合声明过的键**；发明全新插槽键需要由 owner 包声明（那是唯一需要 fork 的场景）。
- `dsh.client.external` 目前为空：本插件没有非基线运行时依赖。

## 卸载

```bash
rm -rf "$DSH_HOME/profiles/ctx-audit-web"
```
