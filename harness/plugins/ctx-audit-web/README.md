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

## 数据端点（控制面板的数据层）

前缀 `/ctx-audit/api` 由本插件独占；全部 **GET/HEAD**，其它方法 405，未知子路径 404。

| 端点 | 内容 |
|---|---|
| `/status` | MCP 行回显（serverName / transport / command / **二进制是否存在** / 工具名前缀）、工作区、证据目录、**有界（≤30 项）的 `.ctx-audit/` 清单 + 计数**、可用 `.log` 文件列表 |
| `/engine` | **真实 MCP 握手**（stdio：`initialize` → `initialized` → `tools/list`）：服务端名与版本、协议版本、**工具清单与描述**。带 6s 超时、5 分钟缓存；`?refresh=1` 强制重探 |
| `/logs?file=<name>&lines=N` | 指定 `.log` 的**末尾 N 行**（≤500 行、只读文件尾 ≤256KB）；`file` 只能是枚举出来的名字，构造值拿不到目录外的文件 |
| `/roadmap` | 随本 bundle 提交的 `roadmap.json`，原样返回 |

只读、有界、**除日志尾读外不返回任何文件内容**；Web server 默认只绑回环（启动器拒绝 `--host 0.0.0.0`）。
`commandFound` 为 `null` 表示命令是裸名（经 PATH 解析，此处无法判定），面板据此显示"经 PATH 解析"而不是猜。
日志与产物清单都是**运行时从工作区读取**，不会写进仓库。

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

## Agent 预设 `ctx-audit`（随本 bundle 一起发布）

`presets/ctx-audit.patch.yml` 是本 bundle 的**第二个 patch 层**（见 `package.json` 的 `dsh.bundle.patch` 数组），做两件事：

1. **把预设 `ctx-audit` 注册进名单**：一行 `@deepseek-ai/dsh-agent-preset`（`config.id / name / description / order / plugins`）；
2. **把它设为部署默认**：覆写 `agent-preset-registry` 的 `default`（该行由 `dsh-web-app` 插入，本层在其之后应用，因此生效）。

> 预设不再是目录：`$DSH_HOME/.agent-presets/<id>/{preset.yml,agent.cordis.yml}` 这条路在 0.2.0-rc.2 已**无人读取**；
> `settings.yaml` 里的默认值键名也不是 `agent-presets: default:`，而是**设置命名空间 = profile 条目 id**：
> `agent-preset-registry: { selectedDefault: ctx-audit }`（只导入一次，随后文件被改名为 `settings.yaml.imported`）。

**设计原则：本预设是内置 `standard` 能力面的超集，不是它的子集。** 审计恰好是最需要"整台机器"的负载——
广度（对大量候选做便宜的分头取证）、深度（对幸存者做链式深审）、长时无人值守、以及不能靠"一次一个工具调用"完成的
批处理。能力行对照实测：本预设 **35 个 id 对 standard 的 34 个**，standard 的每一个能力行都在（只差它自己的两个声明 id）。

**预设内容**（33 个能力行）：

| 部分 | 行 | 对审计的作用 |
|---|---|---|
| 身份 | `persona`（`prefix` 必需字段 + `suffix`） | 审计身份 + 6 条硬规则；并明确"用整台机器"的打法（MCP 取证、jobs 跑长任务、plan mode 先定审计形状、delegation/workflow 做广度、goal 跨轮次、compaction 控上下文） |
| 工作区约定 | `agent-instructions` | 先读目标仓库自己的 AGENTS.md/CLAUDE.md 再判定 |
| 执行面 | `tool-pwsh`｜`tool-bash`（平台互斥）、`tool-fs`、`tool-fs-search`、**`tool-jobs`** | 跑引擎/模糊测试/目标自带测试；长扫描放后台不占住对话 |
| 方法论 | `skill-filesystem` + `tool-skill` | **必需**：Web 面禁用了宿主那两行，不挂就没有 `skill` 工具，而 persona 第一条动作就是加载 skill |
| 长时无人值守 | **`command-goal` + `tool-goal`** | 目标持久化并驱动多轮审计，跨轮次不中断 |
| 先想后做 | **`planning` 组（`isolate.planMode`）→ `plan-mode`** | 先定目标/阶段/验收口径，再执行 |
| 上下文预算 | **`compaction` 组 → `compaction-basic`/`command-compact`/`tool-result-pruner`** | 审计读的原始输出远多于它推理的量；这层决定长审计是否可负担 |
| 广度与深度 | **`delegation` 组**：`tool-subagent-control`、`list-agents`、`tool-subagent`（**`modelSelectionSettings: true`**）、`tool-subagent-fork`、`workflow-ptc`、`tool-workflow`、`tool-ralph`(disabled)、`tool-subagent-codex/claude-code`(disabled) | **便宜模型并行做逐候选取证，本上下文负责判定**；workflow + PTC runtime 是批处理路径（脚本化 fan-out，而不是每条候选一次工具调用） |
| 人机闸门与交付 | `tool-ask-user`、`tool-todo`、`tool-web`、`present` | 外网查公告/修复历史（可达性判定必需）；`present` 出报告 |
| 刻意禁用 | `tool-plugin-manager`(disabled) | 预设行对插件管理本就只读，且审计员不该在运行中改自己的组成 |

**三处刻意的不做（都有理由，不是遗漏）**

1. **不设 `complete: true`**：那会把 persona 变成**唯一**提示词段，"no tool guidance … can append"，工具指引全被丢掉；对必须驱动整面工具的 agent 是错的取舍。方法论交给 `ctx-audit-auditor` skill。
2. **`tool-ralph` 保持 disabled**：它以"worker 自报"作为完成判据而非独立核验，且这种规模的无人值守迭代正是本项目此前 token 预算失控的形态；要开就按部署显式开。
3. **不含 str-replace 编辑器**（standard 也没有）：审计纪律要求对目标项目只读，**能力干脆不授予**，而不是授予后用提示词禁止。同理 `tool-subagent-codex/claude-code` 保持 `disabled`（其 provider 不在本部署里），保留行是为了让工具目录形状与内置预设一致。

**模型不在预设里选**：`dsh-agent-default-model` 属部署层（宿主行），留在 profile patch；预设能给的是**给子代理挑模型**的能力（`modelSelectionSettings`）。

**预设行对插件管理只读**：落地后要改组成，只能重新发 bundle patch。

## 校验（`harness/scripts/verify-ctx-audit-web.mjs`）

预设的行**在启动时不校验**：坏预设照样能起来，只会在**会话挂载**时报 `agent preset <id>: <原因>`（并标 `broken`、从选择器里消失）。所以"启动无报错"**不能**当判活依据（我们做过反向对照证实：把 persona 的 `prefix` 换成 `text`，启动日志依然干净）。

正确做法是用**运行时同一套 schema** 逐个校验本 bundle 的所有行：

```bash
node harness/scripts/verify-ctx-audit-web.mjs --dsh <path to @deepseek-ai/dsh>
# 或 DSH_PACKAGE_DIR=<path> node harness/scripts/verify-ctx-audit-web.mjs
```

它会：解析两个 patch 文件的每一行（含 `@deepseek-ai/dsh-agent-preset` 声明**内部**的嵌套行、`cordis:group` 递归）→ 载入目标包的真实 `Config` schema → 用该行的 `config` 调一次；`!!js` 与子路径导出如实标 `SKIP`，失败行打 `FAIL` 并以退出码 1 结束。

实测：**33 行 = 25 OK / 8 SKIP / 0 FAIL**；把 `prefix` 改成 `text` 后立刻 `FAIL ./presets/ctx-audit.patch.yml#preset-ctx-audit/plugins[0]  $.prefix missing required value`。

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
| 数据端点 | `/status` 200 + `application/json`（61 文件 + 5 目录、6.1 MB、1 个 `.log`）；`/engine` 200 且 `ok=true`（`ctx-audit 3.1.1`、13 工具）；`/logs?lines=3` 200 且返回末尾 3 行、`truncated=true`；`/roadmap` 200 且 6 条；未知子路径 404；POST 405 |
| 端点安全 | `?file=../../package.json` → `unknown_log_file`（`file` 只接受枚举出的名字）；日志只读文件尾 ≤256KB |
| 隔离测试 | 直接 `import` host 半区、伪造 `ctx`/`res` 把四个端点跑一遍：全部通过（含真实 MCP 握手拿到 13 个工具） |
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
