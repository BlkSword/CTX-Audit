# CTX-Audit Public Harness

`harness/` 是 DSH 审计流水线的**公共框架本体**。它包含可安装的 profile/skill、launcher、通用编排脚本，但不包含任何私有路径、密钥、测试机信息或审计方法论细节。

私有用法=把个人配置/文件放到本地 overlay（例如 `~/.ctx-audit/private/`），再通过环境变量或 Pipeline 指向它们。

## 安装

```bash
# 将公共 profile/skill/settings 安装到 DSH_HOME
DSH_HOME="$HOME/.dsh" ./install.sh

# 或直接使用 launcher，首次使用会自动安装
CTX_AUDIT_MCP_CMD=ctx-audit ./bin/ctx-audit-dsh "对 ./project 做安全审计"
```

## 使用

```bash
# 一轮完整审计
./bin/run-round.sh ./project

# 侦察兵 + 狙击手
./bin/run-scout.sh ./project
./bin/run-sniper.sh ./project scout-output.json

# 一次性串联
./scripts/dsh-audit-run.sh ./project R001
```

## Web 定制面（`ctx-audit-web`）

一键安装 + 启动（细节与全部用法见插件自己的 README）：

```bash
# 安装（非破坏性；FORCE=1 覆盖本仓库自带的 profile 与 web bundle）
DSH_HOME="$HOME/.dsh" bash harness/install.sh

# 安装后自检（无需浏览器）
node harness/scripts/verify-ctx-audit-web.mjs --dsh <DSH 包目录>   # patch 逐行校验
node harness/scripts/probe-ctx-audit-web.mjs                      # 组件树探针

# 启动（也可用 launcher：DSH_PROFILE=ctx-audit-web bash harness/bin/ctx-audit-dsh）
dsh --profile ctx-audit-web --port 3081 --no-open
```

完整步骤（前置条件 / 文件布局 / 面板用法 / 换项目根 / 预设 / 工具卡 / 卸载）见
`harness/plugins/ctx-audit-web/README.md` 的「快速开始：安装与使用」。

把 CTX-Audit 接进 DSH 的 Web GUI：插件注册的中心页面 + 侧边栏入口 + MCP 服务器行；页面数据来自该插件
host 半区自己的只读 JSON 端点。**不需要 fork DSH，也不需要改前端**——这是"profile（有序 bundle 列表）"
与"外挂客户端插件（`dsh.client` + `./client` 导出）"两个官方扩展点的组合。

```bash
DSH_HOME="$HOME/.dsh" ./install.sh        # 安装 profile 与 bundle（幂等；装完自动校验组合树）
CTX_AUDIT_MCP_CMD=<abs>/ctx-audit dsh --profile ctx-audit-web --port 3081 --no-open
```

细节见 [plugins/ctx-audit-web/README.md](./plugins/ctx-audit-web/README.md)，其中记录了本次实测踩到的
**静默失败陷阱**：bundle 的 patch 必须为自己插一行，否则客户端半区永远不进 boot graph 且没有任何报错。

**控制面板**（插件注册的 `main` 页面）：顶部状态胶囊（MCP 就绪 / 引擎版本 / 工具数）+ 四个 KPI；
卡片含 **MCP 配置**、**MCP 引擎（实时 stdio 握手：服务端与协议版本、13 个工具及描述）**、
**日志**（从工作区 `.ctx-audit/*.log` 尾部读，可选文件与行数）、**证据产物**（有界清单 + 体积 + 相对时间）、
**路线图**（随仓库提交的 `roadmap.json`）。数据全部来自插件 host 半区的只读端点。
页头还有**目标选择器**：候选由 `/targets` 自动发现（带 `.ctx-audit/` 证据或看起来是项目的目录），选中后产物 / 日志 / **项目体检**（以该目标为 cwd 实时调用 MCP `get_project_index`）都跟随它；目标路径受允许根约束（越权返回 400）。

另有 **Agent 预设**只读名册卡（走宿主自己的 remote 面 `ctx.remote.agentPresets`，显示 id / 默认 / `broken`），
并为 13 个 `mcp__ctxaudit__*` 工具各注册一张 `tool.call.toolview` 卡片（按工具名 keyed，注册失败只告警）。

**审计专用 agent 预设 `ctx-audit`**（`plugins/ctx-audit-web/presets/ctx-audit.patch.yml`）：**内置 `standard` 能力面的超集**（33 个能力行 = jobs / goal / plan mode / workflow-PTC / 委派 / 压缩 / skill / web 全都在），差异只在 persona（审计身份 + 硬规则 + "用整台机器"的打法）、三处刻意不做（不设 `complete: true`、`ralph` 保持 disabled、不含写文件的编辑器）；随 bundle 注册并被设为部署默认（也可在 profile 层覆写 `agent-preset-registry.default`）。

**校验**（预设的行不会在启动时校验，坏预设只在会话挂载时才报）：

```bash
node harness/scripts/verify-ctx-audit-web.mjs --dsh <path to @deepseek-ai/dsh>
# 33 行 = 25 OK / 8 SKIP / 0 FAIL；把 persona 的 prefix 换成旧字段 text 会立刻 FAIL
```

## Agent Preset / 默认模式

- 公共 `harness/` **默认使用 DSH 自带极简/默认模式**，不默认加载自定义 agent preset。
- `bin/run-*.sh` 会在任务中显式要求加载 `ctx-audit-auditor` skill，因此即使没有自定义 preset，审计流程仍会加载 skill。
- 如果你需要审计专用 persona（`ctx-audit-auditor` preset），请通过私有 overlay 提供，不应放入公共框架。
- 做法见 [PRIVATE-USE.md](./PRIVATE-USE.md)。

## 已验证

- LongCat scout 通路：公共 `harness/` + 全新 DSH_HOME + LongCat-2.0，成功调用 MCP 工具并输出 `human_gate` JSON。
- 极简默认模式下仍会加载 `ctx-audit-auditor` skill。
- 无 LLM 自定义 Pipeline 整轮可跑通。

## 公共 / 私有边界

- **公开**：本目录下所有文件。
- **私有**：本地 `harness-private/`、`~/.ctx-audit/private/`、`secrets.env`、方法论、台账。
- 私有内容通过环境变量 / Pipeline 配置 / DSH_HOME overlay 注入，不进入公开仓库。
- 详细接入方式见 [PRIVATE-USE.md](./PRIVATE-USE.md)。