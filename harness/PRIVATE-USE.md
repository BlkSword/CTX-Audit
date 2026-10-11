# 私用接入指南（Private Overlay Guide）

`harness/` 是公共框架。你可以完全用自己的配置、prompt、脚本和密钥来使用它，而无需修改公共仓库。

## 核心理念

公共框架只负责通用机制：

- DSH profile / skill / launcher
- MCP 接入

私有内容全部放在你自己的 overlay：

- 审计方法论 / checklist
- 目标清单 / 台账 / registry
- scout / sniper prompt
- CVE 回放任务
- API key / SearXNG 认证
- 私有大轮 / 反馈脚本

## 推荐目录结构

```text
~/.ctx-audit/private/
├── methodology.md                # 方法论（可选）
├── registry.md                   # 项目台账（可选）
├── targets.txt                   # 每日轮转目标清单
├── feedback-tasks/               # CVE 回放任务 JSON
├── prompts/
│   ├── scout-prompt.md
│   ├── sniper-prompt.md
│   └── cve-library.md
├── logs/                         # 审计日志
├── secrets.env                   # API key，永不提交
└── dsh/
    ├── profiles/                 # 私有 DSH profile 覆盖
    └── skills/                   # 私有 skill 覆盖
```

可以用模板快速初始化：

```bash
./templates/private-overlay.example/init-private.sh
```

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `CTX_AUDIT_HARNESS_DIR` | `<repo>/harness` | 公共 DSH harness 目录 |
| `CTX_AUDIT_PRIVATE_DIR` | `~/.ctx-audit/private` | 私有 overlay 根目录 |
| `AUDIT_LOG_DIR` | `$PRIVATE_DIR/logs` | 审计日志目录 |
| `AUDIT_TARGETS_FILE` | `$PRIVATE_DIR/targets.txt` | 每日轮转目标清单 |
| `AUDIT_FEEDBACK_DIR` | `$PRIVATE_DIR/feedback-tasks` | CVE 回放任务目录 |
| `DSH_SCOUT_PROMPT_FILE` | `$PRIVATE_DIR/prompts/scout-prompt.md` | 侦察兵 prompt |
| `DSH_SNIPER_PROMPT_FILE` | `$PRIVATE_DIR/prompts/sniper-prompt.md` | 狙击手 prompt |
| `CVE_LIBRARY_PROMPT` | `$PRIVATE_DIR/prompts/cve-library.md` | CVE 库补充 prompt |
| `CTX_AUDIT_MCP_CMD` | 自动查找 | ctx-audit 二进制路径 |

## 使用公共 harness

```bash
# 安装公共 framework + 私有 overlay
DSH_HOME="$HOME/.dsh" ./harness/install.sh

# 直接跑一轮
CTX_AUDIT_MCP_CMD=ctx-audit ./harness/bin/ctx-audit-dsh "对 ./project 做安全审计"

# 侦察兵 + 狙击手
./harness/bin/run-scout.sh ./project
./harness/bin/run-sniper.sh ./project scout-output.json
```

## 使用私有脚本

如果你保留自己的私有大轮/反馈脚本（例如 `harness-private/bin/`），它们应通过环境变量指向公共 harness：

```bash
export CTX_AUDIT_HARNESS_DIR="$PWD/harness"
export CTX_AUDIT_PRIVATE_DIR="$HOME/.ctx-audit/private"
export AUDIT_LOG_DIR="$HOME/.ctx-audit/private/logs"
export DSH_SCOUT_PROMPT_FILE="$HOME/.ctx-audit/private/prompts/scout-prompt.md"
export DSH_SNIPER_PROMPT_FILE="$HOME/.ctx-audit/private/prompts/sniper-prompt.md"

# 私有大轮
./harness-private/bin/dsh-daily.sh
./harness-private/bin/dsh-batch-feedback.sh
```

私有脚本只负责“你的流程”，底层全部调用公共 `harness/`。

## 私有大轮/反馈脚本已做的改造

`harness-private/bin/common.sh` 统一解析：

- 公共 harness 位置
- 私有 overlay 位置
- 日志 / targets / feedback-tasks / prompts 默认路径

大轮/反馈脚本不再硬编码 `/root/audit-logs`、`/root/CTX-Audit` 等路径，而是通过环境变量或私有 overlay 解析。

## Agent Preset 说明（0.2.0-rc.2 起：预设是"声明行"，不是目录）

**已作废的旧写法**（本文件此前教的，以及 `harness-private/` 里仍在用的那种）：

```text
$DSH_HOME/.agent-presets/<id>/{preset.yml, agent.cordis.yml}   # 没有任何代码读它
settings.yaml: agent-presets: {default: <id>}                  # 命名空间与字段都不对
```

DSH 自带的组合编辑技能写明 *"Nothing reads that directory any more."*；默认值的正确落点是**设置命名空间 = profile 条目 id**：

```yaml
# $DSH_HOME/settings.yaml —— 只导入一次，随后文件会被改名为 settings.yaml.imported
agent-preset-registry:
  selectedDefault: ctx-audit
```

**现行三种写法（按稳健度递减）**

1. **随 bundle 走（推荐）**：在 bundle 的 patch 里 insert 一行 `@deepseek-ai/dsh-agent-preset`，并覆写注册表的 `default`。仓库自带示例见
   `plugins/ctx-audit-web/presets/ctx-audit.patch.yml`。
2. **profile 层覆写**：在 `$DSH_HOME/profiles/<name>/cordis.patch.yml` 里
   ```yaml
   - id: agent-preset-registry
     name: '@deepseek-ai/dsh-agent-preset-registry'
     config:
       default: ctx-audit
   ```
   （profile 层在所有 bundle 层之后应用）
3. **旧式 settings.yaml**：见上面的 `selectedDefault`。

**要点与坑**

- `order` 只决定名单顺序，**不决定默认值**；默认值 = `selectedDefault ?? default`。
- 预设行对插件管理**只读**：落地后要改组成只能重新发 bundle。
- 覆写预设必须按 Loader 行 id（`preset-<id>`），且 **config 是整体替换**（必须重述所有字段）；id 匹配不到任何行时**只会告警并跳过**。
- 预设 `id` 不得与内置的 `standard` / `ptc` / `minimal` / `cordis` 重名（重名直接抛错）。
- 只有 bundle 列表里含 `@deepseek-ai/dsh-web-app` 时预设才可能注册（注册表那一行由它插入）。
- 组装失败**不中断启动**，只记一条 `agent preset <id>: <原因>` 的 warning；坏掉的预设会从选择器里消失，**判活要看这行日志**。
- skill 仍按原样部署到 `$DSH_HOME/skills/<name>/SKILL.md`（那是默认根之一），但预设里必须挂 `@deepseek-ai/dsh-skill-filesystem` + `@deepseek-ai/dsh-tool-skill`，模型才看得到 skill 工具——Web 面默认禁用了宿主那两行。

**公共默认 vs 私有覆盖**

- 公共/通用场景：DSH 自带 `standard` 预设即可，`run-*.sh` 会把"加载 `ctx-audit-auditor` skill"写进任务。
- 审计场景：用仓库自带的 `ctx-audit` 预设（persona + 审计硬规则 + skill 先加载 + 只读目标项目 + TP 一律 `human_gate`），或再用上面的第 2 种写法把它设为默认。

## 边界红线

- 公共仓库只提交 `harness/` 和 `templates/`。
- 私有 `harness-private/`、`~/.ctx-audit/private/`、`secrets.env` 永不提交。
- API key 只从环境变量 / `secrets.env` 读取。