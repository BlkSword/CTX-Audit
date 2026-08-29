# 私用接入指南（Private Overlay Guide）

`harness/` 是公共框架。你可以完全用自己的配置、prompt、脚本和密钥来使用它，而无需修改公共仓库。

## 核心理念

公共框架只负责通用机制：

- DSH profile / skill / launcher
- Agent Pipeline / Runner
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
├── pipeline.yaml                 # 私人审计 Pipeline
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
| `CTX_AUDIT_PIPELINE_FILE` | 无 | Agent Pipeline 配置 |
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

## 边界红线

- 公共仓库只提交 `harness/` 和 `templates/`。
- 私有 `harness-private/`、`~/.ctx-audit/private/`、`secrets.env` 永不提交。
- API key 只从环境变量 / `secrets.env` 读取。