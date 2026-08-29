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