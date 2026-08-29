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

## 公共 / 私有边界

- **公开**：本目录下所有文件。
- **私有**：你的真实 `harness/dsh-home/`、`harness/bin/` 私有脚本、`secrets.env`、方法论、台账。
- 私有内容通过 `AUDIT_METHODOLOGY_FILE`、`CTX_AUDIT_PIPELINE_FILE`、`DSH_HOME` overlay 注入，不进入公开仓库。