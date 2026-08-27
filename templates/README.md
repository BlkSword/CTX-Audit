# CTX-Audit 公共框架模板

本目录是“阳面”模板：不含任何私有方法论、台账、测试机路径或凭据。
配合私有 overlay 使用，即可实现不同的审计方法。

## 目录

- `pipelines/`：Agent Runner 的 Pipeline 配置示例
  - `ctx-audit-default.yaml`：默认 CTX-Audit 流程等价配置
  - `custom-example.yaml`：私人定制审计示例
- `dsh/`：DSH 公共模板
  - `profiles/`：audit / audit-scout / audit-sniper 的 profile 骨架
  - `skills/`：审计 skill 骨架（不含私有方法论）
  - `bin/`：通用 launcher 模板
  - `install.sh`：非破坏式安装到本地 DSH home
- `private-overlay.example/`：私有 overlay 目录结构示例（不要提交到公共仓库）

## 使用方式

### Agent Pipeline

```bash
# 使用环境变量
export CTX_AUDIT_PIPELINE_FILE=templates/pipelines/custom-example.yaml

# 或写入全局配置
ctx-audit config set agent.native_pipeline.file templates/pipelines/custom-example.yaml
ctx-audit agent round run --target ./project
```

### DSH

```bash
# 把模板安装到本地 DSH home，再覆盖私有方法论/密钥/profile
DSH_HOME="$HOME/.dsh" ./templates/dsh/bin/ctx-audit-dsh "对 ./project 做安全审计"
```

## 公共/私有边界

| 内容 | 应放哪里 |
|---|---|
| Agent 框架、MCP 工具、Pipeline 默认 | 公共仓库 |
| 私有审计方法论、台账、registry | 私有 overlay（例如 `~/.ctx-audit/private/`） |
| DSH 真实 profile、skill、provider 配置 | 本地 `~/.dsh/` |
| API key、测试机路径、SearXNG 认证 | 环境变量 / `secrets.env`，永不入库 |