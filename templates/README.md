# CTX-Audit 公共框架模板


> DSH 公共 harness 本体在 `harness/`，不以 `templates/dsh/` 维护。

## 目录

- `private-overlay.example/`：私有 overlay 目录结构示例（不要提交到公共仓库）

## 使用方式

### DSH

```bash
# 公共 harness 安装到本地 DSH home，再覆盖私有方法论/密钥/profile
DSH_HOME="$HOME/.dsh" ./harness/install.sh
CTX_AUDIT_MCP_CMD=ctx-audit ./harness/bin/ctx-audit-dsh "对 ./project 做安全审计"
```

## 公共/私有边界

| 内容 | 应放哪里 |
|---|---|
| MCP 工具、公共 harness | 公共仓库 |
| DSH 公共 harness | `harness/` |
| 私有审计方法论、台账、registry | 私有 overlay（例如 `~/.ctx-audit/private/`） |
| DSH 真实 profile、skill、provider 配置 | 本地 `~/.dsh/` |
| API key、测试机路径、SearXNG 认证 | 环境变量 / `secrets.env`，永不入库 |
