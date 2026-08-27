# DSH 公共模板

这里的 DSH 模板是“壳”：不包含你的私有 API key、测试机路径、审计方法论和台账。

## 使用方式

1. 运行 `./install.sh` 把公共 profile/skill 骨架安装到 `$DSH_HOME`（已有文件不会被覆盖）。
2. 把 `profiles/*/cordis.patch.yml` 中 `${DSH_PROVIDER}` / `${DSH_MODEL}` 替换成你实际的 DSH provider。
3. 通过 `AUDIT_METHODOLOGY_FILE` 指向你自己的私有方法论文件。
4. 通过 `secrets.env` 注入 API key，绝不提交。

```bash
export DSH_HOME="$HOME/.dsh"
./install.sh

export AUDIT_METHODOLOGY_FILE="$HOME/.ctx-audit/private/methodology.md"
CTX_AUDIT_MCP_CMD=ctx-audit ./bin/ctx-audit-dsh "对 ./project 做安全审计"
```

## 私有/公共边界

- 公共：launcher、profile 骨架、skill 骨架
- 私有：真实 provider 配置、skill 里的方法论细节、SearXNG 认证、目标清单、审计产物