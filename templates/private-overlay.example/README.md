# 私有 Overlay 示例

把本目录复制到本地（例如 `~/.ctx-audit/private/`），这些文件**不要提交到公共仓库**。

```
private/
├── prompts/
│   ├── my-triage.md
│   └── my-deep-review.md
├── methodology.md          # 你的审计方法论/checklist（可选）
├── registry.md             # 你的共享项目库/台账（可选）
├── pipeline.yaml           # 你的 Pipeline 配置（可被 templates/pipelines 覆盖）
├── dsh/
│   ├── profiles/           # 你的真实 DSH profile 覆盖
│   └── skills/             # 你的真实 skill 覆盖
└── secrets.env             # API key，永不入库
```

## 接线

```bash
export CTX_AUDIT_PIPELINE_FILE="$HOME/.ctx-audit/private/pipeline.yaml"
export AUDIT_METHODOLOGY_FILE="$HOME/.ctx-audit/private/methodology.md"
export CTX_AUDIT_PROJECT_REGISTRY="$HOME/.ctx-audit/private/registry.md"

# 或写入全局配置
ctx-audit config set agent.native_pipeline.file "$HOME/.ctx-audit/private/pipeline.yaml"
```

## Git 建议

公共仓库保留 `templates/`，私有 overlay 使用独立目录或私有仓库，并在公共仓库 `.gitignore` 中排除：`/.ctx-audit-private/`、`secrets.env`、`audit-logs/`。