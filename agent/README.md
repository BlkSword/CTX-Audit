# ctx-audit-agent 框架

`agent/` 提供通用 LLM Agent 基础设施和可配置审计流水线（Pipeline）。

## 组成

### 通用层（与具体审计方法无关）

- `provider.rs`：OpenAI-compatible LLM Provider
- `agent.rs`：消息驱动主循环，含预算、doom loop 熔断
- `session.rs`：append-only JSONL 会话，可崩溃恢复/重放
- `tool_adapter.rs`：工具 schema 生成、执行、白名单
- `subagent.rs`：子 Agent（独立 history/预算/白名单）
- `confirm.rs`：工具审批模式（Auto / Gate）
- `cron.rs`：轻量 cron 调度
- `event.rs`：AgentEvent 事件流

### 流水线层（可通过 Pipeline 配置定制）

- `pipeline.rs`：`PipelineConfig` 定义扫描开关、判定阶段、输出契约、TP 提取路径
- `runner.rs`：轮状态机。默认行为等于 CTX-Audit 六阶段审计流水线

## Pipeline 配置

通过 YAML/JSON 文件或 `CTX_AUDIT_PIPELINE_FILE` 环境变量覆盖：

```bash
export CTX_AUDIT_PIPELINE_FILE=templates/pipelines/custom-example.yaml
ctx-audit agent round run --target ./project
```

或写入全局配置：

```bash
ctx-audit config set agent.native_pipeline.file templates/pipelines/custom-example.yaml
ctx-audit config set agent.native_pipeline.judge_prompt_path ./private/prompts/my-judge.md
```

## 公共 / 私有边界

- 公共框架只含通用机制和默认行为。
- 你的审计方法论、私有 prompt、registry、台账应放在本地私有目录，通过 Pipeline 的
  `triage.prompt_path`、`deep_review.prompt_path` 或 `judge_prompt_path` 指向它。
- API key 只从环境变量读取，不落盘。