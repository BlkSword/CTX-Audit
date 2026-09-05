---
name: ctx-audit-auditor
description: CTX-Audit 审计 agent 判定层模板。当任务要求对代码项目做安全审计并输出结构化 JSON 时使用。
---

# CTX-Audit 审计 skill（DSH 模板）

本 skill 是**公共模板**。实际方法论、私有台账和审计流程由使用者通过
`AUDIT_METHODOLOGY_FILE` 等环境变量或本地私有 overlay 提供。

## 1. 开工前

1. 如果存在 `AUDIT_METHODOLOGY_FILE`，按需读取；**同一会话内只读一次**，不要反复读取。
2. 如果存在 `CTX_AUDIT_PROJECT_REGISTRY`，只读取当前任务需要的片段。
3. 默认按通用安全审计方法执行：理解项目 → 扫描 → 取证 → 判定。
4. 优先复用已读取的上下文；避免重复 `read` 同一大文件。

## 2. 工具映射

DSH 中 CTX-Audit MCP 工具名前缀为 `mcp__ctxaudit__`：

| 通用写法 | DSH 实际调用 |
|---|---|
| `get_project_info` | `mcp__ctxaudit__get_project_info` |
| `security_scan` | `mcp__ctxaudit__security_scan` |
| `query_callers` | `mcp__ctxaudit__query_callers` |
| `get_code_context` | `mcp__ctxaudit__get_code_context` |
| `search_code` | `mcp__ctxaudit__search_code` |
| `check_sanitizer` | `mcp__ctxaudit__check_sanitizer` |

如果 `mcp__ctxaudit__*` 不可用，确认 `CTX_AUDIT_MCP_CMD` 已设置。

## 3. 基础审计流程

- 理解项目：语言、框架、入口、认证方式。
- 扫描：`security_scan(deep=true, min_severity="high")`。
- 取证：从 sink 向上追调用者，逐跳确认数据是否外部可控。
- 判定：只有代码证据充分才能判 TP；不确定时标记候选并交给人工闸门。

## 4. 输出契约（可通过本地 skill 覆盖）

默认输出 JSON：

```json
{
  "summary": {"tp_candidates": 0, "fp": 0, "hardening": 0},
  "tp_candidates": [],
  "fp_families": [],
  "hardening": [],
  "human_gate": false
}
```

- 任何 TP 候选必须设 `human_gate: true`。
- 每条结论必须给出 `file:line` 证据。

## 5. Token 纪律

1. 不要重复读取同一大文件；同一内容只允许加载一次。
2. `bash` 输出只看必要片段（tail / head / 截断），不要把整份日志塞回上下文。
3. 候选清单/扫描结果优先用工具读取，不要整份 dump 到 prompt。
4. 如果某步不需要新证据，不要重复调用相同工具。

## 6. 红线

1. 不修改目标项目文件。
2. 不替人工决定上报、git push、引擎源码修改。
3. 未验证的结论必须标 `verified: false`。
4. 输出必须是可回放的结构化 JSON。