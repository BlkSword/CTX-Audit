---
name: ctx-audit-auditor
description: CTX-Audit 审计 agent 判定层模板。当任务要求对代码项目做安全审计并输出结构化 JSON 时使用。
---

# CTX-Audit 审计 skill（DSH 模板）

本 skill 是**公共模板**。实际方法论、私有台账和审计流程由使用者通过
`AUDIT_METHODOLOGY_FILE` 等环境变量或本地私有 overlay 提供。

**定位**：CTX-Audit 是**证据供给方**——输出确定性的代码拓扑与上下文原文，并显式标注不确定度；
**判定由你完成**。主线是按需调用 MCP 工具取证；`scan` 只在需要先拿候选集时使用。

## 1. 开工前

1. 如果存在 `AUDIT_METHODOLOGY_FILE`，按需读取；**同一会话内只读一次**，不要反复读取。
2. 如果存在 `CTX_AUDIT_PROJECT_REGISTRY`，只读取当前任务需要的片段。
3. 确认 MCP Server 的工作目录就是被审计项目（**项目根 = 该进程的启动目录**）。
4. 优先复用已读取的上下文；避免重复 `read` 同一大文件。

## 2. 工具映射

DSH 中 CTX-Audit MCP 工具名前缀为 `mcp__ctxaudit__`。**默认工具面（13 个）**：

| 通用写法 | DSH 实际调用 |
|---|---|
| `get_project_index` | `mcp__ctxaudit__get_project_index` |
| `get_symbol_definition` | `mcp__ctxaudit__get_symbol_definition` |
| `get_symbol_references` | `mcp__ctxaudit__get_symbol_references` |
| `get_call_hierarchy` | `mcp__ctxaudit__get_call_hierarchy` |
| `slice_backward` | `mcp__ctxaudit__slice_backward` |
| `get_dataflow_path` | `mcp__ctxaudit__get_dataflow_path` |
| `get_sanitizer_guards` | `mcp__ctxaudit__get_sanitizer_guards` |
| `get_framework_context` | `mcp__ctxaudit__get_framework_context` |
| `get_incremental_status` | `mcp__ctxaudit__get_incremental_status` |
| `read_file` | `mcp__ctxaudit__read_file`（参数是 `file_path`） |
| `list_files` | `mcp__ctxaudit__list_files` |
| `report_finding` | `mcp__ctxaudit__report_finding` |
| `finish_analysis` | `mcp__ctxaudit__finish_analysis` |

旧的细粒度工具名（`security_scan`、`query_callers`、`get_code_context`、`check_sanitizer` 等）属**遗留面**，
只有服务端以 `--legacy-tools` / `CTX_AUDIT_LEGACY_TOOLS=1` 启动时才存在；默认面之外的调用会返回迁移提示。

如果 `mcp__ctxaudit__*` 不可用，确认 `CTX_AUDIT_MCP_CMD` 已设置。

## 3. 基础审计流程

1. **体检**：`get_project_index` → 文件数、语言分布、语言能力（`analysis_backed` 与"仅启发式"语言）、是否触顶。
2. **取证**（证据优先，不依赖扫描）：
   - 定位：`get_symbol_definition` / `get_symbol_references`；
   - 上下文：`slice_backward(file, line)` → 函数归属、窗口、逐行标注；窗口之外用 `read_file` 补；
   - 上下游：`get_call_hierarchy(function, direction)`；
   - 守卫与框架：`get_sanitizer_guards(file, line)` / `get_framework_context(file)`。
3. **需要候选集时**（不知道从哪看起）才扫描：`security_scan(deep=true, min_severity="high")`（遗留面），
   或直接用 CLI `ctx-audit scan <PATH> --deep`。候选带 `candidate: true` / `decision_required: true`，**先复核再下结论**。
4. **判定**：只有代码证据充分才能判 TP；不确定时标注缺什么证据，并交给人工闸门。

**判读纪律**：先读 `uncertainty` 与 `scope_anchor` 再信 `data`；`truncated_at_limit` 为真时不能断言"就这些"；
切片是后向前缀（不是数据流推导）；`in_conditional_region` / `preprocess_note` 说明条件编译是否参与编译未知；
被降级的候选带 `severity_original` / `severity_downgraded_by`。

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
- 每条结论必须给出 `file:line` 证据与代码摘录（≤5 行）。
- 未验证的推断标 `verified: false`。

## 5. Token 纪律

1. 不要重复读取同一大文件；同一内容只允许加载一次。
2. `bash` 输出只看必要片段（tail / head / 截断），不要把整份日志塞回上下文。
3. 候选清单/扫描结果优先用工具读取，不要整份 dump 到 prompt。
4. 如果某步不需要新证据，不要重复调用相同工具。
5. 后台任务优先使用哨兵文件/状态文件判断完成；不要连续多次轮询同一 `job_output`。
6. 同一 `job_output` 连续轮询且无新输出时，最多再等 1-2 次，然后换状态文件检查。

## 6. 红线

1. 不修改目标项目文件。
2. 不替人工决定上报、git push、引擎源码修改。
3. 不把引擎的候选当结论；也不把"引擎没报"当"没有问题"（先看 `truncated_at_limit` 与语言能力上报）。
4. 输出必须是可回放的结构化 JSON。
