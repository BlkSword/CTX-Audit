---
name: ctx-audit-auditor
description: CTX-Audit 轮式安全审计统一入口。当任务要求对真实项目做安全审计、CVE 回放、漏洞判定、输出结构化 JSON 时使用。让 DSH agent 快速进入审计状态，按主线取证，并与其他 CTX-Audit 会话协作不冲突。
---

# CTX-Audit 审计 skill（DSH 版）

本 skill 是 CTX-Audit 真实项目安全审计的判定层。核心目标三件事：
**① 快速进入状态 ② 按主线取证 ③ 输出可回放的结构化 JSON。**

## 1. 开工前必读（按顺序）

1. `docs/CTX-Audit-会话交接.md` 第 1/2 节——项目定位、环境、遗留、教训。
2. `docs/audit-rounds/projects-registry.md`——共享项目库（单一事实源），选目标前必读。
3. `docs/audit-rounds/methodology.md`——方法论手册：选型策略、流程、报告与披露、checklist、backlog。
4. `docs/audit-rounds/README.md` 头部——轮次台账与最新轮次编号（防撞号）。
5. `CHANGELOG.md` Unreleased——引擎最新改动，避免重复修复。

**关键事实（与主线一致）**：

- 主线是**证据提供**：`ctx-audit mcp`，**项目根 = MCP 进程的启动目录**。默认面 **28 个工具**
  （25 高阶 + 3 基础：`read_file` / `list_files` / `finish_analysis`）；
  **`--read-only` 面 26 个**（另行剔除 `report_finding` / `finish_analysis`）。
  **不先扫描也能用**（首调按需建索引）。
- **两条轴必须分开看**：**候选轴**（从哪儿看起）**弱**——真实 C 用例里绝大多数修复点附近没有候选，
  但**不静默**（上限/截断/空结果/降级留痕都上报），验收看召回、成本、不静默；**证据轴**（这个点能不能判）
  **强**——给定 `file:line` 决定性行齐备，验收看交付率与边界是否如实。⇒ **引擎不能从零定位**，
  它把"点"变成"可判定的材料"；`scan_code` = 给 LLM 批量筛查的 **fuzz 类候选源**。
- **`scan_code` / CLI `scan` 是辅助**：只在需要"哪里可能有问题"的候选集时使用；
  输出带 `candidate: true` / `decision_required: true`，是候选种子而非结论。
- 引擎**不做**漏洞真值判定：判定由人或 LLM 在证据之上完成。
- 报告纪律：只有 0day 产出双份报告；非 0day 只登记台账。
- 长任务用 nohup + 哨兵文件；测试机与私有台账信息不进 tracked 文件。
- 完整流程与**度量纪律**（多 hunk 按 locus 分组取证、事实取漏洞侧原文并逐条自检、纯新增 hunk 显式锚点、
  降级条件必须写进结论）见仓库根 `SKILLS.md`（英文）/ `SKILL-CN.md`（中文）。

## 2. DSH 工具映射

DSH 中 MCP 工具名前缀为 `mcp__ctxaudit__`。**只读面 26 个**，按下表用；表外的名字不存在。

### A. 开局与覆盖（先看这里，不要先扫描）

| 本 skill 写法 | DSH 实际调用 | 用途 |
|---|---|---|
| `audit_brief` | `mcp__ctxaudit__audit_brief` | **推荐第一步**：项目画像 + 覆盖摘要 + 待审清单一次拿全 |
| `coverage_summary` | `mcp__ctxaudit__coverage_summary` | 覆盖率摘要 + 边界（是否触顶 / 未建模框架 / 置信度） |
| `coverage_triage` | `mcp__ctxaudit__coverage_triage` | 排序后的待审端点清单 |
| `get_project_routes` | `mcp__ctxaudit__get_project_routes` | 端点表：方法 / 路径 / 鉴权判定 / 证据行 |
| `explain_route` | `mcp__ctxaudit__explain_route` | 单个端点的鉴权推导链 |
| `assert_verdict` | `mcp__ctxaudit__assert_verdict` | 把"端点是否受保护"的判断固化成可复核结论 |

### B. 定位与切片

| 本 skill 写法 | DSH 实际调用 | 用途 |
|---|---|---|
| `slice_backward` | `mcp__ctxaudit__slice_backward` | `(file, line)` 后向前缀窗口 + 逐行标注 + 函数归属 |
| `read_file` | `mcp__ctxaudit__read_file` | 窗口外补行（参数 `file_path`） |
| `list_files` | `mcp__ctxaudit__list_files` | 列目录 |
| `trace_params` | `mcp__ctxaudit__trace_params` | 函数内 mini-SSA：参数 → 局部 → 实参绑定、隐式汇 |
| `get_framework_context` | `mcp__ctxaudit__get_framework_context` | 框架上下文：注解 / 中间件 / 容器 / 生效范围 |
| `get_sanitizer_guards` | `mcp__ctxaudit__get_sanitizer_guards` | 守卫与净化器清单（含是否截断） |

### C. 链与可达

| 本 skill 写法 | DSH 实际调用 | 用途 |
|---|---|---|
| `candidate_chains` | `mcp__ctxaudit__candidate_chains` | 候选链（入口 → 危险汇），带档位与分数 |
| `chain_dossier` | `mcp__ctxaudit__chain_dossier` | 单链链档：每步 `file:line` / 守卫 / 断点 / 不确定性 / 反证命令 |
| `assert_chain_step` | `mcp__ctxaudit__assert_chain_step` | 逐步证伪 |
| `can_reach` | `mcp__ctxaudit__can_reach` | 两点可达判定 |
| `slice_between` | `mcp__ctxaudit__slice_between` | 两点之间按需切片 |
| `trace_vulnerability_chain` | `mcp__ctxaudit__trace_vulnerability_chain` | 入口 → 汇追踪（含实参） |

### D. 载荷与验证

| 本 skill 写法 | DSH 实际调用 | 用途 |
|---|---|---|
| `payload_viability` | `mcp__ctxaudit__payload_viability` | 载荷存活判定（`payload_killed` / `guard_ineffective_token` / `taint_lost` / `payload_may_survive`） |
| `verify_payload` | `mcp__ctxaudit__verify_payload` | 受限动态验证（需 `CTX_AUDIT_VERIFY_DIR`） |
| `harness_skeleton` | `mcp__ctxaudit__harness_skeleton` | 生成验证夹具骨架 |

### E. SOP 与产出

| 本 skill 写法 | DSH 实际调用 | 用途 |
|---|---|---|
| `audit_workflow` | `mcp__ctxaudit__audit_workflow` | 五阶段一键 SOP：覆盖率 → 待审 → 候选链 → 链档 → 载荷，带稳定证据 id |
| `autopilot` | `mcp__ctxaudit__autopilot` | 预算内自主循环，输出 verdict / findings / trace |
| `poc_package` | `mcp__ctxaudit__poc_package` | PoC 工件：Mermaid 拓扑 + 请求骨架 + Guard Gap + 修复建议 |
| `pr_drift_gate` | `mcp__ctxaudit__pr_drift_gate` | PR 漂移闸门（base/head 两棵树对比） |

### F. 候选源

| 本 skill 写法 | DSH 实际调用 | 用途 |
|---|---|---|
| `scan_code` | `mcp__ctxaudit__scan_code` | 规则 / 污点 / 深度三档扫描；输出是候选种子 |

**只读面的两个缺口**：`report_finding` 与 `finish_analysis` 在 `--read-only` 下不注册。
所以第 4 节的 JSON 契约**写在回复正文里**，无法回写引擎台账；需要回写时由人工在会话语义外登记。

**旧工具名已删除**：`get_project_index`、`get_symbol_definition`、`get_symbol_references`、
`get_call_hierarchy`、`get_dataflow_path`、`get_incremental_status`、`security_scan`、`query_callers`、
`get_code_context`、`check_sanitizer`、`query_middleware_chain`、`trace_taint` 全部**不存在**，
不要调用，也不要照抄旧文档里的调用链。

如果 `mcp__ctxaudit__*` 完全不可用，先检查 MCP server 是否启动：
- 本地 Windows：`CTX_AUDIT_MCP_CMD` 指向 `ctx-audit.exe`
- Linux：`CTX_AUDIT_MCP_CMD=ctx-audit` 或加入 PATH

## 3. 取证优先流程

```
Phase 0 体检（**强制**）：audit_brief（首选）或 coverage_summary + get_project_routes
        读三件事：文件数 / 语言能力（哪些语言只有启发式）/ 是否 index_truncated_at_limit
        **未调用 audit_brief 不得进入 Phase 1** —— 否则你不知道引擎对这个目标是否失明
        （端点轴为 0、语言只有启发式、索引被截断），会把"引擎看不见"误读成"没有问题"
Phase 1 定向取证（主线，不需要先扫描）：
        explain_route(route) 拿单个端点的鉴权推导
        slice_backward(file, line) 拿函数归属 + 窗口 + 逐行标注；窗口外用 read_file 补
        trace_params(function) 拿参数绑定与隐式汇
        get_sanitizer_guards / get_framework_context 拿守卫与中间件生效范围
Phase 2 仅在不知道从哪看起时：scan_code（规则 → 污点 → 深度）→ 按 (vuln_type, file) 分组
Phase 2.5 有候选链时：candidate_chains → chain_dossier → payload_viability 逐跳核实
        每跳只问"流到位吗 / 有净化吗 / 可达吗"
Phase 3 判定：TP 五条件 / FP 六判据
Phase 4 引擎改进：仅通用修复，只降权不丢弃
Phase 5 验证：单测 + before/after 对照，确认不回退
Phase 6 固化：commit + CHANGELOG + 台账 + 报告（0day 才双份）
```

### 3.1 成本纪律（实测数据，必须遵守）

**`slice_backward` 的 `detail` 参数决定成本，默认值不是最优：**

| detail | 保留什么 | 何时用 |
|---|---|---|
| `full`（默认） | 全部：逐行 `provenance`（每行一条）、`reachability`、`dispatch_candidates`、`nearest_declaration` | 需要可达性 / 分派候选 / 最近声明锚点时 |
| `code` | 纯文本窗口 + **`decision_facts`（守卫、容量锚点）**；去掉逐行 provenance 与拓扑附加字段 | **默认应该用这个** |

实测（同一目标、同一 `file:line`）：

| 目标 | `full` | `code` | 倍数 |
|---|---|---|---|
| 真实项目单点 | 21,482 字符 | 4,130 字符 | 5.2× |
| 本仓库大文件 | 202,937 字符 | 63,242 字符 | 3.2× |

**规则**：先 `detail=code` 看代码——它**已经带 `decision_facts`**，判断"有没有守卫 / 容量够不够"够用。
只有当你要 `reachability` / `dispatch_candidates` / `nearest_declaration` 时，才对**那一个**位置补 `detail=full`。

**注意**：`code` 不是"小输出"的保证——窗口本身（`depth` + `forward`）才是主项。窗口大时先收窄
`depth` / `forward`，再考虑换 `detail`。

**超预算时会发生什么**（`CTX_AUDIT_MAX_TOOL_BYTES`，默认 64 KB）：响应会被逐级裁剪，并在
`data` 里如实标注 `truncated_by_budget` / `budget_bytes` / `items_removed`，必要时还有
`provenance_total` / `provenance_kept` / `string_cap_chars`，同时 `uncertainty.reasons` 追加
`truncated_by_payload_budget`。**看到这些字段就说明内容不全**，要么收窄窗口重取，要么换 `detail`。

**同理，`grep` 不是敌人**：找"某个字符串在哪"用 `grep` 比任何 MCP 工具都快。MCP 的价值在**结构化事实**
（守卫判定、可达性、载荷档位），不在"看代码"。真实轮次里 agent 的 MCP 调用只占 4–7%，原因就是
默认 `full` 的输出比裸读贵 5 倍而信息量没多——**用 `detail=code` 才能让证据轴真正被用起来**。

### 3.2 SOP 工具会返回什么（用之前先知道预期）

**`audit_workflow`** —— 五阶段一键 SOP（`coverage → triage → chains → dossier → payload`）：

```json
{
  "schema": "audit-workflow/v1",
  "stages": [{"stage": "coverage", "status": "done", "evidence_ids": ["EV-coverage-1"]}],
  "stopped_after": "payload",
  "evidence": [{"id": "EV-coverage-1", "stage": "coverage", "kind": "...", "summary": "..."}],
  "evidence_counts": {"coverage": 1, "triage": 0, "chains": 0, "dossier": 0, "payload": 0, "total": 1},
  "next_actions": [{"kind": "verify", "evidence_id": "EV-payload-1", "tool": "verify_payload", "hint": "..."}],
  "limits": ["..."],
  "uncertainty": {"level": "medium", "reasons": ["name_level_graph", "heuristic_guards", "static_only"]}
}
```

**用途**：一次调用拿到全链路证据，**证据 id 稳定可引用**。适合"我要快速知道这个项目值不值得深审"。
**不适合**：已经知道要看哪个文件时（直接 `slice_backward` 更快）。
**注意**：`status` 取值是 `done` / `partial`；`limits` 非空说明该阶段被截断或降级，必须读。

**`autopilot`** —— 预算内自主循环：

```json
{
  "schema": "autopilot/v1",
  "verdict": "has_verified_payload|all_candidates_killed|undecided|no_candidate_chains|no_attempt_made",
  "counts": {"candidates": 0, "attempted": 0, "verified": 0, "killed": 0, "undecided": 0, "packaged": 0},
  "findings": [], "packages": [], "undecided": [],
  "workflow_summary": {"stopped_after": "payload", "evidence_counts": {}},
  "trace": [{"step": 1, "action": "workflow", "evidence": 0}]
}
```

**用途**：无人值守跑一轮，`trace` 说明"为什么停在这里"。
**注意**：`verdict` 是**引擎的判定**，不是你的判定 —— 你仍要按 Phase 3 复核。

**`poc_package`** —— 给定 `chain_id`，返回：

```json
{
  "schema": "poc-package/v1",
  "chain": {"chain_id": "...", "entry": {}, "sink": {}, "steps": [], "step_count": 0},
  "verdict": {"payload_tier": "...", "viability": {}, "reachable": {}, "killed_at": null, "taint_lost_at": null, "archetype": "..."},
  "topology": {"format": "mermaid", "diagram": "..."},
  "request": {"method": "...", "route": "...", "params": [], "curl": "...", "test_skeleton": "..."},
  "guard_gap": {"effective": [], "ineffective": [], "unknown": [], "summary": "N effective / N ineffective / N unknown"},
  "remediation": [], "reproduce": []
}
```

**用途**：把一条链变成可交付工件（拓扑 + 请求骨架 + 守卫缺口 + 修复建议）。
**注意**：`request` 为 `null` 表示坐标不全（`incomplete_coordinates`），此时不要编造请求；
`guard_gap.unknown` 非空说明守卫归属未定，**不能当作"无守卫"**。

**判读纪律**：先读 `uncertainty` 与 `scope_anchor` 再信 `data`；`truncated_at_limit` / `total_hits > limit`
不能当"就这些"；切片是**后向前缀**不是数据流；`in_conditional_region` 与 `preprocess_note` 说明条件编译是否
参与编译未知；被降级的候选带 `severity_original` / `severity_downgraded_by`——**不要把"被降级"读成"不存在"**。

## 4. 输出契约（headless 默认）

除非用户明确要求人类可读总结，否则输出严格 JSON：

```json
{
  "round": "<轮号>",
  "target": "<项目>",
  "phase": "triage|deep_review|final",
  "summary": {"tp_candidates": 0, "fp": 0, "hardening": 0},
  "tp_candidates": [
    {
      "title": "...",
      "cwe": "CWE-xxx",
      "chain": ["源 文件:行", "传播 文件:行", "sink 文件:行"],
      "scenario": "攻击者画像+前提+后果",
      "verified": false,
      "verify_plan": "实机验证步骤建议",
      "human_gate": true
    }
  ],
  "fp_families": [{"family": "...", "count": 0, "reason": "...", "examples": ["file:line"]}],
  "hardening": [{"title": "...", "evidence": "file:line"}],
  "deep_review_suggestions": ["..."],
  "human_gate": false
}
```

## 5. 人工闸门（遇到即停）

- 任何 TP_CANDIDATE → `human_gate: true`，不得自行继续。
- 需要联网上报 / git push / 修改引擎源码 → 停。
- 规则 YAML 新增/修改需附回放验证计划。

## 6. 已知 FP 家族（节选）

- React JSX 默认转义 / DOMPurify 白名单 / res.json 非 HTML sink
- DB 自增 ID/UUID/服务端生成路径
- 配置键名映射表常量 / 示例默认凭证 / 测试 fixture
- redirect 固定值或同源相对路径
- Math.random 非安全用途
- vendor/构建产物/自动生成代码
- 模板字面量 `${}` 插值 ≠ 纯字面量
- 定长缓冲区 + `printf` 族格式串：**宽度/整数精度是最小值不是上限**，不能据此断言"输出有界"

## 7. 红线

1. 不降质量标准：宁可诚实 0 TP。
2. 每条结论给证据 `文件:行号 + 代码摘录 ≤5行`，并注明来自哪个工具/哪个 resolver。
3. 未实跑验证的推断标 `"verified": false`。
4. 不修改目标项目文件。
5. 只输出 JSON（除非任务明确要求总结）。
