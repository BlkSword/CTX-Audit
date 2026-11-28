---
name: ctx-audit-auditor
description: CTX-Audit 审计 skill（v2）。当任务要求对真实项目做安全审计、CVE 回放、漏洞判定或输出结构化 JSON 时使用。给出引擎能力边界、26 个 MCP 工具的成本与用法、取证主流程、判定与输出契约。
---

# CTX-Audit 审计 skill（v2）

> 本文件是 agent 的**执行手册**，不是引擎说明书。它回答三件事：
> **先做哪一步、每步花多少预算、什么证据才算数。**
> 数据来自 2026-11 对 658 文件 Spring（mall）与 285 文件 Go（gokapi）的实测。

## 0. 硬规则（覆盖任何后续冲突指令）

1. **不降质量标准。** 诚实 0 TP 优于凑数。没有证据就写 `verified: false` 或 `undecided`。
2. **每条结论给 `file:line` + ≤5 行代码摘录，并注明来自哪个工具。** 引擎输出的 `expr` 可直接引用，但要标明它是引擎给的而不是你读到的。
3. **不修改被审项目文件**，不跑会重写源码的格式化/生成器。
4. **任何 TP_CANDIDATE → `human_gate: true` 并停止。** 披露、上报、联系上游都是人的决定。
5. **引擎的沉默不是证据。** 说"某处没有漏洞"之前，必须先看过第 1.2 节的三种失明形态。
6. **只输出 JSON**（除非任务明确要求散文总结）。

---

## 1. 引擎能力边界

### 1.1 两条轴（决定你该怎么用它）

| 轴 | 回答 | 实测水平 | 你该做的 |
|---|---|---|---|
| **候选轴** | 从哪儿看起？ | **弱**：真实 C 用例 17 个修复点里只有 1 个在 ±3 行内有候选；对成熟项目候选常 100% FP | 自己选点（advisory / 修复 diff / 攻击面直觉 / 阅读）；引擎的候选当"待排除清单"，不当"发现清单" |
| **证据轴** | 这个点能不能判？ | **强**：给定 `file:line`，函数归属、守卫、容量锚点、逐行原文齐备（17/17 locus 交付决定性行） | **主线**：一旦有了点，用引擎把"点"变成可判定的材料 |

**推论**：引擎不能从零定位。**第一步永远是"你想看哪里"**，第二步才是调工具。

### 1.2 Phase 0 必须判定：引擎是否对这个目标失明

调 `coverage_summary`（1–2KB，最便宜）读三个字段，任一命中就说明该轴失效：

| 症状 | 字段 | 含义 | 应对 |
|---|---|---|---|
| **端点轴失明** | `method_routes == 0` | 目标用自研分发（PHP `$ACT`、Go `mux.HandleFunc` 包装、动态 `*Server`），或框架未被建模。`unmodelled_route_stacks` 非空说明引擎猜到了某个框架（**可能猜错**，实测把 DokuWiki 猜成 Laravel） | 放弃端点/鉴权驱动，转人工读码 + `scan_code` |
| **鉴权链失明** | `chain_count == 0` 且 `reasons` 含 `no_security_chain_found` | 没有 Spring Security / Shiro / Sa-Token / Express-Flask-Next 中间件 | 鉴权结论只能靠读代码；`explain_route` 的 verdict 不可信 |
| **索引残缺** | `index_truncated_at_limit == true` | 文件数触顶（默认 2000） | **一切"没找到"都不能当"不存在"**，必须在报告里声明 |

补充：`confidence` 是**鉴权建模**的置信度，不是整体回答的可信度。`confidence: high` + `method_routes: 0` 是自相矛盾的组合，**以 method_routes 为准**。

### 1.3 语言能力分档（决定投入产出比）

| 档 | 语言 | 能做什么 |
|---|---|---|
| T1 | Java/Spring、JS/TS/Next(.js) | 端点枚举 + 鉴权覆盖 + 候选链 + 载荷档位全套 |
| T2 | Python（FastAPI/Flask/Django） | 端点与守卫可用；候选链较弱 |
| T3 | Go / PHP / .NET / Laravel | **只枚举端点与汇**，包装器/中间件常解析不了；候选基本不可用 |
| — | C/C++/Rust | 只有规则与局部证据，无端点轴 |
| **盲区** | `.tmpl` / `.html` / `.vue` / `.jsx` 模板文件 | **完全不解析**。模板里的泄露/注入必须人工读 |

---

## 2. 工具面：26 个只读工具

`ctx-audit mcp --read-only` 注册 26 个工具（完整 28 个里剔除 `report_finding` / `finish_analysis`）。
**表外的工具名不存在**，不要照抄旧文档。

### 2.1 成本表（实测，单次响应字符数）

三列分别是：20 文件 Java（hard2 夹具）、285 文件 Go（gokapi）、658 文件 Spring（mall）。
"—" 表示未在该类目上测。

| 工具 | 小(20) | 中(285 Go) | 大(658 Spring) | 可调项 |
|---|---|---|---|---|
| `get_sanitizer_guards` | 407 | — | — | 无 |
| `assert_chain_step` | 499 | — | — | 无 |
| `pr_drift_gate light` | — | — | 872 | `light` |
| `coverage_summary` | 1,005 | 1,057 | 1,821 | **无——最便宜，Phase 0 首选** |
| `coverage_triage` | 1,008 | 3,345 | 6,303 | `limit` |
| `trace_params` | 1,183 | — | — | `depth` |
| `can_reach` | 1,199 | — | — | 无 |
| `harness_skeleton` | 1,389 | — | — | 无 |
| `slice_between` | 1,492 | — | — | `radius` |
| `payload_viability` | 1,496 | — | — | 无 |
| `get_framework_context` | 1,648 | — | — | 无 |
| `assert_verdict` | — | — | 1,895 | 无 |
| `get_project_routes brief` | 2,015 | 10,127 | **45,519 ⚠截断** | `route_pattern` `only_uncovered` `limit` |
| `chain_dossier` | 2,276 | — | — | 无 |
| `explain_route` | — | 572 | 2,526 | 无 |
| `autopilot` | 3,339 | 3,349 | — | `budget` |
| `slice_backward code` | 3,163 | — | — | `depth` `forward` |
| `poc_package` | 3,722 | — | — | 无 |
| `trace_vulnerability_chain` | 5,602 | — | — | 无 |
| `audit_brief limit=5` | 5,946 | 7,858 | 12,954 | `limit` |
| `audit_brief` 默认 10 | 6,753 | 10,000 | **19,233** | 同上 |
| `scan_code rules high limit=20` | 917–3,033 | 8,976 | 11,012 | `mode` `limit` `min_severity` |
| `slice_backward full` | 10,301 | — | — | **改用 `detail=code`** |
| `audit_workflow` | 10,390 | 17,819 | — | `*_limit` `stop_after` |
| `candidate_chains limit=5` | 10,719 | 10,390 | 10,911 | `limit`（约 **1.5–2KB/链**，与项目规模无关） |
| `get_project_routes full` | — | 26,372 | 36,000（截断） | 只在需要拦截器/链证据时 |

**从表里能读出的四条规则**：

1. **`coverage_summary` 永远是第一步**——最贵也就 1.8KB，却直接决定后面怎么走。
2. **`get_project_routes` 的成本随项目规模爆炸**（2KB → 45KB），因为响应里带
   `uncovered_endpoints` + `needs_triage.samples` + `dynamic_registration_samples` 的完整数组。
   **大项目必须带 `route_pattern`、`only_uncovered` 或小的 `limit`。**
3. **`candidate_chains` 的成本只跟 `limit` 有关**（≈1.5–2KB/链），跟项目大小无关。
   所以"先拿 5 条看看"在任何项目上都只要 ~10KB。
4. **`detail=full` 是 `detail=code` 的 3–5 倍**（10KB vs 3KB），而 `code` 已经带
   `decision_facts`。没有可达性/分派需求就别用 `full`。

**预算红线**：单次工具响应默认上限 **64KB**（`CTX_AUDIT_MAX_TOOL_BYTES`）。
超限时响应会被裁剪并标注 `truncated_by_budget` / `budget_bytes` / `items_removed`，
必要时还有 `provenance_total` / `provenance_kept` / `string_cap_chars`，
同时 `uncertainty.reasons` 追加 `truncated_by_payload_budget`。
**看到任何一个这些字段 ⇒ 内容不全**，要么收窄参数重取，要么换工具。

### 2.2 分组速查

**A. 开局与覆盖**
| 工具 | 关键参数 | 用途 |
|---|---|---|
| `coverage_summary` | — | **Phase 0 首选**：覆盖率 + 三种失明判据 |
| `coverage_triage` | `limit`(20) | 排序待审清单（不含证据正文） |
| `audit_brief` | `limit`(10, ≤20) | 画像 + 待审 + 头部链；**chains ≤ min(limit,8)** |
| `get_project_routes` | `detail`(brief) `route_pattern` `only_uncovered` `min_role` `limit` `offset` | 端点表；**大项目必须带 `route_pattern` 或 `only_uncovered`** |
| `explain_route` | `route` 或 `file`+`handler` | 单端点鉴权推导链（含 `coverage_caveat`、`sensitive_return`） |
| `assert_verdict` | `route` `expect`(covered/uncovered/permitted/any) | 把判断固化成 pass/fail |

**B. 定位与切片**
| 工具 | 关键参数 | 用途 |
|---|---|---|
| `slice_backward` | `file` `line` `detail`(code) `depth`(40) `forward`(8) | **主力**：函数归属 + 窗口 + `decision_facts`（守卫/容量锚点） |
| `trace_params` | `file` `line` | 函数内 mini-SSA：参数→局部→实参绑定，标隐式汇 |
| `get_sanitizer_guards` | `file` `line` | 变量路径上的条件分支 |
| `get_framework_context` | `file` `handler` | 中间件/拦截器/注解生效范围 |
| `read_file` `list_files` | — | 窗口外补行、列目录 |

**C. 链与可达**
| 工具 | 关键参数 | 用途 |
|---|---|---|
| `candidate_chains` | `limit`(20) `sink` | 入口→汇候选链（**候选，不是结论**） |
| `chain_dossier` | `chain_id` | 单链链档：每步 file:line / 守卫 / 断点 / 反证命令 |
| `trace_vulnerability_chain` | `chain_id` 或 `entry_*`+`sink_*` | **链档+载荷+SSA+最小切片一次给全**（性价比最高） |
| `assert_chain_step` | `chain_id` `step` `expect`(line_present/line_absent) | 逐步证伪 |
| `can_reach` | `from_file/line` `to_file/line` `graph`(scoped/name) | 拓扑可达 |
| `slice_between` | `from_*` `to_*` `radius`(20) | 沿路径按需切片（替代一次性链档） |

**D. 载荷与验证**
| 工具 | 关键参数 | 用途 |
|---|---|---|
| `payload_viability` | `entry_*` `sink_*` `archetype` | 逐跳推演载荷存活 |
| `verify_payload` | `file` `function` `payload` `archetype` | 受限动态验证（Python/Node/Java；需 `CTX_AUDIT_VERIFY_DIR`） |
| `harness_skeleton` | `file` `line` | 生成 curl/MockMvc 骨架（静态，不执行） |

**E. SOP 与产出**
| 工具 | 关键参数 | 用途 |
|---|---|---|
| `audit_workflow` | `triage_limit` `chain_limit` `deep_limit` `stop_after` | 五阶段一次跑完，证据 ID 稳定可引用 |
| `autopilot` | `budget`(1–20) `verify` `poc` | 预算内自主循环，带决策 trace |
| `poc_package` | `chain_id` 或 `entry_*`+`sink_*` | Mermaid 拓扑 + 请求骨架 + Guard Gap + 修复建议 |
| `pr_drift_gate` | `base` `head` `light` `strict_sinks` | PR 漂移判决（block 时 exit_code=2） |

**F. 候选源**
| 工具 | 关键参数 | 用途 |
|---|---|---|
| `scan_code` | `mode`(rules/taint/deep) `min_severity` `limit`(50, 0=200, 上限 500) | 传统 SAST 候选集 |

### 2.3 参数与成本须知

1. **`get_project_routes` 不带过滤 = 贵。** 658 文件 Spring 上 `detail=brief` 是 45KB（已触顶截断）。**永远先给 `route_pattern` 或 `only_uncovered: true`**，或者用 `coverage_triage` 拿排序清单。
2. **`candidate_chains` 每条约 1.5–2KB。** `limit=5` 约 10KB，`limit=20` 约 27KB。先估再调。
3. **`audit_brief` 要显式传 `limit`。** 默认 10 在 658 文件项目上是 19KB。
4. **`verify_payload` 的 `archetype` 参数说明只写了 sql/ssrf，但底层接受 sql/ssrf/path/command/template/deserialize/xss/jndi，并按扩展名分派 Python/Node/Java。** 别被参数描述限制住。
5. **`scan_code` 的 `by_severity` 是全量统计，`findings` 是截断后的。** 实测 658 文件项目报 `critical: 388, high: 293`，但只返回 20 条——**不要以为一共 20 条**。

**`slice_backward` 两种定位都可用了**：给 `line` 直接定位；只给 `symbol` 时引擎会先把它解析成本文件里的定义行（`target_line_source: "symbol"`），函数归属取该符号自身。两者都对不上时才是 `file_end`——那时要自己给 `line`。

---

## 3. 主流程：选档，不要一条路走到黑

### 档 A — 排面（目标 ≤5 分钟，任何项目都先做这个）

```
coverage_summary                       # 1–2KB，判断三种失明
  ├─ 有端点轴 → coverage_triage limit=5~10   # 3–6KB，拿排序清单
  └─ 端点轴失明 → 直接转档 B（人工选点）+ scan_code 兜底
```

产出：一句话结论 + 失明声明 + 3–5 个待看点。**没有待看点就停，不要硬凑。**

### 档 B0 — 没有点时，点从哪来

引擎的候选轴弱，所以"第一个点"通常要靠这五条路（按性价比排序）：

| 来源 | 怎么拿 | 适用 |
|---|---|---|
| **鉴权面** | `get_project_routes(only_uncovered: true)` 找 `no_global_*`；或找 `permitted_by_global_config`（**显式放行，最高价值**） | 有端点轴的项目 |
| **修复 diff** | `git log --since=6.months -- '*.java'`，读 security 相关提交；或项目 advisory | 任何项目，命中率最高 |
| **危险面清单** | 人工列：上传/解析、导出/下载、URL 抓取、命令执行、模板渲染、反序列化入口 | 无端点轴的项目（Go/PHP/自研分发） |
| **`scan_code` 分组** | `scan_code(mode: rules, min_severity: high, limit: 50)` → 按 `(vuln_type, file)` 分组，每组抽 1–2 个代表 | 不知道从哪看起时 |
| **候选链按汇过滤** | `candidate_chains(sink: 'deserialize')` 等，按汇类型集中看 | 已建模的项目 |

**不要**把 `scan_code` 的 findings 当发现清单——成熟项目实测近 100% FP，它的价值是"指出该读哪个文件/函数"。

### 档 B — 定向取证（主线，占 80% 的工作量）

前提：**你已经有一个点**（`file:line`、一个路由、或一条候选链）。

```
1. slice_backward(file, line, detail=code)     # ~3KB：函数归属 + decision_facts
2. get_sanitizer_guards(file, line)            # 守卫是否存在（含 total_hits/truncated）
3. trace_params(file, line)                    # 参数绑定：外部输入能不能走到 sink
4. get_framework_context(file, handler)        # 中间件/拦截器是否真的生效
5. explain_route(route) / assert_verdict       # 只有端点轴可用时才做
```

**每步只回答一个问题**，四个问题都答完就是一个完整判定：

| 问 | 工具 | 答不了怎么办 |
|---|---|---|
| 数据流到得了吗？ | `trace_params` / `can_reach` | 手工往前追调用者；名级图不代表真实调用 |
| 有净化吗？ | `get_sanitizer_guards` / `slice_backward` 的 `decision_facts.guards` | 读代码；`no_check_found` 只表示**没检出标记**，不表示没有 |
| 外部可控吗？ | `trace_params` 的 `tainted_args` + 读调用方 | 这是引擎最弱的一环，**必须人工确认** |
| 端点需要鉴权吗？ | `explain_route` / `get_framework_context` | 端点轴失明时只能读 SecurityConfig/中间件 |

### 档 C — 全链深审（已有一条可疑链）

```
trace_vulnerability_chain(chain_id)     # 5.6KB：链档 + 载荷 + SSA + 最小切片一次拿全
  → payload_viability(entry, sink, archetype)   # 载荷在哪一跳被杀/丢失
  → assert_chain_step(chain_id, N)              # 逐步证伪
  → poc_package(chain_id)                       # 变成可交付工件
```

**优先级**：`trace_vulnerability_chain` > `chain_dossier` + `payload_viability` 分开调（前者一次拿全，更省）。

### 档 D — 一键 SOP（判断"值不值得深审"）

```
audit_workflow(triage_limit=10, chain_limit=10, deep_limit=3)   # 10–18KB
autopilot(budget=3)                                             # 3.3KB
```

**用途**：快速知道这个项目值不值得投入，或作为无人值守的初筛。
**注意**：
- `audit_workflow` 的 `limits` 数组非空 = 某阶段被降级，**必须读**。
- `autopilot` 的 `verdict` 是**引擎判定**，不是你的判定；`trace` 说明它为什么停在那里。
- 两者的 `evidence` 里带 `EV-*` 稳定 ID，引用时直接写 ID。

---

## 4. 判读纪律

### 4.1 envelope 三件套

每个响应都是 `{data, provenance, uncertainty}`：

1. **先读 `uncertainty`，再信 `data`。** `level` + `reasons` 是引擎自述"哪些没解析出来"。
2. **`provenance[].resolver` 说明这一行怎么来的**（`slice+line-window`、`symbol-index`、`file-heuristic`…）。一条结论混着不同 resolver 时，按**最弱**的理解。
3. **`provenance` 是逐行记账，不是证据正文。** 它会让响应变大（可占 70%），判断时只看 `data`。

**看到这些就停手重取**：`truncated_at_limit`、`truncated_by_budget`、`total_hits > limit`、`provenance_kept < provenance_total`、`string_cap_chars` 存在。

### 4.2 路由判定词表（`explain_route` / `get_project_routes` 的 `global_coverage`）

| 值 | 归类 | 含义 |
|---|---|---|
| `covered_by_global_config` | 已覆盖 | 命中声明式安全链（Spring/Sa-Token/Shiro/Filter/Interceptor） |
| `covered_by_middleware` | 已覆盖 | Express/Flask/Next 中间件覆盖 |
| `covered_by_annotation` | 已覆盖 | 方法/类注解（`@PreAuthorize` 等）且有消费者 |
| `covered_by_internal_auth` | 已覆盖 | 路由内 helper 做了鉴权（≤3 跳） |
| `permitted_by_global_config` | **放行** | 明确 `permitAll` / 白名单——**这是高危信号，不是"已保护"** |
| `no_global_config_found` | 未覆盖 | 项目里没有任何安全链 |
| `no_global_match_found` | 未覆盖 | 有安全链但这条路由没被匹配 |
| `excluded_from_interceptor` | 未覆盖 | 被拦截器的 exclude 排除 |
| `unknown` / `coverage_unknown` | **待判** | 建模不足——**不能当已覆盖** |
| `ambiguous_across_chains` | **待判** | 多条链给出不同结论，引擎不挑乐观的那条 |
| `not_an_endpoint` | 非端点 | Spring Bean 但无路由映射 |
| `framework_not_modeled` | **待判** | 框架未建模 |

**`permitted_by_global_config` 是审计中最常见的高价值入口**：它意味着"这条路由被显式放行了"，只需再确认 handler 里没有自建鉴权。

### 4.3 `coverage_caveat`（非空即不得把判定当定论）

`dynamic_matcher_unresolved` / `route_excluded_from_interceptor` / `declaring_class_not_a_bean` / `unmodeled_protection_signal` / `index_truncated_at_limit`

### 4.4 载荷 / 守卫 / 汇 词表

**载荷档位 `tier`**（从"死"到"活"）：

`unreachable` < `taint_lost` < `payload_killed` < `guard_ineffective_token` < `payload_may_survive` < `payload_verified`

- `payload_killed`：守卫真的把载荷杀了（**这是排除依据**）
- `guard_ineffective_token`：有守卫但只挡了部分 token（**值得深挖**）
- `taint_lost`：参数名在途中不匹配（**可能是假阴性，要人工确认**）
- `payload_may_survive`：静态推演活到了 sink（**仍不等于可利用**）
- `payload_verified`：动态验证真的跑到了（最强的证据）

**守卫类型 `guard.kind`**：`allowlist` `sanitize` `signature` `bounds` `path_check` `ssrf_check` `template_escape` `auth`
→ `guard.verdict` 为 `partial` 时要读 `evidence` 那一行原文，判断它到底挡了什么。

**汇类型 `sink.kind`**：`exec` `eval` `sql` `template` `deserialize` `jndi` `ssrf` `file_write` `module_access` `reflect` `xml_parse` `redirect` `header_injection`

**载荷原型 `archetype`**：`sql` `path` `jndi` `template` `deser` `command` `ssrf` `xss` `xxe` `redirect` `header`

### 4.5 三个最容易读错的字段

| 字段 | 错误读法 | 正确读法 |
|---|---|---|
| `no_check_found: true` | "没有守卫" | "作用域内没检出检查标记"——守卫可能以别的形态存在（自定义函数、AOP、框架默认） |
| `controllability: unknown` | "不可控" | "引擎不知道"——必须人工从调用方确认 |
| `taint_lost` | "不可利用" | "参数名在传递中丢了"——很可能是 name-level 分析的假阴性 |

---

### 4.6 上下文预算纪律

一次审计的上下文是有限的，实测最容易烧穿的三处：

| 烧穿点 | 单次 | 应对 |
|---|---|---|
| `audit_brief` 不传 `limit` | ~19KB | 显式 `limit: 5` |
| `get_project_routes` 不带过滤 | ~45KB | 加 `route_pattern` / `only_uncovered` |
| `slice_backward detail=full` | 10–200KB | 用 `detail=code` |

**推荐的单次审计预算分配**（以一次中等规模审计为例）：

- Phase 0：**≤3%**（coverage_summary + triage）
- 每个候选点：**≤8%**（slice + guards + trace_params + 一次读代码）
- 深审链：**≤15%**（trace_vulnerability_chain + payload_viability）
- 留 **≥40%** 给"读代码"——引擎给的是材料，判断要看原文

**超了怎么办**：不要硬扛。把已得结论写成 JSON 落盘（`write`），再开新一轮。这正是 `engine_blindness` 和 `fp_families` 要写进契约的原因——它是给下一轮复用的。

---

## 5. 判定标准

**TP 需同时满足**：
1. 可达：source→sink 路径存在
2. **攻击者可控**（引擎最弱，必须人工确认）
3. 无有效净化/屏障
4. 生产代码（`file_role: production`，不是 test/build/vendor）
5. 有可复现的验证思路（或已 `payload_verified`）

置信度标注：`0.95+`（多证据交叉）/ `0.7–0.95`（一维未验证）/ `<0.7`（标 `needs_review`）

**FP 满足其一即可**：不可达 / 有效净化 / 有效屏障 / 非生产代码 / 参数不可控（常量、数值、服务端生成）/ 设计内功能 / 漏洞类型与上下文不匹配

**攻击链写法**（TP 必填）：`外部输入点 → 中间传播(file:line) → sink(file:line)`，每环标注角色：入口 | 传播 | gadget | sink

---

## 6. 输出契约

```json
{
  "round": "<轮号>",
  "target": "<项目>",
  "phase": "triage|deep_review|final",
  "engine_blindness": ["endpoint_axis", "auth_chain", "index_truncated"],
  "summary": {"tp_candidates": 0, "fp": 0, "hardening": 0},
  "tp_candidates": [{
    "title": "...",
    "cwe": "CWE-xxx",
    "chain": ["源 file:line", "传播 file:line", "sink file:line"],
    "scenario": "攻击者画像 + 前提 + 后果",
    "evidence_refs": ["file:line + ≤5 行摘录（注明工具）"],
    "verified": false,
    "verify_plan": "...",
    "human_gate": true
  }],
  "fp_families": [{"family": "...", "count": 0, "reason": "...", "examples": ["file:line"]}],
  "hardening": [{"title": "...", "evidence": "file:line"}],
  "deep_review_suggestions": ["..."],
  "human_gate": false
}
```

`engine_blindness` 非空时，报告正文必须有一句"引擎对这个目标的 X 轴失明，以下结论不含 X 轴判断"。

---

## 7. 人工闸门（遇到即停）

- 任何 TP_CANDIDATE → `human_gate: true`，不再继续。
- 需要联网上报 / git push / 修改引擎源码 → 停。
- 规则 YAML 新增或修改 → 需附回放验证计划。

---

## 8. 已知 FP 家族（先查这个再下判断）

- React JSX 默认转义 / DOMPurify 白名单 / `res.json` 非 HTML sink
- DB 自增 ID / UUID / 服务端生成路径（不是用户可控）
- 配置键名常量 / 示例默认凭证 / 测试 fixture
- redirect 固定值或同源相对路径
- `Math.random` 非安全用途
- vendor / 构建产物 / min 化 bundle / 自动生成代码
- 第三方前端 JS（swagger-ui / chosen / asciinema player）
- Go 字符串常量被当成端点（`"/error"` 是健康检查常量）
- Go 路由包装器（`mux.HandleFunc(w, requireLogin(h))`）被当成未鉴权
- 模板字面量 `${}` 插值 ≠ 纯字面量
- 定长缓冲区 + `printf` 族：**宽度/整数精度是最小值不是上限**，不能据此断言输出有界
- CWE-1333（正则回溯）要先验证量词是否被字面量分隔符钉死——钉死的是线性，实测 3/4 是 FP

---

## 9. 反模式（这些做法实测有害）

| 反模式 | 为什么错 | 正确做法 |
|---|---|---|
| 一上来 `scan_code(deep)` 全量 | 成熟项目 100% FP，且返回 20 条却报 681 条 | Phase 0 用 `coverage_summary`，扫描只在"不知道从哪看起"时用 |
| 把 `candidate_chains` 的 100 条逐条核实 | 单链核实成本 > 直接读代码 | 先按 `payload.tier` + `score` 排序，只深挖 `guard_ineffective_token` / `payload_may_survive` |
| 相信 `confidence: high` | 它只描述鉴权建模，不描述整体可信度 | 以 `method_routes` / `index_truncated_at_limit` / `uncertainty.reasons` 为准 |
| 用 `symbol` 代替 `line` 调 `slice_backward` | 函数归属会指错 | 先 `grep` 拿行号 |
| 引擎没报就当没有 | 端点轴/模板/Go 包装器都是盲区 | 先判 1.2 节的失明形态，再决定"没报"能不能当证据 |
| 为了产出而凑 finding | 降标准比 0 TP 伤害更大 | 诚实 0 TP + `hardening` 列表 |

---

## 10. 环境

| 项 | 值 |
|---|---|
| 启动 | `ctx-audit mcp [--read-only]`（stdio JSON-RPC） |
| 项目根 | **MCP 进程的启动目录**；所有工具有 `project_path` 可覆盖 |
| 必须先扫描吗 | **不需要**。首次调用按需建索引（`index.hit_source=miss` + `build_ms`） |
| 索引缓存 | TTL 内复用；改代码后传 `refresh: true` |
| 动态验证 | 需 `CTX_AUDIT_VERIFY_DIR` 指向白名单 fixture 目录；Java 额外可给 `CTX_AUDIT_VERIFY_CLASSPATH` |
| 载荷预算 | `CTX_AUDIT_MAX_TOOL_BYTES`（默认 64KB） |
| 索引上限 | `CTX_AUDIT_INDEX_MAX_FILES`（默认 2000） |

---

## 11. 引擎缺口（判定时要主动规避）

这些是**已知**的，不是你判断失误：

1. **`.tmpl` / `.html` / `.vue` 模板文件不解析** —— 模板里的泄露/注入必须人工读。
2. **Go 路由包装器不建模** —— `mux.HandleFunc` + 中间件链解析不了，鉴权结论不可信。
3. **"路径/参数是否用户可控"判断弱** —— `controllability` 常为 `unknown`。
4. **名级图无类型解析** —— `can_reach` 的 `reachable: true` 只代表拓扑可能。
5. **候选轴对成熟项目近 100% FP** —— 候选当"排除清单"用。
6. **第三方静态资产不过滤** —— min 化 JS 会进候选。

遇到这些，**如实写进报告**，不要替引擎圆场，也不要因此否定整个结论。
