> **⚠️ 版本状态：`0.x`（初始研发线）**
>
> 本项目的公开 API **未稳定**：CLI 命令、MCP 工具面、输出 schema 均可能在小版本内变动。
> 破坏性变更只涨 `0.MINOR`，修复只涨 `0.MINOR.PATCH`，详见 [VERSIONING.md](VERSIONING.md)。
> 请锁定版本使用，并预期 minor 升级需要适配；生产环境建议先在测试/预发验证。

# CTX-Audit

<div align="center">

**确定性代码安全事实引擎 · PR 漂移闸门 · 面向 Agent 的取证工具面（MCP）· 审计控制台**

确定性地回答四类问题：**这个 PR 是否引入安全漂移**、**这些端点谁有鉴权**、**入口到汇的路径通不通**、**载荷能否活着到达 sink**。

不追求通用漏洞发现：候选链与事实层交给 LLM/人做最终判定；每个结论都带 `provenance` 与 `uncertainty`，可复核、可证伪。

[![Rust](https://img.shields.io/badge/Rust-2021-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=flat-square&logo=apache)](LICENSE)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-blue?style=flat-square)](.github/workflows/ci.yml)

[English](README_EN.md)

</div>

---

## 目录

- [定位](#定位)
- [核心能力](#核心能力)
- [快速开始](#快速开始)
- [一键审计工作流](#一键审计工作流)
- [自动驾驶（带预算）](#自动驾驶带预算)
- [PoC 工件打包](#poc-工件打包)
- [PR 安全漂移闸门](#pr-安全漂移闸门)
- [MCP 工具面](#mcp-工具面)
- [审计控制台](#审计控制台)
- [实测数据与验证方法](#实测数据与验证方法)
- [能力边界](#能力边界)
- [架构](#架构)
- [开发与测试](#开发与测试)
- [许可证](#许可证)

---

## 定位

CTX-Audit 是**事实引擎**，不是漏洞扫描器：

| 它做 | 它不做 |
|---|---|
| 枚举端点与鉴权覆盖（声明式 + 中间件） | 宣称"这里一定有漏洞" |
| 对比 base/head，输出 PR 漂移判决 | 全量 SAST / 规则堆砌 |
| 给出入口→汇的可达路径与链档 | 执行目标代码（动态验证需显式开启） |
| 逐跳推演载荷状态（killed / may_survive / taint_lost） | 类型/别名完整的 CPG 数据流 |
| 输出可复现的 curl/MockMvc 验证骨架 | 自动生成 PoC 并攻击目标 |
| 把整轮审计串成带证据 ID 的工作流 | 替代人工判定 |

**设计原则**：零构建、亚秒级、确定性（同输入多次运行逐字节一致）、每条事实带出处与不确定性。

---

## 核心能力

### 1. PR 安全漂移闸门

只看"本次改动引入的变化"，回答"是否让原本受保护的路径裸奔"。

- **阻断判决**：`new_unauthenticated_route`、`auth_regression`、`auth_config_regression`、`guard_removed`、`dangerous_sink_added`
- **信息判决**：`new_route_covered`、`guard_added`、`new_sink_candidate`
- 支持目录对比与 git ref 对比（`--git <repo>`，自动导出树）；block 时退出码 2
- 豁免（`--allow` / `<head>/.ctx-audit/gate-allow.json`）、严格模式（`--strict-sinks`）、快照缓存（`--cache-dir`）、轻量模式（`--light`）
- CI 集成：workflow 示例 + **composite 一键 Action**（下载 release 二进制、PR 评论、artifact、required check）；PR 评论先给"判决/原因/证据"三行，明细表折叠在后

### 2. 端点与鉴权覆盖

- 声明式：Spring Security（`SecurityFilterChain`/`requestMatchers`）、Sa-Token、Shiro、容器 Filter、拦截器
- 中间件：Express `app.use([prefix,] authMw)`、Flask `before_request`、Next.js `middleware.ts` + `config.matcher`
- 覆盖率标签：`covered_by_global_config` / `covered_by_middleware` / `permitted_by_global_config` / `no_global_match_found` / `coverage_unknown` 等，逐个带规则出处

### 3. 候选链 / 链档 / 证伪

- 反向可达（汇→入口）+ 权重（构造/数据流/载荷跳/间接调用）
- **候选与探针同口径**：每条候选在输出前跑一次可达性校验，不可达的不输出（不再给出探针无法复核的链）
- 链档（≤12KB）：每步行号、符号、守卫、断点、不确定性、反证命令；并自动附带该链的**载荷判定**
- `assert_chain_step` 逐步骤核对"链条是否仍在源码中"
- `chain --compare` 输出修复前后守卫增量；`chain --learn` 从修复 diff 派生词汇

### 4. 按需探针

- `can_reach`：两点之间是否存在调用路径（名字级 BFS，≤20 跳，显式 uncertainty）
- `slice_between`：沿路径按需切代码窗口（≤12KB），替代一次性整档

### 5. 函数内 mini-SSA

- `trace_params`：参数 → 局部变量 → 调用实参绑定；标注反射/属性访问/表达式/JNDI/反序列化等隐式汇
- 响应体重绑定（`execute().body()` / `httpResponse` / `requests.get` 等）会切断污点

### 6. 载荷存活判定

- `payload_viability`：沿可达路径逐跳推演指定载荷类型（sql / path / jndi / template / deser / command / ssrf / xss）
- 守卫 = 杀伤（allowlist / sanitize / path_check / ssrf_check / template_escape / 参数化查询 / 输入过滤等），decode/parse = 变异
- 分档：`payload_killed` / `guard_ineffective_token` / `taint_lost` / `payload_may_survive`
- 结果自动附加到链档的 `payload` 字段（无需额外调用）

### 7. 验证骨架与受限动态验证

- `harness_skeleton`：为 handler 生成路由/参数/守卫/curl（`MARKER` 占位）/MockMvc/人工验证计划
- `verify_payload`（**默认关闭，需显式开启**）：仅在 `CTX_AUDIT_VERIFY_DIR` 白名单目录内执行，返回 `payload_verified` / `verified_killed`
  - **Python**：注入 fake DB cursor / requests / open / os.system / jinja2 / pickle
  - **Node**：注入 fake `require`（child_process / http / https / fs）+ fake `document`
  - **Java**：把危险 API 改写为记录参数的桩（Statement / Http / Parser / ObjectInputStream / Runtime.exec / JNDI），`javac` 编译后反射调用入口
  - 不做网络/文件系统沙箱，仅适用于本地 fixture

### 8. 一键审计工作流

五阶段固定 SOP，每步产出**稳定证据 ID**，可被 Agent 引用、被报告导出、被人工复核。

### 9. 自动驾驶（带预算）

在预算内自主循环：工作流 → 排序 → 动态验证 → PoC 打包 → 结论，每步写入决策轨迹。

### 10. 审计控制台

工作区中心化的 Web 控制台：总览台账、审计会话、覆盖待审、候选链、载荷档位、能力动作、漂移闸门、报告、审计助手。

---

## 快速开始

### 构建

```bash
git clone https://github.com/BlkSword/CTX-Audit.git
cd CTX-Audit
cargo build --release
# 产物：target/release/ctx-audit、target/release/ctx-audit-daemon
```

### 只跑引擎（CI / 脚本）

上面的二进制就是完整的确定性分析能力，不依赖任何 agent 环境。

### 跑审计 agent（`ctxh`）

需要一个会读证据、做判定的 LLM agent 时，装最小运行时：

```bash
./harness/bin/ctxh-install.sh        # Node >= 24.9；装到 ~/.ctxh，约 254 MB
export COMMANDCODE_API_KEY=...
cd /path/to/target
/path/to/CTX-Audit/harness/bin/ctxh "完整审计这个项目，按 ctx-audit-auditor skill 输出 JSON"
```

它装的是 **base + headless 两个 DSH bundle + 本仓库的 preset / MCP 行 / skill**，
不含 Web 控制台、Office 渲染、语音等审计用不到的部分。对比 `npm i -g @deepseek-ai/dsh`
的 1,165 MB，实测 **254 MB**，且宿主不需要装全局 DSH（启动器用 profile 内的瘦 CLI）。

需要 Web 控制台时用 `ctxa`（完整运行时，见 `harness/README.md`）。

### 常用命令

```bash
# 1) PR 漂移闸门：两个目录
ctx-audit gate --base ./old-tree --head ./new-tree -o md

# 2) PR 漂移闸门：git ref（CI 推荐，配合缓存）
ctx-audit gate --git . --base <base-sha> --head <head-sha> \
  --cache-dir .ctx-audit/gate-cache -o md

# 3) 单条端点判定（可机械证伪）
ctx-audit explain-route ./myproject /admin/users --assert uncovered

# 4) 候选链 / 链档
ctx-audit chain ./myproject --list
ctx-audit chain ./myproject --id <chain-id>

# 5) 按需探针
ctx-audit probe reach ./myproject \
  --from-file src/Controller.java --from-line 37 \
  --to-file   src/Service.java    --to-line   243 -o json

# 6) 载荷存活判定（入口 → 汇）
ctx-audit payload viability . --entry-file src/App.java --entry-line 12 \
  --sink-file src/App.java --sink-line 30 --archetype command -o json

# 7) 一键审计工作流（五阶段 + 证据 ID）
ctx-audit workflow ./myproject --triage-limit 20 --chain-limit 20 --deep-limit 3 -o json

# 8) 自动驾驶（预算内自主循环）
ctx-audit autopilot ./myproject --budget 3 -o json

# 9) PoC 工件打包（Mermaid + 修复建议）
ctx-audit poc ./myproject --chain-id <chain-id> -o md

# 10) MCP server（stdio）
ctx-audit mcp
```

### GitHub Actions（示例）

```yaml
name: security-drift-gate
on: [pull_request]
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: actions/cache@v4
        with:
          path: .ctx-audit/gate-cache
          key: gate-${{ github.event.pull_request.base.sha }}
      - run: cargo build --release
      - run: ./target/release/ctx-audit gate --git . \
          --base ${{ github.event.pull_request.base.sha }} \
          --head ${{ github.event.pull_request.head.sha }} \
          --cache-dir .ctx-audit/gate-cache -o md
```

### 一键 Action（composite）

```yaml
- uses: BlkSword/CTX-Audit/.github/actions/pr-gate@v1
  with:
    base: ${{ github.event.pull_request.base.sha }}
    head: ${{ github.event.pull_request.head.sha }}
    strict: "false"          # true = 受保护接口新增危险汇也阻断
    comment: "true"          # PR 三行证据评论
    fail-on-block: "true"    # block 时 required check 失败
```

---

## 一键审计工作流

`ctx-audit workflow` 把分散的能力串成一条可复现、可中断、带证据 ID 的流水线。

### 五个阶段

| 阶段 | 产出 | 证据 ID |
|---|---|---|
| `coverage` | 端点总数、未覆盖数、置信度、边界（动态注册/未建模路由/索引截断） | `EV-coverage-1` |
| `triage` | 按风险排序的待审清单（分数 + 信号） | `EV-triage-1..N` |
| `chains` | 候选链（入口→危险汇，含档位与分数） | `EV-chain-1..N` |
| `dossier` | 前 N 条链的链档（步骤/守卫/断点/证伪命令） | `EV-dossier-1..N` |
| `payload` | 前 N 条链的载荷存活判定（档位 + 证据） | `EV-payload-1..N` |

### 设计约束

- **确定性**：同输入产出同样的阶段顺序、同样的证据 ID、同样的排序（耗时字段不进入输出）
- **有界**：每阶段都有条数上限，超限显式记录在 `limits`
- **可中断**：`--stop-after` 只跑到某阶段，便于分步复核
- **不判定**：只给证据与档位，最终结论仍由人或 Agent 给出

```bash
# 只跑到候选链阶段
ctx-audit workflow ./myproject --stop-after chains -o json

# 完整五阶段
ctx-audit workflow ./myproject --triage-limit 30 --chain-limit 30 --deep-limit 5 -o json
```

---

## 自动驾驶（带预算）

`ctx-audit autopilot` 在预算内自主决定下一步并执行，直到预算耗尽或无事可做。

### 循环体（固定决策规则，非随机、非 LLM）

1. 跑一轮工作流；
2. 从载荷证据里挑出"仍需判定"的链，按优先级排序；
3. 在预算内逐条尝试动态验证；
4. 为已确认/可能存活的链打包 PoC；
5. 汇总结论（`has_verified_payload` / `all_candidates_killed` / `undecided` / `no_candidate_chains`）。

### 输出

```jsonc
{
  "schema": "autopilot/v1",
  "verdict": "has_verified_payload",
  "counts": { "candidates": 3, "attempted": 3, "verified": 1, "killed": 2, "packaged": 3 },
  "findings": [ /* 已确认的链 + 验证证据 */ ],
  "packages": [ /* PoC 工件摘要 */ ],
  "trace": [ /* 每步决策与耗时，可复核"为什么停在这里" */ ]
}
```

```bash
# 预算 3 条链，开启动态验证
CTX_AUDIT_VERIFY_DIR=/path/to/fixtures ctx-audit autopilot ./myproject --budget 3 --verify -o json
```

---

## PoC 工件打包

`ctx-audit poc` 把一条链整理成可直接交付的工件：

| 部分 | 内容 |
|---|---|
| **Mermaid 拓扑** | 入口 → 中间步骤 → 汇，守卫以虚线旁注 |
| **请求骨架** | 入口是 HTTP 路由时给出 method / route / curl / MockMvc |
| **Guard Gap** | 守卫按 有效 / 无效 / 未知 三分类（断点计入未知，避免"0 缺口"假象） |
| **修复建议** | 按 sink archetype 给具体改法（12 类：SQL / 命令 / 路径 / 反序列化 / JNDI / 模板 / SSRF / XSS / XXE / 重定向 / 头注入等） |
| **复现步骤** | 从静态证据到动态验证的完整命令序列 |

```bash
ctx-audit poc ./myproject --chain-id <chain-id> -o md
```

---

## PR 安全漂移闸门

### 判决语义

| 判决 | 严重度 | 含义 |
|---|---|---|
| `new_unauthenticated_route` | block | 新增入口没有任何声明式/中间件鉴权覆盖 |
| `auth_regression` | block | 原本受保护的端点失去鉴权 |
| `auth_config_regression` | block | 安全配置收紧变宽松（如规则删除/改为 permitAll） |
| `guard_removed` | block | 端点/调用路径上的守卫被删除 |
| `dangerous_sink_added` | block | 新增直达危险汇的链路（严格模式下含已覆盖接口） |
| `new_route_covered` | info | 新增入口但已有覆盖 |
| `guard_added` | info | 新增守卫（正向变化） |
| `new_sink_candidate` | info | 新增候选汇（未确认可利用） |

### 豁免与严格模式

```jsonc
// .ctx-audit/gate-allow.json
{
  "rules": [
    { "kind": "new_unauthenticated_route", "route": "/api/share/**", "reason": "公开分享接口（设计如此）" }
  ]
}
```

```bash
ctx-audit gate --base A --head B --allow .ctx-audit/gate-allow.json   # 豁免 → waived，退出码 0
ctx-audit gate --base A --head B --strict-sinks                       # 受保护接口新增危险汇也阻断
```

### 豁免生成器（首次接入）

```bash
# observe 结果 → gate-allow.json 草稿（只生成路由级候选，危险类只统计不自动豁免）
ctx-audit gate --git . --base <base> --head <head> \
  --no-fail-on-block --suggest-waivers .ctx-audit/gate-allow.draft.json
```

### 汇总报告（CI artifact）

```bash
ctx-audit report --from .ctx-audit/gate-artifacts -o md    # 运行数/block 率/类型分布/Top 路由/耗时
ctx-audit report --from .ctx-audit/gate-artifacts -o json  # 机器可读 gate-report/v1
```

---

## MCP 工具面

默认 **25 个高阶工具 + 3 个基础工具（read_file / list_files / finish_analysis，共 28 个）**；遗留细粒度工具面需 `--legacy-tools` 或 `CTX_AUDIT_LEGACY_TOOLS=1` 开启。所有响应使用统一 envelope：`data` + `provenance` + `uncertainty`。

### 只读模式

`ctx-audit mcp --read-only` 不注册两个写操作工具（`report_finding` / `finish_analysis`），
适合无人值守的 Agent 会话：Agent 可以取证，但不能写结论或关闭分析。

### 工具清单

| 工具 | 用途 |
|---|---|
| `get_project_routes` | 项目端点表（含覆盖标签与出处） |
| `coverage_summary` | 鉴权覆盖汇总（比例、未覆盖列表、caveat） |
| `coverage_triage` | 待审队列（按风险排序） |
| `explain_route` | 单条端点判定 + `--assert` 可证伪 |
| `slice_backward` | 反向切片 |
| `get_sanitizer_guards` | 守卫识别 |
| `get_framework_context` | 框架/中间件上下文 |
| `assert_verdict` | 覆盖结论断言（CI/脚本化复核） |
| `candidate_chains` | 候选链列表 |
| `chain_dossier` | 单链链档（含 `payload` 判定） |
| `assert_chain_step` | 链步骤证伪 |
| `pr_drift_gate` | PR 漂移判决（base/head/strict/light） |
| `can_reach` | 两点可达性（路径 + 不确定性） |
| `slice_between` | 沿路径按需切片 |
| `harness_skeleton` | 路由/参数/守卫/curl/MockMvc 骨架 |
| `trace_params` | 函数内 mini-SSA（实参绑定 + 隐式汇） |
| `payload_viability` | 载荷存活推演（四档证据分级） |
| `verify_payload` | 受限动态验证（默认关闭，白名单 fixture） |
| `audit_brief` | 一次性审计简报：待审队列 + 头部链档 + 载荷档位（有界） |
| `trace_vulnerability_chain` | SOP 级链路追踪：链档 + 载荷档位 + SSA + 最小切片 + 下一步动作 |
| **`audit_workflow`** | **一键跑五阶段 SOP，返回带稳定 ID 的证据** |
| **`autopilot`** | **按预算自主循环（工作流→排序→动态验证→PoC→结论）** |
| **`poc_package`** | **单条链打包为可交付工件（Mermaid + 修复建议）** |
| `report_finding` | 结论回写（供 agent 工作流；只读模式不注册） |

### 接入示例

```jsonc
// DSH / Claude Code 等 MCP 客户端
{
  "mcpServers": {
    "ctx-audit": {
      "command": "/path/to/ctx-audit",
      "args": ["mcp", "--read-only"],
      "cwd": "/path/to/project"
    }
  }
}
```

工具支持 `project_path` 参数覆盖索引根目录，因此一个会话可以审计多个仓库。

---

## 审计控制台

`console/` 是面向审计员的 Web 控制台：每个审计项目 = 一个 workspace。

### 视图

总览（含审计台账）、审计流、覆盖与待审、候选链（含链档路径图）、载荷档位、能力动作、漂移闸门、报告、审计助手。

### 审计会话

- **一键审计**：在总览页选预算后点一下，跑完整 SOP 并把结果落为会话；
- **台账**：会话数 / 证据数 / 发现数 / 完成失败统计；
- **证据表**：每条证据带稳定 ID（`EV-coverage-1`、`EV-payload-1`…），可被 Agent 按 ID 引用；
- **多会话**：一个工作区可保留多次审计记录，跨重启持久化。

### 两种运行方式

```bash
# 独立运行
cd console && ./scripts/start-console.ps1     # 构建 + 类型检查 + 测试 + 启动

# 或由 DSH 插件挂到 Web 面的 /console
```

- **14 个受校验动作**：`audit` / `chains` / `chain-dossier` / `explain-route` / `payload` / `baseline` / `probe-reach` / `probe-slice` / `analyze` / `signal-chain` / `diff-routes` / `gate` / `scan` / `report`；参数在服务端按形状校验，异常值直接 400；
- **工作区 Agent 闭环**：控制台把审计简报发给绑定该工作区的 DSH 会话，并回读 Agent 回复与工具调用轨迹；
- 安全边界：仅回环监听、无 shell（argv spawn）、请求体/输出/耗时都有上限、只读分析。

---

## 实测数据与验证方法

> 全部数字来自可复现 bench；评测脚本与语料在私有评测集中维护，下表为公开口径。

### 闸门

| 项目 | 结果 |
|---|---|
| 种子 PR（拦截/放行/严格/豁免共 14 场景） | **7/7 拦截、0/7 误报** |
| 真实 CVE 修复 PR 回放（5 个） | **0/5 误报** |
| 真实仓库历史 PR（68 次运行） | 6 次拦截（8.8%），全部可解释/可豁免 |
| 耗时 | 590 文件仓库 **772ms**；3357 文件仓库 light 稳态 **2.82s wall**（base 缓存命中），热启动 4ms |
| 轻/重模式判决 | 一致 |
| 快速外部观察（3 个公开应用仓库 60 个 PR + 既有语料 43 个 PR） | 公开仓库 **0 拦截**；既有语料 **4 次拦截 / 14 verdicts（全部可解释、可豁免）**；总 block 率 3.9%；单次 **43–79ms** |

### 事实与载荷判定

| 项目 | 结果 |
|---|---|
| 端点鉴权判定（历史语料） | 398 条记录 **0 假安全** |
| 候选链与探针一致性 | **128/128 = 100%**（候选生成即用探针同口径校验，属构造性结果；召回未下降） |
| 载荷判定（fixture 语料，10 链） | **10/10**，假 shown 0 |
| 载荷判定（真实仓库链，10 条） | **9/10 = 90%**，假 flow 0（1 例跨 12 跳链仍失配） |
| 死链剪枝（8 守卫链 + 5 真实链） | **13/13 = 100%** |
| 确定性 | 同输入 5 次运行载荷 JSON sha256 一致 |
| 动态验证（Python / Node / Java fixture） | **12/12 + 5/5 + 11/11** 闭环（payload_verified / verified_killed） |
| 探针缓存后延迟 | `can_reach` **15ms**、`payload_viability` **39ms**（复调） |

### 工作流与自动驾驶

| 项目 | 结果 |
|---|---|
| 五阶段工作流（中型仓库） | **13.1s**，18 条证据，`--stop-after` 各前缀返回预期阶段数 |
| 工作流确定性 | 同输入两次运行 sha256 一致（剔除 wall-clock 字段） |
| 自动驾驶（fixture，预算 3） | `has_verified_payload`：**1 verified / 2 killed / 3 packaged** |
| 自动驾驶确定性 | 同输入两次运行结论一致 |

### 控制台

| 项目 | 结果 |
|---|---|
| 会话存储单测 | **13/13** |
| 浏览器冒烟（无头 Chrome，CDP 驱动） | **11/11**（独立与编辑器内嵌两个入口各一次） |
| 覆盖断言 | 页面加载、总览指标、KPI 条、状态栏、会话面板、一键审计端到端、链视图、动作目录、动作执行、助手页、无未捕获错误 |

---

## 能力边界

1. **名字级图**：不做类型/别名解析；`reachable=true` 只表示"拓扑可能"。
2. **守卫为启发式**：守卫归属按函数体与 token 匹配；中间件执行顺序未建模。
3. **`taint_lost` ≠ 不可利用**：仅表示入口参数到不了 sink，可能仍有其他入口。
4. **载荷判定是静态推演**：`payload_may_survive` 不等于可利用；`payload_verified` 需动态验证且仅限白名单 fixture。
5. **动态验证不做沙箱**：只保证注入依赖不产生真实外部调用；不要指向生产代码。
6. **Java 动态验证仅支持自包含 fixture**：真实项目 controller 依赖同项目其他模块，当前缺模块级 classpath，会返回 `compile_failed`。
7. **候选链可能包含测试文件**：测试代码里的危险调用会被识别为汇，需人工按 `min_role` 过滤。
8. **不宣称通用漏洞发现**：候选链/事实层供 LLM 与人工判定；通用注入发现能力有限，已明确降级为证据层。
9. **尚无外部团队 CI 试点数据**：真实仓库观察来自内部验证环境；Next.js app-router 的路由枚举尚未覆盖（试点中该类仓库出现 0 路由，不能据此判安全）。

---

## 架构

```
cli/      命令行（ctx-audit）：gate / chain / probe / explain-route / workflow / autopilot / poc / mcp ...
core/     基础分析引擎（AST/规则/索引/差异）
daemon/   常驻进程与增量缓存
tools/    高阶代码智能工具面（MCP）
  code_intel_tools.rs     工具面与 envelope
  framework.rs/routes.rs  端点枚举、鉴权覆盖、中间件建模
  chain.rs/chain_scan.rs  候选链、链档、证伪、修复差分
  gate.rs                 PR 漂移判决
  ssa.rs                  mini-SSA（trace_params）
  ant.rs                  载荷存活推演（payload_viability）
  verify.rs               受限动态验证（verify_payload）
  verify_java.rs          Java 动态验证（桩注入 + javac/java）
  probe.rs                can_reach / slice_between
  harness.rs              验证骨架
  workflow.rs             一键审计工作流（五阶段 + 证据 ID）
  autopilot.rs            自动驾驶（预算内自主循环）
  poc.rs                  PoC 工件打包（Mermaid + 修复建议）
  file_cache.rs           文件表/解析表缓存
console/  审计控制台（Vite + React SPA + 零依赖 Node API）
  server/api.mjs          共享 API（独立服务与 DSH 插件共用）
  server/sessions.mjs     审计会话持久化与台账
  server/actions.mjs      14 个受校验动作
  scripts/browser-smoke.mjs  无头浏览器冒烟（CDP，零依赖）
```

---

## 开发与测试

```bash
cargo build --release
cargo test --workspace
cargo fmt
cargo clippy --workspace -- -D warnings   # 咨询性质，逐步收敛

# 控制台
cd console
npm test              # 会话存储 + 动作校验单测
node scripts/e2e.mjs  # 端到端 API 检查
node scripts/browser-smoke.mjs  # 无头浏览器冒烟
```

单元/集成测试覆盖工具面、鉴权覆盖、中间件建模、链档、闸门、SSA、载荷判定、三类动态验证器、工作流、自动驾驶、PoC 打包、会话存储；私有评测集（不随仓库公开）包含种子 PR、真实仓库链、死链标注与动态验证 fixture。

---

## 许可证

Apache-2.0，见 [LICENSE](LICENSE)。
