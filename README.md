# CTX-Audit

<div align="center">

**确定性代码安全事实引擎 · PR 漂移闸门 · 面向 Agent 的取证工具面（MCP）**

确定性地回答四类问题：**这个 PR 是否引入安全漂移**、**这些端点谁有鉴权**、**入口到汇的路径通不通**、**载荷能否活着到达 sink**。

不追求通用漏洞发现：候选链与事实层交给 LLM/人做最终判定；每个结论都带 `provenance` 与 `uncertainty`，可复核、可证伪。

[![Rust](https://img.shields.io/badge/Rust-2021-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=flat-square)](LICENSE)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-blue?style=flat-square)](.github/workflows/ci.yml)

[English](README_EN.md)

</div>

---

## 目录

- [定位](#定位)
- [核心能力](#核心能力)
- [快速开始](#快速开始)
- [PR 安全漂移闸门](#pr-安全漂移闸门)
- [MCP 工具面](#mcp-工具面)
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

**设计原则**：零构建、亚秒级、确定性（同输入多次运行逐字节一致）、每条事实带出处与不确定性。

---

## 核心能力

### 1. PR 安全漂移闸门

只看"本次改动引入的变化"，回答"是否让原本受保护的路径裸奔"。

- **阻断判决**：`new_unauthenticated_route`、`auth_regression`、`auth_config_regression`、`guard_removed`、`dangerous_sink_added`
- **信息判决**：`new_route_covered`、`guard_added`、`new_sink_candidate`
- 支持目录对比与 git ref 对比（`--git <repo>`，自动导出树）；block 时退出码 2
- 豁免（`--allow` / `<head>/.ctx-audit/gate-allow.json`）、严格模式（`--strict-sinks`）、快照缓存（`--cache-dir`）、轻量模式（`--light`）
- CI 集成：GitHub Action 示例（`.github/workflows/pr-gate.yml`），PR 评论先给"判决/原因/证据"三行，明细表折叠在后

### 2. 端点与鉴权覆盖

- 声明式：Spring Security（`SecurityFilterChain`/`requestMatchers`）、Sa-Token、Shiro、容器 Filter、拦截器
- 中间件：Express `app.use([prefix,] authMw)`、Flask `before_request`、Next.js `middleware.ts` + `config.matcher`
- 覆盖率标签：`covered_by_global_config` / `covered_by_middleware` / `permitted_by_global_config` / `no_global_match_found` / `coverage_unknown` 等，逐个带规则出处

### 3. 候选链 / 链档 / 证伪

- 反向可达（汇→入口）+ 权重（构造/数据流/载荷跳/间接调用）
- 链档（≤12KB）：每步行号、符号、守卫、断点、不确定性、反证命令；并自动附带该链的**载荷判定**（`payload` 字段）
- `assert_chain_step` 逐步骤核对"链条是否仍在源码中"
- `chain --compare` 输出修复前后守卫增量（`new_guards` / `removed_risky` / `added_hardening`）
- `chain --learn` 从修复 diff 派生词汇

### 4. 按需探针

- `can_reach`：两点之间是否存在调用路径（名字级 BFS，≤20 跳，显式 uncertainty）
- `slice_between`：沿路径按需切代码窗口（≤12KB），替代一次性整档

### 5. 函数内 mini-SSA

- `trace_params`：参数 → 局部变量 → 调用实参绑定；标注反射/属性访问/表达式/JNDI/反序列化等隐式汇
- 响应体重绑定（`execute().body()` / `httpResponse` / `requests.get` 等）会切断污点，避免"响应体被当成入口参数"

### 6. 载荷存活判定

- `payload_viability`：沿可达路径逐跳推演指定载荷类型（sql / path / jndi / template / deser / command / ssrf / xss）
- 守卫 = 杀伤（allowlist / sanitize / path_check / ssrf_check / template_escape / 参数化查询 / 输入过滤等），decode/parse = 变异
- 分档：`payload_killed` / `guard_ineffective_token` / `taint_lost` / `payload_may_survive`
- 结果自动附加到链档的 `payload` 字段（无需额外调用）

### 7. 验证骨架与受限动态验证

- `harness_skeleton`：为 handler 生成路由/参数/守卫/curl（`MARKER` 占位）/MockMvc/人工验证计划
- `verify_payload`（**默认关闭，需显式开启**）：仅在 `CTX_AUDIT_VERIFY_DIR` 白名单目录内的 Python fixture 上执行，注入 fake DB cursor / fake requests，返回 `payload_verified` / `verified_killed`；不做网络/文件系统沙箱，仅适用于本地 fixture

---

## 快速开始

### 构建

```bash
git clone https://github.com/BlkSword/CTX-Audit.git
cd CTX-Audit
cargo build --release
# 产物：target/release/ctx-audit、target/release/ctx-audit-daemon
```

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
ctx-audit chain ./myproject --list --id <chain-id>

# 5) 按需探针
ctx-audit probe reach ./myproject \
  --from-file src/Controller.java --from-line 37 \
  --to-file   src/Service.java    --to-line   243 -o json

# 6) MCP server（stdio）
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

---

## MCP 工具面

默认**19 个高阶工具 + 3 个基础工具（read_file / list_files / finish_analysis）**；遗留细粒度工具面需 `--legacy-tools` 或 `CTX_AUDIT_LEGACY_TOOLS=1` 开启。所有响应使用统一 envelope：`data` + `provenance` + `uncertainty`。

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
| `verify_payload` | 受限动态验证（默认关闭，白名单 Python fixture） |
| `report_finding` | 结论回写（供 agent 工作流） |

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

### 事实与载荷判定

| 项目 | 结果 |
|---|---|
| 端点鉴权判定（历史语料） | 398 条记录 **0 假安全** |
| 载荷判定（fixture 语料，10 链） | **10/10**，假 shown 0 |
| 载荷判定（真实仓库链，10 条） | **9/10 = 90%**，假 flow 0（1 例跨 12 跳链仍失配） |
| 死链剪枝（8 守卫链 + 5 真实链） | **13/13 = 100%** |
| 确定性 | 同输入 5 次运行载荷 JSON sha256 一致 |
| 动态验证（Python fixture） | **4/4** 闭环（payload_verified / verified_killed） |
| 探针缓存后延迟 | `can_reach` **15ms**、`payload_viability` **39ms**（复调） |

---

## 能力边界

1. **名字级图**：不做类型/别名解析；`reachable=true` 只表示"拓扑可能"。
2. **守卫为启发式**：守卫归属按函数体与 token 匹配；中间件执行顺序未建模。
3. **`taint_lost` ≠ 不可利用**：仅表示入口参数到不了 sink，可能仍有其他入口。
4. **载荷判定是静态推演**：`payload_may_survive` 不等于可利用；`payload_verified` 需动态验证且仅限白名单 fixture。
5. **动态验证不做沙箱**：只保证注入依赖不产生真实外部调用；不要指向生产代码。
6. **不宣称通用漏洞发现**：候选链/事实层供 LLM 与人工判定；通用注入发现能力有限，已明确降级为证据层。
7. **尚无外部团队 CI 试点数据**：真实仓库观察来自内部测试机。

---

## 架构

```
cli/      命令行（ctx-audit）：gate / chain / probe / explain-route / diff-routes / mcp ...
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
  probe.rs                can_reach / slice_between
  harness.rs              验证骨架
  file_cache.rs           文件表/解析表缓存
```

---

## 开发与测试

```bash
cargo build --release
cargo test --workspace
cargo fmt
cargo clippy --workspace -- -D warnings   # 咨询性质，逐步收敛
```

单元/集成测试覆盖工具面、鉴权覆盖、中间件建模、链档、闸门、SSA、载荷判定、验证器；私有评测集（不随仓库公开）包含种子 PR、真实仓库链、死链标注与动态验证 fixture。

---

## 许可证

Apache-2.0，见 [LICENSE](LICENSE)。
