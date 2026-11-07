# CTX-Audit

<div align="center">

**Deterministic code-security fact engine · PR drift gate · MCP surface for agents**

Answers four questions deterministically: **does this PR introduce security drift**, **which endpoints are authenticated**, **is the entry-to-sink path real**, **can a payload survive to the sink**.

It is not a general vulnerability scanner: candidates and facts are for LLM/human judgement; every result carries `provenance` and `uncertainty`.

[![Rust](https://img.shields.io/badge/Rust-2021-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=flat-square)](LICENSE)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-blue?style=flat-square)](.github/workflows/ci.yml)

[中文](README.md)

</div>

---

## What it is

| It does | It does not |
|---|---|
| Enumerate endpoints and auth coverage (declarative + middleware) | Claim "there is a vulnerability here" |
| Diff base/head and emit PR drift verdicts | Full SAST / rule stacks |
| Build entry-to-sink reachability and chain dossiers | Execute target code (dynamic verification is opt-in only) |
| Walk payload state per hop (killed / may_survive / taint_lost) | Full type/alias-aware CPG dataflow |
| Emit reproducible curl/MockMvc skeletons | Auto-generate PoCs or attack targets |

**Design goals**: no build step, sub-second where possible, deterministic (identical output for identical input), every fact with provenance and uncertainty.

---

## Capabilities

### PR security drift gate
Detects what this change introduced: `new_unauthenticated_route`, `auth_regression`, `auth_config_regression`, `guard_removed`, `dangerous_sink_added` (block) plus `new_route_covered`, `guard_added`, `new_sink_candidate` (info). Directory or git-ref comparison, exit code 2 on block, waivers (`--allow`), strict sinks, snapshot cache, light mode, GitHub Action with a three-line block summary.

### Endpoint & auth coverage
Declarative: Spring Security, Sa-Token, Shiro, servlet filters, interceptors. Middleware: Express `app.use([prefix,] authMw)`, Flask `before_request`, Next.js `middleware.ts` with `config.matcher`. Labels such as `covered_by_global_config`, `covered_by_middleware`, `no_global_match_found` each point to the rule that produced them.

### Chains, dossiers, falsification
Reverse reachability from sinks to entries, chain dossiers (bounded size) with per-step file/line/symbol/guards/breakpoints, `assert_chain_step` to re-check a step against the source, guard deltas between vulnerable and fixed trees (`chain --compare`), vocabulary learned from fix diffs (`chain --learn`).

### On-demand probes
`can_reach` (name-level bounded BFS) and `slice_between` (code windows along the path) instead of one-shot huge dossiers.

### Intra-procedural mini-SSA
`trace_params`: parameter → local variable → call argument binding, with implicit-sink tagging (reflection, property access, expression, JNDI, deserialization) and taint cut-off on response-body rebinding.

### Payload viability
`payload_viability` walks the reachable path for an archetype (sql / path / jndi / template / deser / command / ssrf / xss), where guards kill and decode/parse mutate. Tiers: `payload_killed`, `guard_ineffective_token`, `taint_lost`, `payload_may_survive`. The verdict is attached to chain dossiers automatically.

### Verification skeleton and opt-in dynamic verification
`harness_skeleton` builds route/params/guards/curl (`MARKER`) / MockMvc / manual plan. `verify_payload` is **disabled by default** and only runs Python fixtures inside `CTX_AUDIT_VERIFY_DIR`, injecting fake DB cursors and fake requests, returning `payload_verified` / `verified_killed`; it is not a network/filesystem sandbox and must never point at production code.

---

## Quick start

```bash
cargo build --release

# PR drift gate: directories
ctx-audit gate --base ./old-tree --head ./new-tree -o md

# PR drift gate: git refs with cache
ctx-audit gate --git . --base <base-sha> --head <head-sha> \
  --cache-dir .ctx-audit/gate-cache -o md

# Single route verdict (falsifiable)
ctx-audit explain-route ./myproject /admin/users --assert uncovered

# Chains and dossiers
ctx-audit chain ./myproject --list
ctx-audit chain ./myproject --list --id <chain-id>

# On-demand probe
ctx-audit probe reach ./myproject \
  --from-file src/Controller.java --from-line 37 \
  --to-file   src/Service.java    --to-line   243 -o json

# MCP server (stdio)
ctx-audit mcp
```

---

## MCP surface

19 high-level tools + 3 base tools (`read_file`, `list_files`, `finish_analysis`); legacy fine-grained tools are opt-in via `--legacy-tools`. Every response uses the same envelope: `data` + `provenance` + `uncertainty`.

| Tool | Purpose |
|---|---|
| `get_project_routes` | endpoint table with coverage labels |
| `coverage_summary` / `coverage_triage` | coverage overview / review queue |
| `explain_route` / `assert_verdict` | single-route verdict and assertion |
| `slice_backward` / `get_sanitizer_guards` / `get_framework_context` | backward slice, guard facts, framework context |
| `candidate_chains` / `chain_dossier` / `assert_chain_step` | chain candidates, dossier (with payload verdict), step falsification |
| `pr_drift_gate` | PR drift decision |
| `can_reach` / `slice_between` | reachability and on-demand slices |
| `harness_skeleton` | verification skeleton |
| `trace_params` | intra-procedural mini-SSA |
| `payload_viability` | payload survival walk (evidence tiers) |
| `verify_payload` | opt-in dynamic verification (whitelisted Python fixtures) |
| `report_finding` | result write-back for agent workflows |

---

## Measured results

All numbers come from reproducible benchmarks; scripts live in a private evaluation set.

| Item | Result |
|---|---|
| Seeded PR scenarios (block/pass/strict/waiver, 14) | **7/7 blocks, 0/7 false positives** |
| Real CVE fix PR replay (5) | **0/5 false positives** |
| Real repository history (68 runs) | 6 blocks (8.8%), all explainable/waivable |
| Latency | 590-file repo **772 ms**; 3357-file repo light steady state **2.82 s wall** (base cache), warm 4 ms |
| Auth coverage corpus | 398 records, **0 false-safe** |
| Payload viability, fixture corpus (10 chains) | **10/10**, zero false shown |
| Payload viability, real repository chains (10) | **9/10 = 90%**, zero false flows (one 12-hop chain still lost) |
| Dead-chain pruning (8 guarded chains + 5 real chains) | **13/13 = 100%** |
| Determinism | five runs produce identical payload JSON (sha256) |
| Opt-in dynamic verification (Python fixtures) | **4/4** (`payload_verified` / `verified_killed`) |
| Cached probe latency | `can_reach` **15 ms**, `payload_viability` **39 ms** |

---

## Boundaries

1. **Name-level graph**: no type/alias resolution; `reachable=true` means "topologically possible".
2. **Heuristic guards**: guard attribution is function-body/token based; middleware execution order is not modelled.
3. **`taint_lost` is not "not exploitable"**: it only means the entry parameters do not reach the sink.
4. **Payload verdicts are static**: `payload_may_survive` is not "exploitable"; `payload_verified` requires opt-in dynamic verification.
5. **Dynamic verification is not a sandbox**: only injected dependencies are faked; use local fixtures only.
6. **Not a general vulnerability finder**: the fact layer serves LLM and human judgement.
7. **No external CI pilot data yet**: real-repository observations come from internal runs.

---

## Architecture

```
cli/      CLI (ctx-audit): gate / chain / probe / explain-route / diff-routes / mcp ...
core/     base analysis (AST, rules, indexing, diff)
daemon/   resident daemon and incremental cache
tools/    high-level MCP surface
  framework.rs / routes.rs  endpoint enumeration, coverage, middleware modelling
  chain.rs / chain_scan.rs  candidates, dossiers, falsification, fix deltas
  gate.rs                   PR drift verdicts
  ssa.rs                    mini-SSA (trace_params)
  ant.rs                    payload viability (payload_viability)
  verify.rs                 opt-in dynamic verification (verify_payload)
  probe.rs                  can_reach / slice_between
  harness.rs                verification skeleton
  file_cache.rs             file/parse table caches
```

---

## Development

```bash
cargo build --release
cargo test --workspace
cargo fmt
cargo clippy --workspace -- -D warnings   # advisory, converging
```

Private evaluation sets (not in the repository): seeded PR scenarios, real-repository chains, dead-chain labels, dynamic-verification fixtures.

---

## License

Apache-2.0, see [LICENSE](LICENSE).
