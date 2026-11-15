> **⚠️ Development status**: This project is in an **experimental R&D stage**. Interfaces and output schemas may change substantially, and releases may not keep pace with the latest changes. Use it **with caution in production**: validate in test or staging first, and pin the version you depend on.

# CTX-Audit

<div align="center">

**Deterministic code-security fact engine · PR drift gate · MCP surface for agents · audit console**

Answers four questions deterministically: **does this PR introduce security drift**, **which endpoints are authenticated**, **is the entry-to-sink path real**, **can a payload survive to the sink**.

It is not a general vulnerability scanner: candidates and facts are for LLM/human judgement; every result carries `provenance` and `uncertainty`.

[![Rust](https://img.shields.io/badge/Rust-2021-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=flat-square&logo=apache)](LICENSE)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-blue?style=flat-square)](.github/workflows/ci.yml)

[中文](README.md)

</div>

---

## Contents

- [What it is](#what-it-is)
- [Capabilities](#capabilities)
- [Quick start](#quick-start)
- [One-command audit workflow](#one-command-audit-workflow)
- [Autopilot (budgeted)](#autopilot-budgeted)
- [PoC packaging](#poc-packaging)
- [PR security drift gate](#pr-security-drift-gate)
- [MCP surface](#mcp-surface)
- [Audit console](#audit-console)
- [Measured results](#measured-results)
- [Boundaries](#boundaries)
- [Architecture](#architecture)
- [Development](#development)
- [License](#license)

---

## What it is

| It does | It does not |
|---|---|
| Enumerate endpoints and auth coverage (declarative + middleware) | Claim "there is a vulnerability here" |
| Diff base/head and emit PR drift verdicts | Full SAST / rule stacks |
| Build entry-to-sink reachability and chain dossiers | Execute target code (dynamic verification is opt-in only) |
| Walk payload state per hop (killed / may_survive / taint_lost) | Full type/alias-aware CPG dataflow |
| Emit reproducible curl/MockMvc skeletons | Auto-generate PoCs or attack targets |
| Chain a whole audit pass into a workflow with evidence ids | Replace human judgement |

**Design goals**: no build step, sub-second where possible, deterministic (identical output for identical input), every fact with provenance and uncertainty.

---

## Capabilities

### PR security drift gate
Detects what this change introduced: `new_unauthenticated_route`, `auth_regression`, `auth_config_regression`, `guard_removed`, `dangerous_sink_added` (block) plus `new_route_covered`, `guard_added`, `new_sink_candidate` (info). Directory or git-ref comparison, exit code 2 on block, waivers (`--allow`), strict sinks, snapshot cache, light mode, GitHub Action with a three-line block summary.

### Endpoint & auth coverage
Declarative: Spring Security, Sa-Token, Shiro, servlet filters, interceptors. Middleware: Express `app.use([prefix,] authMw)`, Flask `before_request`, Next.js `middleware.ts` with `config.matcher`. Labels such as `covered_by_global_config`, `covered_by_middleware`, `no_global_match_found` each point to the rule that produced them.

### Chains, dossiers, falsification
Reverse reachability from sinks to entries, chain dossiers (bounded size) with per-step file/line/symbol/guards/breakpoints, `assert_chain_step` to re-check a step against the source, guard deltas between vulnerable and fixed trees (`chain --compare`), vocabulary learned from fix diffs (`chain --learn`).

Candidates are validated against the same reachability report the probe exposes, so a chain that the probe cannot confirm is never emitted.

### On-demand probes
`can_reach` (name-level bounded BFS) and `slice_between` (code windows along the path) instead of one-shot huge dossiers.

### Intra-procedural mini-SSA
`trace_params`: parameter → local variable → call argument binding, with implicit-sink tagging (reflection, property access, expression, JNDI, deserialization) and taint cut-off on response-body rebinding.

### Payload viability
`payload_viability` walks the reachable path for an archetype (sql / path / jndi / template / deser / command / ssrf / xss / xxe / redirect / header), where guards kill and decode/parse mutate. Tiers: `payload_killed`, `guard_ineffective_token`, `taint_lost`, `payload_may_survive`. The verdict is attached to chain dossiers automatically.

### Verification skeleton and opt-in dynamic verification
`harness_skeleton` builds route/params/guards/curl (`MARKER`) / MockMvc / manual plan. `verify_payload` is **disabled by default** and only runs fixtures inside `CTX_AUDIT_VERIFY_DIR`, returning `payload_verified` / `verified_killed`:

- **Python**: fake DB cursors, requests, open, os.system, jinja2, pickle;
- **Node**: fake `require` (child_process / http / https / fs) and a fake `document`;
- **Java**: dangerous APIs are rewritten to stubs that record their arguments (Statement, Http, Parser, ObjectInputStream, Runtime.exec, JNDI), then `javac` compiles and a generated harness invokes the entry method.

It is not a network/filesystem sandbox and must never point at production code.

### One-command audit workflow
Five fixed stages, each producing evidence with a stable id that an agent can cite, a report can export, and a reviewer can re-check.

### Autopilot (budgeted)
A fixed decision loop inside an explicit budget: workflow → rank → dynamic verification → PoC packaging → conclusion, with every step recorded in a trace.

### Audit console
A workspace-centric web console: overview ledger, audit sessions, coverage and triage, chains, payload tiers, capability actions, drift gate, reports, and an audit assistant.

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
ctx-audit chain ./myproject --id <chain-id>

# On-demand probe
ctx-audit probe reach ./myproject \
  --from-file src/Controller.java --from-line 37 \
  --to-file   src/Service.java    --to-line   243 -o json

# Payload viability (entry -> sink)
ctx-audit payload viability . --entry-file src/App.java --entry-line 12 \
  --sink-file src/App.java --sink-line 30 --archetype command -o json

# One-command audit workflow (five stages + evidence ids)
ctx-audit workflow ./myproject --triage-limit 20 --chain-limit 20 --deep-limit 3 -o json

# Autopilot (budgeted loop)
ctx-audit autopilot ./myproject --budget 3 -o json

# PoC packaging (Mermaid + remediation)
ctx-audit poc ./myproject --chain-id <chain-id> -o md

# MCP server (stdio)
ctx-audit mcp
```

---

## One-command audit workflow

`ctx-audit workflow` chains the individual capabilities into one reproducible, interruptible pipeline with evidence ids.

| Stage | Output | Evidence ids |
|---|---|---|
| `coverage` | endpoint count, uncovered count, confidence, boundaries | `EV-coverage-1` |
| `triage` | risk-ranked review queue (score + signals) | `EV-triage-1..N` |
| `chains` | candidate chains (entry → sink, tier and score) | `EV-chain-1..N` |
| `dossier` | dossiers for the top N chains (steps/guards/breakpoints/falsification) | `EV-dossier-1..N` |
| `payload` | payload viability for the top N chains | `EV-payload-1..N` |

Design constraints:

- **Deterministic**: identical input yields the same stage order, the same evidence ids and the same ranking (timing fields are excluded from the output);
- **Bounded**: every stage has a cap and records what it dropped in `limits`;
- **Interruptible**: `--stop-after` runs only a prefix of the pipeline;
- **Non-judgemental**: it emits evidence and tiers; the conclusion stays with a human or an agent.

```bash
ctx-audit workflow ./myproject --stop-after chains -o json
ctx-audit workflow ./myproject --triage-limit 30 --chain-limit 30 --deep-limit 5 -o json
```

---

## Autopilot (budgeted)

`ctx-audit autopilot` decides the next step itself inside a budget and stops when the budget is spent or nothing is left to do.

The loop is a fixed rule set, not randomness and not an LLM:

1. run one workflow pass;
2. rank the chains that still need a verdict;
3. attempt dynamic verification for as many as the budget allows;
4. package PoC artifacts for the confirmed or surviving chains;
5. conclude (`has_verified_payload` / `all_candidates_killed` / `undecided` / `no_candidate_chains`).

```jsonc
{
  "schema": "autopilot/v1",
  "verdict": "has_verified_payload",
  "counts": { "candidates": 3, "attempted": 3, "verified": 1, "killed": 2, "packaged": 3 },
  "findings": [ /* confirmed chains with verification evidence */ ],
  "packages": [ /* PoC artifact summaries */ ],
  "trace": [ /* per-step decision and timing, so a reviewer sees why it stopped */ ]
}
```

```bash
CTX_AUDIT_VERIFY_DIR=/path/to/fixtures ctx-audit autopilot ./myproject --budget 3 --verify -o json
```

---

## PoC packaging

`ctx-audit poc` turns one chain into a deliverable artifact:

| Part | Content |
|---|---|
| **Mermaid topology** | entry → intermediate steps → sink, with guards attached as annotations |
| **Request skeleton** | method / route / curl / MockMvc when the entry is an HTTP route |
| **Guard gap** | guards split into effective / ineffective / unknown (breakpoints count as unknown, so an unresolved boundary never reads as "no gap") |
| **Remediation** | concrete steps per sink archetype (SQL, command, path, deserialization, JNDI, template, SSRF, XSS, XXE, redirect, header injection) |
| **Reproduction** | the command sequence from static evidence to dynamic verification |

```bash
ctx-audit poc ./myproject --chain-id <chain-id> -o md
```

---

## PR security drift gate

| Verdict | Severity | Meaning |
|---|---|---|
| `new_unauthenticated_route` | block | a new entry has no declarative or middleware auth coverage |
| `auth_regression` | block | a previously protected endpoint lost its auth |
| `auth_config_regression` | block | security configuration became looser |
| `guard_removed` | block | a guard on the endpoint or path was removed |
| `dangerous_sink_added` | block | a new path reaches a dangerous sink (strict mode includes covered endpoints) |
| `new_route_covered` | info | new entry, already covered |
| `guard_added` | info | a guard was added |
| `new_sink_candidate` | info | a new candidate sink (not confirmed exploitable) |

```jsonc
// .ctx-audit/gate-allow.json
{
  "rules": [
    { "kind": "new_unauthenticated_route", "route": "/api/share/**", "reason": "public share endpoint by design" }
  ]
}
```

```bash
ctx-audit gate --base A --head B --allow .ctx-audit/gate-allow.json   # waived, exit code 0
ctx-audit gate --base A --head B --strict-sinks                       # also block dangerous sinks on covered endpoints

# First-time onboarding: draft a waiver file from an observe run
ctx-audit gate --git . --base <base> --head <head> \
  --no-fail-on-block --suggest-waivers .ctx-audit/gate-allow.draft.json

# Aggregate CI artifacts
ctx-audit report --from .ctx-audit/gate-artifacts -o md
```

---

## MCP surface

24 high-level tools + 3 base tools (`read_file`, `list_files`, `finish_analysis`); legacy fine-grained tools are opt-in via `--legacy-tools`. Every response uses the same envelope: `data` + `provenance` + `uncertainty`.

`ctx-audit mcp --read-only` withholds the two write tools (`report_finding`, `finish_analysis`), so an unattended agent can gather evidence but cannot record findings or close an analysis.

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
| `verify_payload` | opt-in dynamic verification (whitelisted fixtures; Python / Node / Java) |
| `audit_brief` | bounded audit brief: triage queue + top chains + payload tiers |
| `trace_vulnerability_chain` | SOP trace: steps + payload tier + SSA + minimal slice + next actions in one call |
| **`audit_workflow`** | **run the five-stage SOP and return evidence with stable ids** |
| **`autopilot`** | **budgeted loop: workflow → rank → verify → PoC → conclusion** |
| **`poc_package`** | **package one chain into a deliverable artifact** |
| `report_finding` | result write-back for agent workflows (not registered in read-only mode) |

Every tool accepts an optional `project_path`, so one session can audit several repositories.

```jsonc
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

---

## Audit console

`console/` is a workspace-centric web console for auditors: one workspace per audited project.

Views: overview (with the audit ledger), audit stream, coverage and triage, chains (with dossier path graphs), payload tiers, capability actions, drift gate, reports, and the audit assistant.

Audit sessions:

- **one-click audit** — pick a budget on the overview page and run the whole SOP, stored as a session;
- **ledger** — session count, evidence count, finding count, done/failed;
- **evidence table** — every entry carries a stable id (`EV-coverage-1`, `EV-payload-1`, …) that an agent can cite;
- **multiple sessions** — a workspace keeps its audit history across restarts.

```bash
cd console && ./scripts/start-console.ps1     # build + typecheck + tests + serve
```

- **14 validated actions**: `audit` / `chains` / `chain-dossier` / `explain-route` / `payload` / `baseline` / `probe-reach` / `probe-slice` / `analyze` / `signal-chain` / `diff-routes` / `gate` / `scan` / `report`; arguments are shape-checked server-side and rejected with 400;
- **agent loop**: the console sends the audit brief to the DSH session bound to the workspace and reads back replies and tool calls;
- **safety**: loopback only, no shell (argv spawn), bounded request body / output / duration, read-only analysis.

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
| Candidate/probe consistency | **128/128 = 100%** (candidates are validated against the probe report, so this is constructive; recall did not drop) |
| Payload viability, fixture corpus (10 chains) | **10/10**, zero false shown |
| Payload viability, real repository chains (10) | **9/10 = 90%**, zero false flows (one 12-hop chain still lost) |
| Dead-chain pruning (8 guarded chains + 5 real chains) | **13/13 = 100%** |
| Determinism | five runs produce identical payload JSON (sha256) |
| Opt-in dynamic verification (Python / Node / Java fixtures) | **12/12 + 5/5 + 11/11** (`payload_verified` / `verified_killed`) |
| Cached probe latency | `can_reach` **15 ms**, `payload_viability` **39 ms** |
| Quick external observation (3 public app repos, 60 PRs + 43 existing PRs) | **0 blocks** on public repos; **4 blocked runs / 14 verdicts** (all explainable/waivable) on existing corpora; 3.9% total block rate; **43–79 ms** per check |
| Five-stage workflow (mid-size repo) | **13.1 s**, 18 evidence entries, every `--stop-after` prefix returns the expected stage count |
| Workflow determinism | two runs hash identically once wall-clock fields are excluded |
| Autopilot (fixtures, budget 3) | `has_verified_payload`: **1 verified / 2 killed / 3 packaged**, same conclusion on a repeat run |
| Console session store | **13/13** unit tests |
| Console browser smoke (headless Chrome over CDP) | **11/11** on both the standalone and the editor-embedded entry points |

---

## Boundaries

1. **Name-level graph**: no type/alias resolution; `reachable=true` means "topologically possible".
2. **Heuristic guards**: guard attribution is function-body/token based; middleware execution order is not modelled.
3. **`taint_lost` is not "not exploitable"**: it only means the entry parameters do not reach the sink.
4. **Payload verdicts are static**: `payload_may_survive` is not "exploitable"; `payload_verified` requires opt-in dynamic verification.
5. **Dynamic verification is not a sandbox**: only injected dependencies are faked; use local fixtures only.
6. **Java dynamic verification only handles self-contained fixtures**: real controllers depend on sibling modules, and without a module-level classpath the verifier reports `compile_failed`.
7. **Candidate chains may include test files**: dangerous calls in test code are recognised as sinks and need filtering by role.
8. **Not a general vulnerability finder**: the fact layer serves LLM and human judgement.
9. **No external CI pilot data yet**: real-repository observations come from internal validation runs; Next.js app-router endpoints are not enumerated yet (one pilot repo showed 0 routes, which must not be read as safe).

---

## Architecture

```
cli/      CLI (ctx-audit): gate / chain / probe / explain-route / workflow / autopilot / poc / mcp ...
core/     base analysis (AST, rules, indexing, diff)
daemon/   resident daemon and incremental cache
tools/    high-level MCP surface
  framework.rs / routes.rs  endpoint enumeration, coverage, middleware modelling
  chain.rs / chain_scan.rs  candidates, dossiers, falsification, fix deltas
  gate.rs                   PR drift verdicts
  ssa.rs                    mini-SSA (trace_params)
  ant.rs                    payload viability (payload_viability)
  verify.rs                 opt-in dynamic verification (verify_payload)
  verify_java.rs            Java dynamic verification (stub injection + javac/java)
  probe.rs                  can_reach / slice_between
  harness.rs                verification skeleton
  workflow.rs               one-command audit workflow (five stages + evidence ids)
  autopilot.rs              budgeted decision loop
  poc.rs                    PoC packaging (Mermaid + remediation)
  file_cache.rs             file/parse table caches
console/  audit console (Vite + React SPA + zero-dependency Node API)
  server/api.mjs            shared API (standalone server and editor plugin)
  server/sessions.mjs       audit session persistence and ledger
  server/actions.mjs        14 validated actions
  scripts/browser-smoke.mjs headless browser smoke (CDP, no dependencies)
```

---

## Development

```bash
cargo build --release
cargo test --workspace
cargo fmt
cargo clippy --workspace -- -D warnings   # advisory, converging

cd console
npm test                        # session store + action validation
node scripts/e2e.mjs            # end-to-end API checks
node scripts/browser-smoke.mjs  # headless browser smoke
```

Unit and integration tests cover the tool surface, auth coverage, middleware modelling, dossiers, the gate, SSA, payload viability, all three dynamic verifiers, the workflow, autopilot, PoC packaging and the session store. Private evaluation sets (not in the repository) hold seeded PR scenarios, real-repository chains, dead-chain labels and dynamic-verification fixtures.

---

## License

Apache-2.0, see [LICENSE](LICENSE).
