# CTX-Audit LLM Collaboration Skill

You are a security auditor. CTX-Audit is the **evidence supplier** in this workflow: it emits
deterministic code topology and local source context, and it states its own uncertainty instead of
guessing. **The verdict is yours.** This file is the English edition; the Chinese edition is
[SKILL-CN.md](SKILL-CN.md).

---

## 0. Read this first: what this engine is good at, and what it is not

Work on this engine is organised around **two independent axes**. Mixing them produces wrong
conclusions, so keep them separate when you use or evaluate it.

| Axis | Question it answers | Metric | What the engine does today |
|---|---|---|---|
| **Candidate axis** | *Where should I look?* Cheaply propose suspicious locations (precision may be low) | Does a candidate cover the true location? Is anything dropped silently? Cost per candidate | **Weak.** Across 8 real C cases, only 1 of 17 fix loci had a candidate within ±3 lines. It is honest though: limits, truncation, empty results and severity downgrades are all reported |
| **Evidence axis** | *Can this location be judged?* Given a location, deliver the decisive source lines | Are the decisive lines delivered, and are the boundaries stated? | **Strong.** 17 of 17 loci delivered their decisive lines (16/17 if you only count lines inside the window and not attached declaration lines), and 3 of 3 blind derivations reached a verdict |

Two consequences you must internalise:

1. **The engine cannot locate a C vulnerability from zero.** It converts *a point* into *decidable
   material*. Choosing the first point is done by the candidate axis, by an external tool, or by you.
2. **Its detector role is a fuzz-like auxiliary candidate source** for batch screening. Its acceptance
   criteria on that axis are recall, cost, and *never dropping a candidate silently* — not accuracy.
   Judgement and convergence happen on top of the evidence.

The full chain is: **locate → gather evidence → judge**. The engine owns the middle step, contributes
weakly to the first, and does not own the last.

---

## 1. Startup facts

| Item | Fact |
|---|---|
| Start | `ctx-audit mcp` (stdio JSON-RPC, one request per line) |
| **Project root** | **The working directory the process was started in.** There is no `--project` flag; every `file` argument is relative to it |
| Must I scan first? | **No.** Evidence tools build the index on demand: the first call returns `index.hit_source=miss` plus `build_ms` and `files_indexed`; the index is persisted and reused. Pass `refresh: true` after editing code |
| Default tool surface | **13 tools** = 9 high-level capabilities + `read_file` / `list_files` / `report_finding` / `finish_analysis`. The legacy fine-grained surface needs `--legacy-tools` |
| Who judges | You. Findings are candidates; every conclusion must trace back to tool output |

---

## 2. The flow: locate → evidence → judge

### 2.1 Locate (get a first point)

| Path | How | Reality check |
|---|---|---|
| Rule / taint scan | `ctx-audit scan <PATH> --deep --min-severity low -o json` | Low recall on C: a scan hit is a bonus, not an expectation |
| From the attack surface | `get_framework_context(file)` for routes, then `get_call_hierarchy(f, direction: "callees")` | Mostly applies to framework languages, rarely to C |
| From a sink upward | `get_symbol_references("<dangerous API>")` then `get_call_hierarchy(f, direction: "callers")` | Works, but noisy in large C code bases |
| From data flow / dispatch | `get_dataflow_path(source, sink)`; `dispatch_candidates` (see §3) for unresolved indirect calls | The dispatch candidate set is the engine's only mechanical help for indirect calls |
| Outside the engine | Your own hypothesis, a fuzzer, an advisory or a fix diff | Today this is the most productive path — say so in your report instead of pretending the engine found it |

### 2.2 Evidence (turn the point into decidable material)

```text
slice_backward         {file, line, depth: 40}   → owning function, window, per-line markers
get_sanitizer_guards   {file, line}              → checks/branches on the path
get_call_hierarchy     {function, direction}     → callers/callees, unresolved_edges, candidates
get_symbol_definition  {symbol} / get_symbol_references {symbol}   → where it lives / who uses it
get_dataflow_path      {source, sink}            → source→sink path (needs a rule-backed label)
get_framework_context  {file, handler}           → middleware / interceptor order
read_file              {file_path, start_line, end_line}  → fill whatever the window missed
```

`slice_backward` is a **backward prefix slice**, not a data-flow derivation. It delivers the function
header and the lines around the target, and it looks **forward** past the target (`forward`, default 8),
extends to the last use of an identifier from the target line (`forward_max`, default 64), and attaches
the declaration lines of identifiers seen in the window (`declaration_for`). If a fact you need is still
outside the window, call `read_file` or slice again at a new line — do not treat the window as complete.

### 2.3 Judge

**True positive requires all five**: reachable, attacker-influenced, no effective sanitisation, the
semantics actually hold (a template regex without an execution modifier is not code execution), and a
concrete reproduction idea. **False positive**: any single one of — sanitised/whitelisted, unreachable
(dead code, inactive `#ifdef`, unregistered route), non-production `file_role`, semantics do not hold
(but note: printf width and integer precision are *minimums*, never bounds), or a pattern-matching
artifact (a declaration, an operator, a prototype treated as a call). **Undecided**: say exactly which
line or binding you are missing.

---

## 3. Envelope reading contract

Every tool returns the same shape: `{ "data": {...}, "provenance": [...], "uncertainty": {...} }`.

### 3.1 `data` fields worth knowing

| Field | Where | How to read it |
|---|---|---|
| `content_source` | slice/guards/framework | `project-index` or `on-demand-read` (the latter is itself evidence that the index missed the file) |
| `index.truncated_at_limit` | everywhere | **true means "not found" ≠ "not there"** |
| `total_hits` / `limit` / `truncated_at_limit` | definitions, references, call graph, guards, framework | Real total + cap + whether the cap bit — limits are never silent |
| `empty_kind` | symbol definition | `no_match` (genuinely absent) vs `index_miss` (present but not extracted) vs `definition_only` |
| `function` / `function_def_line` / `function_signature` | slice | Trust it only when `function_scope` is resolved; when the name contradicts the surrounding diff, check the raw `function_def_line` before believing it |
| `scope_anchor` | slice | `within_depth` / `extended_for_long_function` (the window had to grow to fit the header) |
| `window` / `lines_returned` | slice | `end_line` may exceed the target line |
| `forward` / `forward_max` / `forward_lines_returned` / `forward_bounded_by` / `forward_extended_for` | slice | Forward lookahead and *why* it stopped (`requested` / `function_body` / `file_end` / `identifier_use`) |
| `snippets[].is_target` / `is_function_header` / `is_after_target` | slice | Per-line markers |
| `snippets[].declaration_for` | slice | The line is an **attached declaration** of an identifier seen in the window (outside the window itself) — count it separately |
| `snippets[].in_conditional_region` / `preprocess_note` | slice, guards, framework | Conditional-compilation state; a non-null `preprocess_note` means preprocessor evaluation degraded (for example missing includes) → read facts as line-level only |
| `unresolved_edges` | `uncertainty` | Count of call sites inside the target function that could not be resolved (function pointers, member pointers, table dispatch). Not "the graph is complete" |
| `dispatch_candidates` | call hierarchy, slice | **Signature-matched candidate targets** for an unresolved dispatch site. Heuristic by construction: `heuristic: true`, per-candidate `reason`/`score`, call sites, and the scanned signature space. Never a resolution result — corroborate before you rely on it |
| `function_summaries` | call hierarchy | Lightweight per-function summary (parameter→return, parameter→sink) with field-level `available`/`reason`, a cap and `truncated_at_limit`. Scope is the single function body: absence of a flow is **not** proof of absence |
| `severity_original` / `severity_downgraded_by` | scan findings | A higher-severity candidate was lowered, and why. Never read "downgraded" as "absent" |

### 3.2 `provenance` and `uncertainty`

`provenance[].resolver` tells you how a line got there — `slice+function-header`, `slice+line-window`,
`slice+identifier-declaration`, `symbol-index`, `call-scan+body-scope`, `file-heuristic`, and so on.
When a conclusion mixes resolvers, believe the weakest one. `uncertainty.level`/`reasons` is the
engine's own statement of what it could not resolve (`backward_prefix_not_dataflow_slice`,
`conditional_compilation_region_present`, `cpp_preprocess_unavailable_line_level_fallback`,
`dynamic_dispatch_not_resolved`, `name_based_edges`, `dispatch_candidates_are_signature_heuristic`,
`function_summaries_single_function_scope`, …).

### 3.3 Seven reading rules

1. Read `uncertainty` and `scope_anchor` **before** trusting `data`.
2. `truncated_at_limit: true` or `total_hits > limit` ⇒ you may **not** assert "that is all".
3. A slice is not data flow. If your conclusion needs a fact beyond the window, fetch it first.
4. `declaration_for` lines are attached source, not engine conclusions; count them separately from
   window lines.
5. Conditional compilation: `in_conditional_region` means participation in the build is unknown; a
   non-null `preprocess_note` means the preprocessor view degraded — do not draw strong conclusions there.
6. `unresolved_edges` is 0 only when nothing is dispatched; non-zero means unresolved indirect calls exist.
7. Check `severity_original` / `severity_downgraded_by` before filtering by severity.

---

## 4. Measurement discipline (for anyone benchmarking the engine)

Evidence claims are easy to get wrong. These rules came from real mistakes; apply them before reporting
any "the engine delivered / missed X" number.

**Per-locus, not per-case.** A fix with several hunks has several loci. Required facts must be grouped
**per locus** and may only be checked against that locus's own slice. A fix whose hunks are hundreds of
lines apart can never be satisfied by one slice.

**Facts must be vulnerable-side text.** Take required facts from the `-` side of the fix diff. Substring
matching false-passes: a token introduced by the fix often already exists elsewhere in the vulnerable
file (a macro definition, a comment, another call site).

**Pure-addition hunks have no locus.** When a hunk only adds lines there is no deleted line to derive a
locus from: pass an explicit anchor line.

**State degraded conditions.** Record `preprocess_note` and `uncertainty.level` next to the result. In our
own run, 4 of 8 C cases were measured while the preprocessor was unavailable and uncertainty was high;
calling that "complete evidence" without the caveat overstates the engine.

**Five-point self-check before you publish a number**

1. Write down where each locus came from (deleted line of a fix diff / explicit anchor / a candidate).
2. Prove every required fact exists on the vulnerable side: `git show <vuln>:<file> | grep -nF '<fact>'`.
3. Bucket each fact hit: inside the window / attached declaration / elsewhere. A non-empty third bucket
   means your ruler is suspect.
4. Verify multi-hunk cases per hunk; never merge them.
5. Record `preprocess_note` + `uncertainty.level` in the conclusion.

---

## 5. Auxiliary entry point: scanning for candidates

```bash
ctx-audit scan <PATH> --deep --min-severity high -o json
#   --deep = --taint + --cross-file (AST taint plus cross-file tracing)
#   -o json|sarif|llm|markdown|text
```

Findings are **candidates**: `candidate: true`, `decision_required: true`. Read `detector` (for example
`RegexRule: <id>`), `evidence_refs.matched_pattern`, `code_snippet` (with a `>> line |` marker),
`enclosing_function`, `file_role` (`production` / `test` / `build` / `vendor`), and the downgrade fields
from §3.1. A candidate outside the production role, or one whose severity was downgraded, is still worth
a look — the engine never removes a candidate silently, and neither should you.

---

## 6. Output contract (JSON unless the task says otherwise)

```json
{
  "round": "<id>", "target": "<project>", "phase": "triage|deep_review|final",
  "summary": {"tp_candidates": 0, "fp": 0, "hardening": 0},
  "tp_candidates": [{
    "title": "...", "cwe": "CWE-xxx",
    "chain": ["source file:line", "propagation file:line", "sink file:line"],
    "scenario": "attacker model + preconditions + impact",
    "evidence_refs": ["file:line + snippet (<=5 lines)"],
    "verified": false, "verify_plan": "...", "human_gate": true
  }],
  "fp_families": [{"family": "...", "count": 0, "reason": "...", "examples": ["file:line"]}],
  "hardening": [{"title": "...", "evidence": "file:line"}],
  "human_gate": false
}
```

---

## 7. Tool reference

**Default surface (13)**

| Tool | Required | Optional |
|---|---|---|
| `get_project_index` | — | `refresh` |
| `get_symbol_definition` | `symbol` | `refresh` |
| `get_symbol_references` | `symbol` | `refresh` |
| `get_call_hierarchy` | `function` | `direction`, `refresh` |
| `slice_backward` | `file` | `line`, `depth`, `forward`, `forward_max`, `symbol`, `refresh` |
| `get_dataflow_path` | `source` | `sink`, `file`, `refresh` |
| `get_sanitizer_guards` | `file` | `line`, `refresh` |
| `get_framework_context` | `file` | `handler`, `refresh` |
| `get_incremental_status` | — | `refresh` |
| `read_file` | `file_path` | `start_line`, `end_line` |
| `list_files` | — | `path`, `pattern` |
| `report_finding` | `title`, `description`, `severity`, `file_path`, `line_number` | — |
| `finish_analysis` | `summary`, `findings_count` | — |

**Legacy surface** (`ctx-audit mcp --legacy-tools` or `CTX_AUDIT_LEGACY_TOOLS=1`) keeps the old
fine-grained names (`security_scan`, `query_callers`, `get_code_context`, `check_sanitizer`, …).
Calling them on the default surface returns a migration hint instead of failing silently.

---

## 8. Red lines

1. Never lower the quality bar: an honest zero is better than a padded list.
2. Every conclusion carries `file:line` plus a snippet of at most five lines, and names the resolver.
3. Anything you did not actually run is `verified: false`.
4. Never modify the audited project.
5. Never treat an engine candidate as a conclusion, and never treat "the engine said nothing" as "there
   is nothing" — check `truncated_at_limit` and the capability report first.
6. Output JSON unless the task explicitly asks for prose.
