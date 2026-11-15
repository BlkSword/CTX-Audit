// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 自动驾驶（Autopilot）：带预算上限的确定性审计循环。
//!
//! 与"一键审计工作流"的区别：
//! - workflow 只产出证据；
//! - autopilot 会**根据证据自主决定下一步**并执行，直到预算耗尽或无事可做。
//!
//! 循环体（固定决策规则，非随机、非 LLM）：
//! 1. 跑一轮 workflow（覆盖率 → 待审 → 链 → 链档 → 载荷）；
//! 2. 从 `next_actions` 里取出"需要动态验证"的链，按分数排序；
//! 3. 在预算内逐条尝试 `verify_payload`（需 `CTX_AUDIT_VERIFY_DIR`）；
//! 4. 对已确认/可能存活的链打包 PoC 工件；
//! 5. 汇总所有证据为一份结论（含正结论、负结论与未决项）。
//!
//! 预算（`budget`）限制的是**深挖链数**，不是时间；每步都记录在 `trace` 里，
//! 便于复核"为什么停在这里"。

use serde_json::{json, Value};
use std::path::Path;
use std::time::Instant;

/// 自动驾驶选项。
pub struct AutopilotOptions {
    /// 最多深挖多少条链（预算上限）。
    pub budget: usize,
    /// 是否尝试动态验证（需 `CTX_AUDIT_VERIFY_DIR`）。
    pub verify: bool,
    /// 是否打包 PoC 工件。
    pub poc: bool,
    /// 工作流参数。
    pub triage_limit: usize,
    pub chain_limit: usize,
}

impl Default for AutopilotOptions {
    fn default() -> Self {
        Self {
            budget: 3,
            verify: false,
            poc: true,
            triage_limit: 20,
            chain_limit: 20,
        }
    }
}

/// 运行自动驾驶。
pub fn autopilot_report(project: &Path, opts: &AutopilotOptions) -> Result<Value, String> {
    let started = Instant::now();
    let budget = opts.budget.clamp(1, 20);
    let mut trace: Vec<Value> = Vec::new();
    let mut findings: Vec<Value> = Vec::new();
    let mut undecided: Vec<Value> = Vec::new();

    // ── 步骤 1：跑工作流 ────────────────────────────────────────────────
    let t0 = Instant::now();
    let wf_opts = super::workflow::WorkflowOptions {
        triage_limit: opts.triage_limit,
        chain_limit: opts.chain_limit,
        deep_limit: budget.min(5),
        stop_after: None,
        verify: opts.verify,
    };
    let workflow = super::workflow::audit_workflow_report(project, &wf_opts)?;
    trace.push(json!({
        "step": 1,
        "action": "workflow",
        "ms": t0.elapsed().as_millis() as u64,
        "evidence": workflow["evidence_counts"]["total"].clone(),
    }));

    // ── 步骤 2：挑出候选深挖链（按载荷档位 + 分数排序）──────────────────
    let evidence = workflow["evidence"].as_array().cloned().unwrap_or_default();
    let payload_ev: Vec<Value> = evidence
        .iter()
        .filter(|e| e["stage"].as_str() == Some("payload"))
        .cloned()
        .collect();
    let mut ranked: Vec<Value> = payload_ev
        .iter()
        .filter_map(|e| {
            let tier = e["data"]["tier"].as_str().unwrap_or("");
            // payload_killed 与 unreachable 不需要深挖；其余进入预算队列
            let worth = matches!(
                tier,
                "payload_may_survive" | "guard_ineffective_token" | "taint_lost" | "payload_verified"
            );
            if !worth {
                return None;
            }
            Some(json!({
                "evidence_id": e["id"].clone(),
                "chain_id": e["data"]["chain_id"].clone(),
                "archetype": e["data"]["archetype"].clone(),
                "tier": tier,
                "priority": match tier {
                    "payload_may_survive" => 3,
                    "guard_ineffective_token" => 2,
                    "taint_lost" => 1,
                    _ => 0,
                },
            }))
        })
        .collect();
    ranked.sort_by(|a, b| {
        let pa = a["priority"].as_u64().unwrap_or(0);
        let pb = b["priority"].as_u64().unwrap_or(0);
        pb.cmp(&pa)
    });
    trace.push(json!({
        "step": 2,
        "action": "rank_candidates",
        "candidates": ranked.len(),
        "budget": budget,
    }));

    // ── 步骤 3：预算内逐条动态验证 ──────────────────────────────────────
    let mut verified_count = 0usize;
    let mut killed_count = 0usize;
    let mut attempted = 0usize;
    for cand in ranked.iter() {
        if attempted >= budget {
            trace.push(json!({
                "step": 3,
                "action": "verify",
                "status": "budget_exhausted",
                "attempted": attempted,
                "remaining": ranked.len() - attempted,
            }));
            break;
        }
        let tier = cand["tier"].as_str().unwrap_or("");
        // 已确认的不用再验
        if tier == "payload_verified" {
            killed_count += 0;
            verified_count += 1;
            continue;
        }
        if !opts.verify {
            trace.push(json!({
                "step": 3,
                "action": "verify",
                "status": "skipped_dynamic_disabled",
                "chain_id": cand["chain_id"].clone(),
            }));
            attempted += 1;
            undecided.push(cand.clone());
            continue;
        }
        // 需要从链里取入口坐标
        let chain_id = cand["chain_id"].as_str().unwrap_or("");
        let Some(dossier) = super::chain_dossier_report(project, chain_id).ok() else {
            trace.push(json!({
                "step": 3, "action": "verify", "status": "dossier_missing", "chain_id": chain_id,
            }));
            attempted += 1;
            continue;
        };
        let entry = &dossier["entry"];
        let ef = entry["file"].as_str().unwrap_or("");
        let el = entry["handler_line"]
            .as_u64()
            .or_else(|| entry["line"].as_u64())
            .unwrap_or(0) as u32;
        // library_entry 的 `route` 字段就是函数名（如 `process`）；HTTP 入口用 handler/symbol。
        let function = entry["symbol"]
            .as_str()
            .or_else(|| entry["handler"].as_str())
            .or_else(|| {
                let kind = entry["entry_kind"].as_str().unwrap_or("");
                if kind == "library_entry" {
                    entry["route"].as_str()
                } else {
                    None
                }
            })
            .unwrap_or("");
        let archetype = cand["archetype"].as_str().unwrap_or("");
        if ef.is_empty() || function.is_empty() || el == 0 {
            trace.push(json!({
                "step": 3, "action": "verify", "status": "incomplete_coordinates", "chain_id": chain_id,
            }));
            attempted += 1;
            continue;
        }
        let verify_arch = normalize_archetype(archetype);
        match super::verify::verify_payload_report(
            project,
            ef,
            function,
            "CTXMARKER",
            verify_arch,
        ) {
            Ok(v) => {
                attempted += 1;
                let vt = v["tier"].as_str().unwrap_or("unknown");
                if vt == "payload_verified" {
                    verified_count += 1;
                    findings.push(json!({
                        "kind": "payload_verified",
                        "chain_id": chain_id,
                        "evidence_id": cand["evidence_id"].clone(),
                        "file": ef,
                        "function": function,
                        "archetype": verify_arch,
                        "verify_tier": vt,
                        "evidence": v["evidence"].clone(),
                    }));
                } else if vt == "verified_killed" {
                    killed_count += 1;
                } else {
                    undecided.push(json!({
                        "chain_id": chain_id,
                        "evidence_id": cand["evidence_id"].clone(),
                        "verify_tier": vt,
                    }));
                }
                trace.push(json!({
                    "step": 3, "action": "verify", "status": "done",
                    "chain_id": chain_id, "tier": vt,
                }));
            }
            Err(e) => {
                attempted += 1;
                trace.push(json!({
                    "step": 3, "action": "verify", "status": "error",
                    "chain_id": chain_id, "error": e,
                }));
            }
        }
    }

    // ── 步骤 4：为已确认/可能存活的链打包 PoC ───────────────────────────
    let mut packages: Vec<Value> = Vec::new();
    if opts.poc {
        let t4 = Instant::now();
        let mut packaged = 0usize;
        for cand in ranked.iter() {
            if packaged >= budget {
                break;
            }
            let Some(cid) = cand["chain_id"].as_str() else {
                continue;
            };
            if cid.is_empty() {
                continue;
            }
            match super::poc::poc_package_report(project, Some(cid), None, None, None, None) {
                Ok(p) => {
                    packages.push(json!({
                        "chain_id": cid,
                        "payload_tier": p["verdict"]["payload_tier"].clone(),
                        "guard_gap": p["guard_gap"]["summary"].clone(),
                        "remediation": p["remediation"]["summary"].clone(),
                    }));
                    packaged += 1;
                }
                Err(e) => {
                    trace.push(json!({
                        "step": 4, "action": "poc", "status": "error", "chain_id": cid, "error": e,
                    }));
                }
            }
        }
        trace.push(json!({
            "step": 4,
            "action": "poc",
            "ms": t4.elapsed().as_millis() as u64,
            "packaged": packages.len(),
        }));
    }

    // ── 步骤 5：汇总结论 ────────────────────────────────────────────────
    let verdict = if verified_count > 0 {
        "has_verified_payload"
    } else if killed_count > 0 {
        "all_candidates_killed"
    } else if ranked.is_empty() {
        "no_candidate_chains"
    } else if attempted == 0 {
        "no_attempt_made"
    } else {
        // 有候选、也尝试过，但没有一条能给出确定结论（坐标不全 / 动态验证未开启）
        "undecided"
    };
    trace.push(json!({
        "step": 5,
        "action": "conclude",
        "verdict": verdict,
        "verified": verified_count,
        "killed": killed_count,
        "undecided": undecided.len(),
    }));

    Ok(json!({
        "schema": "autopilot/v1",
        "project": project.to_string_lossy(),
        "budget": budget,
        "verify_enabled": opts.verify,
        "verdict": verdict,
        "counts": {
            "candidates": ranked.len(),
            "attempted": attempted,
            "verified": verified_count,
            "killed": killed_count,
            "undecided": undecided.len(),
            "packaged": packages.len(),
        },
        "findings": findings,
        "packages": packages,
        "undecided": undecided,
        "workflow_summary": {
            "stopped_after": workflow["stopped_after"].clone(),
            "evidence_counts": workflow["evidence_counts"].clone(),
        },
        "trace": trace,
        "total_ms": started.elapsed().as_millis() as u64,
        "limits": [
            format!("深挖预算 {budget} 条链"),
            "动态验证需显式开启 CTX_AUDIT_VERIFY_DIR",
            "决策规则固定，不含随机与 LLM 推断",
        ],
        "uncertainty": {
            "level": "medium",
            "reasons": ["name_level_graph", "heuristic_guards", "static_only"],
        },
    }))
}

/// 把链的 sink 档位映射为 verify 接受的 archetype。
fn normalize_archetype(a: &str) -> &'static str {
    match a {
        "sql" => "sql",
        "command" | "exec" => "command",
        "path" | "file_write" | "file_read" => "path",
        "deserialize" | "deser" => "deserialize",
        "jndi" => "jndi",
        "template" | "template_eval" | "expression_eval" | "eval" => "template",
        "ssrf" | "ssrf_http" => "ssrf",
        "xss" => "xss",
        _ => "sql",
    }
}
