// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 一键审计工作流（SOP）：把分散的能力串成一条可复现、可中断、带证据 id 的流水线。
//!
//! 阶段固定为五步，每步都产出结构化证据并分配稳定 id（`EV-<stage>-<n>`），
//! 供 Agent 引用、供控制台展示、供报告导出：
//!
//! 1. `coverage`  —— 覆盖率摘要（端点/未覆盖/置信/边界）
//! 2. `triage`    —— 排序后的待审清单（风险分 + 信号）
//! 3. `chains`    —— 候选链（入口→危险汇）
//! 4. `dossier`   —— 前 N 条链的链档（步骤/守卫/断点）
//! 5. `payload`   —— 前 N 条链的载荷存活判定（档位 + 证据）
//!
//! 设计约束：
//! - **确定性**：同样的输入产出同样的阶段顺序、同样的证据 id、同样的排序；
//! - **有界**：每阶段都有条数上限与时间预算，超限显式记录在 `limits`；
//! - **可中断**：`stop_after` 可只跑到某阶段，便于分步复核；
//! - **不判定**：只给证据与档位，最终结论仍由人或 Agent 给出。

use serde_json::{json, Value};
use std::path::Path;
use std::time::Instant;

/// 工作流阶段（顺序即执行顺序）。
pub const STAGES: [&str; 5] = ["coverage", "triage", "chains", "dossier", "payload"];

/// 工作流选项。
pub struct WorkflowOptions {
    /// 待审条数上限（0 = 全部，内部再夹到 200）。
    pub triage_limit: usize,
    /// 候选链条数上限。
    pub chain_limit: usize,
    /// 做链档与载荷判定的链数上限。
    pub deep_limit: usize,
    /// 只跑到该阶段（含）；None = 全部。
    pub stop_after: Option<String>,
    /// 是否尝试动态验证（需 CTX_AUDIT_VERIFY_DIR）。
    pub verify: bool,
}

impl Default for WorkflowOptions {
    fn default() -> Self {
        Self {
            triage_limit: 20,
            chain_limit: 20,
            deep_limit: 3,
            stop_after: None,
            verify: false,
        }
    }
}

fn stage_index(name: &str) -> Option<usize> {
    STAGES.iter().position(|s| *s == name)
}

/// 运行一键审计工作流。
pub fn audit_workflow_report(project: &Path, opts: &WorkflowOptions) -> Result<Value, String> {
    let started = Instant::now();
    let stop_at = match opts.stop_after.as_deref() {
        Some(name) => {
            let idx = stage_index(name)
                .ok_or_else(|| format!("未知阶段 {name}；可选：{}", STAGES.join(" / ")))?;
            idx
        }
        None => STAGES.len() - 1,
    };

    let mut stages: Vec<Value> = Vec::new();
    let mut evidence: Vec<Value> = Vec::new();
    let mut next_actions: Vec<Value> = Vec::new();
    let mut limits: Vec<Value> = Vec::new();

    // ── 1. coverage ──────────────────────────────────────────────────────
    let t0 = Instant::now();
    let bundle = super::audit_bundle(project)?;
    let coverage = bundle["coverage"].clone();
    let method_routes = coverage["method_routes"].as_u64().unwrap_or(0);
    let uncovered = coverage["uncovered"].as_u64().unwrap_or(0);
    let confidence = coverage["confidence"].as_str().unwrap_or("unknown").to_string();
    evidence.push(json!({
        "id": "EV-coverage-1",
        "stage": "coverage",
        "kind": "coverage_summary",
        "summary": format!("{method_routes} endpoints, {uncovered} uncovered, confidence {confidence}"),
        "data": {
            "method_routes": method_routes,
            "uncovered": uncovered,
            "annotation_covered": coverage["annotation_covered"].clone(),
            "confidence": confidence,
            "by_verdict": coverage["by_verdict"].clone(),
            "boundaries": {
                "dynamic_registrations": coverage["dynamic_endpoint_registrations"].clone(),
                "unmodelled_route_files": coverage["unmodelled_route_files"].clone(),
                "index_truncated": coverage["index_truncated_at_limit"].clone(),
            },
        },
    }));
    stages.push(json!({
        "stage": "coverage",
        "status": "done",
        "ms": t0.elapsed().as_millis() as u64,
        "evidence_ids": ["EV-coverage-1"],
    }));
    if stop_at == 0 {
        return Ok(finish(project, stages, evidence, next_actions, limits, started, stop_at));
    }

    // ── 2. triage ────────────────────────────────────────────────────────
    let t1 = Instant::now();
    let worklist = bundle["worklist"].as_array().cloned().unwrap_or_default();
    let triage_cap = if opts.triage_limit == 0 { 200 } else { opts.triage_limit.min(200) };
    let triage: Vec<Value> = worklist.iter().take(triage_cap).cloned().collect();
    if worklist.len() > triage.len() {
        limits.push(json!({
            "stage": "triage",
            "returned": triage.len(),
            "total": worklist.len(),
            "note": "提高 triage_limit 或分页获取",
        }));
    }
    for (i, item) in triage.iter().enumerate() {
        evidence.push(json!({
            "id": format!("EV-triage-{}", i + 1),
            "stage": "triage",
            "kind": "route_triage",
            "summary": format!(
                "{} {} — {}",
                item["method"].as_str().unwrap_or("ANY"),
                item["route"].as_str().unwrap_or(""),
                item["verdict"].as_str().unwrap_or("unknown")
            ),
            "data": {
                "score": item["score"].clone(),
                "signals": item["signals"].clone(),
                "method": item["method"].clone(),
                "route": item["route"].clone(),
                "file": item["file"].clone(),
                "line": item["line"].clone(),
                "verdict": item["verdict"].clone(),
            },
        }));
    }
    stages.push(json!({
        "stage": "triage",
        "status": "done",
        "ms": t1.elapsed().as_millis() as u64,
        "evidence_ids": (1..=triage.len()).map(|i| format!("EV-triage-{i}")).collect::<Vec<_>>(),
    }));
    if stop_at == 1 {
        return Ok(finish(project, stages, evidence, next_actions, limits, started, stop_at));
    }

    // ── 3. chains ────────────────────────────────────────────────────────
    let t2 = Instant::now();
    let chain_report = super::chain_candidates_report(
        project,
        opts.chain_limit,
        None,
        None,
        None,
        true,
    )?;
    let chains = chain_report["chains"].as_array().cloned().unwrap_or_default();
    // 只保留语义统计：`t_*_ms` 是耗时测量，会破坏同输入逐字节一致的确定性红线。
    let chain_stats = {
        let mut stats = serde_json::Map::new();
        if let Some(obj) = chain_report["stats"].as_object() {
            for (k, v) in obj {
                if k.starts_with("t_") && k.ends_with("_ms") {
                    continue;
                }
                stats.insert(k.clone(), v.clone());
            }
        }
        Value::Object(stats)
    };
    for (i, c) in chains.iter().enumerate() {
        evidence.push(json!({
            "id": format!("EV-chain-{}", i + 1),
            "stage": "chains",
            "kind": "candidate_chain",
            "summary": format!(
                "{} · {} · sink {}",
                c["chain_id"].as_str().unwrap_or(""),
                c["tier"].as_str().unwrap_or(""),
                c["sink"]["kind"].as_str().unwrap_or("")
            ),
            "data": {
                "chain_id": c["chain_id"].clone(),
                "tier": c["tier"].clone(),
                "score": c["score"].clone(),
                "entry": c["entry"].clone(),
                "sink": c["sink"].clone(),
                "guards": c["guards"].as_array().map(|a| a.len()).unwrap_or(0),
            },
        }));
    }
    stages.push(json!({
        "stage": "chains",
        "status": "done",
        "ms": t2.elapsed().as_millis() as u64,
        "evidence_ids": (1..=chains.len()).map(|i| format!("EV-chain-{i}")).collect::<Vec<_>>(),
        "stats": chain_stats,
    }));
    if stop_at == 2 {
        return Ok(finish(project, stages, evidence, next_actions, limits, started, stop_at));
    }

    // ── 4. dossier ───────────────────────────────────────────────────────
    let t3 = Instant::now();
    let deep: Vec<Value> = chains.iter().take(opts.deep_limit).cloned().collect();
    let mut dossier_ids: Vec<String> = Vec::new();
    for (i, c) in deep.iter().enumerate() {
        let cid = c["chain_id"].as_str().unwrap_or("");
        if cid.is_empty() {
            continue;
        }
        match super::chain_dossier_report(project, cid) {
            Ok(d) => {
                let id = format!("EV-dossier-{}", i + 1);
                dossier_ids.push(id.clone());
                evidence.push(json!({
                    "id": id,
                    "stage": "dossier",
                    "kind": "chain_dossier",
                    "summary": format!(
                        "{cid} · {} steps · {} guards",
                        d["steps"].as_array().map(|a| a.len()).unwrap_or(0),
                        d["guards"].as_array().map(|a| a.len()).unwrap_or(0)
                    ),
                    "data": {
                        "chain_id": cid,
                        "tier": d["tier"].clone(),
                        "steps": d["steps"].clone(),
                        "guards": d["guards"].clone(),
                        "breakpoints": d["breakpoints"].clone(),
                        "falsify": d["falsify"].clone(),
                    },
                }));
            }
            Err(e) => {
                stages.push(json!({
                    "stage": "dossier",
                    "status": "partial",
                    "ms": t3.elapsed().as_millis() as u64,
                    "error": e,
                }));
            }
        }
    }
    stages.push(json!({
        "stage": "dossier",
        "status": "done",
        "ms": t3.elapsed().as_millis() as u64,
        "evidence_ids": dossier_ids,
    }));
    if stop_at == 3 {
        return Ok(finish(project, stages, evidence, next_actions, limits, started, stop_at));
    }

    // ── 5. payload ───────────────────────────────────────────────────────
    let t4 = Instant::now();
    let mut payload_ids: Vec<String> = Vec::new();
    for (i, c) in deep.iter().enumerate() {
        let entry = &c["entry"];
        let sink = &c["sink"];
        let ef = entry["file"].as_str().unwrap_or("");
        let el = entry["handler_line"]
            .as_u64()
            .or_else(|| entry["line"].as_u64())
            .unwrap_or(0) as u32;
        let sf = sink["file"].as_str().unwrap_or("");
        let sl = sink["line"].as_u64().unwrap_or(0) as u32;
        if ef.is_empty() || sf.is_empty() || el == 0 || sl == 0 {
            continue;
        }
        let kind = sink["kind"].as_str().unwrap_or("");
        let arch = super::archetype_for_sink(kind);
        match super::ant::payload_viability_report(project, ef, el, sf, sl, arch) {
            Ok(p) => {
                let id = format!("EV-payload-{}", i + 1);
                payload_ids.push(id.clone());
                let tier = p["tier"].as_str().unwrap_or("unknown").to_string();
                evidence.push(json!({
                    "id": id,
                    "stage": "payload",
                    "kind": "payload_viability",
                    "summary": format!("{} · {tier}", c["chain_id"].as_str().unwrap_or("")),
                    "data": {
                        "chain_id": c["chain_id"].clone(),
                        "archetype": arch,
                        "tier": p["tier"].clone(),
                        "viability": p["viability"].clone(),
                        "reachable": p["reachable"].clone(),
                        "killed_at": p["killed_at"].clone(),
                        "taint_lost_at": p["taint_lost_at"].clone(),
                        "steps": p["steps"].as_array().map(|a| a.len()).unwrap_or(0),
                    },
                }));
                if tier == "payload_may_survive" {
                    next_actions.push(json!({
                        "kind": "verify",
                        "evidence_id": id,
                        "tool": "verify_payload",
                        "hint": format!("--file {ef} --archetype {arch}（需 CTX_AUDIT_VERIFY_DIR）"),
                    }));
                }
            }
            Err(e) => {
                limits.push(json!({"stage": "payload", "chain_id": c["chain_id"], "error": e}));
            }
        }
    }
    stages.push(json!({
        "stage": "payload",
        "status": "done",
        "ms": t4.elapsed().as_millis() as u64,
        "evidence_ids": payload_ids,
    }));

    Ok(finish(project, stages, evidence, next_actions, limits, started, stop_at))
}

fn finish(
    project: &Path,
    stages: Vec<Value>,
    evidence: Vec<Value>,
    next_actions: Vec<Value>,
    limits: Vec<Value>,
    started: Instant,
    stop_at: usize,
) -> Value {
    let by_stage = |name: &str| -> usize {
        evidence
            .iter()
            .filter(|e| e["stage"].as_str() == Some(name))
            .count()
    };
    json!({
        "schema": "audit-workflow/v1",
        "project": project.to_string_lossy(),
        "stages": stages,
        "stopped_after": STAGES[stop_at],
        "evidence": evidence,
        "evidence_counts": {
            "coverage": by_stage("coverage"),
            "triage": by_stage("triage"),
            "chains": by_stage("chains"),
            "dossier": by_stage("dossier"),
            "payload": by_stage("payload"),
            "total": evidence.len(),
        },
        "next_actions": next_actions,
        "limits": limits,
        "total_ms": started.elapsed().as_millis() as u64,
        "uncertainty": {
            "level": "medium",
            "reasons": ["name_level_graph", "heuristic_guards", "static_only"],
        },
    })
}
