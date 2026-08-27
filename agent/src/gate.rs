// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! human gate：TP 候选的人工闸门
//!
//! 深审产出 TP 候选后，轮次暂停在 AwaitHuman：
//! - 写 gate 通知文件 `<state_dir>/gate-<round_id>.json`（候选清单+证据摘要+轮次上下文）；
//! - 可选 webhook POST（配置 `agent.native_gate.webhook_url`，失败只告警不阻断）；
//! - 人工通过 CLI approve/reject 后写决策文件 `<state_dir>/gate-<round_id>-decision.json`，
//!   轮次才进入登记草稿阶段。
//!
//! 边界（§3.2）：TP 认定与上报决策永久人工，agent 只产出候选与证据链。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// TP 候选（从深审/初审的结构化 JSON 输出中提取）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpCandidate {
    /// 标题
    pub title: String,
    /// CWE 编号
    #[serde(default)]
    pub cwe: Option<String>,
    /// 攻击场景描述
    #[serde(default)]
    pub scenario: Option<String>,
    /// 攻击链（源→传播→sink 的 文件:行号 列表）
    #[serde(default)]
    pub chain: Vec<String>,
    /// 原始 JSON 条目（保留 verified/verify_plan 等全部字段）
    #[serde(default)]
    pub raw: serde_json::Value,
}

/// gate 通知（写给人工的待决事项）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateNotice {
    /// 轮次 ID
    pub round_id: String,
    /// 审计目标
    pub target: String,
    /// 触发阶段（通常为 deep_review）
    pub phase: String,
    /// TP 候选清单
    pub tp_candidates: Vec<TpCandidate>,
    /// 证据摘要（攻击链拼接的纯文本）
    pub evidence_summary: String,
    /// 轮次上下文：阶段产物路径
    pub artifacts: BTreeMap<String, String>,
    /// 创建时间
    pub created_at: DateTime<Utc>,
}

/// gate 决策
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateDecision {
    /// true=认定 TP 成立，false=驳回
    pub approve: bool,
    /// 人工备注
    #[serde(default)]
    pub note: Option<String>,
    /// 决策时间
    pub decided_at: DateTime<Utc>,
}

/// gate 通知文件路径
pub fn notice_path(state_dir: &Path, round_id: &str) -> PathBuf {
    state_dir.join(format!("gate-{}.json", round_id))
}

/// gate 决策文件路径
pub fn decision_path(state_dir: &Path, round_id: &str) -> PathBuf {
    state_dir.join(format!("gate-{}-decision.json", round_id))
}

/// 写 gate 通知文件
pub fn write_notice(state_dir: &Path, notice: &GateNotice) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(state_dir)?;
    let path = notice_path(state_dir, &notice.round_id);
    let json = serde_json::to_string_pretty(notice)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(&path, json)?;
    Ok(path)
}

/// 写 gate 决策文件
pub fn write_decision(
    state_dir: &Path,
    round_id: &str,
    decision: &GateDecision,
) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(state_dir)?;
    let path = decision_path(state_dir, round_id);
    let json = serde_json::to_string_pretty(decision)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(&path, json)?;
    Ok(path)
}

/// 读取已有决策（不存在返回 None）
pub fn read_decision(state_dir: &Path, round_id: &str) -> Option<GateDecision> {
    let path = decision_path(state_dir, round_id);
    let content = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

/// 发送 webhook 通知（失败由调用方降级为告警，不阻断轮次）
pub async fn send_webhook(url: &str, notice: &GateNotice) -> Result<(), reqwest::Error> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    client
        .post(url)
        .json(notice)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

/// 从 agent 输出的结构化 JSON 提取 TP 候选
///
/// 兼容两种形态（round-agent.md 输出契约 + verdict 形态）：
/// - 顶层 `tp_candidates` 数组的全部条目；
/// - 顶层 `findings` 数组中 `verdict` 为 "TP"/"TP_CANDIDATE" 的条目。
pub fn extract_tp_candidates(output: &serde_json::Value) -> Vec<TpCandidate> {
    let mut candidates = Vec::new();

    if let Some(arr) = output.get("tp_candidates").and_then(|v| v.as_array()) {
        for item in arr {
            candidates.push(parse_candidate(item));
        }
    }
    if let Some(arr) = output.get("findings").and_then(|v| v.as_array()) {
        for item in arr {
            let verdict = item
                .get("verdict")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_uppercase();
            if verdict == "TP" || verdict == "TP_CANDIDATE" {
                candidates.push(parse_candidate(item));
            }
        }
    }

    candidates
}

/// 解析单条候选（字段缺失时给默认值，不拒绝）
pub(crate) fn parse_candidate(item: &serde_json::Value) -> TpCandidate {
    let get_str = |key: &str| {
        item.get(key)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };
    let chain = item
        .get("chain")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    TpCandidate {
        title: get_str("title").unwrap_or_else(|| "(未命名候选)".to_string()),
        cwe: get_str("cwe"),
        scenario: get_str("scenario"),
        chain,
        raw: item.clone(),
    }
}

/// 拼接证据摘要（gate 通知用）
pub fn build_evidence_summary(candidates: &[TpCandidate]) -> String {
    let mut out = String::new();
    for (i, c) in candidates.iter().enumerate() {
        out.push_str(&format!(
            "{}. {} ({})\n",
            i + 1,
            c.title,
            c.cwe.as_deref().unwrap_or("CWE 未标")
        ));
        if let Some(ref scenario) = c.scenario {
            out.push_str(&format!("   场景: {}\n", scenario));
        }
        for step in &c.chain {
            out.push_str(&format!("   - {}\n", step));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_state_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ctx-audit-gate-test-{}-{}",
            tag,
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 从 tp_candidates 数组提取
    #[test]
    fn test_extract_from_tp_candidates_array() {
        let output = serde_json::json!({
            "phase": "deep_review",
            "tp_candidates": [
                {
                    "title": "存储型 XSS",
                    "cwe": "CWE-79",
                    "scenario": "攻击者提交恶意文件名",
                    "chain": ["源 src/upload.js:10", "sink src/serve.js:42"],
                    "verified": false
                }
            ]
        });
        let candidates = extract_tp_candidates(&output);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].title, "存储型 XSS");
        assert_eq!(candidates[0].cwe.as_deref(), Some("CWE-79"));
        assert_eq!(candidates[0].chain.len(), 2);
        assert_eq!(candidates[0].raw["verified"], false);
    }

    /// 从 findings verdict=TP 提取；FP 不提取
    #[test]
    fn test_extract_from_verdict_findings() {
        let output = serde_json::json!({
            "findings": [
                {"title": "命令注入", "verdict": "TP", "cwe": "CWE-78"},
                {"title": "误报项", "verdict": "FP"},
                {"title": "加固项", "verdict": "HARDENING"}
            ]
        });
        let candidates = extract_tp_candidates(&output);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].title, "命令注入");
    }

    /// 无候选时返回空
    #[test]
    fn test_extract_empty() {
        let output = serde_json::json!({"phase": "triage", "summary": {}});
        assert!(extract_tp_candidates(&output).is_empty());
    }

    /// 通知与决策文件的写入/读取
    #[test]
    fn test_notice_and_decision_files() {
        let dir = temp_state_dir("files");
        let notice = GateNotice {
            round_id: "AR-1".into(),
            target: "/tmp/proj".into(),
            phase: "deep_review".into(),
            tp_candidates: vec![TpCandidate {
                title: "t".into(),
                cwe: None,
                scenario: None,
                chain: vec![],
                raw: serde_json::Value::Null,
            }],
            evidence_summary: "1. t\n".into(),
            artifacts: BTreeMap::new(),
            created_at: Utc::now(),
        };
        let path = write_notice(&dir, &notice).unwrap();
        assert!(path.exists());
        assert_eq!(path, notice_path(&dir, "AR-1"));

        // 决策前无决策文件
        assert!(read_decision(&dir, "AR-1").is_none());

        let decision = GateDecision {
            approve: true,
            note: Some("人工确认成立".into()),
            decided_at: Utc::now(),
        };
        write_decision(&dir, "AR-1", &decision).unwrap();
        let loaded = read_decision(&dir, "AR-1").unwrap();
        assert!(loaded.approve);
        assert_eq!(loaded.note.as_deref(), Some("人工确认成立"));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// 证据摘要拼接
    #[test]
    fn test_evidence_summary() {
        let candidates = vec![TpCandidate {
            title: "XSS".into(),
            cwe: Some("CWE-79".into()),
            scenario: Some("场景".into()),
            chain: vec!["a.js:1".into(), "b.js:2".into()],
            raw: serde_json::Value::Null,
        }];
        let summary = build_evidence_summary(&candidates);
        assert!(summary.contains("XSS"));
        assert!(summary.contains("a.js:1"));
        assert!(summary.contains("场景"));
    }
}
