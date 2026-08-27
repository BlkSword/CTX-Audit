// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 可配置审计流水线（Pipeline）
//!
//! 目的是把 `runner.rs` 中写死的 CTX-Audit 审计流程逐步数据化：
//! 扫描开关、判定阶段 prompt、输出契约、闸门提取规则都可以通过
//! YAML/TOML/JSON 配置覆盖。默认值与当前 CTX-Audit 行为完全一致。
//!
//! 典型用法（YAML）：
//!
//! ```yaml
//! name: my-audit
//! scan:
//!   enable_taint: true
//!   enable_cross_file: true
//! triage:
//!   prompt_path: ./prompts/my-triage.md
//! deep_review:
//!   prompt_path: ./prompts/my-deep-review.md
//! output:
//!   tp_candidates_path: ["candidates"]
//!   verdict_findings_path: ["results"]
//!   accepted_verdicts: ["TP", "TP_CANDIDATE"]
//! gate_enabled: true
//! ```

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::gate::TpCandidate;

/// 完整流水线配置
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PipelineConfig {
    /// 配置名
    pub name: String,
    /// 说明
    pub description: Option<String>,
    /// 确定性扫描阶段
    pub scan: ScanConfig,
    /// 初审（triage）LLM 判定阶段
    pub triage: JudgeConfig,
    /// 深审（deep_review）LLM 判定阶段
    pub deep_review: JudgeConfig,
    /// 输出契约：从 LLM 结构化 JSON 中提取 TP/FP 等字段
    pub output: OutputContract,
    /// 是否启用 TP 候选人工闸门
    pub gate_enabled: bool,
    /// 登记草稿配置
    pub registration: RegistrationConfig,
    /// 额外 LLM 审计阶段（在深审之后、进入闸门/登记之前按顺序执行）
    pub extra_phases: Vec<ExtraJudgePhase>,
}

/// 确定性扫描阶段配置
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    /// 启用 AST 污点
    pub enable_taint: bool,
    /// 启用跨文件追踪
    pub enable_cross_file: bool,
    /// 最低严重度过滤（None = 不限）
    pub min_severity: Option<String>,
    /// 自定义规则目录（None = 使用内置规则）
    pub rules_dir: Option<PathBuf>,
}

/// 额外 LLM 审计阶段
///
/// 每个阶段独立使用自己的 prompt / system prompt / 输出契约，
/// 产物写入 `extra_phase_<id>.json`，TP 候选会与深审候选一起进入人工闸门。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ExtraJudgePhase {
    /// 阶段 ID（用于 artifact 命名与日志）
    pub id: String,
    /// prompt 文件路径（相对 Pipeline 配置文件解析）
    pub prompt_path: Option<PathBuf>,
    /// 直接覆盖 system prompt 文本
    pub system_prompt: Option<String>,
    /// 独立输出契约；None = 使用顶层 Pipeline output
    pub output: Option<OutputContract>,
    /// 是否启用
    pub enabled: bool,
}

impl Default for ExtraJudgePhase {
    fn default() -> Self {
        Self {
            id: String::new(),
            prompt_path: None,
            system_prompt: None,
            output: None,
            enabled: true,
        }
    }
}

/// 登记草稿配置
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RegistrationConfig {
    /// 登记草稿是否用 LLM 润色（默认 false = 纯模板）
    pub polish_draft: bool,
}

impl Default for RegistrationConfig {
    fn default() -> Self {
        Self { polish_draft: false }
    }
}

/// 单个 LLM 判定阶段配置
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct JudgeConfig {
    /// 显式 prompt 文件；None 时回退到 RunnerConfig::judge_prompt_path 再回退到默认搜索路径
    pub prompt_path: Option<PathBuf>,
    /// 覆盖 system prompt 文本；优先级高于 prompt_path 文件内容
    pub system_prompt: Option<String>,
    /// 该阶段是否启用；false 时跳过对应 LLM 阶段
    pub enabled: bool,
    /// 初审分片阈值：findings 数超过该值时按 (漏洞类型, 文件) 分片并行；
    /// None = 使用 RunnerConfig.subagent_threshold（默认 50），0 = 禁用分片
    pub shard_threshold: Option<usize>,
}

/// 输出契约
///
/// 用于把任意 LLM 结构化输出映射成统一的 `TpCandidate` 列表，
/// 从而支持不同的私人审计输出格式。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OutputContract {
    /// TP 候选数组的 JSON 路径（从输出根开始）
    pub tp_candidates_path: Vec<String>,
    /// findings 数组的 JSON 路径（可选，兼容 verdict 形态）
    pub verdict_findings_path: Vec<String>,
    /// findings 条目中的判定字段名
    pub verdict_field: String,
    /// 视为 TP 候选的判定值（大小写不敏感）
    pub accepted_verdicts: Vec<String>,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            name: "ctx-audit-default".to_string(),
            description: Some("CTX-Audit 默认六阶段审计流水线".to_string()),
            scan: ScanConfig::default(),
            triage: JudgeConfig::default(),
            deep_review: JudgeConfig::default(),
            output: OutputContract::default(),
            gate_enabled: true,
            registration: RegistrationConfig::default(),
            extra_phases: Vec::new(),
        }
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            enable_taint: true,
            enable_cross_file: true,
            min_severity: None,
            rules_dir: None,
        }
    }
}

impl Default for JudgeConfig {
    fn default() -> Self {
        Self {
            prompt_path: None,
            system_prompt: None,
            enabled: true,
            shard_threshold: None,
        }
    }
}

impl Default for OutputContract {
    fn default() -> Self {
        Self {
            tp_candidates_path: vec!["tp_candidates".to_string()],
            verdict_findings_path: vec!["findings".to_string()],
            verdict_field: "verdict".to_string(),
            accepted_verdicts: vec!["TP".to_string(), "TP_CANDIDATE".to_string()],
        }
    }
}

impl PipelineConfig {
    /// 从 YAML/JSON 文件加载；解析失败时返回带路径的错误
    pub fn load(path: &Path) -> Result<Self, PipelineError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| PipelineError::io(path.to_path_buf(), e))?;
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let err = |e: String| PipelineError::parse(path.to_path_buf(), e);
        let mut config = if ext == "json" {
            serde_json::from_str::<Self>(&content).map_err(|e| err(e.to_string()))?
        } else {
            serde_yaml::from_str::<Self>(&content).map_err(|e| err(e.to_string()))?
        };
        if let Some(base) = path.parent() {
            config.resolve_relative_paths(base);
        }
        Ok(config)
    }

    /// 把相对路径按配置文件所在目录解析为绝对路径
    pub fn resolve_relative_paths(&mut self, base: &Path) {
        let resolve = |p: &mut Option<PathBuf>| {
            if let Some(path) = p {
                if path.is_relative() {
                    *path = base.join(&*path);
                }
            }
        };
        resolve(&mut self.scan.rules_dir);
        resolve(&mut self.triage.prompt_path);
        resolve(&mut self.deep_review.prompt_path);
        for phase in &mut self.extra_phases {
            resolve(&mut phase.prompt_path);
        }
    }

    /// 从 JSON 值构造（CLI/测试用）
    pub fn from_value(value: serde_json::Value) -> Result<Self, PipelineError> {
        serde_json::from_value(value)
            .map_err(|e| PipelineError::parse(PathBuf::from("<json>"), e.to_string()))
    }

    /// 按顶层输出契约提取 TP 候选
    ///
    /// 默认契约等价于旧 `gate::extract_tp_candidates`。
    pub fn extract_tp_candidates(&self, output: &serde_json::Value) -> Vec<TpCandidate> {
        self.extract_tp_candidates_with_contract(output, &self.output)
    }

    /// 按指定输出契约提取 TP 候选（额外阶段可覆盖契约）
    pub fn extract_tp_candidates_with_contract(
        &self,
        output: &serde_json::Value,
        contract: &OutputContract,
    ) -> Vec<TpCandidate> {
        let mut candidates = Vec::new();

        // 1) tp_candidates 路径
        if let Some(arr) = lookup_array(output, &contract.tp_candidates_path) {
            for item in arr {
                candidates.push(crate::gate::parse_candidate(item));
            }
        }
        // 2) verdict/findings 路径
        if let Some(arr) = lookup_array(output, &contract.verdict_findings_path) {
            for item in arr {
                let verdict = item
                    .get(&contract.verdict_field)
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_uppercase();
                if contract
                    .accepted_verdicts
                    .iter()
                    .any(|v| v.eq_ignore_ascii_case(&verdict))
                {
                    candidates.push(crate::gate::parse_candidate(item));
                }
            }
        }

        // 去重：同一条目同时出现在两个路径时只保留一次（按原始 JSON 相等）
        let mut seen = Vec::new();
        candidates.retain(|c| {
            if seen.contains(&c.raw) {
                false
            } else {
                seen.push(c.raw.clone());
                true
            }
        });
        candidates
    }
}

/// 流水线配置错误
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    /// 文件读取失败
    #[error("读取流水线配置失败 {path}: {source}")]
    Io {
        /// 配置文件路径
        path: PathBuf,
        /// IO 错误
        #[source]
        source: std::io::Error,
    },
    /// 解析失败
    #[error("流水线配置解析失败 {path}: {message}")]
    Parse {
        /// 配置文件路径
        path: PathBuf,
        /// 解析错误
        message: String,
    },
}

impl PipelineError {
    fn io(path: PathBuf, source: std::io::Error) -> Self {
        Self::Io { path, source }
    }

    fn parse(path: PathBuf, message: String) -> Self {
        Self::Parse { path, message }
    }
}

/// 按 JSON 路径取数组：路径每段依次取 object key；不存在或类型不匹配返回 None
fn lookup_array<'a>(
    root: &'a serde_json::Value,
    path: &[String],
) -> Option<&'a Vec<serde_json::Value>> {
    let mut cur = root;
    for key in path {
        cur = cur.get(key)?;
    }
    cur.as_array()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_matches_ctx_contract() {
        let p = PipelineConfig::default();
        let output = serde_json::json!({
            "phase": "deep_review",
            "tp_candidates": [
                {"title": "A", "cwe": "CWE-79"}
            ]
        });
        let cs = p.extract_tp_candidates(&output);
        assert_eq!(cs.len(), 1);
        assert_eq!(cs[0].title, "A");
        assert_eq!(cs[0].cwe.as_deref(), Some("CWE-79"));
    }

    #[test]
    fn test_custom_contract_paths() {
        let p = PipelineConfig {
            output: OutputContract {
                tp_candidates_path: vec!["results".to_string(), "tps".to_string()],
                verdict_findings_path: vec![],
                ..OutputContract::default()
            },
            ..PipelineConfig::default()
        };
        let output = serde_json::json!({
            "results": {"tps": [{"title": "B"}]}
        });
        let cs = p.extract_tp_candidates(&output);
        assert_eq!(cs.len(), 1);
        assert_eq!(cs[0].title, "B");
    }

    #[test]
    fn test_custom_verdict_fields() {
        let p = PipelineConfig {
            output: OutputContract {
                tp_candidates_path: vec![],
                verdict_findings_path: vec!["items".to_string()],
                verdict_field: "decision".to_string(),
                accepted_verdicts: vec!["confirmed".to_string()],
            },
            ..PipelineConfig::default()
        };
        let output = serde_json::json!({
            "items": [
                {"title": "C", "decision": "CONFIRMED"},
                {"title": "D", "decision": "FP"}
            ]
        });
        let cs = p.extract_tp_candidates(&output);
        assert_eq!(cs.len(), 1);
        assert_eq!(cs[0].title, "C");
    }

    #[test]
    fn test_load_yaml_roundtrip() {
        let dir =
            std::env::temp_dir().join(format!("ctx-audit-pipeline-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pipeline.yaml");
        std::fs::write(
            &path,
            r#"
name: custom
scan:
  enable_taint: false
  enable_cross_file: false
triage:
  prompt_path: ./my-triage.md
deep_review:
  system_prompt: "你是自定义审计员"
output:
  tp_candidates_path: ["candidates"]
"#,
        )
        .unwrap();
        let p = PipelineConfig::load(&path).unwrap();
        assert_eq!(p.name, "custom");
        assert!(!p.scan.enable_taint);
        assert_eq!(
            p.triage.prompt_path.as_deref(),
            Some(dir.join("my-triage.md").as_path())
        );
        assert_eq!(
            p.deep_review.system_prompt.as_deref(),
            Some("你是自定义审计员")
        );
        assert_eq!(p.output.tp_candidates_path, vec!["candidates".to_string()]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_deduplicate_same_item() {
        let p = PipelineConfig::default();
        let item = serde_json::json!({"title": "X", "verdict": "TP"});
        let output = serde_json::json!({
            "tp_candidates": [item.clone()],
            "findings": [item]
        });
        let cs = p.extract_tp_candidates(&output);
        assert_eq!(cs.len(), 1);
    }
}
