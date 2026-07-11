// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 污点步进式调查器
//!
//! 让 LLM 像人工审计员一样，从 sink 出发沿着数据流反向追踪到 source。
//! 每轮 LLM 决定下一步动作（读代码、查调用、解析方法、检查 sanitizer），
//! 调查器执行对应工具并把观察结果写回链，最终给出带完整路径的判定。

use std::sync::Arc;

use anyhow::{Context, Result};
use serde_json::json;

use deepaudit_core::scanning::Finding;
use deepaudit_core::taint::{Sanitizer, TaintAnalyzer, VulnerabilityType};

use crate::agent::evidence::Evidence;
use crate::agent::heuristics::{judge_finding, Verdict};
use crate::agent::investigator::{InvestigationOutcome, InvestigationStep};
use crate::agent::llm_client::LlmClient;
use crate::agent::prompts::{build_taint_walk_prompt, TaintChainStep, TaintFocus};
use crate::agent::specialist::SpecialistContext;

/// 污点步进调查器
pub struct TaintWalkInvestigator {
    llm_client: Arc<dyn LlmClient>,
    max_steps: usize,
}

impl TaintWalkInvestigator {
    pub fn new(llm_client: Arc<dyn LlmClient>, max_steps: usize) -> Self {
        Self {
            llm_client,
            max_steps: max_steps.max(1),
        }
    }

    /// 对单个 finding 执行污点步进调查
    pub async fn investigate(
        &self,
        ctx: &SpecialistContext,
        hypothesis: &str,
    ) -> Result<InvestigationOutcome> {
        let finding = &ctx.finding;
        let evidence = &ctx.evidence;

        // 初始焦点：sink 所在位置，symbol 先用 detector 占位
        let mut focus = TaintFocus {
            file_path: finding.file_path.clone(),
            line: finding.line_start,
            symbol: sink_symbol_from_finding(finding),
            role: "sink".to_string(),
        };

        let mut chain: Vec<TaintChainStep> = vec![TaintChainStep {
            step_number: 0,
            file_path: focus.file_path.clone(),
            line: focus.line,
            symbol: focus.symbol.clone(),
            step_type: "sink".to_string(),
            code_snippet: evidence.code_context.clone().unwrap_or_default(),
            reasoning: hypothesis.to_string(),
            confidence: 0.5,
        }];

        let mut steps: Vec<InvestigationStep> = Vec::new();

        for step_number in 1..=self.max_steps {
            let prompt =
                build_taint_walk_prompt(finding, evidence, &focus, &chain, &available_actions());

            let value = self
                .llm_client
                .chat_json(&prompt)
                .await
                .with_context(|| format!("LLM 污点步进决策解析失败 (step {})", step_number))?;

            let decision = parse_taint_walk_decision(&value)?;

            match decision {
                TaintWalkDecision::Finish {
                    verdict,
                    confidence,
                    reasoning,
                    chain_summary,
                } => {
                    let final_reasoning = if chain_summary.is_empty() {
                        reasoning
                    } else {
                        format!("{}\n路径摘要: {}", reasoning, chain_summary)
                    };
                    return Ok(InvestigationOutcome {
                        verdict,
                        confidence,
                        reasoning: final_reasoning,
                        steps,
                    });
                }
                TaintWalkDecision::NextAction {
                    action,
                    params,
                    reasoning,
                } => {
                    let observation = self
                        .execute_action(ctx, &action, &params, &reasoning, &mut focus, &mut chain)
                        .await;
                    steps.push(InvestigationStep {
                        step_number,
                        tool_name: action,
                        tool_input: params,
                        observation,
                        reasoning,
                        reflection: None,
                    });
                }
            }
        }

        // 达到最大步数，使用已有链做兜底判定
        fallback_outcome(finding, evidence, steps, &chain)
    }

    async fn execute_action(
        &self,
        ctx: &SpecialistContext,
        action: &str,
        params: &serde_json::Value,
        reasoning: &str,
        focus: &mut TaintFocus,
        chain: &mut Vec<TaintChainStep>,
    ) -> String {
        let Some(ref tool_ctx) = ctx.tool_context else {
            return "错误：AgentToolContext 未注入".to_string();
        };

        // 所有动作都需要 project_path
        let mut input = params.clone();
        if let Some(obj) = input.as_object_mut() {
            if !obj.contains_key("project_path") {
                obj.insert(
                    "project_path".to_string(),
                    json!(ctx.project_path.to_string_lossy().to_string()),
                );
            }
        }

        let observation = match action {
            "read_context" => {
                let file_path = params["file_path"]
                    .as_str()
                    .unwrap_or(&focus.file_path)
                    .to_string();
                let line = params["line"]
                    .as_u64()
                    .map(|v| v as usize)
                    .unwrap_or(focus.line);
                let radius = params["radius"].as_u64().map(|v| v as usize).unwrap_or(30);

                let start = line.saturating_sub(radius).max(1);
                let end = line + radius;

                let mut read_input = json!({
                    "file_path": file_path,
                    "start_line": start,
                    "end_line": end,
                });
                if let Some(obj) = read_input.as_object_mut() {
                    obj.insert(
                        "project_path".to_string(),
                        json!(ctx.project_path.to_string_lossy().to_string()),
                    );
                }

                match tool_ctx.execute_tool("read_file", read_input).await {
                    Ok(result) => {
                        focus.file_path = file_path;
                        focus.line = line;
                        if result.is_error {
                            format!("读取失败: {}", result.text)
                        } else {
                            result.text
                        }
                    }
                    Err(e) => format!("读取工具调用失败: {}", e),
                }
            }
            "query_callers" | "query_callees" => {
                let tool_name = action;
                match tool_ctx.execute_tool(tool_name, input).await {
                    Ok(result) => {
                        if !result.is_error {
                            // 如果只有一个调用者，可把焦点迁移过去
                            try_update_focus_from_call_result(focus, &result, action);
                        }
                        result.text
                    }
                    Err(e) => format!("调用 {} 失败: {}", tool_name, e),
                }
            }
            "resolve_call" => match tool_ctx.execute_tool("resolve_method_call", input).await {
                Ok(result) => {
                    if !result.is_error {
                        try_update_focus_from_resolve(focus, &result);
                    }
                    result.text
                }
                Err(e) => format!("resolve_method_call 失败: {}", e),
            },
            "check_sanitizer" => {
                let symbol = params["symbol"].as_str().unwrap_or("");
                let vuln_type = params["vuln_type"]
                    .as_str()
                    .unwrap_or(&ctx.finding.vuln_type);
                check_sanitizer(symbol, vuln_type)
            }
            _ => match tool_ctx.execute_tool(action, input).await {
                Ok(result) => {
                    if result.is_error {
                        format!("工具执行出错: {}", result.text)
                    } else {
                        result.text
                    }
                }
                Err(e) => format!("调用工具 {} 失败: {}", action, e),
            },
        };

        // 把本步观察写回污点链，让 LLM 在下一步能看到完整路径
        let step_type = match action {
            "check_sanitizer" if observation.contains("命中 sanitizer") => "sanitizer",
            _ => "propagation",
        };
        chain.push(TaintChainStep {
            step_number: chain.len(),
            file_path: focus.file_path.clone(),
            line: focus.line,
            symbol: focus.symbol.clone(),
            step_type: step_type.to_string(),
            code_snippet: observation.chars().take(1000).collect(),
            reasoning: reasoning.to_string(),
            confidence: if step_type == "sanitizer" { 0.85 } else { 0.6 },
        });

        observation
    }
}

fn available_actions() -> Vec<serde_json::Value> {
    vec![
        json!({
            "action": "read_context",
            "description": "读取焦点附近的代码上下文",
            "params": { "file_path": "string", "line": "integer", "radius": "integer" }
        }),
        json!({
            "action": "query_callers",
            "description": "反向查询谁调用了指定函数",
            "params": { "file_path": "string", "function_name": "string", "recursive": "boolean" }
        }),
        json!({
            "action": "query_callees",
            "description": "正向查询指定函数调用了谁",
            "params": { "file_path": "string", "function_name": "string", "recursive": "boolean" }
        }),
        json!({
            "action": "resolve_call",
            "description": "解析 obj.method() 的实际实现",
            "params": { "file_path": "string", "line": "integer", "receiver": "string", "method": "string" }
        }),
        json!({
            "action": "check_sanitizer",
            "description": "检查某函数/变量是否被认定为 sanitizer",
            "params": { "symbol": "string", "vuln_type": "string" }
        }),
        json!({
            "action": "finish",
            "description": "结束调查并给出判定",
            "params": { "verdict": "string", "confidence": "number", "reasoning": "string", "chain_summary": "string" }
        }),
    ]
}

#[derive(Debug, Clone)]
enum TaintWalkDecision {
    NextAction {
        action: String,
        params: serde_json::Value,
        reasoning: String,
    },
    Finish {
        verdict: Verdict,
        confidence: f64,
        reasoning: String,
        chain_summary: String,
    },
}

fn parse_taint_walk_decision(value: &serde_json::Value) -> Result<TaintWalkDecision> {
    let action = value
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("finish")
        .to_string();

    if action == "finish"
        || value
            .get("finish")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    {
        let verdict = parse_verdict(
            value
                .get("verdict")
                .and_then(|v| v.as_str())
                .unwrap_or("needs_review"),
        );
        let confidence = value
            .get("confidence")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.5)
            .clamp(0.0, 1.0);
        let reasoning = value
            .get("reasoning")
            .and_then(|v| v.as_str())
            .unwrap_or("LLM 未提供理由")
            .to_string();
        let chain_summary = value
            .get("chain_summary")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        return Ok(TaintWalkDecision::Finish {
            verdict,
            confidence,
            reasoning,
            chain_summary,
        });
    }

    let params = value.get("params").cloned().unwrap_or_else(|| json!({}));
    let reasoning = value
        .get("reasoning")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Ok(TaintWalkDecision::NextAction {
        action,
        params,
        reasoning,
    })
}

fn parse_verdict(s: &str) -> Verdict {
    match s {
        "true_positive" => Verdict::TruePositive,
        "false_positive" => Verdict::FalsePositive,
        _ => Verdict::NeedsReview,
    }
}

/// 从 finding 提取一个默认 sink symbol（函数名或变量名占位）
///
/// 优先使用 sink_snippet，然后尝试从 code_snippet / evidence 中提取调用名，
/// 最后回退到 detector 名称。
fn sink_symbol_from_finding(finding: &Finding) -> String {
    if let Some(ref sink) = finding.sink_snippet {
        if !sink.is_empty() {
            return sink.clone();
        }
    }

    // 尝试从代码片段中提取最可能的调用函数名
    let code = finding
        .code_snippet
        .as_deref()
        .or_else(|| finding.source_snippet.as_deref())
        .unwrap_or("");
    if let Some(name) = extract_call_name(code) {
        return name;
    }

    finding.detector.clone()
}

/// 从单行代码片段中提取调用函数名（如 `db.query(sql)` → `query`）
fn extract_call_name(code: &str) -> Option<String> {
    // 优先匹配 object.method(args) 或 function(args)
    let re = regex::Regex::new(r#"(?:(\w+)\s*[.:\s]+)?(\w+)\s*\("#).ok()?;
    let first_line = code.lines().next().unwrap_or(code);
    re.captures(first_line)
        .and_then(|caps| caps.get(2).map(|m| m.as_str().to_string()))
}

/// 将 finding 中的 vuln_type 字符串映射为 core 的 VulnerabilityType
fn vuln_type_to_core(vuln_type: &str) -> Option<VulnerabilityType> {
    let lower = vuln_type.to_lowercase();
    if lower.contains("89") || lower.contains("sql") {
        Some(VulnerabilityType::SqlInjection)
    } else if lower.contains("79") || lower.contains("xss") {
        Some(VulnerabilityType::CrossSiteScripting)
    } else if lower.contains("78") || lower.contains("command") {
        Some(VulnerabilityType::CommandInjection)
    } else if lower.contains("502") || lower.contains("deserialization") {
        Some(VulnerabilityType::InsecureDeserialization)
    } else if lower.contains("22") || lower.contains("path") {
        Some(VulnerabilityType::PathTraversal)
    } else if lower.contains("918") || lower.contains("ssrf") {
        Some(VulnerabilityType::ServerSideRequestForgery)
    } else if lower.contains("94") || lower.contains("code") {
        Some(VulnerabilityType::CodeInjection)
    } else if lower.contains("611") || lower.contains("xxe") {
        Some(VulnerabilityType::XmlExternalEntity)
    } else if lower.contains("90") || lower.contains("ldap") {
        Some(VulnerabilityType::LdapInjection)
    } else if lower.contains("643") || lower.contains("xpath") {
        Some(VulnerabilityType::XPathInjection)
    } else if lower.contains("328") || lower.contains("weak") || lower.contains("hash") {
        Some(VulnerabilityType::WeakHashAlgorithm)
    } else if lower.contains("501") || lower.contains("trust") {
        Some(VulnerabilityType::TrustBoundaryViolation)
    } else if lower.contains("614") || lower.contains("cookie") {
        Some(VulnerabilityType::InsecureCookie)
    } else if lower.contains("117") || lower.contains("log") {
        Some(VulnerabilityType::LogInjection)
    } else if lower.contains("601") || lower.contains("open") {
        Some(VulnerabilityType::OpenRedirect)
    } else if lower.contains("644") || lower.contains("header") {
        Some(VulnerabilityType::HeaderInjection)
    } else {
        None
    }
}

/// 复用 core 的 sanitizer 规则检查 symbol 是否命中净化函数
fn check_sanitizer(symbol: &str, vuln_type: &str) -> String {
    let target = match vuln_type_to_core(vuln_type) {
        Some(t) => t,
        None => {
            return format!(
                "'{}' 未命中 sanitizer（无法识别漏洞类型 '{}'）",
                symbol, vuln_type
            );
        }
    };

    let sanitizers = TaintAnalyzer::default_sanitizers();

    let symbol_lower = symbol.to_lowercase();
    let matched = sanitizers.iter().find(|s| {
        (s.targets.is_empty() || s.targets.contains(&target))
            && symbol_lower.contains(&s.pattern.to_lowercase())
    });

    match matched {
        Some(s) => format!(
            "'{}' 命中 sanitizer '{}'（{}），针对 {:?}",
            symbol, s.pattern, s.description, target
        ),
        None => format!(
            "'{}' 未命中针对 {:?} 的 sanitizer 规则（共 {} 条）",
            symbol,
            target,
            sanitizers.len()
        ),
    }
}

/// 从 query_callers / query_callees 结果中尝试迁移焦点
fn try_update_focus_from_call_result(
    focus: &mut TaintFocus,
    result: &ctx_audit_tools::ToolResult,
    action: &str,
) {
    // 简单启发：解析 JSON 结果，取第一个 caller/callee 的函数名
    if let Some(data) = result.data.as_ref() {
        let key = if action == "query_callers" {
            "callers"
        } else {
            "callees"
        };
        if let Some(arr) = data.get(key).and_then(|v| v.as_array()) {
            if let Some(first) = arr.first() {
                let file = first
                    .get(if action == "query_callers" {
                        "caller_file"
                    } else {
                        "callee_file"
                    })
                    .and_then(|v| v.as_str())
                    .unwrap_or(&focus.file_path)
                    .to_string();
                let function = first
                    .get(if action == "query_callers" {
                        "caller_function"
                    } else {
                        "callee_function"
                    })
                    .and_then(|v| v.as_str())
                    .unwrap_or(&focus.symbol)
                    .to_string();
                let line = first
                    .get(if action == "query_callers" {
                        "caller_line"
                    } else {
                        "callee_line"
                    })
                    .and_then(|v| v.as_u64())
                    .map(|v| v as usize)
                    .unwrap_or(focus.line);
                focus.file_path = file;
                focus.line = line;
                focus.symbol = function;
                focus.role = "propagation".to_string();
            }
        }
    }
}

fn try_update_focus_from_resolve(focus: &mut TaintFocus, result: &ctx_audit_tools::ToolResult) {
    if let Some(data) = result.data.as_ref() {
        if let Some(best) = data.get("best_match") {
            let file = best
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or(&focus.file_path)
                .to_string();
            let function = best
                .get("function_name")
                .and_then(|v| v.as_str())
                .unwrap_or(&focus.symbol)
                .to_string();
            let line = best
                .get("line")
                .and_then(|v| v.as_u64())
                .map(|v| v as usize)
                .unwrap_or(focus.line);
            focus.file_path = file;
            focus.line = line;
            focus.symbol = function;
            focus.role = "propagation".to_string();
        }
    }
}

fn fallback_outcome(
    finding: &Finding,
    evidence: &Evidence,
    steps: Vec<InvestigationStep>,
    chain: &[TaintChainStep],
) -> Result<InvestigationOutcome> {
    // 如果链上出现 source 且无 sanitizer/barrier，判 TP
    let has_source = chain.iter().any(|s| s.step_type == "source");
    let has_sanitizer = chain.iter().any(|s| s.step_type == "sanitizer");
    let verdict = if has_source && !has_sanitizer && !evidence.has_effective_sanitizer {
        Verdict::TruePositive
    } else {
        judge_finding(finding, evidence)
    };

    Ok(InvestigationOutcome {
        verdict,
        confidence: 0.6,
        reasoning: format!(
            "达到最大调查步数。污点链包含 {} 步，source={}, sanitizer={}。使用规则兜底。",
            chain.len(),
            has_source,
            has_sanitizer
        ),
        steps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::evidence::Evidence;
    use crate::agent::llm_client::LlmClient;
    use crate::agent::llm_client::LlmTriageResult;
    use crate::agent::specialist::SpecialistContext;
    use crate::agent::tools::AgentToolContext;
    use async_trait::async_trait;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn mock_finding() -> Finding {
        Finding {
            finding_id: "f1".to_string(),
            file_path: "app.js".to_string(),
            line_start: 5,
            line_end: 5,
            detector: "test".to_string(),
            vuln_type: "CWE-78".to_string(),
            severity: "high".to_string(),
            description: "command injection".to_string(),
            analysis_trail: None,
            llm_output: None,
            confidence: None,
            corroboration_count: None,
            code_snippet: None,
            source_snippet: None,
            sink_snippet: Some("sink".to_string()),
            file_role: Some("production".to_string()),
            barriers: None,
            reasoning_hint: None,
            evidence_refs: None,
        }
    }

    struct MockTaintWalkLlm {
        steps: Vec<serde_json::Value>,
        call_index: AtomicUsize,
    }

    #[async_trait]
    impl LlmClient for MockTaintWalkLlm {
        async fn triage(
            &self,
            _finding: &Finding,
            _evidence: &Evidence,
        ) -> anyhow::Result<LlmTriageResult> {
            Ok(LlmTriageResult {
                verdict: Verdict::NeedsReview,
                confidence: 0.5,
                reasoning: "mock".to_string(),
                suggested_specialist: None,
            })
        }

        async fn chat_json(&self, _prompt: &str) -> anyhow::Result<serde_json::Value> {
            let idx = self.call_index.fetch_add(1, Ordering::SeqCst);
            Ok(self.steps.get(idx).cloned().unwrap_or_else(|| {
                serde_json::json!({
                    "action": "finish",
                    "verdict": "needs_review",
                    "confidence": 0.5,
                    "reasoning": "mock fallback"
                })
            }))
        }
    }

    fn build_context(tool_ctx: Option<AgentToolContext>) -> SpecialistContext {
        SpecialistContext {
            project_path: PathBuf::from("."),
            finding: mock_finding(),
            evidence: Evidence {
                code_context: Some("sink(v)".to_string()),
                ..Evidence::default()
            },
            query_engine: None,
            tool_context: tool_ctx,
        }
    }

    #[tokio::test]
    async fn test_taint_walk_finish_directly() {
        let llm = Arc::new(MockTaintWalkLlm {
            steps: vec![serde_json::json!({
                "action": "finish",
                "verdict": "true_positive",
                "confidence": 0.9,
                "reasoning": "直接判定",
                "chain_summary": "source -> sink"
            })],
            call_index: AtomicUsize::new(0),
        });

        let inv = TaintWalkInvestigator::new(llm, 3);
        let outcome = inv.investigate(&build_context(None), "假设").await.unwrap();

        assert_eq!(outcome.verdict, Verdict::TruePositive);
        assert!((outcome.confidence - 0.9).abs() < f64::EPSILON);
        assert!(outcome.reasoning.contains("直接判定"));
        assert!(outcome.steps.is_empty());
    }

    #[tokio::test]
    async fn test_taint_walk_executes_one_action_then_finishes() {
        let llm = Arc::new(MockTaintWalkLlm {
            steps: vec![
                serde_json::json!({
                    "action": "read_context",
                    "params": { "file_path": "app.js", "line": 5, "radius": 5 },
                    "reasoning": "读取 sink 上下文"
                }),
                serde_json::json!({
                    "action": "finish",
                    "verdict": "false_positive",
                    "confidence": 0.85,
                    "reasoning": "无 source",
                    "chain_summary": ""
                }),
            ],
            call_index: AtomicUsize::new(0),
        });

        let inv = TaintWalkInvestigator::new(llm, 3);
        let outcome = inv.investigate(&build_context(None), "假设").await.unwrap();

        assert_eq!(outcome.verdict, Verdict::FalsePositive);
        assert_eq!(outcome.steps.len(), 1);
        assert_eq!(outcome.steps[0].tool_name, "read_context");
        // 没有 tool_context，读取会失败，但不应 panic
        assert!(
            outcome.steps[0].observation.contains("未注入")
                || outcome.steps[0].observation.contains("错误")
        );
    }

    #[tokio::test]
    async fn test_taint_walk_traces_through_callers_and_callees() {
        // 创建临时项目，包含 source -> handler -> sink 调用链
        let tmp =
            std::env::temp_dir().join(format!("ctx-taint-walk-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let app_js = tmp.join("app.js");
        std::fs::write(
            &app_js,
            r#"function source() { return req.query.id; }
function handler() { let v = source(); sink(v); }
function sink(v) { eval(v); }
"#,
        )
        .unwrap();

        let project_path = tmp.to_string_lossy().to_string();
        let mut analyzer = deepaudit_core::CrossFileTaintAnalyzer::new();
        let result = analyzer.analyze_project(&tmp);
        let engine = Arc::new(deepaudit_core::CallGraphQueryEngine::from_result(&result));
        let tool_ctx = AgentToolContext::new_with_registry(engine, project_path.clone()).await;

        let mut finding = mock_finding();
        finding.file_path = "app.js".to_string();

        let ctx = SpecialistContext {
            project_path: tmp.clone(),
            finding,
            evidence: Evidence {
                code_context: Some("eval(v)".to_string()),
                ..Evidence::default()
            },
            query_engine: None,
            tool_context: Some(tool_ctx),
        };

        let llm = Arc::new(MockTaintWalkLlm {
            steps: vec![
                serde_json::json!({
                    "action": "query_callers",
                    "params": { "file_path": "app.js", "function_name": "sink" },
                    "reasoning": "谁调用了 sink"
                }),
                serde_json::json!({
                    "action": "query_callees",
                    "params": { "file_path": "app.js", "function_name": "handler" },
                    "reasoning": "handler 调用了谁"
                }),
                serde_json::json!({
                    "action": "finish",
                    "verdict": "true_positive",
                    "confidence": 0.9,
                    "reasoning": "source 可达 sink",
                    "chain_summary": "source -> handler -> sink"
                }),
            ],
            call_index: AtomicUsize::new(0),
        });

        let inv = TaintWalkInvestigator::new(llm, 5);
        let outcome = inv.investigate(&ctx, "假设").await.unwrap();

        assert_eq!(outcome.verdict, Verdict::TruePositive);
        assert!(outcome.steps.len() >= 2);
        assert!(
            outcome.steps[0].observation.contains("找到")
                || outcome.steps[0].observation.contains("调用")
        );
        assert!(outcome.reasoning.contains("source 可达 sink"));

        // 清理临时目录
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
