// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! ReAct 风格自主调查器
//!
//! 借鉴 `LLM-AUDIT-SKILL.md` 的调查式协作思想：
//! 给定一个 finding 和假设，Agent 通过多轮工具调用主动收集证据，
//! 每轮由 LLM 决定下一步使用哪个工具，最终输出带完整调查轨迹的结论。

pub mod taint_walk;
pub use taint_walk::TaintWalkInvestigator;

use std::sync::Arc;

use anyhow::{Context, Result};
use serde_json::json;

use deepaudit_core::scanning::Finding;

use crate::agent::evidence::Evidence;
use crate::agent::heuristics::{judge_finding, Verdict};
use crate::agent::llm_client::LlmClient;
use crate::agent::specialist::SpecialistContext;

/// 单步调查记录
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InvestigationStep {
    pub step_number: usize,
    pub tool_name: String,
    pub tool_input: serde_json::Value,
    pub observation: String,
    pub reasoning: String,
    /// 反思：该步骤是否让 LLM 修正了假设或决定重规划
    pub reflection: Option<String>,
}

/// 调查记忆：已执行步骤 + 当前假设
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct InvestigationMemory {
    pub hypothesis: String,
    pub steps: Vec<InvestigationStep>,
}

impl InvestigationMemory {
    pub fn new(hypothesis: impl Into<String>) -> Self {
        Self {
            hypothesis: hypothesis.into(),
            steps: Vec::new(),
        }
    }

    pub fn add_step(&mut self, step: InvestigationStep) {
        self.steps.push(step);
    }

    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
}

/// 调查结论
#[derive(Debug, Clone)]
pub struct InvestigationOutcome {
    pub verdict: Verdict,
    pub confidence: f64,
    pub reasoning: String,
    pub steps: Vec<InvestigationStep>,
}

/// LLM 决策：继续调用工具 或 结束调查
#[derive(Debug, Clone)]
pub enum InvestigationDecision {
    NextTool {
        tool_name: String,
        tool_input: serde_json::Value,
        reasoning: String,
    },
    Finish {
        verdict: Verdict,
        confidence: f64,
        reasoning: String,
    },
}

/// 候选工具描述
#[derive(Debug, Clone)]
pub struct ToolDescription {
    pub name: &'static str,
    pub description: &'static str,
    pub parameters_schema: serde_json::Value,
}

/// ReAct 调查器
pub struct ToolUsingInvestigator {
    max_steps: usize,
    llm_client: Arc<dyn LlmClient>,
}

impl ToolUsingInvestigator {
    pub fn new(llm_client: Arc<dyn LlmClient>, max_steps: usize) -> Self {
        Self {
            max_steps: max_steps.max(1),
            llm_client,
        }
    }

    /// 对单个 finding 执行迭代调查
    pub async fn investigate(
        &self,
        ctx: &SpecialistContext,
        hypothesis: &str,
    ) -> Result<InvestigationOutcome> {
        let mut memory = InvestigationMemory::new(hypothesis);
        let available_tools = build_available_tools(ctx.tool_context.as_ref()).await;

        for step_number in 1..=self.max_steps {
            let decision = self
                .llm_client
                .investigate_decision(&ctx.finding, &ctx.evidence, &memory, &available_tools)
                .await?;

            match decision {
                InvestigationDecision::Finish {
                    verdict,
                    confidence,
                    reasoning,
                } => {
                    return Ok(InvestigationOutcome {
                        verdict,
                        confidence,
                        reasoning,
                        steps: memory.steps,
                    });
                }
                InvestigationDecision::NextTool {
                    tool_name,
                    tool_input,
                    reasoning,
                } => {
                    let observation = self
                        .execute_tool_and_observe(ctx, &tool_name, &tool_input)
                        .await;
                    memory.add_step(InvestigationStep {
                        step_number,
                        tool_name,
                        tool_input,
                        observation,
                        reasoning,
                        reflection: None,
                    });
                }
            }
        }

        // 达到最大步数仍未结束，使用当前证据做兜底判定
        let fallback = fallback_verdict(&ctx.finding, &ctx.evidence, &memory);
        Ok(InvestigationOutcome {
            verdict: fallback.verdict,
            confidence: fallback.confidence,
            reasoning: format!(
                "达到最大调查步数（{}），使用已有证据兜底判定。{}",
                self.max_steps, fallback.reasoning
            ),
            steps: memory.steps,
        })
    }

    async fn execute_tool_and_observe(
        &self,
        ctx: &SpecialistContext,
        tool_name: &str,
        tool_input: &serde_json::Value,
    ) -> String {
        let Some(ref tool_ctx) = ctx.tool_context else {
            return "错误：AgentToolContext 未注入".to_string();
        };

        // 自动注入 project_path（所有候选工具都需要）
        let mut input = tool_input.clone();
        if let Some(obj) = input.as_object_mut() {
            if !obj.contains_key("project_path") {
                obj.insert(
                    "project_path".to_string(),
                    json!(ctx.project_path.to_string_lossy().to_string()),
                );
            }
        }

        match tool_ctx.execute_tool(tool_name, input).await {
            Ok(result) => {
                if result.is_error {
                    format!("工具执行出错：{}", result.text)
                } else {
                    result.text
                }
            }
            Err(e) => format!("调用工具失败：{}", e),
        }
    }
}

/// 候选工具清单：优先从 ToolRegistry 动态拉取真实定义，避免 ToolNotFound
pub async fn build_available_tools(
    tool_context: Option<&crate::agent::tools::AgentToolContext>,
) -> Vec<ToolDescription> {
    if let Some(ctx) = tool_context {
        let definitions = ctx.registry().get_definitions().await;
        let mut tools: Vec<ToolDescription> = definitions
            .into_iter()
            .filter(|d| {
                // 排除报告类/完成类工具，仅保留可用于调查的证据/搜索/文件工具
                !matches!(d.category, ctx_audit_tools::ToolCategory::Reporting)
            })
            .map(tool_definition_to_description)
            .collect();
        if !tools.is_empty() {
            return tools;
        }
    }
    // 退化：注册表未加载时返回核心硬编码工具
    build_hardcoded_tools()
}

fn tool_definition_to_description(def: ctx_audit_tools::ToolDefinition) -> ToolDescription {
    ToolDescription {
        name: def.name.leak(),
        description: def.description.leak(),
        parameters_schema: parameters_to_json_schema(&def.parameters),
    }
}

fn parameters_to_json_schema(params: &[ctx_audit_tools::ToolParameter]) -> serde_json::Value {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();
    for p in params {
        let typ = match p.param_type {
            ctx_audit_tools::ToolParameterType::String => "string",
            ctx_audit_tools::ToolParameterType::Number => "number",
            ctx_audit_tools::ToolParameterType::Integer => "integer",
            ctx_audit_tools::ToolParameterType::Boolean => "boolean",
            ctx_audit_tools::ToolParameterType::Array => "array",
            ctx_audit_tools::ToolParameterType::Object => "object",
        };
        let mut prop = serde_json::json!({
            "type": typ,
            "description": &p.description,
        });
        if let Some(ref items) = p.items {
            prop["items"] = parameters_to_json_schema(std::slice::from_ref(items));
        }
        if let Some(ref props) = p.properties {
            let mut obj = serde_json::Map::new();
            for (k, v) in props {
                obj.insert(
                    k.clone(),
                    parameters_to_json_schema(std::slice::from_ref(v)),
                );
            }
            prop["properties"] = serde_json::Value::Object(obj);
        }
        properties.insert(p.name.clone(), prop);
        if p.required {
            required.push(p.name.clone());
        }
    }
    serde_json::json!({
        "type": "object",
        "properties": properties,
        "required": required,
    })
}

fn build_hardcoded_tools() -> Vec<ToolDescription> {
    vec![
        ToolDescription {
            name: "find_call_path",
            description:
                "在跨文件调用图中查找从 source 函数到 sink 函数的精确调用路径，是确定性可达性证据",
            parameters_schema: json!({
                "source_file": "string",
                "source_function": "string",
                "sink_file": "string",
                "sink_function": "string"
            }),
        },
        ToolDescription {
            name: "query_callers",
            description: "反向追踪：谁调用了指定函数？用于从 sink 回溯到入口点",
            parameters_schema: json!({
                "file_path": "string",
                "function_name": "string"
            }),
        },
        ToolDescription {
            name: "query_callees",
            description: "正向追踪：指定函数调用了谁？",
            parameters_schema: json!({
                "file_path": "string",
                "function_name": "string"
            }),
        },
        ToolDescription {
            name: "trace_variable_flow",
            description: "追踪变量/函数从 source 出发到达的所有 sink",
            parameters_schema: json!({
                "file_path": "string",
                "function_name": "string"
            }),
        },
        ToolDescription {
            name: "get_graph_stats",
            description: "获取调用图统计概览",
            parameters_schema: json!({}),
        },
    ]
}

/// 兜底判定：证据充分则直接判，否则 needs_review
fn fallback_verdict(
    finding: &Finding,
    evidence: &Evidence,
    memory: &InvestigationMemory,
) -> InvestigationOutcome {
    // 如果调查过程中已确认 call_path 且无 barrier/sanitizer → TP
    let has_path = evidence.call_path.is_some()
        || memory
            .steps
            .iter()
            .any(|s| s.tool_name == "find_call_path" && !s.observation.contains("未找到"));

    if evidence.has_effective_sanitizer || !evidence.barriers.is_empty() {
        let barrier_list = if evidence.barriers.is_empty() {
            "有效 sanitizer".to_string()
        } else {
            evidence.barriers.join(", ")
        };
        return InvestigationOutcome {
            verdict: Verdict::FalsePositive,
            confidence: 0.85,
            reasoning: format!("检测到安全屏障/净化器：{}，判定为误报。", barrier_list),
            steps: memory.steps.clone(),
        };
    }

    if has_path {
        return InvestigationOutcome {
            verdict: Verdict::TruePositive,
            confidence: 0.8,
            reasoning: "调用路径存在且无有效防护，判定为真阳性。".to_string(),
            steps: memory.steps.clone(),
        };
    }

    let verdict = judge_finding(finding, evidence);
    InvestigationOutcome {
        verdict,
        confidence: 0.5,
        reasoning: "证据仍不足，使用启发式规则兜底。".to_string(),
        steps: memory.steps.clone(),
    }
}

/// 从字符串解析 InvestigationDecision（保留兼容性，主要供测试使用）
#[allow(dead_code)]
pub fn parse_investigation_decision(text: &str) -> Result<InvestigationDecision> {
    let json_text = match extract_json(text) {
        Ok(t) => t,
        Err(_) => {
            tracing::warn!("Investigator LLM 响应未找到 JSON，回退到 needs_review: {}", text.chars().take(200).collect::<String>());
            return Ok(InvestigationDecision::Finish {
                verdict: Verdict::NeedsReview,
                confidence: 0.5,
                reasoning: "LLM 未返回可解析 JSON，回退到 needs_review".to_string(),
            });
        }
    };
    let value: serde_json::Value = match serde_json::from_str(json_text) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("Investigator LLM 响应 JSON 解析失败 ({}): {}", e, text.chars().take(200).collect::<String>());
            return Ok(InvestigationDecision::Finish {
                verdict: Verdict::NeedsReview,
                confidence: 0.5,
                reasoning: "LLM 返回 JSON 解析失败，回退到 needs_review".to_string(),
            });
        }
    };
    parse_investigation_decision_from_value(value)
}

/// 从 JSON Value 解析 InvestigationDecision
pub fn parse_investigation_decision_from_value(value: serde_json::Value) -> Result<InvestigationDecision> {
    let has_finish = value.get("finish").and_then(|v| v.as_bool()).unwrap_or(false);
    let has_verdict = value.get("verdict").is_some();
    let has_next_tool = value.get("next_tool").is_some();

    // 若显式 finish=true，或提供了 verdict 且没有 next_tool，则视为结束调查
    if has_finish || (has_verdict && !has_next_tool) {
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
        return Ok(InvestigationDecision::Finish {
            verdict,
            confidence,
            reasoning,
        });
    }

    let tool_name = value
        .get("next_tool")
        .and_then(|v| v.as_str())
        .context("LLM 决策缺少 next_tool")?
        .to_string();
    // 兼容 LLM 把 tool_input 写成 JSON 字符串的情况
    let tool_input = match value.get("tool_input") {
        Some(serde_json::Value::String(s)) => {
            serde_json::from_str(s).unwrap_or_else(|_| json!({"raw": s.clone()}))
        }
        Some(v) => v.clone(),
        None => json!({}),
    };
    let reasoning = value
        .get("reasoning")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Ok(InvestigationDecision::NextTool {
        tool_name,
        tool_input,
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

#[allow(dead_code)]
fn extract_json(text: &str) -> Result<&str> {
    if let Some(start) = text.find('{') {
        if let Some(end) = text.rfind('}') {
            return Ok(&text[start..=end]);
        }
    }
    anyhow::bail!("未在 LLM 输出中找到 JSON 块")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::evidence::Evidence;
    use crate::agent::llm_client::{LlmClient, LlmTriageResult};
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
            vuln_type: "CWE-89".to_string(),
            severity: "high".to_string(),
            description: "sqli".to_string(),
            analysis_trail: None,
            llm_output: None,
            confidence: None,
            corroboration_count: None,
            code_snippet: None,
            source_snippet: None,
            sink_snippet: None,
            file_role: Some("production".to_string()),
            barriers: None,
            reasoning_hint: None,
            evidence_refs: None,
        }
    }

    struct MockInvestigationLlm {
        steps: Vec<InvestigationDecision>,
        call_index: AtomicUsize,
    }

    #[async_trait]
    impl LlmClient for MockInvestigationLlm {
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

        async fn investigate_decision(
            &self,
            _finding: &Finding,
            _evidence: &Evidence,
            _memory: &InvestigationMemory,
            _available_tools: &[ToolDescription],
        ) -> Result<InvestigationDecision> {
            let idx = self.call_index.fetch_add(1, Ordering::SeqCst);
            Ok(self
                .steps
                .get(idx)
                .cloned()
                .unwrap_or_else(|| InvestigationDecision::Finish {
                    verdict: Verdict::NeedsReview,
                    confidence: 0.5,
                    reasoning: "mock fallback".to_string(),
                }))
        }
    }

    fn build_tool_context() -> AgentToolContext {
        let source_id = "app.js:source";
        let sink_id = "app.js:sink";
        let mut call_graph = deepaudit_core::taint::CallGraph::new();
        call_graph.add_node(deepaudit_core::taint::CallGraphNode {
            id: source_id.to_string(),
            name: "source".to_string(),
            file_path: "app.js".to_string(),
            start_line: 2,
            end_line: 2,
            parameters: Vec::new(),
            return_type: None,
            calls: Vec::new(),
            called_by: Vec::new(),
            is_external: false,
            is_taint_source: true,
            is_taint_sink: false,
            sink_type: None,
            is_callback: false,
            parent_call_site: None,
        });
        call_graph.add_node(deepaudit_core::taint::CallGraphNode {
            id: sink_id.to_string(),
            name: "sink".to_string(),
            file_path: "app.js".to_string(),
            start_line: 5,
            end_line: 5,
            parameters: Vec::new(),
            return_type: None,
            calls: Vec::new(),
            called_by: Vec::new(),
            is_external: false,
            is_taint_source: false,
            is_taint_sink: true,
            sink_type: None,
            is_callback: false,
            parent_call_site: None,
        });
        call_graph.add_call(source_id, sink_id);

        let engine = Arc::new(deepaudit_core::CallGraphQueryEngine::new(
            Arc::new(call_graph),
            deepaudit_core::analysis::type_hierarchy::TypeHierarchy::new(),
            deepaudit_core::analysis::middleware::MiddlewareModel::new(),
            std::collections::HashMap::new(),
        ));

        // 使用 new_with_registry 需要 async；测试函数中 await
        // 但此处先返回 engine，调用方再构造 tool_context
        AgentToolContext::new(engine)
    }

    #[tokio::test]
    async fn test_parse_investigation_decision() {
        let text = r#"{
            "thought": "需要确认路径",
            "next_tool": "find_call_path",
            "tool_input": {"source_file":"a.js","source_function":"src","sink_file":"b.js","sink_function":"sink"},
            "reasoning": "验证可达性"
        }"#;
        let decision = parse_investigation_decision(text).unwrap();
        match decision {
            InvestigationDecision::NextTool {
                tool_name,
                tool_input,
                ..
            } => {
                assert_eq!(tool_name, "find_call_path");
                assert_eq!(tool_input["source_file"], "a.js");
            }
            _ => panic!("应为 NextTool"),
        }

        let finish =
            r#"{"finish":true,"verdict":"true_positive","confidence":0.9,"reasoning":"路径存在"}"#;
        match parse_investigation_decision(finish).unwrap() {
            InvestigationDecision::Finish {
                verdict,
                confidence,
                ..
            } => {
                assert_eq!(verdict, Verdict::TruePositive);
                assert!((confidence - 0.9).abs() < f64::EPSILON);
            }
            _ => panic!("应为 Finish"),
        }
    }

    #[tokio::test]
    async fn test_investigator_executes_tool_and_reaches_verdict() {
        let tool_ctx =
            AgentToolContext::new_with_registry(build_tool_context().query_engine().clone(), ".")
                .await;
        let mut finding = mock_finding();
        finding.evidence_refs = Some(deepaudit_core::scanning::EvidenceRefs {
            source_sink_path: Some(deepaudit_core::scanning::SourceSinkEvidence {
                source_file: "app.js".to_string(),
                source_function: "source".to_string(),
                source_line: 2,
                source_node_id: None,
                sink_file: "app.js".to_string(),
                sink_function: "sink".to_string(),
                sink_line: 5,
                sink_node_id: None,
                path_length: 0,
                path_steps: Vec::new(),
            }),
            sanitizer_chain: Vec::new(),
            middleware_coverage: Vec::new(),
            graph_snapshot: None,
        });
        let ctx = SpecialistContext {
            project_path: PathBuf::from("."),
            finding,
            evidence: Evidence {
                code_context: Some("db.query(v)".to_string()),
                evidence_refs: None,
                ..Evidence::default()
            },
            query_engine: None,
            tool_context: Some(tool_ctx),
        };

        let steps = vec![
            InvestigationDecision::NextTool {
                tool_name: "find_call_path".to_string(),
                tool_input: json!({
                    "source_file": "app.js",
                    "source_function": "source",
                    "sink_file": "app.js",
                    "sink_function": "sink"
                }),
                reasoning: "验证 source→sink 是否可达".to_string(),
            },
            InvestigationDecision::Finish {
                verdict: Verdict::TruePositive,
                confidence: 0.9,
                reasoning: "调用路径存在，且无防护".to_string(),
            },
        ];
        let llm = Arc::new(MockInvestigationLlm {
            steps,
            call_index: AtomicUsize::new(0),
        });

        let inv = ToolUsingInvestigator::new(llm, 5);
        let outcome = inv.investigate(&ctx, "测试假设").await.unwrap();

        assert_eq!(outcome.verdict, Verdict::TruePositive);
        assert_eq!(outcome.steps.len(), 1);
        assert_eq!(outcome.steps[0].tool_name, "find_call_path");
        assert!(
            outcome.steps[0].observation.contains("找到调用路径")
                || outcome.steps[0].observation.contains("调用路径")
        );
    }
}
