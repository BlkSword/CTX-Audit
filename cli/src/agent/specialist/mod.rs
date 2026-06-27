// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! CWE Specialist Agent 框架
//!
//! 为特定 CWE 类型提供深度判定能力，复用调用图、中间件、sanitizer、文件角色等
//! 项目既有能力生成额外证据。

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use serde_json::json;

use deepaudit_core::scanning::Finding;
use deepaudit_core::CallGraphQueryEngine;

use crate::agent::evidence::Evidence;
use crate::agent::heuristics::Verdict;
use crate::agent::tools::AgentToolContext;

pub mod sqli;
pub mod xss;

pub use sqli::SQLiSpecialist;
pub use xss::XssSpecialist;

/// Specialist 调查上下文
#[derive(Clone)]
pub struct SpecialistContext {
    pub project_path: PathBuf,
    pub finding: Finding,
    pub evidence: Evidence,
    pub query_engine: Option<Arc<CallGraphQueryEngine>>,
    pub tool_context: Option<AgentToolContext>,
}

impl SpecialistContext {
    pub fn code_context(&self) -> Option<&str> {
        self.evidence.code_context.as_deref()
    }

    /// 尝试从 evidence_refs 中提取 source/sink，并用工具查询调用路径
    fn evidence_refs(&self) -> Option<&deepaudit_core::scanning::EvidenceRefs> {
        self.evidence
            .evidence_refs
            .as_ref()
            .or_else(|| self.finding.evidence_refs.as_ref())
    }

    pub fn query_attack_path(&self) -> Option<deepaudit_core::CallPath> {
        let tc = self.tool_context.as_ref()?;
        let refs = self.evidence_refs()?;
        let ss = refs.source_sink_path.as_ref()?;
        tc.try_find_attack_path(
            &ss.source_file,
            &ss.source_function,
            &ss.sink_file,
            &ss.sink_function,
        )
    }

    /// 查询 sink 函数的直接调用者
    pub fn query_sink_callers(&self) -> Vec<deepaudit_core::CallerEvidence> {
        if let (Some(tc), Some(refs)) = (self.tool_context.as_ref(), self.evidence_refs()) {
            if let Some(ref ss) = refs.source_sink_path {
                return tc.query_callers(&ss.sink_file, &ss.sink_function);
            }
        }
        Vec::new()
    }
}

/// Specialist 调查结果
#[derive(Debug, Clone)]
pub struct SpecialistResult {
    pub specialist_name: String,
    pub verdict: Verdict,
    pub confidence: f64,
    pub reasoning: String,
    pub observations: serde_json::Value,
}

/// CWE Specialist trait
#[async_trait]
pub trait Specialist: Send + Sync {
    /// Specialist 唯一名称
    fn name(&self) -> &'static str;

    /// 是否能处理该 finding
    fn can_handle(&self, finding: &Finding) -> bool;

    /// 执行专项调查
    async fn investigate(&self, ctx: SpecialistContext) -> Result<SpecialistResult>;
}

/// Specialist 注册表
#[derive(Default, Clone)]
pub struct SpecialistRegistry {
    specialists: Vec<Arc<dyn Specialist>>,
}

impl SpecialistRegistry {
    pub fn new() -> Self {
        Self {
            specialists: Vec::new(),
        }
    }

    /// 注册内置 Specialist（SQLi、XSS）
    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.register(Arc::new(SQLiSpecialist));
        registry.register(Arc::new(XssSpecialist));
        registry
    }

    pub fn register(&mut self, specialist: Arc<dyn Specialist>) {
        self.specialists.push(specialist);
    }

    /// 根据 finding 的漏洞类型查找所有可处理的 specialist
    pub fn find_handlers(&self, finding: &Finding) -> Vec<Arc<dyn Specialist>> {
        self.specialists
            .iter()
            .filter(|s| s.can_handle(finding))
            .cloned()
            .collect()
    }

    /// 按名称查找 specialist
    pub fn get(&self, name: &str) -> Option<Arc<dyn Specialist>> {
        self.specialists.iter().find(|s| s.name() == name).cloned()
    }
}

/// 将 verdict 与 confidence 融合：specialist 置信度更高时采用 specialist 判定
pub fn merge_specialist_verdict(
    base_verdict: Verdict,
    base_confidence: f64,
    specialist: &SpecialistResult,
) -> (Verdict, f64) {
    if specialist.confidence > base_confidence {
        (specialist.verdict, specialist.confidence)
    } else {
        (base_verdict, base_confidence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_finding(vuln_type: &str) -> Finding {
        Finding {
            finding_id: "test-1".to_string(),
            file_path: "app.js".to_string(),
            line_start: 10,
            line_end: 10,
            detector: "test".to_string(),
            vuln_type: vuln_type.to_string(),
            severity: "high".to_string(),
            description: "test finding".to_string(),
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

    #[test]
    fn test_registry_routes_by_vuln_type() {
        let registry = SpecialistRegistry::with_defaults();

        let sqli = registry.find_handlers(&dummy_finding("CWE-89"));
        assert_eq!(sqli.len(), 1);
        assert_eq!(sqli[0].name(), "sqli");

        let xss = registry.find_handlers(&dummy_finding("CWE-79"));
        assert_eq!(xss.len(), 1);
        assert_eq!(xss[0].name(), "xss");

        let generic = registry.find_handlers(&dummy_finding("CWE-22"));
        assert!(generic.is_empty());
    }

    #[test]
    fn test_registry_name_lookup() {
        let registry = SpecialistRegistry::with_defaults();
        assert!(registry.get("sqli").is_some());
        assert!(registry.get("xss").is_some());
        assert!(registry.get("ssrf").is_none());
    }

    #[test]
    fn test_merge_specialist_verdict() {
        let specialist = SpecialistResult {
            specialist_name: "sqli".to_string(),
            verdict: Verdict::TruePositive,
            confidence: 0.95,
            reasoning: "sqli".to_string(),
            observations: json!({}),
        };

        let (v, c) = merge_specialist_verdict(Verdict::NeedsReview, 0.5, &specialist);
        assert_eq!(v, Verdict::TruePositive);
        assert!((c - 0.95).abs() < f64::EPSILON);

        let (v2, c2) = merge_specialist_verdict(Verdict::FalsePositive, 0.95, &specialist);
        // 置信度相同时保留基础判定
        assert_eq!(v2, Verdict::FalsePositive);
        assert!((c2 - 0.95).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_specialist_uses_tool_context_to_find_path() {
        use std::sync::Arc;

        // 构造一个确定性调用图：app.js:source -> app.js:sink
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
        let tool_context = Some(crate::agent::tools::AgentToolContext::new(engine));

        let mut finding = dummy_finding("CWE-89");
        finding.evidence_refs = Some(deepaudit_core::scanning::EvidenceRefs {
            source_sink_path: Some(deepaudit_core::scanning::SourceSinkEvidence {
                source_file: "app.js".to_string(),
                source_function: "source".to_string(),
                source_line: 2,
                sink_file: "app.js".to_string(),
                sink_function: "sink".to_string(),
                sink_line: 5,
                path_length: 0,
                path_steps: Vec::new(),
            }),
            sanitizer_chain: Vec::new(),
            middleware_coverage: Vec::new(),
            graph_snapshot: None,
        });

        let ctx = SpecialistContext {
            project_path: std::path::PathBuf::from("."),
            finding,
            evidence: Evidence {
                code_context: Some("db.query(v)".to_string()),
                evidence_refs: None,
                ..Evidence::default()
            },
            query_engine: None,
            tool_context,
        };

        let res = SQLiSpecialist.investigate(ctx).await.unwrap();
        assert_eq!(res.verdict, Verdict::TruePositive);
        assert!(
            res.reasoning.contains("工具查询") || res.reasoning.contains("调用路径"),
            "specialist 应说明通过工具查询确认路径: {}",
            res.reasoning
        );
    }
}
