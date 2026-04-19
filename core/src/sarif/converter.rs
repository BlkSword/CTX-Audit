// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! SARIF 转换器
//!
//! 将内部数据模型 (FindingData, TaintFlow) 转换为 SARIF 2.1.0 格式

use super::rules::{built_in_rules, find_rule_index};
use super::types::*;

use crate::analysis::taint::{
    FlowNodeType, FlowLocation, TaintFlow,
};

/// 污点流摘要 — 轻量版，供外部 crate 传递
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TaintFlowSummary {
    /// 污点源
    pub source: FlowLocationSummary,
    /// 污点汇
    pub sink: FlowLocationSummary,
    /// 传播步骤
    pub steps: Vec<FlowStepSummary>,
    /// 漏洞类型
    pub vulnerability_type: String,
    /// 置信度
    pub confidence: f32,
}

/// 流位置摘要
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FlowLocationSummary {
    pub file_path: String,
    pub line: usize,
    pub column: Option<usize>,
    pub symbol: String,
    pub code_snippet: Option<String>,
}

/// 传播步骤摘要
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FlowStepSummary {
    pub step_type: String,
    pub file_path: String,
    pub line: usize,
    pub symbol: String,
    pub code_snippet: Option<String>,
}

/// 修复建议
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FixSuggestion {
    pub description: String,
    pub fix_type: FixType,
    pub old_code: Option<String>,
    pub new_code: Option<String>,
}

/// 修复类型
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum FixType {
    Replacement,
    Wrap,
    Remove,
}

impl std::fmt::Display for FixType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FixType::Replacement => write!(f, "replacement"),
            FixType::Wrap => write!(f, "wrap"),
            FixType::Remove => write!(f, "remove"),
        }
    }
}

/// 漏洞数据 — 供外部 crate 传递给转换器
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FindingInput {
    /// 漏洞 ID
    pub id: Option<String>,
    /// 漏洞标题
    pub title: Option<String>,
    /// 漏洞描述
    pub description: String,
    /// 严重程度 (critical, high, medium, low, info)
    pub severity: String,
    /// 类别
    pub category: String,
    /// CWE ID (如 "CWE-89")
    pub cwe_id: Option<String>,
    /// 文件路径
    pub file_path: String,
    /// 起始行号
    pub start_line: u32,
    /// 结束行号
    pub end_line: Option<u32>,
    /// 起始列号
    pub start_column: Option<u32>,
    /// 结束列号
    pub end_column: Option<u32>,
    /// 代码片段
    pub code_snippet: Option<String>,
    /// 修复建议
    pub recommendation: Option<String>,
    /// 状态
    pub status: String,
    /// 验证状态
    pub verification_status: Option<String>,
    /// 发现者
    pub discovered_by: Option<String>,
    /// 污点路径
    pub code_flows: Option<Vec<TaintFlowSummary>>,
    /// 结构化修复建议
    pub fix_suggestions: Option<Vec<FixSuggestion>>,
    /// 置信度
    pub confidence: Option<f32>,
}

/// SARIF 转换器
pub struct SarifConverter {
    rules: Vec<ReportingDescriptor>,
    tool_name: String,
    tool_version: String,
    tool_info_uri: String,
}

impl SarifConverter {
    /// 创建新的转换器（使用内置规则）
    pub fn new() -> Self {
        Self {
            rules: built_in_rules(),
            tool_name: "CTX-Audit".to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            tool_info_uri: "https://github.com/ctx-audit/ctx-audit".to_string(),
        }
    }

    /// 使用自定义工具信息
    pub fn with_tool_info(
        mut self,
        name: impl Into<String>,
        version: impl Into<String>,
        info_uri: impl Into<String>,
    ) -> Self {
        self.tool_name = name.into();
        self.tool_version = version.into();
        self.tool_info_uri = info_uri.into();
        self
    }

    /// 添加自定义规则
    pub fn add_rule(&mut self, rule: ReportingDescriptor) {
        self.rules.push(rule);
    }

    /// 将漏洞列表转换为完整 SARIF 日志
    pub fn convert(&self, findings: &[FindingInput]) -> SarifLog {
        let invocations = vec![Invocation {
            execution_successful: true,
            start_time: None,
            end_time: Some(chrono::Utc::now().to_rfc3339()),
            exit_code: Some(0),
            tool_execution_notifications: None,
        }];

        let results: Vec<SarifResult> = findings
            .iter()
            .map(|f| self.finding_to_result(f))
            .collect();

        let run = Run {
            tool: Tool {
                driver: ToolComponent {
                    name: self.tool_name.clone(),
                    version: self.tool_version.clone(),
                    information_uri: self.tool_info_uri.clone(),
                    rules: self.rules.clone(),
                },
            },
            invocations,
            results,
            default_severity: None,
        };

        SarifLog::new(vec![run])
    }

    /// 将 SARIF 日志序列化为 JSON 字符串
    pub fn to_json(&self, log: &SarifLog) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(log)?)
    }

    /// 便捷方法：直接从漏洞列表生成 SARIF JSON
    pub fn convert_to_json(&self, findings: &[FindingInput]) -> anyhow::Result<String> {
        let log = self.convert(findings);
        self.to_json(&log)
    }

    /// 单个漏洞 → SARIF Result
    fn finding_to_result(&self, finding: &FindingInput) -> SarifResult {
        let rule_id = finding
            .cwe_id
            .clone()
            .unwrap_or_else(|| "CTX-AUDIT/GENERIC".to_string());

        let rule_index = find_rule_index(&self.rules, &rule_id);

        let level = severity_to_level(&finding.severity);

        let message = Message::new(
            finding
                .title
                .as_deref()
                .unwrap_or(&finding.category),
        );

        let locations = vec![Location {
            physical_location: PhysicalLocation {
                artifact_location: ArtifactLocation {
                    uri: Some(finding.file_path.clone()),
                    uri_base_id: None,
                },
                region: Region {
                    start_line: finding.start_line,
                    start_column: finding.start_column,
                    end_line: finding.end_line,
                    end_column: finding.end_column,
                    byte_offset: None,
                    byte_length: None,
                    snippet: finding.code_snippet.as_ref().map(|s| ArtifactContent {
                        text: s.clone(),
                    }),
                },
            },
        }];

        // 转换污点路径为 CodeFlows
        let code_flows = finding
            .code_flows
            .as_ref()
            .map(|flows| flows.iter().map(taint_flow_to_code_flow).collect())
            .unwrap_or_default();

        // 转换修复建议
        let fixes = finding
            .fix_suggestions
            .as_ref()
            .map(|suggestions| {
                suggestions
                    .iter()
                    .filter_map(|s| fix_suggestion_to_fix(s, &finding.file_path))
                    .collect()
            })
            .unwrap_or_default();

        // 构建属性包
        let mut properties = PropertyBag::new();
        if let Some(ref id) = finding.id {
            properties = properties.with("id".into(), serde_json::json!(id));
        }
        if let Some(conf) = finding.confidence {
            properties = properties.with("confidence".into(), serde_json::json!(conf));
        }
        if let Some(ref status) = finding.verification_status {
            properties =
                properties.with("verificationStatus".into(), serde_json::json!(status));
        }
        if let Some(ref by) = finding.discovered_by {
            properties = properties.with("discoveredBy".into(), serde_json::json!(by));
        }

        SarifResult {
            rule_id,
            rule_index,
            level,
            message,
            locations,
            code_flows,
            fixes,
            related_locations: vec![],
            suppressions: vec![],
            properties: Some(properties),
        }
    }
}

impl Default for SarifConverter {
    fn default() -> Self {
        Self::new()
    }
}

/// 将 TaintFlowSummary 转换为 SARIF CodeFlow
fn taint_flow_to_code_flow(flow: &TaintFlowSummary) -> CodeFlow {
    let mut tf_locations = Vec::new();

    // 源节点
    tf_locations.push(ThreadFlowLocation {
        location: flow_location_to_location(&flow.source),
        module: Some("source".into()),
        nesting_level: 0,
        state: Some(
            PropertyBag::new()
                .with("symbol".into(), serde_json::json!(flow.source.symbol))
                .with(
                    "snippet".into(),
                    serde_json::json!(flow.source.code_snippet),
                ),
        ),
    });

    // 传播步骤
    for (i, step) in flow.steps.iter().enumerate() {
        let module = match step.step_type.as_str() {
            "Sanitization" => "sanitizer",
            _ => "propagation",
        };

        tf_locations.push(ThreadFlowLocation {
            location: Location {
                physical_location: PhysicalLocation {
                    artifact_location: ArtifactLocation {
                        uri: Some(step.file_path.clone()),
                        uri_base_id: None,
                    },
                    region: Region {
                        start_line: step.line as u32,
                        start_column: None,
                        end_line: None,
                        end_column: None,
                        byte_offset: None,
                        byte_length: None,
                        snippet: step.code_snippet.as_ref().map(|s| ArtifactContent {
                            text: s.clone(),
                        }),
                    },
                },
            },
            module: Some(module.to_string()),
            nesting_level: i + 1,
            state: Some(
                PropertyBag::new()
                    .with("symbol".into(), serde_json::json!(step.symbol))
                    .with("stepType".into(), serde_json::json!(step.step_type)),
            ),
        });
    }

    // 汇节点
    tf_locations.push(ThreadFlowLocation {
        location: flow_location_to_location(&flow.sink),
        module: Some("sink".into()),
        nesting_level: flow.steps.len() + 1,
        state: Some(
            PropertyBag::new()
                .with("symbol".into(), serde_json::json!(flow.sink.symbol))
                .with(
                    "snippet".into(),
                    serde_json::json!(flow.sink.code_snippet),
                ),
        ),
    });

    CodeFlow {
        thread_flows: vec![ThreadFlow {
            locations: tf_locations,
        }],
    }
}

/// FlowLocationSummary → SARIF Location
fn flow_location_to_location(loc: &FlowLocationSummary) -> Location {
    Location {
        physical_location: PhysicalLocation {
            artifact_location: ArtifactLocation {
                uri: Some(loc.file_path.clone()),
                uri_base_id: None,
            },
            region: Region {
                start_line: loc.line as u32,
                start_column: loc.column.map(|c| c as u32),
                end_line: None,
                end_column: None,
                byte_offset: None,
                byte_length: None,
                snippet: loc.code_snippet.as_ref().map(|s| ArtifactContent {
                    text: s.clone(),
                }),
            },
        },
    }
}

/// 将内部 TaintFlow 转换为 TaintFlowSummary
pub fn taint_flow_to_summary(flow: &TaintFlow) -> TaintFlowSummary {
    TaintFlowSummary {
        source: FlowLocationSummary {
            file_path: flow.source.file_path.clone(),
            line: flow.source.line,
            column: flow.source.column,
            symbol: flow.source.symbol.clone(),
            code_snippet: flow.source.code_snippet.clone(),
        },
        sink: FlowLocationSummary {
            file_path: flow.sink.file_path.clone(),
            line: flow.sink.line,
            column: flow.sink.column,
            symbol: flow.sink.symbol.clone(),
            code_snippet: flow.sink.code_snippet.clone(),
        },
        steps: flow
            .path
            .iter()
            .filter(|n| {
                !matches!(n.node_type, FlowNodeType::Source | FlowNodeType::Sink)
            })
            .map(|n| FlowStepSummary {
                step_type: match n.node_type {
                    FlowNodeType::Assignment => "Assignment",
                    FlowNodeType::Call => "Call",
                    FlowNodeType::Return => "Return",
                    FlowNodeType::FieldAccess => "FieldAccess",
                    FlowNodeType::IndexAccess => "IndexAccess",
                    FlowNodeType::Sanitized => "Sanitization",
                    FlowNodeType::Statement => "Statement",
                    _ => "Unknown",
                }
                .to_string(),
                file_path: n.file_path.clone(),
                line: n.line,
                symbol: n.symbol.clone(),
                code_snippet: n.code_snippet.clone(),
            })
            .collect(),
        vulnerability_type: format!("{}", flow.vulnerability_type),
        confidence: flow.confidence,
    }
}

/// FixSuggestion → SARIF Fix
fn fix_suggestion_to_fix(
    suggestion: &FixSuggestion,
    file_path: &str,
) -> Option<Fix> {
    // 如果没有 old_code/new_code 对，生成描述性修复
    let (deleted_region, inserted_content) = match &suggestion.fix_type {
        FixType::Replacement => {
            let old = suggestion.old_code.as_ref()?;
            let new = suggestion.new_code.as_ref()?;
            (
                Region {
                    start_line: 0, // 占位，实际需要精确行号
                    start_column: None,
                    end_line: None,
                    end_column: None,
                    byte_offset: None,
                    byte_length: None,
                    snippet: Some(ArtifactContent {
                        text: old.clone(),
                    }),
                },
                Some(ArtifactContent {
                    text: new.clone(),
                }),
            )
        }
        FixType::Wrap => (
            Region {
                start_line: 0,
                start_column: None,
                end_line: None,
                end_column: None,
                byte_offset: None,
                byte_length: None,
                snippet: None,
            },
            suggestion
                .new_code
                .as_ref()
                .map(|c| ArtifactContent { text: c.clone() }),
        ),
        FixType::Remove => (
            Region {
                start_line: 0,
                start_column: None,
                end_line: None,
                end_column: None,
                byte_offset: None,
                byte_length: None,
                snippet: suggestion.old_code.as_ref().map(|c| ArtifactContent {
                    text: c.clone(),
                }),
            },
            None,
        ),
    };

    Some(Fix {
        description: Message::new(&suggestion.description),
        artifact_changes: vec![ArtifactChange {
            artifact_location: ArtifactLocation {
                uri: Some(file_path.to_string()),
                uri_base_id: None,
            },
            replacements: vec![Replacement {
                deleted_region,
                inserted_content,
            }],
        }],
    })
}

/// 严重程度 → SARIF level
fn severity_to_level(severity: &str) -> String {
    match severity.to_lowercase().as_str() {
        "critical" | "high" => "error".to_string(),
        "medium" => "warning".to_string(),
        "low" | "info" => "note".to_string(),
        _ => "none".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_converter_creates_valid_sarif() {
        let converter = SarifConverter::new();
        let findings = vec![FindingInput {
            id: Some("test-1".into()),
            title: Some("SQL Injection".into()),
            description: "User input flows into SQL query".into(),
            severity: "critical".into(),
            category: "SQL Injection".into(),
            cwe_id: Some("CWE-89".into()),
            file_path: "src/main.py".into(),
            start_line: 42,
            end_line: Some(42),
            start_column: None,
            end_column: None,
            code_snippet: Some("cursor.execute(query)".into()),
            recommendation: Some("Use parameterized queries".into()),
            status: "confirmed".into(),
            verification_status: None,
            discovered_by: Some("taint-engine".into()),
            code_flows: None,
            fix_suggestions: None,
            confidence: Some(0.85),
        }];

        let json = converter.convert_to_json(&findings).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(parsed["runs"][0]["results"][0]["ruleId"], "CWE-89");
        assert_eq!(parsed["runs"][0]["results"][0]["level"], "error");
        assert_eq!(
            parsed["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap().len(),
            6
        );
    }

    #[test]
    fn test_taint_flow_to_code_flow() {
        let flow = TaintFlowSummary {
            source: FlowLocationSummary {
                file_path: "a.py".into(),
                line: 1,
                column: None,
                symbol: "request.args".into(),
                code_snippet: Some("id = request.args.get('id')".into()),
            },
            sink: FlowLocationSummary {
                file_path: "a.py".into(),
                line: 3,
                column: None,
                symbol: "cursor.execute".into(),
                code_snippet: Some("cursor.execute(query)".into()),
            },
            steps: vec![FlowStepSummary {
                step_type: "Assignment".into(),
                file_path: "a.py".into(),
                line: 2,
                symbol: "query".into(),
                code_snippet: Some("query = 'SELECT * FROM users WHERE id=' + id".into()),
            }],
            vulnerability_type: "SQL Injection".into(),
            confidence: 0.8,
        };

        let code_flow = taint_flow_to_code_flow(&flow);
        assert_eq!(code_flow.thread_flows.len(), 1);
        assert_eq!(code_flow.thread_flows[0].locations.len(), 3); // source + step + sink
        assert_eq!(
            code_flow.thread_flows[0].locations[0].module,
            Some("source".into())
        );
        assert_eq!(
            code_flow.thread_flows[0].locations[2].module,
            Some("sink".into())
        );
    }

    #[test]
    fn test_empty_findings() {
        let converter = SarifConverter::new();
        let json = converter.convert_to_json(&[]).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["runs"][0]["results"].as_array().unwrap().len(), 0);
        // rules 仍然存在
        assert!(parsed["runs"][0]["tool"]["driver"]["rules"].is_array());
    }

    #[test]
    fn test_severity_mapping() {
        assert_eq!(severity_to_level("critical"), "error");
        assert_eq!(severity_to_level("high"), "error");
        assert_eq!(severity_to_level("medium"), "warning");
        assert_eq!(severity_to_level("low"), "note");
        assert_eq!(severity_to_level("info"), "note");
    }
}
