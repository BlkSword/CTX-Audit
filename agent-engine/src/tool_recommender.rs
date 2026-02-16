// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 智能工具推荐系统
//!
//! 根据当前审计状态和上下文推荐最佳工具组合

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::audit_chain::{AuditThinkingPhase, SecurityAuditChain, VulnerabilityType};
use crate::audit_state::{AuditPhase, SecurityAuditState, TargetType};

/// 工具推荐
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolRecommendation {
    /// 工具名称
    pub tool_name: String,
    /// 推荐优先级 (1-10)
    pub priority: u8,
    /// 推荐原因
    pub reason: String,
    /// 建议的参数
    pub suggested_params: Option<serde_json::Value>,
    /// 预期效果
    pub expected_outcome: String,
}

/// 工具组合
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCombo {
    /// 组合名称
    pub name: String,
    /// 工具序列
    pub tools: Vec<ToolSequenceItem>,
    /// 组合描述
    pub description: String,
    /// 适用场景
    pub applicable_scenarios: Vec<String>,
}

/// 工具序列项
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSequenceItem {
    /// 工具名称
    pub tool_name: String,
    /// 执行顺序
    pub order: u8,
    /// 是否必须
    pub required: bool,
    /// 前置条件
    pub precondition: Option<String>,
}

/// 工具推荐器
pub struct ToolRecommender {
    /// 工具效果历史
    effectiveness_history: HashMap<String, f32>,
    /// 工具适用场景
    tool_scenarios: HashMap<String, Vec<ToolScenario>>,
}

/// 工具场景
#[derive(Debug, Clone)]
struct ToolScenario {
    /// 场景类型
    scenario_type: ScenarioType,
    /// 适用条件
    condition: String,
    /// 效果分数
    effectiveness: f32,
}

/// 场景类型
#[derive(Debug, Clone)]
enum ScenarioType {
    /// 漏洞检测
    VulnerabilityDetection,
    /// 数据流追踪
    DataFlowTracing,
    /// 代码理解
    CodeUnderstanding,
    /// 验证确认
    Verification,
}

impl ToolRecommender {
    /// 创建新的推荐器
    pub fn new() -> Self {
        let mut recommender = Self {
            effectiveness_history: HashMap::new(),
            tool_scenarios: HashMap::new(),
        };
        recommender.initialize_scenarios();
        recommender
    }

    /// 初始化工具场景
    fn initialize_scenarios(&mut self) {
        // 污点分析工具场景
        self.tool_scenarios.insert(
            "trace_taint".to_string(),
            vec![
                ToolScenario {
                    scenario_type: ScenarioType::DataFlowTracing,
                    condition: "发现了可疑的用户输入点".to_string(),
                    effectiveness: 0.9,
                },
                ToolScenario {
                    scenario_type: ScenarioType::VulnerabilityDetection,
                    condition: "需要验证 SQL 注入、命令注入等".to_string(),
                    effectiveness: 0.85,
                },
            ],
        );

        // 模式检测工具场景
        self.tool_scenarios.insert(
            "detect_vulnerability_patterns".to_string(),
            vec![
                ToolScenario {
                    scenario_type: ScenarioType::VulnerabilityDetection,
                    condition: "需要快速扫描常见漏洞模式".to_string(),
                    effectiveness: 0.8,
                },
            ],
        );

        // 批量扫描工具场景
        self.tool_scenarios.insert(
            "batch_pattern_scan".to_string(),
            vec![
                ToolScenario {
                    scenario_type: ScenarioType::VulnerabilityDetection,
                    condition: "需要扫描整个项目".to_string(),
                    effectiveness: 0.75,
                },
            ],
        );

        // 全局污点分析工具场景
        self.tool_scenarios.insert(
            "global_taint_analysis".to_string(),
            vec![
                ToolScenario {
                    scenario_type: ScenarioType::DataFlowTracing,
                    condition: "需要跨文件污点追踪".to_string(),
                    effectiveness: 0.85,
                },
            ],
        );
    }

    /// 根据审计状态推荐工具
    pub fn recommend(&self, state: &SecurityAuditState) -> Vec<ToolRecommendation> {
        let mut recommendations = Vec::new();

        match state.current_phase {
            AuditPhase::Initialization => {
                // 初始化阶段：信息收集
                recommendations.push(ToolRecommendation {
                    tool_name: "list_files".to_string(),
                    priority: 10,
                    reason: "首先了解项目结构".to_string(),
                    suggested_params: Some(serde_json::json!({"path": state.project_path})),
                    expected_outcome: "获取项目文件列表".to_string(),
                });
            }
            AuditPhase::DeterministicScan => {
                // 确定性扫描阶段：使用专业分析工具
                recommendations.push(ToolRecommendation {
                    tool_name: "global_taint_analysis".to_string(),
                    priority: 9,
                    reason: "执行全局污点分析，发现候选漏洞".to_string(),
                    suggested_params: Some(serde_json::json!({
                        "project_path": state.project_path
                    })),
                    expected_outcome: "发现污点流和候选漏洞".to_string(),
                });

                recommendations.push(ToolRecommendation {
                    tool_name: "batch_pattern_scan".to_string(),
                    priority: 8,
                    reason: "批量检测常见漏洞模式".to_string(),
                    suggested_params: Some(serde_json::json!({
                        "path": state.project_path
                    })),
                    expected_outcome: "发现模式匹配的漏洞".to_string(),
                });
            }
            AuditPhase::DeepAnalysis => {
                // 深度分析阶段：针对性分析
                let high_priority_candidates = state.get_high_priority_candidates();

                if !high_priority_candidates.is_empty() {
                    for candidate in high_priority_candidates.iter().take(3) {
                        recommendations.push(ToolRecommendation {
                            tool_name: "trace_taint".to_string(),
                            priority: 9,
                            reason: format!(
                                "验证候选漏洞: {}:{}",
                                candidate.file_path, candidate.line
                            ),
                            suggested_params: Some(serde_json::json!({
                                "file_path": candidate.file_path,
                                "entry_line": candidate.line
                            })),
                            expected_outcome: "获取详细的污点传播路径".to_string(),
                        });
                    }
                }

                // 如果有未处理的目标
                if !state.pending_targets.is_empty() {
                    if let Some(target) = state.pending_targets.front() {
                        recommendations.push(ToolRecommendation {
                            tool_name: "read_file".to_string(),
                            priority: 7,
                            reason: format!("分析目标文件: {}", target.file_path),
                            suggested_params: Some(serde_json::json!({
                                "file_path": target.file_path
                            })),
                            expected_outcome: "获取文件内容进行分析".to_string(),
                        });
                    }
                }
            }
            AuditPhase::Verification => {
                // 验证阶段：交叉验证
                for vuln in state.confirmed_vulnerabilities.iter().take(3) {
                    recommendations.push(ToolRecommendation {
                        tool_name: "detect_vulnerability_patterns".to_string(),
                        priority: 8,
                        reason: format!("交叉验证漏洞: {}", vuln.vulnerability_type),
                        suggested_params: Some(serde_json::json!({
                            "path": vuln.file_path
                        })),
                        expected_outcome: "验证漏洞模式存在".to_string(),
                    });
                }
            }
            AuditPhase::Reporting | AuditPhase::Completed => {
                // 报告阶段：无推荐
            }
        }

        // 按优先级排序
        recommendations.sort_by(|a, b| b.priority.cmp(&a.priority));
        recommendations
    }

    /// 根据思维链状态推荐工具
    pub fn recommend_for_chain(&self, chain: &SecurityAuditChain) -> Vec<ToolRecommendation> {
        let mut recommendations = Vec::new();

        match chain.phase {
            AuditThinkingPhase::InformationGathering => {
                recommendations.push(ToolRecommendation {
                    tool_name: "list_files".to_string(),
                    priority: 10,
                    reason: "收集项目结构信息".to_string(),
                    suggested_params: None,
                    expected_outcome: "了解项目布局".to_string(),
                });
                recommendations.push(ToolRecommendation {
                    tool_name: "get_file_structure".to_string(),
                    priority: 9,
                    reason: "提取关键文件的代码结构".to_string(),
                    suggested_params: None,
                    expected_outcome: "识别类、函数、入口点".to_string(),
                });
            }
            AuditThinkingPhase::HypothesisGeneration => {
                // 根据已有信息推荐假设生成工具
                recommendations.push(ToolRecommendation {
                    tool_name: "global_taint_analysis".to_string(),
                    priority: 9,
                    reason: "基于污点分析生成漏洞假设".to_string(),
                    suggested_params: None,
                    expected_outcome: "发现潜在的污点流".to_string(),
                });
                recommendations.push(ToolRecommendation {
                    tool_name: "batch_pattern_scan".to_string(),
                    priority: 8,
                    reason: "基于模式匹配生成漏洞假设".to_string(),
                    suggested_params: None,
                    expected_outcome: "发现漏洞模式匹配".to_string(),
                });
            }
            AuditThinkingPhase::EvidenceCollection => {
                // 为活跃假设收集证据
                for hypothesis in chain.get_active_hypotheses().iter().take(3) {
                    recommendations.push(ToolRecommendation {
                        tool_name: "trace_taint".to_string(),
                        priority: 9,
                        reason: format!(
                            "为假设 {} 收集污点流证据",
                            hypothesis.vuln_type.display_name()
                        ),
                        suggested_params: Some(serde_json::json!({
                            "file_path": hypothesis.entry_point.file_path,
                            "entry_line": hypothesis.entry_point.start_line
                        })),
                        expected_outcome: "获取完整的污点传播路径".to_string(),
                    });
                }
            }
            AuditThinkingPhase::HypothesisVerification => {
                // 交叉验证工具
                recommendations.push(ToolRecommendation {
                    tool_name: "detect_vulnerability_patterns".to_string(),
                    priority: 9,
                    reason: "交叉验证漏洞假设".to_string(),
                    suggested_params: None,
                    expected_outcome: "确认漏洞模式存在".to_string(),
                });
            }
            AuditThinkingPhase::Conclusion => {
                // 结论阶段：无推荐
            }
        }

        recommendations.sort_by(|a, b| b.priority.cmp(&a.priority));
        recommendations
    }

    /// 推荐工具组合
    pub fn recommend_combo(&self, vuln_type: VulnerabilityType) -> ToolCombo {
        match vuln_type {
            VulnerabilityType::SqlInjection => ToolCombo {
                name: "SQL 注入检测组合".to_string(),
                tools: vec![
                    ToolSequenceItem {
                        tool_name: "text_search".to_string(),
                        order: 1,
                        required: true,
                        precondition: Some("搜索 SQL 关键词".to_string()),
                    },
                    ToolSequenceItem {
                        tool_name: "trace_taint".to_string(),
                        order: 2,
                        required: true,
                        precondition: Some("追踪用户输入到 SQL 执行".to_string()),
                    },
                    ToolSequenceItem {
                        tool_name: "detect_vulnerability_patterns".to_string(),
                        order: 3,
                        required: false,
                        precondition: Some("验证 SQL 注入模式".to_string()),
                    },
                ],
                description: "用于检测 SQL 注入漏洞的工具组合".to_string(),
                applicable_scenarios: vec!["Web 应用".to_string(), "数据库操作".to_string()],
            },
            VulnerabilityType::CommandInjection => ToolCombo {
                name: "命令注入检测组合".to_string(),
                tools: vec![
                    ToolSequenceItem {
                        tool_name: "text_search".to_string(),
                        order: 1,
                        required: true,
                        precondition: Some("搜索命令执行函数".to_string()),
                    },
                    ToolSequenceItem {
                        tool_name: "trace_taint".to_string(),
                        order: 2,
                        required: true,
                        precondition: Some("追踪用户输入到命令执行".to_string()),
                    },
                ],
                description: "用于检测命令注入漏洞的工具组合".to_string(),
                applicable_scenarios: vec!["Shell 调用".to_string(), "系统命令".to_string()],
            },
            VulnerabilityType::Xss => ToolCombo {
                name: "XSS 检测组合".to_string(),
                tools: vec![
                    ToolSequenceItem {
                        tool_name: "text_search".to_string(),
                        order: 1,
                        required: true,
                        precondition: Some("搜索 HTML 输出函数".to_string()),
                    },
                    ToolSequenceItem {
                        tool_name: "trace_taint".to_string(),
                        order: 2,
                        required: true,
                        precondition: Some("追踪用户输入到 HTML 输出".to_string()),
                    },
                    ToolSequenceItem {
                        tool_name: "detect_vulnerability_patterns".to_string(),
                        order: 3,
                        required: false,
                        precondition: Some("验证 XSS 模式".to_string()),
                    },
                ],
                description: "用于检测 XSS 漏洞的工具组合".to_string(),
                applicable_scenarios: vec!["Web 前端".to_string(), "模板渲染".to_string()],
            },
            _ => ToolCombo {
                name: "通用漏洞检测组合".to_string(),
                tools: vec![
                    ToolSequenceItem {
                        tool_name: "detect_vulnerability_patterns".to_string(),
                        order: 1,
                        required: true,
                        precondition: None,
                    },
                    ToolSequenceItem {
                        tool_name: "trace_taint".to_string(),
                        order: 2,
                        required: false,
                        precondition: None,
                    },
                ],
                description: "通用漏洞检测工具组合".to_string(),
                applicable_scenarios: vec!["通用".to_string()],
            },
        }
    }

    /// 根据迭代次数推荐下一步工具
    pub fn recommend_by_iteration(&self, iteration: u32, used_tools: &[String]) -> Option<ToolRecommendation> {
        // 检查是否使用过专业分析工具
        let professional_tools = ["trace_taint", "detect_vulnerability_patterns", "global_taint_analysis"];
        let has_used_professional = used_tools.iter().any(|t| professional_tools.contains(&t.as_str()));

        match iteration {
            0..=2 => {
                // 早期迭代：信息收集
                if !used_tools.contains(&"list_files".to_string()) {
                    Some(ToolRecommendation {
                        tool_name: "list_files".to_string(),
                        priority: 10,
                        reason: "首先了解项目结构".to_string(),
                        suggested_params: None,
                        expected_outcome: "获取项目文件列表".to_string(),
                    })
                } else {
                    None
                }
            }
            3..=5 => {
                // 中期迭代：强烈建议使用专业工具
                if !has_used_professional {
                    Some(ToolRecommendation {
                        tool_name: "trace_taint".to_string(),
                        priority: 10,
                        reason: "强烈建议：使用污点分析进行确定性安全分析".to_string(),
                        suggested_params: None,
                        expected_outcome: "获取结构化的污点传播路径".to_string(),
                    })
                } else {
                    None
                }
            }
            _ => {
                // 后期迭代：提醒使用专业工具
                if !has_used_professional {
                    Some(ToolRecommendation {
                        tool_name: "detect_vulnerability_patterns".to_string(),
                        priority: 8,
                        reason: "建议使用模式检测工具验证发现".to_string(),
                        suggested_params: None,
                        expected_outcome: "验证漏洞模式".to_string(),
                    })
                } else {
                    None
                }
            }
        }
    }
}

impl Default for ToolRecommender {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recommender_creation() {
        let recommender = ToolRecommender::new();
        assert!(!recommender.tool_scenarios.is_empty());
    }

    #[test]
    fn test_recommend_by_iteration() {
        let recommender = ToolRecommender::new();

        // 早期迭代
        let rec = recommender.recommend_by_iteration(1, &[]);
        assert!(rec.is_some());
        assert_eq!(rec.unwrap().tool_name, "list_files");

        // 中期迭代，未使用专业工具
        let rec = recommender.recommend_by_iteration(4, &["read_file".to_string()]);
        assert!(rec.is_some());
        assert_eq!(rec.unwrap().tool_name, "trace_taint");

        // 已使用专业工具
        let rec = recommender.recommend_by_iteration(4, &["trace_taint".to_string()]);
        assert!(rec.is_none());
    }

    #[test]
    fn test_recommend_combo() {
        let recommender = ToolRecommender::new();

        let combo = recommender.recommend_combo(VulnerabilityType::SqlInjection);
        assert_eq!(combo.name, "SQL 注入检测组合");
        assert!(!combo.tools.is_empty());
    }
}
