// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 自我质疑器
//!
//! 对初次判断进行主动质疑，尝试证伪，降低误报率

use crate::audit_state::VulnerabilityCandidate;
use crate::verification::dual_verification::{Judgment, VerificationContext};
use ctx_audit_llm::{LLMClient, LLMMessage, MessageRole, MessageContent};
use std::sync::Arc;
use serde::{Deserialize, Serialize};

/// 自我质疑器
pub struct SelfQuestioner {
    /// LLM 客户端
    llm: Arc<dyn LLMClient>,
}

impl SelfQuestioner {
    /// 创建新的自我质疑器
    pub fn new(llm: Arc<dyn LLMClient>) -> Self {
        Self { llm }
    }

    /// 对初次判断进行质疑
    pub async fn question(
        &self,
        candidate: &VulnerabilityCandidate,
        primary_judgment: &Judgment,
        context: &VerificationContext,
    ) -> crate::verification::dual_verification::SelfQuestioningResult {
        let mut contradictions_found = Vec::new();
        let mut assumptions_checked = Vec::new();
        let mut attacker_perspectives = Vec::new();
        let mut missed_protections = Vec::new();
        let mut reasoning = String::new();

        // 如果初次判断认为不是漏洞，无需质疑
        if !primary_judgment.is_vulnerable {
            return crate::verification::dual_verification::SelfQuestioningResult {
                contradictions_found,
                assumptions_checked,
                attacker_perspectives,
                missed_protections,
                adjusted_confidence: primary_judgment.confidence,
                reasoning: "初次判断为非漏洞，跳过质疑".to_string(),
            };
        }

        // 执行所有质疑策略
        // 1. 发现矛盾证据
        let contradictions = self.find_contradicting_evidence(candidate, context).await;
        contradictions_found.extend(contradictions);

        // 2. 检查假设
        let assumptions = self.check_assumptions(candidate, primary_judgment, context).await;
        assumptions_checked.extend(assumptions);

        // 3. 攻击者视角分析
        let perspectives = self.analyze_attacker_perspective(candidate, context).await;
        attacker_perspectives.extend(perspectives);

        // 4. 发现遗漏保护
        let protections = self.find_missed_protections(candidate, context).await;
        missed_protections.extend(protections);

        // 计算调整后的置信度
        let adjusted_confidence = self.calculate_adjusted_confidence(
            primary_judgment.confidence,
            &contradictions_found,
            &missed_protections,
        );

        // 构建推理说明
        reasoning = self.build_questioning_reasoning(
            &contradictions_found,
            &assumptions_checked,
            &attacker_perspectives,
            &missed_protections,
        );

        crate::verification::dual_verification::SelfQuestioningResult {
            contradictions_found,
            assumptions_checked,
            attacker_perspectives,
            missed_protections,
            adjusted_confidence,
            reasoning,
        }
    }

    /// 发现矛盾证据
    async fn find_contradicting_evidence(
        &self,
        candidate: &VulnerabilityCandidate,
        context: &VerificationContext,
    ) -> Vec<ContradictionEvidence> {
        let code_snippet = candidate.code_snippet.as_deref().unwrap_or("N/A");
        let prompt = format!(
            r#"你是安全审计专家，请查找以下漏洞判断的**矛盾证据**：

**漏洞类型**: {}
**代码位置**: {}:{}
**代码**:
```{}
{}
```

请查找可能证明这不是漏洞的证据，例如：
1. 输入验证函数
2. 净化/转义函数
3. 框架内置保护
4. 编译时检查
5. 运行时保护

返回 JSON 格式：{{"evidence": [{{"type": string, "description": string, "location": string}}]}}"#,
            candidate.vulnerability_type,
            candidate.file_path,
            candidate.line,
            context.language,
            code_snippet
        );

        let messages = vec![
            LLMMessage {
                role: MessageRole::User,
                content: vec![MessageContent::Text { text: prompt }],
                cache_control: None,
            }
        ];

        let response = self.llm.generate(messages, 2000, 0.3).await;
        match response {
            Ok(resp) => self.parse_contradiction_evidence(self.extract_content(&resp)),
            Err(_) => Vec::new(),
        }
    }

    /// 从 LLMResponse 中提取文本内容
    fn extract_content(&self, response: &ctx_audit_llm::LLMResponse) -> String {
        // LLMResponse.content 是 Vec<MessageContent>
        response.content.iter()
            .filter_map(|mc| {
                if let ctx_audit_llm::MessageContent::Text { text } = mc {
                    Some(text.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// 解析矛盾证据
    fn parse_contradiction_evidence(&self, response: String) -> Vec<ContradictionEvidence> {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&response) {
            if let Some(evidence) = parsed["evidence"].as_array() {
                return evidence.iter().filter_map(|e| {
                    Some(ContradictionEvidence {
                        evidence_type: e["type"].as_str()?.to_string(),
                        description: e["description"].as_str()?.to_string(),
                        location: e["location"].as_str().map(|s| s.to_string()),
                    })
                }).collect();
            }
        }
        Vec::new()
    }

    /// 检查假设
    async fn check_assumptions(
        &self,
        candidate: &VulnerabilityCandidate,
        primary_judgment: &Judgment,
        context: &VerificationContext,
    ) -> Vec<AssumptionCheck> {
        let prompt = format!(
            r#"你是安全审计专家，请检查以下判断的**假设**：

**漏洞判断**: {}

**漏洞候选**:
- 类型: {}
- 位置: {}:{}

请列出初次判断依赖的假设，并验证这些假设是否成立。

返回 JSON 格式：{{"assumptions": [{{"assumption": string, "is_valid": bool, "reasoning": string}}]}}"#,
            primary_judgment.reasoning,
            candidate.vulnerability_type,
            candidate.file_path,
            candidate.line
        );

        let messages = vec![
            LLMMessage {
                role: MessageRole::User,
                content: vec![MessageContent::Text { text: prompt }],
                cache_control: None,
            }
        ];

        let response = self.llm.generate(messages, 2000, 0.3).await;
        match response {
            Ok(resp) => self.parse_assumption_checks(self.extract_content(&resp)),
            Err(_) => Vec::new(),
        }
    }

    /// 解析假设检查
    fn parse_assumption_checks(&self, response: String) -> Vec<AssumptionCheck> {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&response) {
            if let Some(assumptions) = parsed["assumptions"].as_array() {
                return assumptions.iter().filter_map(|a| {
                    Some(AssumptionCheck {
                        assumption: a["assumption"].as_str()?.to_string(),
                        is_valid: a["is_valid"].as_bool().unwrap_or(false),
                        reasoning: a["reasoning"].as_str()?.to_string(),
                    })
                }).collect();
            }
        }
        Vec::new()
    }

    /// 分析攻击者视角
    async fn analyze_attacker_perspective(
        &self,
        candidate: &VulnerabilityCandidate,
        context: &VerificationContext,
    ) -> Vec<AttackerPerspective> {
        let code_snippet = candidate.code_snippet.as_deref().unwrap_or("N/A");
        let prompt = format!(
            r#"你是安全审计专家，请从**攻击者视角**分析以下漏洞：

**漏洞类型**: {}
**代码**:
```{}
{}
```

请分析：
1. 攻击者如何利用这个漏洞？
2. 需要什么条件？
3. 影响范围有多大？
4. 是否有实际利用价值？

返回 JSON 格式：{{"perspectives": [{{"attack_vector": string, "required_conditions": [string], "impact": string, "exploitability": string}}]}}"#,
            candidate.vulnerability_type,
            context.language,
            code_snippet
        );

        let messages = vec![
            LLMMessage {
                role: MessageRole::User,
                content: vec![MessageContent::Text { text: prompt }],
                cache_control: None,
            }
        ];

        let response = self.llm.generate(messages, 2000, 0.3).await;
        match response {
            Ok(resp) => self.parse_attacker_perspectives(self.extract_content(&resp)),
            Err(_) => Vec::new(),
        }
    }

    /// 解析攻击者视角
    fn parse_attacker_perspectives(&self, response: String) -> Vec<AttackerPerspective> {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&response) {
            if let Some(perspectives) = parsed["perspectives"].as_array() {
                return perspectives.iter().filter_map(|p| {
                    Some(AttackerPerspective {
                        attack_vector: p["attack_vector"].as_str()?.to_string(),
                        required_conditions: p["required_conditions"].as_array()?
                            .iter().filter_map(|c| c.as_str().map(|s| s.to_string())).collect(),
                        impact: p["impact"].as_str()?.to_string(),
                        exploitability: p["exploitability"].as_str()?.to_string(),
                    })
                }).collect();
            }
        }
        Vec::new()
    }

    /// 发现遗漏的保护
    async fn find_missed_protections(
        &self,
        candidate: &VulnerabilityCandidate,
        context: &VerificationContext,
    ) -> Vec<MissedProtection> {
        let prompt = format!(
            r#"你是安全审计专家，请查找**遗漏的保护措施**：

**漏洞类型**: {}
**代码位置**: {}:{}
**相关文件**: {:?}

请查找项目中的保护措施，例如：
1. 中间件/拦截器
2. 框架级别的安全设置
3. 全局输入验证
4. CSP/CORS 等安全头

返回 JSON 格式：{{"protections": [{{"type": string, "location": string, "description": string}}]}}"#,
            candidate.vulnerability_type,
            candidate.file_path,
            candidate.line,
            format!("{:?}", context.related_files)
        );

        let messages = vec![
            LLMMessage {
                role: MessageRole::User,
                content: vec![MessageContent::Text { text: prompt }],
                cache_control: None,
            }
        ];

        let response = self.llm.generate(messages, 2000, 0.3).await;
        match response {
            Ok(resp) => self.parse_missed_protections(self.extract_content(&resp)),
            Err(_) => Vec::new(),
        }
    }

    /// 解析遗漏保护
    fn parse_missed_protections(&self, response: String) -> Vec<MissedProtection> {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&response) {
            if let Some(protections) = parsed["protections"].as_array() {
                return protections.iter().filter_map(|p| {
                    Some(MissedProtection {
                        protection_type: p["type"].as_str()?.to_string(),
                        location: p["location"].as_str()?.to_string(),
                        description: p["description"].as_str()?.to_string(),
                    })
                }).collect();
            }
        }
        Vec::new()
    }

    /// 计算调整后的置信度
    fn calculate_adjusted_confidence(
        &self,
        original_confidence: f32,
        contradictions: &[ContradictionEvidence],
        missed_protections: &[MissedProtection],
    ) -> f32 {
        let mut adjusted = original_confidence;

        // 每个矛盾证据降低 15% 置信度
        adjusted -= contradictions.len() as f32 * 0.15;

        // 每个遗漏保护降低 10% 置信度
        adjusted -= missed_protections.len() as f32 * 0.10;

        // 确保在合理范围内
        adjusted.max(0.0).min(1.0)
    }

    /// 构建质疑推理说明
    fn build_questioning_reasoning(
        &self,
        contradictions: &[ContradictionEvidence],
        assumptions: &[AssumptionCheck],
        perspectives: &[AttackerPerspective],
        protections: &[MissedProtection],
    ) -> String {
        let mut reasoning = String::from("自我质疑结果：\n");

        if !contradictions.is_empty() {
            reasoning.push_str(&format!("- 发现 {} 条矛盾证据\n", contradictions.len()));
        }

        let invalid_assumptions = assumptions.iter().filter(|a| !a.is_valid).count();
        if invalid_assumptions > 0 {
            reasoning.push_str(&format!("- {} 条假设不成立\n", invalid_assumptions));
        }

        if !perspectives.is_empty() {
            reasoning.push_str(&format!("- 分析了 {} 种攻击视角\n", perspectives.len()));
        }

        if !protections.is_empty() {
            reasoning.push_str(&format!("- 发现 {} 处遗漏保护\n", protections.len()));
        }

        reasoning
    }
}

/// 质疑策略
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum QuestioningStrategy {
    /// 发现矛盾证据
    FindContradictingEvidence,

    /// 检查假设
    CheckAssumptions,

    /// 攻击者视角
    AttackerPerspective,

    /// 发现遗漏保护
    FindMissedProtections,
}

/// 矛盾证据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContradictionEvidence {
    /// 证据类型
    pub evidence_type: String,

    /// 描述
    pub description: String,

    /// 位置
    pub location: Option<String>,
}

/// 假设检查
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssumptionCheck {
    /// 假设内容
    pub assumption: String,

    /// 是否有效
    pub is_valid: bool,

    /// 推理
    pub reasoning: String,
}

/// 攻击者视角
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackerPerspective {
    /// 攻击向量
    pub attack_vector: String,

    /// 所需条件
    pub required_conditions: Vec<String>,

    /// 影响
    pub impact: String,

    /// 可利用性
    pub exploitability: String,
}

/// 遗漏的保护
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissedProtection {
    /// 保护类型
    pub protection_type: String,

    /// 位置
    pub location: String,

    /// 描述
    pub description: String,
}
