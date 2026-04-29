// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 双重验证系统
//!
//! 实现初次判断 -> 自我质疑 -> 综合判断的三阶段验证流程

use crate::audit_state::VulnerabilityCandidate;
use crate::verification::self_questioner::SelfQuestioner;
use ctx_audit_llm::{LLMClient, LLMMessage, MessageRole, MessageContent};
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// 双重验证系统配置
#[derive(Debug, Clone)]
pub struct DualVerificationConfig {
    /// 是否启用自我质疑
    pub enable_self_questioning: bool,

    /// 是否启用交叉验证
    pub enable_cross_validation: bool,

    /// 自我质疑次数
    pub question_rounds: usize,

    /// 最小置信度阈值
    pub min_confidence_threshold: f32,

    /// 是否使用贪心解码（提高可重现性）
    pub greedy_decoding: bool,
}

impl Default for DualVerificationConfig {
    fn default() -> Self {
        Self {
            enable_self_questioning: true,
            enable_cross_validation: true,
            question_rounds: 2,
            min_confidence_threshold: 0.6,
            greedy_decoding: true,
        }
    }
}

/// 双重验证系统
pub struct DualVerificationSystem {
    /// LLM 客户端
    llm: Arc<dyn LLMClient>,

    /// 自我质疑器
    self_questioner: SelfQuestioner,

    /// 配置
    config: DualVerificationConfig,
}

impl DualVerificationSystem {
    /// 创建新的双重验证系统
    pub fn new(llm: Arc<dyn LLMClient>) -> Self {
        Self::with_config(llm, DualVerificationConfig::default())
    }

    /// 使用配置创建双重验证系统
    pub fn with_config(llm: Arc<dyn LLMClient>, config: DualVerificationConfig) -> Self {
        Self {
            llm: llm.clone(),
            self_questioner: SelfQuestioner::new(llm),
            config,
        }
    }

    /// 验证漏洞候选
    pub async fn verify(
        &self,
        candidate: &VulnerabilityCandidate,
        context: &VerificationContext,
    ) -> EnhancedVerificationResult {
        let start_time = Utc::now();
        let mut confidence_history = Vec::new();

        // === 第一阶段：初次判断 ===
        let primary_judgment = self
            .make_primary_judgment(candidate, context)
            .await;
        confidence_history.push(ConfidenceRecord {
            phase: "primary".to_string(),
            confidence: primary_judgment.confidence,
            timestamp: Utc::now(),
        });

        // === 第二阶段：自我质疑 ===
        let self_questioning = if self.config.enable_self_questioning {
            let questioning_result = self
                .self_questioner
                .question(candidate, &primary_judgment, context)
                .await;

            confidence_history.push(ConfidenceRecord {
                phase: "questioning".to_string(),
                confidence: questioning_result.adjusted_confidence,
                timestamp: Utc::now(),
            });

            questioning_result
        } else {
            SelfQuestioningResult {
                contradictions_found: vec![],
                assumptions_checked: vec![],
                attacker_perspectives: vec![],
                missed_protections: vec![],
                adjusted_confidence: primary_judgment.confidence,
                reasoning: "自我质疑已禁用".to_string(),
            }
        };

        // === 第三阶段：综合判断 ===
        let final_conclusion = self
            .make_final_conclusion(&primary_judgment, &self_questioning)
            .await;

        confidence_history.push(ConfidenceRecord {
            phase: "final".to_string(),
            confidence: final_conclusion.confidence,
            timestamp: Utc::now(),
        });

        EnhancedVerificationResult {
            candidate_id: candidate.id.clone(),
            primary_judgment,
            self_questioning,
            final_conclusion,
            confidence_history,
            verification_duration: Utc::now().signed_duration_since(start_time).num_milliseconds() as u64,
        }
    }

    /// 初次判断
    async fn make_primary_judgment(
        &self,
        candidate: &VulnerabilityCandidate,
        context: &VerificationContext,
    ) -> Judgment {
        // 构建 LLM 提示
        let prompt = self.build_primary_judgment_prompt(candidate, context);

        // 创建 LLM 消息
        let messages = vec![
            LLMMessage {
                role: MessageRole::User,
                content: vec![MessageContent::Text { text: prompt }],
                cache_control: None,
            }
        ];

        // 调用 LLM
        let response = self.llm.generate(messages, 2000, 0.3).await;

        // 解析响应
        match response {
            Ok(resp) => self.parse_judgment_response(self.extract_content(&resp)),
            Err(e) => Judgment {
                is_vulnerable: false,
                confidence: 0.0,
                reasoning: format!("LLM 调用失败: {}", e),
                false_positive_reason: Some("LLM 调用失败".to_string()),
            }
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

    /// 构建初次判断提示
    fn build_primary_judgment_prompt(
        &self,
        candidate: &VulnerabilityCandidate,
        context: &VerificationContext,
    ) -> String {
        let code_snippet = candidate.code_snippet.as_deref().unwrap_or("N/A");
        let call_chain = if context.call_chain.is_empty() {
            "N/A".to_string()
        } else {
            context.call_chain.join(" -> ")
        };
        let data_flow = if context.data_flow.is_empty() {
            "N/A".to_string()
        } else {
            context.data_flow.join(" -> ")
        };

        let taint_evidence_section = match &context.taint_flow_evidence {
            Some(evidence) => format!(
                "\n**确定性污点分析结果**:\n\
                 - 污点源: {} ({}:{}), 代码: {}\n\
                 - 污点汇: {} ({}:{}), 代码: {}\n\
                 - 传播路径: {}\n\
                 - 引擎置信度: {:.0}%\n\
                 - 注意: 确定性引擎已确认该数据流路径存在，请在分析中参考此证据。",
                evidence.source.symbol,
                evidence.source.file_path,
                evidence.source.line,
                evidence.source.code_snippet.as_deref().unwrap_or("N/A"),
                evidence.sink.symbol,
                evidence.sink.file_path,
                evidence.sink.line,
                evidence.sink.code_snippet.as_deref().unwrap_or("N/A"),
                evidence.propagation_summary.join(" → "),
                evidence.confidence * 100.0,
            ),
            None => String::new(),
        };

        format!(
            r#"你是安全审计专家，请分析以下漏洞候选：

**漏洞类型**: {}
**文件路径**: {}
**代码位置**: 第 {} 行
**代码片段**:
```{}
{}
```

**上下文信息**:
- 调用链: {}
- 数据流: {}
{}
请提供：
1. 是否确认这是真实漏洞？(true/false)
2. 置信度 (0.0-1.0)
3. 判断依据
4. 可能的误报原因（如果认为不是漏洞）

以 JSON 格式回复：{{"is_vulnerable": bool, "confidence": float, "reasoning": string, "false_positive_reason": string}}"#,
            candidate.vulnerability_type,
            candidate.file_path,
            candidate.line,
            context.language,
            code_snippet,
            call_chain,
            data_flow,
            taint_evidence_section,
        )
    }

    /// 解析判断响应
    fn parse_judgment_response(&self, response: String) -> Judgment {
        // 尝试解析 JSON
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&response) {
            return Judgment {
                is_vulnerable: parsed["is_vulnerable"].as_bool().unwrap_or(false),
                confidence: parsed["confidence"].as_f64().unwrap_or(0.5) as f32,
                reasoning: parsed["reasoning"].as_str().unwrap_or("").to_string(),
                false_positive_reason: parsed["false_positive_reason"].as_str().map(|s| s.to_string()),
            };
        }

        // 解析失败，返回保守判断
        Judgment {
            is_vulnerable: false,
            confidence: 0.3,
            reasoning: "无法解析 LLM 响应".to_string(),
            false_positive_reason: Some("响应格式错误".to_string()),
        }
    }

    /// 综合判断
    async fn make_final_conclusion(
        &self,
        primary_judgment: &Judgment,
        self_questioning: &SelfQuestioningResult,
    ) -> FinalConclusion {
        // 基于自我质疑结果调整置信度
        let mut adjusted_confidence = self_questioning.adjusted_confidence;

        // 如果发现了矛盾证据或遗漏保护，降低置信度
        let has_contradictions = !self_questioning.contradictions_found.is_empty();
        let has_missed_protections = !self_questioning.missed_protections.is_empty();

        if has_contradictions {
            adjusted_confidence = (adjusted_confidence - 0.1).max(0.0);
        }
        if has_missed_protections {
            adjusted_confidence = (adjusted_confidence - 0.15).max(0.0);
        }

        // 决定最终结论
        let is_confirmed = adjusted_confidence >= self.config.min_confidence_threshold
            && primary_judgment.is_vulnerable;

        FinalConclusion {
            is_confirmed,
            confidence: adjusted_confidence,
            conclusion_type: if is_confirmed {
                ConclusionType::Confirmed
            } else if has_contradictions || has_missed_protections {
                ConclusionType::FalsePositive
            } else {
                ConclusionType::Uncertain
            },
            summary: self.build_conclusion_summary(primary_judgment, self_questioning),
        }
    }

    /// 带确定性证据的综合判断（交叉验证）
    pub async fn verify_with_taint_evidence(
        &self,
        candidate: &VulnerabilityCandidate,
        context: &VerificationContext,
        taint_confidence: Option<f32>,
    ) -> EnhancedVerificationResult {
        // 先执行标准验证流程
        let mut result = self.verify(candidate, context).await;

        // 如果有确定性污点证据，进行交叉验证
        if let Some(det_confidence) = taint_confidence {
            let llm_confirms = result.final_conclusion.is_confirmed;
            let det_confirms = det_confidence >= 0.5;

            match (llm_confirms, det_confirms) {
                // 双方都确认：高置信度
                (true, true) => {
                    let boosted = (result.final_conclusion.confidence * 0.6
                        + det_confidence * 0.4)
                        .min(1.0);
                    result.final_conclusion.confidence = boosted;
                    result.final_conclusion.conclusion_type = ConclusionType::Confirmed;
                    result.final_conclusion.summary.push_str(&format!(
                        "\n[交叉验证] LLM + 确定性引擎均确认，综合置信度: {:.0}%",
                        boosted * 100.0,
                    ));
                }
                // LLM 确认但确定性引擎未确认：中等置信度
                (true, false) => {
                    result.final_conclusion.summary.push_str(
                        "\n[交叉验证] LLM 确认但确定性引擎未发现完整数据流，置信度不变",
                    );
                }
                // 确定性引擎确认但 LLM 否认：标记为待复查
                (false, true) => {
                    result.final_conclusion.conclusion_type = ConclusionType::Uncertain;
                    result.final_conclusion.summary.push_str(
                        "\n[交叉验证] 确定性引擎发现数据流但 LLM 未确认，标记为待复查",
                    );
                }
                // 双方都不确认：误报
                (false, false) => {
                    result.final_conclusion.conclusion_type = ConclusionType::FalsePositive;
                    result.final_conclusion.summary.push_str(
                        "\n[交叉验证] LLM + 确定性引擎均不确认，判定为误报",
                    );
                }
            }
        }

        result
    }

    /// 构建结论摘要
    fn build_conclusion_summary(
        &self,
        primary_judgment: &Judgment,
        self_questioning: &SelfQuestioningResult,
    ) -> String {
        let mut summary = format!("初次判断: {} (置信度: {:.2})\n",
            if primary_judgment.is_vulnerable { "漏洞" } else { "非漏洞" },
            primary_judgment.confidence
        );

        if !self_questioning.contradictions_found.is_empty() {
            summary.push_str(&format!("发现 {} 条矛盾证据\n", self_questioning.contradictions_found.len()));
        }

        if !self_questioning.missed_protections.is_empty() {
            summary.push_str(&format!("发现 {} 处遗漏保护\n", self_questioning.missed_protections.len()));
        }

        summary.push_str(&format!("调整后置信度: {:.2}", self_questioning.adjusted_confidence));

        summary
    }
}

/// 验证上下文
#[derive(Debug, Clone)]
pub struct VerificationContext {
    /// 编程语言
    pub language: String,

    /// 调用链
    pub call_chain: Vec<String>,

    /// 数据流
    pub data_flow: Vec<String>,

    /// 相关文件
    pub related_files: Vec<String>,

    /// 框架信息
    pub framework_info: Option<FrameworkInfo>,

    /// 确定性污点分析结果（AST 引擎输出）
    pub taint_flow_evidence: Option<TaintFlowEvidence>,
}

/// 确定性污点分析证据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintFlowEvidence {
    /// 污点源信息
    pub source: TaintPointInfo,
    /// 污点汇信息
    pub sink: TaintPointInfo,
    /// 传播路径摘要
    pub propagation_summary: Vec<String>,
    /// 确定性引擎置信度 (0.0-1.0)
    pub confidence: f32,
}

/// 污点点信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintPointInfo {
    pub file_path: String,
    pub line: usize,
    pub symbol: String,
    pub code_snippet: Option<String>,
}

/// 框架信息
#[derive(Debug, Clone)]
pub struct FrameworkInfo {
    pub name: String,
    pub version: Option<String>,
    pub security_features: Vec<String>,
}

/// 增强验证结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedVerificationResult {
    /// 候选 ID
    pub candidate_id: String,

    /// 初次判断
    pub primary_judgment: Judgment,

    /// 自我质疑结果
    pub self_questioning: SelfQuestioningResult,

    /// 最终结论
    pub final_conclusion: FinalConclusion,

    /// 置信度历史
    pub confidence_history: Vec<ConfidenceRecord>,

    /// 验证耗时（毫秒）
    pub verification_duration: u64,
}

/// 判断结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Judgment {
    /// 是否是漏洞
    pub is_vulnerable: bool,

    /// 置信度
    pub confidence: f32,

    /// 判断依据
    pub reasoning: String,

    /// 误报原因（如果不是漏洞）
    pub false_positive_reason: Option<String>,
}

/// 自我质疑结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfQuestioningResult {
    /// 发现的矛盾证据
    pub contradictions_found: Vec<ContradictionEvidence>,

    /// 检查的假设
    pub assumptions_checked: Vec<AssumptionCheck>,

    /// 攻击者视角
    pub attacker_perspectives: Vec<AttackerPerspective>,

    /// 遗漏的保护
    pub missed_protections: Vec<MissedProtection>,

    /// 调整后的置信度
    pub adjusted_confidence: f32,

    /// 推理过程
    pub reasoning: String,
}

// 重新导出 self_questioner 模块的类型
pub use crate::verification::self_questioner::{
    ContradictionEvidence, AssumptionCheck, AttackerPerspective, MissedProtection,
};

/// 最终结论
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalConclusion {
    /// 是否确认
    pub is_confirmed: bool,

    /// 最终置信度
    pub confidence: f32,

    /// 结论类型
    pub conclusion_type: ConclusionType,

    /// 结论摘要
    pub summary: String,
}

/// 结论类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConclusionType {
    /// 确认是漏洞
    Confirmed,

    /// 确认是误报
    FalsePositive,

    /// 不确定
    Uncertain,
}

/// 置信度记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceRecord {
    /// 验证阶段
    pub phase: String,

    /// 置信度
    pub confidence: f32,

    /// 时间戳
    pub timestamp: DateTime<Utc>,
}
