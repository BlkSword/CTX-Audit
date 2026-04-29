// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 专业安全审计思维链
//!
//! 实现结构化的安全分析思维框架：
//! 假设 → 证据 → 验证 → 结论

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 漏洞类型枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VulnerabilityType {
    /// SQL 注入
    SqlInjection,
    /// 命令注入
    CommandInjection,
    /// 跨站脚本
    Xss,
    /// 路径遍历
    PathTraversal,
    /// SSRF
    Ssrf,
    /// 不安全反序列化
    InsecureDeserialization,
    /// XXE
    Xxe,
    /// 开放重定向
    OpenRedirect,
    /// 敏感数据泄露
    SensitiveDataExposure,
    /// 认证绕过
    AuthBypass,
    /// 授权绕过
    AuthzBypass,
    /// 硬编码密钥
    HardcodedSecret,
    /// 弱加密
    WeakCrypto,
    /// 日志注入
    LogInjection,
    /// LDAP 注入
    LdapInjection,
    /// 自定义类型
    Custom,
}

impl VulnerabilityType {
    /// 获取显示名称
    pub fn display_name(&self) -> &str {
        match self {
            VulnerabilityType::SqlInjection => "SQL 注入",
            VulnerabilityType::CommandInjection => "命令注入",
            VulnerabilityType::Xss => "跨站脚本 (XSS)",
            VulnerabilityType::PathTraversal => "路径遍历",
            VulnerabilityType::Ssrf => "服务端请求伪造 (SSRF)",
            VulnerabilityType::InsecureDeserialization => "不安全反序列化",
            VulnerabilityType::Xxe => "XML 外部实体 (XXE)",
            VulnerabilityType::OpenRedirect => "开放重定向",
            VulnerabilityType::SensitiveDataExposure => "敏感数据泄露",
            VulnerabilityType::AuthBypass => "认证绕过",
            VulnerabilityType::AuthzBypass => "授权绕过",
            VulnerabilityType::HardcodedSecret => "硬编码密钥",
            VulnerabilityType::WeakCrypto => "弱加密算法",
            VulnerabilityType::LogInjection => "日志注入",
            VulnerabilityType::LdapInjection => "LDAP 注入",
            VulnerabilityType::Custom => "其他漏洞",
        }
    }

    /// 获取 CWE ID
    pub fn cwe_id(&self) -> &str {
        match self {
            VulnerabilityType::SqlInjection => "CWE-89",
            VulnerabilityType::CommandInjection => "CWE-78",
            VulnerabilityType::Xss => "CWE-79",
            VulnerabilityType::PathTraversal => "CWE-22",
            VulnerabilityType::Ssrf => "CWE-918",
            VulnerabilityType::InsecureDeserialization => "CWE-502",
            VulnerabilityType::Xxe => "CWE-611",
            VulnerabilityType::OpenRedirect => "CWE-601",
            VulnerabilityType::SensitiveDataExposure => "CWE-200",
            VulnerabilityType::AuthBypass => "CWE-287",
            VulnerabilityType::AuthzBypass => "CWE-863",
            VulnerabilityType::HardcodedSecret => "CWE-798",
            VulnerabilityType::WeakCrypto => "CWE-327",
            VulnerabilityType::LogInjection => "CWE-117",
            VulnerabilityType::LdapInjection => "CWE-90",
            VulnerabilityType::Custom => "CWE-200",
        }
    }

    /// 获取严重程度基准
    pub fn base_severity(&self) -> Severity {
        match self {
            VulnerabilityType::SqlInjection
            | VulnerabilityType::CommandInjection
            | VulnerabilityType::InsecureDeserialization
            | VulnerabilityType::AuthBypass => Severity::Critical,
            VulnerabilityType::Xss
            | VulnerabilityType::PathTraversal
            | VulnerabilityType::Ssrf
            | VulnerabilityType::Xxe
            | VulnerabilityType::AuthzBypass
            | VulnerabilityType::HardcodedSecret => Severity::High,
            VulnerabilityType::OpenRedirect
            | VulnerabilityType::SensitiveDataExposure
            | VulnerabilityType::WeakCrypto
            | VulnerabilityType::LogInjection
            | VulnerabilityType::LdapInjection => Severity::Medium,
            VulnerabilityType::Custom => Severity::Medium,
        }
    }
}

/// 严重程度
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    /// 低危
    Low,
    /// 中危
    Medium,
    /// 高危
    High,
    /// 严重
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// 代码位置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeLocation {
    /// 文件路径
    pub file_path: String,
    /// 起始行
    pub start_line: usize,
    /// 结束行
    pub end_line: Option<usize>,
    /// 起始列
    pub start_col: Option<usize>,
    /// 代码片段
    pub snippet: Option<String>,
}

impl CodeLocation {
    pub fn new(file_path: String, line: usize) -> Self {
        Self {
            file_path,
            start_line: line,
            end_line: None,
            start_col: None,
            snippet: None,
        }
    }

    pub fn with_snippet(mut self, snippet: String) -> Self {
        self.snippet = Some(snippet);
        self
    }
}

/// 数据流步骤
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowStep {
    /// 步骤类型
    pub step_type: DataFlowStepType,
    /// 位置
    pub location: CodeLocation,
    /// 变量名
    pub variable: String,
    /// 相关代码
    pub code: Option<String>,
    /// 描述
    pub description: String,
}

/// 数据流步骤类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataFlowStepType {
    /// 污点源
    Source,
    /// 变量赋值
    Assignment,
    /// 函数参数传递
    ParameterPass,
    /// 函数返回值
    ReturnValue,
    /// 字段访问
    FieldAccess,
    /// 数组/对象索引
    IndexAccess,
    /// 净化处理
    Sanitization,
    /// 污点汇
    Sink,
}

/// 漏洞假设
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityHypothesis {
    /// 假设 ID
    pub id: String,
    /// 漏洞类型
    pub vuln_type: VulnerabilityType,
    /// 假设描述
    pub description: String,
    /// 入口点
    pub entry_point: CodeLocation,
    /// 汇点
    pub sink_point: CodeLocation,
    /// 数据流路径（假设）
    pub data_flow: Vec<DataFlowStep>,
    /// 初始置信度
    pub initial_confidence: f32,
    /// 当前置信度
    pub current_confidence: f32,
    /// 验证状态
    pub status: HypothesisStatus,
    /// 创建时间
    pub created_at: DateTime<Utc>,
    /// 更新时间
    pub updated_at: DateTime<Utc>,
}

impl VulnerabilityHypothesis {
    pub fn new(
        vuln_type: VulnerabilityType,
        entry_point: CodeLocation,
        sink_point: CodeLocation,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string()[..8].to_string(),
            vuln_type,
            description: format!(
                "假设在 {}:{} 存在 {} 漏洞",
                entry_point.file_path,
                entry_point.start_line,
                vuln_type.display_name()
            ),
            entry_point,
            sink_point,
            data_flow: Vec::new(),
            initial_confidence: 0.3,
            current_confidence: 0.3,
            status: HypothesisStatus::Proposed,
            created_at: now,
            updated_at: now,
        }
    }

    /// 添加数据流步骤
    pub fn add_data_flow_step(&mut self, step: DataFlowStep) {
        self.data_flow.push(step);
        self.updated_at = Utc::now();
    }

    /// 更新置信度
    pub fn update_confidence(&mut self, delta: f32, reason: &str) {
        self.current_confidence = (self.current_confidence + delta).clamp(0.0, 1.0);
        self.updated_at = Utc::now();
        // 可以记录原因
    }

    /// 标记为已验证
    pub fn mark_verified(&mut self, confidence: f32) {
        self.current_confidence = confidence;
        self.status = if confidence >= 0.7 {
            HypothesisStatus::Confirmed
        } else if confidence >= 0.4 {
            HypothesisStatus::Likely
        } else {
            HypothesisStatus::Unlikely
        };
        self.updated_at = Utc::now();
    }

    /// 标记为误报
    pub fn mark_false_positive(&mut self, reason: &str) {
        self.status = HypothesisStatus::FalsePositive;
        self.current_confidence = 0.0;
        self.updated_at = Utc::now();
    }
}

/// 假设状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HypothesisStatus {
    /// 已提出
    Proposed,
    /// 正在验证
    Verifying,
    /// 可能存在
    Likely,
    /// 已确认
    Confirmed,
    /// 不太可能
    Unlikely,
    /// 误报
    FalsePositive,
    /// 需要更多信息
    NeedsMoreInfo,
}

/// 证据类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EvidenceType {
    /// 代码模式匹配
    PatternMatch,
    /// 污点分析结果
    TaintFlow,
    /// 数据流追踪
    DataFlowTrace,
    /// 函数调用链
    CallChain,
    /// 配置问题
    Configuration,
    /// 依赖漏洞
    Dependency,
    /// LLM 分析结论
    LLMAnalysis,
}

/// 证据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// 证据 ID
    pub id: String,
    /// 关联的假设 ID
    pub hypothesis_id: String,
    /// 证据类型
    pub evidence_type: EvidenceType,
    /// 证据位置
    pub location: CodeLocation,
    /// 证据内容
    pub content: String,
    /// 对假设的支持程度 (-1.0 到 1.0)
    pub support_score: f32,
    /// 发现时间
    pub discovered_at: DateTime<Utc>,
    /// 来源工具
    pub source_tool: String,
}

impl Evidence {
    pub fn new(
        hypothesis_id: &str,
        evidence_type: EvidenceType,
        location: CodeLocation,
        content: String,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string()[..8].to_string(),
            hypothesis_id: hypothesis_id.to_string(),
            evidence_type,
            location,
            content,
            support_score: 0.0,
            discovered_at: Utc::now(),
            source_tool: "unknown".to_string(),
        }
    }

    pub fn with_support(mut self, score: f32) -> Self {
        self.support_score = score.clamp(-1.0, 1.0);
        self
    }

    pub fn with_source(mut self, tool: &str) -> Self {
        self.source_tool = tool.to_string();
        self
    }
}

/// 验证结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// 关联的假设 ID
    pub hypothesis_id: String,
    /// 验证方法
    pub method: VerificationMethod,
    /// 验证结论
    pub conclusion: VerificationConclusion,
    /// 置信度
    pub confidence: f32,
    /// 详细说明
    pub details: String,
    /// PoC 代码（如果生成）
    pub poc_code: Option<String>,
    /// 验证时间
    pub verified_at: DateTime<Utc>,
}

/// 验证方法
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerificationMethod {
    /// 静态分析
    StaticAnalysis,
    /// 数据流验证
    DataFlowVerification,
    /// 模式验证
    PatternVerification,
    /// LLM 验证
    LLMVerification,
    /// 人工审查
    ManualReview,
    /// 工具交叉验证
    CrossToolValidation,
}

/// 验证结论
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationConclusion {
    /// 确认存在
    Confirmed,
    /// 可能存在
    Likely,
    /// 不太可能
    Unlikely,
    /// 确认不存在（误报）
    FalsePositive,
    /// 无法确定
    Inconclusive,
}

/// 安全审计思维链
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAuditChain {
    /// 当前阶段
    pub phase: AuditThinkingPhase,
    /// 漏洞假设列表
    pub hypotheses: Vec<VulnerabilityHypothesis>,
    /// 收集的证据
    pub evidence: Vec<Evidence>,
    /// 验证结果
    pub verification_results: Vec<VerificationResult>,
    /// 思考历史
    pub thought_history: Vec<ThoughtRecord>,
    /// 分析上下文
    pub context: AuditContext,
    /// 统计信息
    pub stats: ChainStats,
}

/// 审计思维阶段
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditThinkingPhase {
    /// 信息收集
    InformationGathering,
    /// 假设生成
    HypothesisGeneration,
    /// 证据收集
    EvidenceCollection,
    /// 假设验证
    HypothesisVerification,
    /// 结论形成
    Conclusion,
}

impl AuditThinkingPhase {
    pub fn display_name(&self) -> &str {
        match self {
            AuditThinkingPhase::InformationGathering => "信息收集",
            AuditThinkingPhase::HypothesisGeneration => "假设生成",
            AuditThinkingPhase::EvidenceCollection => "证据收集",
            AuditThinkingPhase::HypothesisVerification => "假设验证",
            AuditThinkingPhase::Conclusion => "结论形成",
        }
    }
}

/// 思考记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThoughtRecord {
    /// 阶段
    pub phase: AuditThinkingPhase,
    /// 思考内容
    pub thought: String,
    /// 推理过程
    pub reasoning: String,
    /// 下一步计划
    pub next_action: Option<String>,
    /// 时间戳
    pub timestamp: DateTime<Utc>,
}

/// 审计上下文
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditContext {
    /// 项目信息
    pub project_info: HashMap<String, String>,
    /// 已分析的入口点
    pub analyzed_entry_points: Vec<String>,
    /// 已识别的净化函数
    pub identified_sanitizers: Vec<String>,
    /// 关注的高风险区域
    pub high_risk_areas: Vec<String>,
    /// 排除的安全区域
    pub excluded_areas: Vec<String>,
}

/// 思维链统计
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChainStats {
    /// 生成假设数
    pub hypotheses_generated: usize,
    /// 确认漏洞数
    pub confirmed_vulnerabilities: usize,
    /// 排除误报数
    pub false_positives_excluded: usize,
    /// 收集证据数
    pub evidence_collected: usize,
    /// 思考迭代数
    pub thought_iterations: usize,
}

impl SecurityAuditChain {
    /// 创建新的审计思维链
    pub fn new() -> Self {
        Self {
            phase: AuditThinkingPhase::InformationGathering,
            hypotheses: Vec::new(),
            evidence: Vec::new(),
            verification_results: Vec::new(),
            thought_history: Vec::new(),
            context: AuditContext::default(),
            stats: ChainStats::default(),
        }
    }

    /// 添加假设
    pub fn add_hypothesis(&mut self, hypothesis: VulnerabilityHypothesis) {
        self.stats.hypotheses_generated += 1;
        self.hypotheses.push(hypothesis);
    }

    /// 获取活跃假设（待验证的）
    pub fn get_active_hypotheses(&self) -> Vec<&VulnerabilityHypothesis> {
        self.hypotheses
            .iter()
            .filter(|h| {
                matches!(
                    h.status,
                    HypothesisStatus::Proposed
                        | HypothesisStatus::Verifying
                        | HypothesisStatus::Likely
                )
            })
            .collect()
    }

    /// 添加证据
    pub fn add_evidence(&mut self, evidence: Evidence) {
        self.stats.evidence_collected += 1;
        self.evidence.push(evidence);
    }

    /// 获取假设的所有证据
    pub fn get_evidence_for_hypothesis(&self, hypothesis_id: &str) -> Vec<&Evidence> {
        self.evidence
            .iter()
            .filter(|e| e.hypothesis_id == hypothesis_id)
            .collect()
    }

    /// 记录思考
    pub fn record_thought(
        &mut self,
        thought: String,
        reasoning: String,
        next_action: Option<String>,
    ) {
        self.stats.thought_iterations += 1;
        self.thought_history.push(ThoughtRecord {
            phase: self.phase,
            thought,
            reasoning,
            next_action,
            timestamp: Utc::now(),
        });
    }

    /// 进入下一阶段
    pub fn advance_phase(&mut self) {
        self.phase = match self.phase {
            AuditThinkingPhase::InformationGathering => AuditThinkingPhase::HypothesisGeneration,
            AuditThinkingPhase::HypothesisGeneration => AuditThinkingPhase::EvidenceCollection,
            AuditThinkingPhase::EvidenceCollection => AuditThinkingPhase::HypothesisVerification,
            AuditThinkingPhase::HypothesisVerification => AuditThinkingPhase::Conclusion,
            AuditThinkingPhase::Conclusion => AuditThinkingPhase::Conclusion,
        };
    }

    /// 计算假设的综合置信度
    pub fn calculate_hypothesis_confidence(&self, hypothesis_id: &str) -> f32 {
        let evidence = self.get_evidence_for_hypothesis(hypothesis_id);
        if evidence.is_empty() {
            return 0.3; // 默认低置信度
        }

        // 计算证据支持分数的加权平均
        let total_weight: f32 = evidence.len() as f32;
        let support_sum: f32 = evidence.iter().map(|e| e.support_score).sum();

        // 将支持分数 (-1 到 1) 映射到置信度 (0 到 1)
        let avg_support = support_sum / total_weight;
        let confidence = (avg_support + 1.0) / 2.0;

        confidence.clamp(0.0, 1.0)
    }

    /// 根据位置计算假设置信度
    pub fn calculate_hypothesis_confidence_by_location(&self, file_path: &str, line: usize) -> f32 {
        // 查找匹配位置的假设
        let hypothesis = self.hypotheses.iter()
            .find(|h| h.entry_point.file_path == file_path && h.entry_point.start_line == line);

        if let Some(h) = hypothesis {
            // 如果假设有证据，使用证据计算置信度
            let evidence = self.get_evidence_for_hypothesis(&h.id);
            if !evidence.is_empty() {
                let support_sum: f32 = evidence.iter().map(|e| e.support_score).sum();
                let avg_support = support_sum / evidence.len() as f32;
                let confidence = (avg_support + 1.0) / 2.0;
                return confidence.clamp(0.0, 1.0);
            }
            // 如果没有证据，返回假设当前置信度
            return h.current_confidence;
        }

        // 如果没有找到假设，返回默认值
        0.3
    }

    /// 获取已确认的漏洞
    pub fn get_confirmed_vulnerabilities(&self) -> Vec<&VulnerabilityHypothesis> {
        self.hypotheses
            .iter()
            .filter(|h| h.status == HypothesisStatus::Confirmed)
            .collect()
    }

    /// 生成思维链摘要
    pub fn generate_summary(&self) -> String {
        format!(
            "[审计思维链摘要]\n\
             当前阶段: {}\n\
             生成假设: {} 个\n\
             确认漏洞: {} 个\n\
             排除误报: {} 个\n\
             收集证据: {} 条\n\
             思考迭代: {} 次",
            self.phase.display_name(),
            self.stats.hypotheses_generated,
            self.stats.confirmed_vulnerabilities,
            self.stats.false_positives_excluded,
            self.stats.evidence_collected,
            self.stats.thought_iterations
        )
    }
}

impl Default for SecurityAuditChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerability_type_severity() {
        assert_eq!(
            VulnerabilityType::SqlInjection.base_severity(),
            Severity::Critical
        );
        assert_eq!(VulnerabilityType::Xss.base_severity(), Severity::High);
        assert_eq!(VulnerabilityType::OpenRedirect.base_severity(), Severity::Medium);
    }

    #[test]
    fn test_hypothesis_creation() {
        let entry = CodeLocation::new("test.py".to_string(), 10);
        let sink = CodeLocation::new("test.py".to_string(), 20);
        let hypothesis = VulnerabilityHypothesis::new(VulnerabilityType::SqlInjection, entry, sink);

        assert_eq!(hypothesis.status, HypothesisStatus::Proposed);
        assert_eq!(hypothesis.vuln_type, VulnerabilityType::SqlInjection);
    }

    #[test]
    fn test_audit_chain() {
        let mut chain = SecurityAuditChain::new();
        assert_eq!(chain.phase, AuditThinkingPhase::InformationGathering);

        chain.advance_phase();
        assert_eq!(chain.phase, AuditThinkingPhase::HypothesisGeneration);

        let hypothesis = VulnerabilityHypothesis::new(
            VulnerabilityType::SqlInjection,
            CodeLocation::new("test.py".to_string(), 10),
            CodeLocation::new("test.py".to_string(), 20),
        );
        chain.add_hypothesis(hypothesis);

        assert_eq!(chain.stats.hypotheses_generated, 1);
    }

    #[test]
    fn test_evidence_support() {
        let mut chain = SecurityAuditChain::new();

        let hypothesis = VulnerabilityHypothesis::new(
            VulnerabilityType::SqlInjection,
            CodeLocation::new("test.py".to_string(), 10),
            CodeLocation::new("test.py".to_string(), 20),
        );
        let hyp_id = hypothesis.id.clone();
        chain.add_hypothesis(hypothesis);

        // 添加支持性证据
        chain.add_evidence(
            Evidence::new(
                &hyp_id,
                EvidenceType::TaintFlow,
                CodeLocation::new("test.py".to_string(), 15),
                "发现完整的污点传播路径".to_string(),
            )
            .with_support(0.8),
        );

        let confidence = chain.calculate_hypothesis_confidence(&hyp_id);
        assert!(confidence > 0.5);
    }
}
