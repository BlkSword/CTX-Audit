// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 专业安全审计状态管理
//!
//! 实现阶段化、目标导向的审计流程

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

/// 审计阶段
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditPhase {
    /// 初始化阶段 - 项目扫描、技术栈识别
    Initialization,
    /// 确定性扫描阶段 - 污点分析、模式检测
    DeterministicScan,
    /// 深度分析阶段 - LLM 驱动的漏洞验证
    DeepAnalysis,
    /// 验证阶段 - 漏洞验证和 PoC 生成
    Verification,
    /// 报告阶段 - 生成最终报告
    Reporting,
    /// 已完成
    Completed,
}

impl std::fmt::Display for AuditPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditPhase::Initialization => write!(f, "初始化"),
            AuditPhase::DeterministicScan => write!(f, "确定性扫描"),
            AuditPhase::DeepAnalysis => write!(f, "深度分析"),
            AuditPhase::Verification => write!(f, "验证"),
            AuditPhase::Reporting => write!(f, "报告"),
            AuditPhase::Completed => write!(f, "已完成"),
        }
    }
}

/// 分析目标优先级
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TargetPriority {
    /// 低优先级
    Low = 1,
    /// 中等优先级
    Medium = 2,
    /// 高优先级
    High = 3,
    /// 关键优先级
    Critical = 4,
}

/// 分析目标
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisTarget {
    /// 目标 ID
    pub id: String,

    /// 目标类型
    pub target_type: TargetType,

    /// 文件路径
    pub file_path: String,

    /// 起始行
    pub start_line: Option<usize>,

    /// 结束行
    pub end_line: Option<usize>,

    /// 优先级
    pub priority: TargetPriority,

    /// 状态
    pub status: TargetStatus,

    /// 关联的候选漏洞
    pub candidate_vulnerabilities: Vec<String>,

    /// 分析原因
    pub reason: String,

    /// 创建时间
    pub created_at: DateTime<Utc>,

    /// 完成时间
    pub completed_at: Option<DateTime<Utc>>,
}

/// 目标类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TargetType {
    /// 文件
    File,
    /// 函数
    Function,
    /// 类/模块
    Class,
    /// API 端点
    ApiEndpoint,
    /// 入口点
    EntryPoint,
    /// 数据流路径
    DataFlowPath,
}

/// 目标状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetStatus {
    /// 待处理
    Pending,
    /// 处理中
    InProgress,
    /// 已完成 - 发现漏洞
    CompletedWithFindings,
    /// 已完成 - 无漏洞
    CompletedClean,
    /// 跳过
    Skipped,
    /// 失败
    Failed,
}

/// 候选漏洞（来自确定性扫描）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityCandidate {
    /// 候选 ID
    pub id: String,

    /// 漏洞类型
    pub vulnerability_type: String,

    /// 严重程度
    pub severity: String,

    /// 置信度 (0.0 - 1.0)
    pub confidence: f32,

    /// 来源 (taint_analysis, pattern_detection, etc.)
    pub source: String,

    /// 文件路径
    pub file_path: String,

    /// 行号
    pub line: usize,

    /// 代码片段
    pub code_snippet: Option<String>,

    /// 传播路径 (如果是污点分析)
    pub propagation_path: Option<Vec<PropagationStepInfo>>,

    /// 验证状态
    pub verification_status: VerificationStatus,

    /// 验证结果
    pub verification_result: Option<String>,
}

/// 传播步骤信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationStepInfo {
    /// 行号
    pub line: usize,
    /// 变量
    pub symbol: String,
    /// 代码
    pub code: Option<String>,
}

/// 验证状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationStatus {
    /// 待验证
    Pending,
    /// 已确认
    Confirmed,
    /// 可能是误报
    LikelyFalsePositive,
    /// 确认误报
    FalsePositive,
    /// 需要更多信息
    NeedsMoreInfo,
}

/// 项目信息
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectInfo {
    /// 项目类型
    pub project_type: Option<String>,

    /// 技术栈
    pub tech_stack: Vec<String>,

    /// 入口点
    pub entry_points: Vec<String>,

    /// 框架
    pub frameworks: Vec<String>,

    /// 数据库类型
    pub databases: Vec<String>,

    /// 认证机制
    pub auth_mechanisms: Vec<String>,

    /// 敏感文件
    pub sensitive_files: Vec<String>,

    /// 依赖项
    pub dependencies: Vec<DependencyInfo>,
}

/// 依赖信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyInfo {
    pub name: String,
    pub version: Option<String>,
    pub is_dev: bool,
}

/// 安全审计状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAuditState {
    // ========== 基本信息 ==========
    /// 项目路径
    pub project_path: String,

    /// 会话 ID
    pub session_id: String,

    /// 开始时间
    pub started_at: DateTime<Utc>,

    /// 最后更新时间
    pub updated_at: DateTime<Utc>,

    // ========== 阶段管理 ==========
    /// 当前阶段
    pub current_phase: AuditPhase,

    /// 阶段历史
    pub phase_history: Vec<PhaseRecord>,

    // ========== 项目信息 ==========
    /// 项目信息
    pub project_info: ProjectInfo,

    // ========== 目标管理 ==========
    /// 待处理的目标队列
    pub pending_targets: VecDeque<AnalysisTarget>,

    /// 正在处理的目标
    pub current_target: Option<AnalysisTarget>,

    /// 已完成的目标
    pub completed_targets: Vec<AnalysisTarget>,

    /// 已分析的文件集合
    pub analyzed_files: HashSet<String>,

    // ========== 漏洞管理 ==========
    /// 候选漏洞（来自确定性扫描）
    pub vulnerability_candidates: Vec<VulnerabilityCandidate>,

    /// 已确认的漏洞
    pub confirmed_vulnerabilities: Vec<VulnerabilityCandidate>,

    /// 误报列表
    pub false_positives: Vec<VulnerabilityCandidate>,

    // ========== 上下文管理 ==========
    /// 工作记忆 - 存储重要发现供后续参考
    pub working_memory: HashMap<String, serde_json::Value>,

    /// 分析上下文 - 累积的发现
    pub analysis_context: AnalysisContext,

    // ========== 统计信息 ==========
    /// 统计
    pub stats: AuditStats,
}

/// 阶段记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseRecord {
    pub phase: AuditPhase,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub summary: Option<String>,
}

/// 分析上下文
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnalysisContext {
    /// 发现的敏感函数调用
    pub sensitive_functions: Vec<SensitiveFunctionCall>,

    /// 发现的用户输入点
    pub user_input_points: Vec<UserInputPoint>,

    /// 发现的数据流路径
    pub data_flow_paths: Vec<DataFlowPathInfo>,

    /// 关注点（需要深入分析）
    pub focus_areas: Vec<String>,

    /// 排除的文件（已确认安全）
    pub excluded_files: Vec<String>,
}

/// 敏感函数调用
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitiveFunctionCall {
    pub function_name: String,
    pub file_path: String,
    pub line: usize,
    pub risk_category: String,
}

/// 用户输入点
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInputPoint {
    pub source_type: String, // HTTP param, file input, env var, etc.
    pub file_path: String,
    pub line: usize,
    pub variable_name: String,
}

/// 数据流路径信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowPathInfo {
    pub source_file: String,
    pub source_line: usize,
    pub sink_file: String,
    pub sink_line: usize,
    pub vulnerability_type: String,
}

/// 审计统计
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditStats {
    /// LLM 调用次数
    pub llm_calls: u32,

    /// 工具调用次数
    pub tool_calls: u32,

    /// 确定性扫描发现数
    pub deterministic_findings: usize,

    /// 已确认漏洞数
    pub confirmed_findings: usize,

    /// 误报数
    pub false_positives: usize,

    /// 分析的文件数
    pub files_analyzed: usize,

    /// 分析的代码行数
    pub lines_analyzed: usize,

    /// 总耗时（毫秒）
    pub total_duration_ms: u64,
}

impl SecurityAuditState {
    /// 创建新的审计状态
    pub fn new(project_path: String) -> Self {
        let now = Utc::now();
        Self {
            project_path,
            session_id: uuid::Uuid::new_v4().to_string(),
            started_at: now,
            updated_at: now,
            current_phase: AuditPhase::Initialization,
            phase_history: Vec::new(),
            project_info: ProjectInfo::default(),
            pending_targets: VecDeque::new(),
            current_target: None,
            completed_targets: Vec::new(),
            analyzed_files: HashSet::new(),
            vulnerability_candidates: Vec::new(),
            confirmed_vulnerabilities: Vec::new(),
            false_positives: Vec::new(),
            working_memory: HashMap::new(),
            analysis_context: AnalysisContext::default(),
            stats: AuditStats::default(),
        }
    }

    /// 切换到新阶段
    pub fn transition_to(&mut self, new_phase: AuditPhase) {
        // 记录当前阶段的完成
        if let Some(last_record) = self.phase_history.last_mut() {
            if last_record.completed_at.is_none() {
                last_record.completed_at = Some(Utc::now());
            }
        }

        // 创建新阶段记录
        self.phase_history.push(PhaseRecord {
            phase: new_phase,
            started_at: Utc::now(),
            completed_at: None,
            summary: None,
        });

        self.current_phase = new_phase;
        self.updated_at = Utc::now();
    }

    /// 添加分析目标
    pub fn add_target(&mut self, target: AnalysisTarget) {
        // 避免重复添加已分析的文件
        if self.analyzed_files.contains(&target.file_path) {
            return;
        }

        // 按优先级插入
        let priority = target.priority;
        let insert_pos = self.pending_targets
            .iter()
            .position(|t| t.priority < priority)
            .unwrap_or(self.pending_targets.len());

        self.pending_targets.insert(insert_pos, target);
        self.updated_at = Utc::now();
    }

    /// 获取下一个目标
    pub fn get_next_target(&mut self) -> Option<AnalysisTarget> {
        if let Some(target) = self.pending_targets.pop_front() {
            self.current_target = Some(target.clone());
            self.analyzed_files.insert(target.file_path.clone());
            Some(target)
        } else {
            None
        }
    }

    /// 完成当前目标
    pub fn complete_current_target(&mut self, status: TargetStatus) {
        if let Some(mut target) = self.current_target.take() {
            target.status = status;
            target.completed_at = Some(Utc::now());
            self.completed_targets.push(target);
            self.updated_at = Utc::now();
        }
    }

    /// 添加候选漏洞
    pub fn add_vulnerability_candidate(&mut self, candidate: VulnerabilityCandidate) {
        self.vulnerability_candidates.push(candidate);
        self.stats.deterministic_findings = self.vulnerability_candidates.len();
        self.updated_at = Utc::now();
    }

    /// 确认漏洞
    pub fn confirm_vulnerability(&mut self, candidate_id: &str) {
        if let Some(pos) = self.vulnerability_candidates.iter().position(|c| c.id == candidate_id) {
            let mut candidate = self.vulnerability_candidates.remove(pos);
            candidate.verification_status = VerificationStatus::Confirmed;
            self.confirmed_vulnerabilities.push(candidate);
            self.stats.confirmed_findings = self.confirmed_vulnerabilities.len();
            self.updated_at = Utc::now();
        }
    }

    /// 标记为误报
    pub fn mark_false_positive(&mut self, candidate_id: &str, reason: Option<String>) {
        if let Some(pos) = self.vulnerability_candidates.iter().position(|c| c.id == candidate_id) {
            let mut candidate = self.vulnerability_candidates.remove(pos);
            candidate.verification_status = VerificationStatus::FalsePositive;
            candidate.verification_result = reason;
            self.false_positives.push(candidate);
            self.stats.false_positives = self.false_positives.len();
            self.updated_at = Utc::now();
        }
    }

    /// 获取待验证的高优先级候选
    pub fn get_high_priority_candidates(&self) -> Vec<&VulnerabilityCandidate> {
        self.vulnerability_candidates
            .iter()
            .filter(|c| c.verification_status == VerificationStatus::Pending && c.confidence >= 0.5)
            .collect()
    }

    /// 存储工作记忆
    pub fn set_memory(&mut self, key: &str, value: serde_json::Value) {
        self.working_memory.insert(key.to_string(), value);
        self.updated_at = Utc::now();
    }

    /// 获取工作记忆
    pub fn get_memory(&self, key: &str) -> Option<&serde_json::Value> {
        self.working_memory.get(key)
    }

    /// 更新统计
    pub fn increment_stat(&mut self, stat: &str) {
        match stat {
            "llm_calls" => self.stats.llm_calls += 1,
            "tool_calls" => self.stats.tool_calls += 1,
            "files_analyzed" => self.stats.files_analyzed += 1,
            _ => {}
        }
        self.updated_at = Utc::now();
    }

    /// 检查是否完成
    pub fn is_complete(&self) -> bool {
        matches!(self.current_phase, AuditPhase::Completed)
    }

    /// 获取进度百分比
    pub fn progress_percentage(&self) -> f32 {
        match self.current_phase {
            AuditPhase::Initialization => 0.1,
            AuditPhase::DeterministicScan => 0.25,
            AuditPhase::DeepAnalysis => {
                let total = self.completed_targets.len() + self.pending_targets.len();
                if total == 0 {
                    0.4
                } else {
                    0.4 + 0.35 * (self.completed_targets.len() as f32 / total as f32)
                }
            }
            AuditPhase::Verification => 0.8,
            AuditPhase::Reporting => 0.9,
            AuditPhase::Completed => 1.0,
        }
    }

    /// 生成摘要
    pub fn generate_summary(&self) -> String {
        format!(
            "审计进度: {:.0}%\n\
             阶段: {}\n\
             候选漏洞: {}\n\
             已确认: {}\n\
             误报: {}\n\
             分析文件: {}\n\
             LLM 调用: {}",
            self.progress_percentage() * 100.0,
            self.current_phase,
            self.vulnerability_candidates.len(),
            self.confirmed_vulnerabilities.len(),
            self.false_positives.len(),
            self.stats.files_analyzed,
            self.stats.llm_calls
        )
    }
}

impl AnalysisTarget {
    /// 创建文件目标
    pub fn file(file_path: String, priority: TargetPriority, reason: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            target_type: TargetType::File,
            file_path,
            start_line: None,
            end_line: None,
            priority,
            status: TargetStatus::Pending,
            candidate_vulnerabilities: Vec::new(),
            reason,
            created_at: Utc::now(),
            completed_at: None,
        }
    }

    /// 创建函数目标
    pub fn function(file_path: String, start_line: usize, end_line: usize, name: String, priority: TargetPriority) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            target_type: TargetType::Function,
            file_path,
            start_line: Some(start_line),
            end_line: Some(end_line),
            priority,
            status: TargetStatus::Pending,
            candidate_vulnerabilities: Vec::new(),
            reason: format!("分析函数: {}", name),
            created_at: Utc::now(),
            completed_at: None,
        }
    }

    /// 关联候选漏洞
    pub fn add_candidate(&mut self, candidate_id: String) {
        if !self.candidate_vulnerabilities.contains(&candidate_id) {
            self.candidate_vulnerabilities.push(candidate_id);
        }
    }
}

impl VulnerabilityCandidate {
    /// 创建新候选
    pub fn new(
        vulnerability_type: String,
        severity: String,
        confidence: f32,
        source: String,
        file_path: String,
        line: usize,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            vulnerability_type,
            severity,
            confidence,
            source,
            file_path,
            line,
            code_snippet: None,
            propagation_path: None,
            verification_status: VerificationStatus::Pending,
            verification_result: None,
        }
    }

    /// 添加代码片段
    pub fn with_code(mut self, code: String) -> Self {
        self.code_snippet = Some(code);
        self
    }

    /// 添加传播路径
    pub fn with_propagation_path(mut self, path: Vec<PropagationStepInfo>) -> Self {
        self.propagation_path = Some(path);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_state_creation() {
        let state = SecurityAuditState::new("/test/project".to_string());
        assert_eq!(state.current_phase, AuditPhase::Initialization);
        assert!(state.pending_targets.is_empty());
    }

    #[test]
    fn test_phase_transition() {
        let mut state = SecurityAuditState::new("/test".to_string());
        state.transition_to(AuditPhase::DeterministicScan);
        assert_eq!(state.current_phase, AuditPhase::DeterministicScan);
        assert_eq!(state.phase_history.len(), 1); // DeterministicScan record
    }

    #[test]
    fn test_target_priority() {
        let mut state = SecurityAuditState::new("/test".to_string());

        // 添加低优先级目标
        state.add_target(AnalysisTarget::file(
            "low.txt".to_string(),
            TargetPriority::Low,
            "test".to_string(),
        ));

        // 添加高优先级目标
        state.add_target(AnalysisTarget::file(
            "high.txt".to_string(),
            TargetPriority::High,
            "test".to_string(),
        ));

        // 高优先级应该先被取出
        let next = state.get_next_target().unwrap();
        assert_eq!(next.file_path, "high.txt");
    }

    #[test]
    fn test_vulnerability_candidate() {
        let mut state = SecurityAuditState::new("/test".to_string());

        let candidate = VulnerabilityCandidate::new(
            "SQL Injection".to_string(),
            "high".to_string(),
            0.8,
            "taint_analysis".to_string(),
            "test.py".to_string(),
            42,
        );

        let id = candidate.id.clone();
        state.add_vulnerability_candidate(candidate);

        assert_eq!(state.vulnerability_candidates.len(), 1);

        state.confirm_vulnerability(&id);
        assert_eq!(state.confirmed_vulnerabilities.len(), 1);
        assert_eq!(state.vulnerability_candidates.len(), 0);
    }
}
