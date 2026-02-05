//! 审计相关的数据模型

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// 导入事件模块的 ProgressData
use crate::models::events::ProgressData;

/// 审计类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditType {
    /// 完整审计
    Full,
    /// 快速扫描
    Quick,
    /// 增量审计
    Incremental,
    /// 自定义审计
    Custom,
}

impl std::fmt::Display for AuditType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditType::Full => write!(f, "full"),
            AuditType::Quick => write!(f, "quick"),
            AuditType::Incremental => write!(f, "incremental"),
            AuditType::Custom => write!(f, "custom"),
        }
    }
}

impl std::str::FromStr for AuditType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "full" => Ok(AuditType::Full),
            "quick" => Ok(AuditType::Quick),
            "incremental" => Ok(AuditType::Incremental),
            "custom" => Ok(AuditType::Custom),
            _ => Err(format!("Unknown audit type: {}", s)),
        }
    }
}

/// 审计状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatus {
    /// 初始化中
    Initializing,
    /// 运行中
    Running,
    /// 暂停
    Paused,
    /// 已完成
    Completed,
    /// 失败
    Failed,
    /// 已取消
    Cancelled,
}

impl std::fmt::Display for AuditStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditStatus::Initializing => write!(f, "initializing"),
            AuditStatus::Running => write!(f, "running"),
            AuditStatus::Paused => write!(f, "paused"),
            AuditStatus::Completed => write!(f, "completed"),
            AuditStatus::Failed => write!(f, "failed"),
            AuditStatus::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl std::str::FromStr for AuditStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "initializing" => Ok(AuditStatus::Initializing),
            "running" => Ok(AuditStatus::Running),
            "paused" => Ok(AuditStatus::Paused),
            "completed" => Ok(AuditStatus::Completed),
            "failed" => Ok(AuditStatus::Failed),
            "cancelled" => Ok(AuditStatus::Cancelled),
            _ => Err(format!("Unknown audit status: {}", s)),
        }
    }
}

/// 审计阶段
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditPhase {
    /// 初始化
    Initialization,
    /// 规划
    Planning,
    /// 索引构建
    Indexing,
    /// 侦察
    Reconnaissance,
    /// 分析
    Analysis,
    /// 验证
    Verification,
    /// 报告生成
    Reporting,
    /// 完成
    Complete,
    /// 失败
    Failed,
    /// 取消
    Cancelled,
}

impl std::fmt::Display for AuditPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditPhase::Initialization => write!(f, "initialization"),
            AuditPhase::Planning => write!(f, "planning"),
            AuditPhase::Indexing => write!(f, "indexing"),
            AuditPhase::Reconnaissance => write!(f, "reconnaissance"),
            AuditPhase::Analysis => write!(f, "analysis"),
            AuditPhase::Verification => write!(f, "verification"),
            AuditPhase::Reporting => write!(f, "reporting"),
            AuditPhase::Complete => write!(f, "complete"),
            AuditPhase::Failed => write!(f, "failed"),
            AuditPhase::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl std::str::FromStr for AuditPhase {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "initialization" => Ok(AuditPhase::Initialization),
            "planning" => Ok(AuditPhase::Planning),
            "indexing" => Ok(AuditPhase::Indexing),
            "reconnaissance" => Ok(AuditPhase::Reconnaissance),
            "analysis" => Ok(AuditPhase::Analysis),
            "verification" => Ok(AuditPhase::Verification),
            "reporting" => Ok(AuditPhase::Reporting),
            "complete" => Ok(AuditPhase::Complete),
            "failed" => Ok(AuditPhase::Failed),
            "cancelled" => Ok(AuditPhase::Cancelled),
            _ => Err(format!("Unknown audit phase: {}", s)),
        }
    }
}

/// 审计会话
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSession {
    /// 会话 ID
    pub id: String,

    /// 项目 ID
    pub project_id: String,

    /// 审计类型
    pub audit_type: AuditType,

    /// 审计状态
    pub status: AuditStatus,

    /// 当前阶段
    pub current_phase: Option<AuditPhase>,

    /// 配置
    pub config: Option<serde_json::Value>,

    /// 进度百分比 (0-100)
    pub progress_percentage: u8,

    /// 总文件数
    pub total_files: usize,

    /// 已索引文件数
    pub indexed_files: usize,

    /// 已分析文件数
    pub analyzed_files: usize,

    /// 检测到的漏洞数
    pub findings_detected: usize,

    /// 总 token 使用量
    pub total_tokens: u64,

    /// 工具调用次数
    pub tool_calls: u64,

    /// 错误信息（如果有）
    pub error_message: Option<String>,

    /// 开始时间
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,

    /// 完成时间
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,

    /// 创建时间
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// 更新时间
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl AuditSession {
    /// 创建新的审计会话
    pub fn new(id: &str, project_id: &str, audit_type: AuditType) -> Self {
        let now = chrono::Utc::now();
        Self {
            id: id.to_string(),
            project_id: project_id.to_string(),
            audit_type,
            status: AuditStatus::Initializing,
            current_phase: Some(AuditPhase::Initialization),
            config: None,
            progress_percentage: 0,
            total_files: 0,
            indexed_files: 0,
            analyzed_files: 0,
            findings_detected: 0,
            total_tokens: 0,
            tool_calls: 0,
            error_message: None,
            started_at: Some(now),
            completed_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// 更新进度
    pub fn update_progress(&mut self, percentage: u8) {
        self.progress_percentage = percentage.min(100);
        self.updated_at = chrono::Utc::now();
    }

    /// 增加已分析文件数
    pub fn increment_analyzed(&mut self, count: usize) {
        self.analyzed_files += count;
        self.updated_at = chrono::Utc::now();
    }

    /// 增加检测到的漏洞数
    pub fn increment_findings(&mut self, count: usize) {
        self.findings_detected += count;
        self.updated_at = chrono::Utc::now();
    }

    /// 增加工具调用次数
    pub fn increment_tool_calls(&mut self, count: u64) {
        self.tool_calls += count;
        self.updated_at = chrono::Utc::now();
    }

    /// 增加使用量
    pub fn add_tokens(&mut self, tokens: u64) {
        self.total_tokens += tokens;
        self.updated_at = chrono::Utc::now();
    }

    /// 标记为完成
    pub fn mark_completed(&mut self) {
        self.status = AuditStatus::Completed;
        self.current_phase = Some(AuditPhase::Complete);
        self.completed_at = Some(chrono::Utc::now());
        self.progress_percentage = 100;
        self.updated_at = chrono::Utc::now();
    }

    /// 标记为失败
    pub fn mark_failed(&mut self, error: String) {
        self.status = AuditStatus::Failed;
        self.current_phase = Some(AuditPhase::Failed);
        self.error_message = Some(error);
        self.completed_at = Some(chrono::Utc::now());
        self.updated_at = chrono::Utc::now();
    }

    /// 标记为取消
    pub fn mark_cancelled(&mut self) {
        self.status = AuditStatus::Cancelled;
        self.current_phase = Some(AuditPhase::Cancelled);
        self.completed_at = Some(chrono::Utc::now());
        self.updated_at = chrono::Utc::now();
    }
}

/// 审计启动请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStartRequest {
    /// 项目 ID
    pub project_id: String,

    /// 审计类型
    pub audit_type: AuditType,

    /// 配置选项
    pub config: Option<AuditConfig>,
}

/// 审计配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// 启用的 Agent 类型
    pub enabled_agents: Vec<String>,

    /// 最大并发文件分析数
    pub max_concurrent_files: usize,

    /// 启用验证阶段
    pub enable_verification: bool,

    /// 启用外部工具
    pub enable_external_tools: bool,

    /// 包含的文件模式
    pub include_patterns: Vec<String>,

    /// 排除的文件模式
    pub exclude_patterns: Vec<String>,

    /// 自定义规则路径
    pub custom_rules_path: Option<String>,

    /// 额外配置
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled_agents: vec![
                "orchestrator".to_string(),
                "recon".to_string(),
                "analysis".to_string(),
            ],
            max_concurrent_files: 5,
            enable_verification: false,
            enable_external_tools: true,
            include_patterns: vec!["**/*.rs".to_string(), "**/*.ts".to_string(), "**/*.tsx".to_string()],
            exclude_patterns: vec![
                "**/node_modules/**".to_string(),
                "**/target/**".to_string(),
                "**/.git/**".to_string(),
            ],
            custom_rules_path: None,
            extra: HashMap::new(),
        }
    }
}

/// 审计启动响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStartResponse {
    /// 审计 ID
    pub audit_id: String,

    /// 审计状态
    pub status: AuditStatus,
}

/// 审计状态响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStatusResponse {
    /// 审计 ID
    pub audit_id: String,

    /// 审计状态
    pub status: AuditStatus,

    /// 当前进度
    pub progress: ProgressData,

    /// 统计信息
    pub stats: AuditStats,
}

/// 审计统计
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStats {
    /// 总 token 使用量
    pub total_tokens: u64,

    /// 工具调用次数
    pub tool_calls: u64,

    /// LLM 调用次数
    pub llm_calls: u64,

    /// 运行时长（秒）
    pub duration_seconds: u64,
}

/// 漏洞数据（重新导出）
pub use crate::models::events::FindingData;
