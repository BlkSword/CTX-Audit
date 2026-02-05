//! 事件系统数据模型

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 事件类型
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    // ===== 基础事件 =====
    /// 开始
    Start,
    /// 停止
    Stop,
    /// 暂停
    Pause,
    /// 继续
    Resume,
    /// 错误
    Error,
    /// 完成
    Complete,
    /// 状态更新
    StatusUpdate,
    /// 进度更新
    ProgressUpdate,

    // ===== Agent 特定事件 =====
    /// Agent 创建
    AgentCreated,
    /// Agent 启动
    AgentStarted,
    /// Agent 完成
    AgentCompleted,
    /// Agent 失败
    AgentFailed,

    // ===== 思考和决策事件 =====
    /// 思考中
    Thinking,
    /// LLM 思考
    LlmThought,
    /// LLM 决策
    LlmDecision,
    /// LLM 行动
    LlmAction,

    // ===== 工具事件 =====
    /// 工具调用
    ToolCall,
    /// 工具结果
    ToolResult,
    /// 工具错误
    ToolError,

    // ===== 审计阶段事件 =====
    /// 阶段开始
    PhaseStart,
    /// 阶段完成
    PhaseComplete,
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

    // ===== 发现相关事件 =====
    /// 新发现
    FindingNew,
    /// 发现已验证
    FindingVerified,
    /// 误报标记
    FindingFalsePositive,
    /// 漏洞检测
    VulnerabilityDetected,
    /// 安全问题发现
    SecurityIssueFound,

    // ===== 消息事件 =====
    /// 消息接收
    MessageReceived,
    /// 消息发送
    MessageSent,
    /// 任务交接
    TaskHandoff,

    // ===== 心跳和系统事件 =====
    /// 心跳
    Heartbeat,
    /// 关闭
    Shutdown,
    /// 取消
    Cancel,

    // ===== 通用信息 =====
    Info,
    Warning,
    TaskComplete,

    /// 自定义事件类型
    Custom(String),
}

impl EventType {
    /// 获取事件类型的字符串表示
    pub fn as_str(&self) -> &str {
        match self {
            EventType::Start => "start",
            EventType::Stop => "stop",
            EventType::Pause => "pause",
            EventType::Resume => "resume",
            EventType::Error => "error",
            EventType::Complete => "complete",
            EventType::StatusUpdate => "status_update",
            EventType::ProgressUpdate => "progress_update",
            EventType::AgentCreated => "agent_created",
            EventType::AgentStarted => "agent_started",
            EventType::AgentCompleted => "agent_completed",
            EventType::AgentFailed => "agent_failed",
            EventType::Thinking => "thinking",
            EventType::LlmThought => "llm_thought",
            EventType::LlmDecision => "llm_decision",
            EventType::LlmAction => "llm_action",
            EventType::ToolCall => "tool_call",
            EventType::ToolResult => "tool_result",
            EventType::ToolError => "tool_error",
            EventType::PhaseStart => "phase_start",
            EventType::PhaseComplete => "phase_complete",
            EventType::Initialization => "initialization",
            EventType::Planning => "planning",
            EventType::Indexing => "indexing",
            EventType::Reconnaissance => "reconnaissance",
            EventType::Analysis => "analysis",
            EventType::Verification => "verification",
            EventType::Reporting => "reporting",
            EventType::FindingNew => "finding_new",
            EventType::FindingVerified => "finding_verified",
            EventType::FindingFalsePositive => "finding_false_positive",
            EventType::VulnerabilityDetected => "vulnerability_detected",
            EventType::SecurityIssueFound => "security_issue_found",
            EventType::MessageReceived => "message_received",
            EventType::MessageSent => "message_sent",
            EventType::TaskHandoff => "task_handoff",
            EventType::Heartbeat => "heartbeat",
            EventType::Shutdown => "shutdown",
            EventType::Cancel => "cancel",
            EventType::Info => "info",
            EventType::Warning => "warning",
            EventType::TaskComplete => "task_complete",
            EventType::Custom(s) => s,
        }
    }

    /// 从字符串解析事件类型
    pub fn from_str(s: &str) -> Self {
        match s {
            "start" => EventType::Start,
            "stop" => EventType::Stop,
            "pause" => EventType::Pause,
            "resume" => EventType::Resume,
            "error" => EventType::Error,
            "complete" => EventType::Complete,
            "status_update" => EventType::StatusUpdate,
            "progress_update" => EventType::ProgressUpdate,
            "agent_created" => EventType::AgentCreated,
            "agent_started" => EventType::AgentStarted,
            "agent_completed" => EventType::AgentCompleted,
            "agent_failed" => EventType::AgentFailed,
            "thinking" => EventType::Thinking,
            "llm_thought" => EventType::LlmThought,
            "llm_decision" => EventType::LlmDecision,
            "llm_action" => EventType::LlmAction,
            "tool_call" => EventType::ToolCall,
            "tool_result" => EventType::ToolResult,
            "tool_error" => EventType::ToolError,
            "phase_start" => EventType::PhaseStart,
            "phase_complete" => EventType::PhaseComplete,
            "initialization" => EventType::Initialization,
            "planning" => EventType::Planning,
            "indexing" => EventType::Indexing,
            "reconnaissance" => EventType::Reconnaissance,
            "analysis" => EventType::Analysis,
            "verification" => EventType::Verification,
            "reporting" => EventType::Reporting,
            "finding_new" => EventType::FindingNew,
            "finding_verified" => EventType::FindingVerified,
            "finding_false_positive" => EventType::FindingFalsePositive,
            "vulnerability_detected" => EventType::VulnerabilityDetected,
            "security_issue_found" => EventType::SecurityIssueFound,
            "message_received" => EventType::MessageReceived,
            "message_sent" => EventType::MessageSent,
            "task_handoff" => EventType::TaskHandoff,
            "heartbeat" => EventType::Heartbeat,
            "shutdown" => EventType::Shutdown,
            "cancel" => EventType::Cancel,
            "info" => EventType::Info,
            "warning" => EventType::Warning,
            "task_complete" => EventType::TaskComplete,
            other => EventType::Custom(other.to_string()),
        }
    }
}

/// Agent 事件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEvent {
    /// 事件 ID（数据库自增）
    #[serde(skip_deserializing)]
    pub id: Option<i64>,

    /// 审计 ID
    pub audit_id: String,

    /// 任务 ID
    pub task_id: String,

    /// 序列号
    pub sequence: i64,

    /// 事件类型
    #[serde(rename = "type")]
    pub event_type: EventType,

    /// Agent 类型
    pub agent_type: Option<String>,

    /// Agent ID
    pub agent_id: Option<String>,

    /// 消息内容
    pub message: Option<String>,

    /// 思考内容
    pub thought: Option<String>,

    /// 累计思考
    pub accumulated_thought: Option<String>,

    /// 结构化数据
    pub data: Option<serde_json::Value>,

    /// 元数据
    pub metadata: Option<HashMap<String, serde_json::Value>>,

    /// 工具名称
    pub tool_name: Option<String>,

    /// 工具输入
    pub tool_input: Option<serde_json::Value>,

    /// 工具输出
    pub tool_output: Option<String>,

    /// 漏洞数据
    pub finding: Option<FindingData>,

    /// 进度信息
    pub progress: Option<ProgressData>,

    /// 时间戳
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl AgentEvent {
    /// 创建新事件
    pub fn new(audit_id: String, task_id: String, event_type: EventType) -> Self {
        Self {
            id: None,
            audit_id,
            task_id,
            sequence: 0,
            event_type,
            agent_type: None,
            agent_id: None,
            message: None,
            thought: None,
            accumulated_thought: None,
            data: None,
            metadata: None,
            tool_name: None,
            tool_input: None,
            tool_output: None,
            finding: None,
            progress: None,
            timestamp: chrono::Utc::now(),
        }
    }

    /// 创建思考事件
    pub fn thought(
        audit_id: String,
        agent_id: String,
        agent_type: String,
        thought: String,
        accumulated_thought: String,
    ) -> Self {
        Self {
            id: None,
            audit_id,
            task_id: agent_id.clone(),
            sequence: 0,
            event_type: EventType::Thinking,
            agent_type: Some(agent_type),
            agent_id: Some(agent_id),
            message: None,
            thought: Some(thought),
            accumulated_thought: Some(accumulated_thought),
            data: None,
            metadata: None,
            tool_name: None,
            tool_input: None,
            tool_output: None,
            finding: None,
            progress: None,
            timestamp: chrono::Utc::now(),
        }
    }

    /// 创建工具调用事件
    pub fn tool_call(
        audit_id: String,
        agent_id: String,
        tool_name: String,
        tool_input: serde_json::Value,
    ) -> Self {
        Self {
            id: None,
            audit_id,
            task_id: agent_id.clone(),
            sequence: 0,
            event_type: EventType::ToolCall,
            agent_type: None,
            agent_id: Some(agent_id),
            message: None,
            thought: None,
            accumulated_thought: None,
            data: None,
            metadata: None,
            tool_name: Some(tool_name),
            tool_input: Some(tool_input),
            tool_output: None,
            finding: None,
            progress: None,
            timestamp: chrono::Utc::now(),
        }
    }

    /// 创建漏洞发现事件
    pub fn finding(audit_id: String, agent_id: String, finding: FindingData) -> Self {
        Self {
            id: None,
            audit_id,
            task_id: agent_id.clone(),
            sequence: 0,
            event_type: EventType::FindingNew,
            agent_type: None,
            agent_id: Some(agent_id),
            message: Some(format!("发现漏洞: {}", finding.title.as_ref().cloned().unwrap_or_default())),
            thought: None,
            accumulated_thought: None,
            data: None,
            metadata: None,
            tool_name: None,
            tool_input: None,
            tool_output: None,
            finding: Some(finding),
            progress: None,
            timestamp: chrono::Utc::now(),
        }
    }

    /// 创建进度更新事件
    pub fn progress(audit_id: String, progress: ProgressData) -> Self {
        Self {
            id: None,
            audit_id,
            task_id: "audit".to_string(),
            sequence: 0,
            event_type: EventType::ProgressUpdate,
            agent_type: None,
            agent_id: None,
            message: None,
            thought: None,
            accumulated_thought: None,
            data: None,
            metadata: None,
            tool_name: None,
            tool_input: None,
            tool_output: None,
            finding: None,
            progress: Some(progress),
            timestamp: chrono::Utc::now(),
        }
    }

    /// 设置序列号
    pub fn with_sequence(mut self, sequence: i64) -> Self {
        self.sequence = sequence;
        self
    }

    /// 设置消息
    pub fn with_message(mut self, message: String) -> Self {
        self.message = Some(message);
        self
    }
}

/// 进度数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressData {
    /// 当前阶段
    pub current_stage: String,

    /// 进度百分比 (0-100)
    pub percentage: u8,

    /// 总文件数
    pub total_files: usize,

    /// 已索引文件数
    pub indexed_files: usize,

    /// 已分析文件数
    pub analyzed_files: usize,

    /// 检测到的漏洞数
    pub findings_detected: usize,

    /// 额外的进度信息
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// 漏洞数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingData {
    /// 漏洞 ID
    pub id: Option<String>,

    /// 漏洞标题
    pub title: Option<String>,

    /// 漏洞描述
    pub description: String,

    /// 严重程度 (critical, high, medium, low, info)
    pub severity: String,

    /// 漏洞类别 (SQL注入, XSS, etc.)
    pub category: String,

    /// CWE 编号
    pub cwe_id: Option<String>,

    /// 受影响的文件路径
    pub file_path: String,

    /// 起始行号
    pub start_line: u32,

    /// 结束行号
    pub end_line: Option<u32>,

    /// 漏洞代码片段
    pub code_snippet: Option<String>,

    /// 修复建议
    pub recommendation: Option<String>,

    /// 状态 (open, verified, false_positive, fixed)
    pub status: String,

    /// 验证状态 (pending, verified, rejected)
    pub verification_status: Option<String>,

    /// 发现此漏洞的 Agent
    pub discovered_by: Option<String>,

    /// 额外的元数据
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// 事件过滤器
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventFilter {
    /// 过滤的事件类型
    pub event_types: Option<Vec<EventType>>,

    /// 过滤的 Agent 类型
    pub agent_types: Option<Vec<String>>,

    /// 过滤的 Agent ID
    pub agent_ids: Option<Vec<String>>,

    /// 起始序列号
    pub after_sequence: Option<i64>,

    /// 结束序列号
    pub before_sequence: Option<i64>,

    /// 起始时间
    pub after_timestamp: Option<chrono::DateTime<chrono::Utc>>,

    /// 结束时间
    pub before_timestamp: Option<chrono::DateTime<chrono::Utc>>,
}
