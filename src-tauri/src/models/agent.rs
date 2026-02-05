//! Agent 相关的数据模型

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// 导入 LLM 配置
use crate::models::llm::LLMProviderConfig;

/// Agent 类型
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentType {
    /// 编排器 Agent
    Orchestrator,
    /// 侦察 Agent
    Recon,
    /// 分析 Agent
    Analysis,
    /// 验证 Agent
    Verification,
    /// 自定义 Agent 类型
    Custom(String),
}

impl std::fmt::Display for AgentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentType::Orchestrator => write!(f, "orchestrator"),
            AgentType::Recon => write!(f, "recon"),
            AgentType::Analysis => write!(f, "analysis"),
            AgentType::Verification => write!(f, "verification"),
            AgentType::Custom(s) => write!(f, "{}", s),
        }
    }
}

impl std::str::FromStr for AgentType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "orchestrator" => Ok(AgentType::Orchestrator),
            "recon" => Ok(AgentType::Recon),
            "analysis" => Ok(AgentType::Analysis),
            "verification" => Ok(AgentType::Verification),
            other => Ok(AgentType::Custom(other.to_string())),
        }
    }
}

/// Agent 状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentStatus {
    /// 已创建，未开始
    Created,
    /// 运行中
    Running,
    /// 等待中
    Waiting,
    /// 已暂停
    Paused,
    /// 已完成
    Completed,
    /// 失败
    Failed,
    /// 被停止
    Stopped,
    /// 正在停止
    Stopping,
}

impl std::fmt::Display for AgentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentStatus::Created => write!(f, "created"),
            AgentStatus::Running => write!(f, "running"),
            AgentStatus::Waiting => write!(f, "waiting"),
            AgentStatus::Paused => write!(f, "paused"),
            AgentStatus::Completed => write!(f, "completed"),
            AgentStatus::Failed => write!(f, "failed"),
            AgentStatus::Stopped => write!(f, "stopped"),
            AgentStatus::Stopping => write!(f, "stopping"),
        }
    }
}

/// Agent 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Agent 类型
    pub agent_type: AgentType,

    /// 最大迭代次数
    pub max_iterations: usize,

    /// 单次迭代超时时间（秒）
    pub iteration_timeout_seconds: u64,

    /// 等待输入超时时间（秒）
    pub waiting_timeout_seconds: u64,

    /// 启用调试模式
    pub debug_mode: bool,

    /// LLM 配置
    pub llm_config: LLMProviderConfig,

    /// 额外的配置参数
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent_type: AgentType::Analysis,
            max_iterations: 50,
            iteration_timeout_seconds: 300,
            waiting_timeout_seconds: 60,
            debug_mode: false,
            llm_config: LLMProviderConfig::default(),
            extra: HashMap::new(),
        }
    }
}

impl AgentConfig {
    /// 从 JSON 创建配置
    pub fn from_json(value: serde_json::Value) -> Result<Self, String> {
        serde_json::from_value(value).map_err(|e| e.to_string())
    }

    /// 转换为 JSON
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}

/// Agent 执行上下文
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentContext {
    /// 审计 ID
    pub audit_id: String,

    /// 项目 ID
    pub project_id: String,

    /// 项目路径
    pub project_path: String,

    /// 审计类型
    pub audit_type: AuditType,

    /// Agent 配置
    pub config: AgentConfig,

    /// 父 Agent ID（如果有）
    pub parent_agent_id: Option<String>,

    /// 之前的执行结果
    pub previous_results: Vec<AgentResult>,

    /// 继承的上下文
    pub inherited_context: HashMap<String, serde_json::Value>,
}

/// Agent 执行结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentResult {
    /// Agent ID
    pub agent_id: String,

    /// Agent 类型
    pub agent_type: AgentType,

    /// 执行状态
    pub status: AgentStatus,

    /// 最终输出消息
    pub message: Option<String>,

    /// 发现的漏洞
    pub findings: Vec<FindingData>,

    /// 执行的思考步骤
    pub thought_chain: Vec<ThoughtEntry>,

    /// 工具调用记录
    pub tool_calls: Vec<ToolCallRecord>,

    /// 统计信息
    pub stats: ExecutionStats,

    /// 错误信息（如果有）
    pub error: Option<String>,

    /// 完成时间
    pub completed_at: chrono::DateTime<chrono::Utc>,
}

/// 思考链条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThoughtEntry {
    /// 迭代次数
    pub iteration: usize,

    /// 思考内容
    pub thought: String,

    /// 累计思考
    pub accumulated_thought: String,

    /// 计划的行动
    pub planned_action: Option<String>,

    /// 时间戳
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// 工具调用记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallRecord {
    /// 工具名称
    pub tool_name: String,

    /// 工具输入
    pub input: serde_json::Value,

    /// 工具输出
    pub output: Option<crate::models::tools::ToolResult>,

    /// 执行时长（毫秒）
    pub duration_ms: u64,

    /// 是否成功
    pub success: bool,

    /// 错误信息（如果有）
    pub error: Option<String>,

    /// 时间戳
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// 执行统计
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionStats {
    /// 总迭代次数
    pub total_iterations: usize,

    /// 总工具调用次数
    pub total_tool_calls: usize,

    /// 总 token 使用量
    pub total_tokens: u64,

    /// 总耗时（毫秒）
    pub total_duration_ms: u64,

    /// LLM 调用次数
    pub llm_calls: usize,
}

impl Default for ExecutionStats {
    fn default() -> Self {
        Self {
            total_iterations: 0,
            total_tool_calls: 0,
            total_tokens: 0,
            total_duration_ms: 0,
            llm_calls: 0,
        }
    }
}

// 导入来自其他模块的类型
use crate::models::audit::{AuditType, FindingData};
