// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Agent 基础 Trait 定义

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Agent 类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AgentType {
    /// 编排器 Agent
    Orchestrator,
    /// 侦察 Agent
    Recon,
    /// 分析 Agent
    Analysis,
    /// 验证 Agent
    Verification,
}

impl std::fmt::Display for AgentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentType::Orchestrator => write!(f, "Orchestrator"),
            AgentType::Recon => write!(f, "Recon"),
            AgentType::Analysis => write!(f, "Analysis"),
            AgentType::Verification => write!(f, "Verification"),
        }
    }
}

/// Agent 状态
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AgentStatus {
    /// 初始化中
    Initializing,
    /// 运行中
    Running,
    /// 已完成
    Completed,
    /// 已暂停
    Paused,
    /// 失败
    Failed,
    /// 已取消
    Cancelled,
}

/// Agent 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Agent 类型
    pub agent_type: AgentType,

    /// Agent 名称
    pub name: String,

    /// Agent 描述
    pub description: Option<String>,

    /// LLM 配置
    pub llm_config: LLMConfig,

    /// 最大迭代次数
    pub max_iterations: u32,

    /// 超时时间（秒）
    pub timeout_secs: Option<u64>,

    /// 自定义配置
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent_type: AgentType::Analysis,
            name: "default".to_string(),
            description: None,
            llm_config: LLMConfig::default(),
            max_iterations: 50,
            timeout_secs: None,
            extra: HashMap::new(),
        }
    }
}

/// LLM 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMConfig {
    /// 最大 tokens
    pub max_tokens: u32,

    /// 温度参数
    pub temperature: f32,

    /// 模型名称
    pub model: Option<String>,

    /// 流式输出
    pub stream: bool,
}

impl Default for LLMConfig {
    fn default() -> Self {
        Self {
            max_tokens: 4096,
            temperature: 0.7,
            model: None,
            stream: false,
        }
    }
}

/// Agent 执行上下文
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentContext {
    /// 项目 ID
    pub project_id: String,

    /// 项目路径
    pub project_path: String,

    /// 会话 ID
    pub session_id: String,

    /// 继承的上下文（来自父 Agent）
    #[serde(default)]
    pub inherited_context: HashMap<String, serde_json::Value>,

    /// 用户提供的额外上下文
    #[serde(default)]
    pub user_context: HashMap<String, serde_json::Value>,
}

/// 思考记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThoughtEntry {
    /// 迭代次数
    pub iteration: u32,

    /// 思考内容
    pub thought: String,

    /// 累积的思考
    pub accumulated_thought: String,

    /// 计划的操作
    pub planned_action: Option<String>,

    /// 操作（用于 ReAct executor）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,

    /// 操作输入（用于 ReAct executor）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_input: Option<serde_json::Value>,

    /// 观察结果（用于 ReAct executor）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation: Option<serde_json::Value>,

    /// 置信度（用于 ReAct executor）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,

    /// 时间戳
    pub timestamp: DateTime<Utc>,
}

impl ThoughtEntry {
    /// 创建新的思考条目
    pub fn new(iteration: u32, thought: String) -> Self {
        let now = Utc::now();
        Self {
            iteration,
            thought,
            accumulated_thought: String::new(),
            planned_action: None,
            action: None,
            action_input: None,
            observation: None,
            confidence: None,
            timestamp: now,
        }
    }
}

/// 工具调用记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallRecord {
    /// 工具名称
    pub tool_name: String,

    /// 输入参数
    pub input: serde_json::Value,

    /// 输出结果（存储为 JSON）
    pub output: Option<serde_json::Value>,

    /// 执行时长（毫秒）
    pub duration_ms: u64,

    /// 是否成功
    pub success: bool,

    /// 错误信息
    pub error: Option<String>,

    /// 时间戳
    pub timestamp: DateTime<Utc>,
}

/// 执行统计
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionStats {
    /// 总迭代次数
    pub total_iterations: u32,

    /// 总工具调用次数
    pub total_tool_calls: usize,

    /// 总 token 使用量
    pub total_tokens: u64,

    /// 总执行时长（毫秒）
    pub total_duration_ms: u64,

    /// LLM 调用次数
    pub llm_calls: u32,
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

    /// 消息
    pub message: Option<String>,

    /// 发现的漏洞（使用 tools 包的 FindingData）
    #[serde(default)]
    pub findings: Vec<ctx_audit_tools::FindingData>,

    /// 思考链
    #[serde(default)]
    pub thought_chain: Vec<ThoughtEntry>,

    /// 工具调用记录
    #[serde(default)]
    pub tool_calls: Vec<ToolCallRecord>,

    /// 执行统计
    pub stats: ExecutionStats,

    /// 错误信息
    pub error: Option<String>,

    /// 完成时间
    pub completed_at: DateTime<Utc>,
}

/// Agent Trait
///
/// 所有 Agent 都需要实现此接口
#[async_trait]
pub trait Agent: Send + Sync {
    /// 获取 Agent 类型
    fn agent_type(&self) -> AgentType;

    /// 获取 Agent ID
    fn agent_id(&self) -> &str;

    /// 获取 Agent 配置
    fn config(&self) -> &AgentConfig;

    /// 执行 Agent 任务
    async fn execute(&self, context: AgentContext) -> AgentResult;
}
