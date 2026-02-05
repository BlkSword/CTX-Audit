//! 消息系统数据模型

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 消息类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageType {
    /// 信息消息
    Information,
    /// 指令消息
    Instruction,
    /// 完成报告
    CompletionReport,
    /// 错误消息
    Error,
    /// 任务交接
    TaskHandoff,
    /// 状态更新
    StatusUpdate,
    /// 思考消息
    Thinking,
}

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageType::Information => write!(f, "information"),
            MessageType::Instruction => write!(f, "instruction"),
            MessageType::CompletionReport => write!(f, "completion_report"),
            MessageType::Error => write!(f, "error"),
            MessageType::TaskHandoff => write!(f, "task_handoff"),
            MessageType::StatusUpdate => write!(f, "status_update"),
            MessageType::Thinking => write!(f, "thinking"),
        }
    }
}

/// 消息优先级
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessagePriority {
    /// 低优先级
    Low = 0,
    /// 普通优先级
    Normal = 1,
    /// 高优先级
    High = 2,
    /// 紧急优先级
    Urgent = 3,
}

impl std::fmt::Display for MessagePriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessagePriority::Low => write!(f, "low"),
            MessagePriority::Normal => write!(f, "normal"),
            MessagePriority::High => write!(f, "high"),
            MessagePriority::Urgent => write!(f, "urgent"),
        }
    }
}

/// Agent 消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMessage {
    /// 消息 ID
    pub id: String,

    /// 发送者 Agent ID
    pub sender: String,

    /// 接收者 Agent ID
    pub recipient: String,

    /// 消息类型
    #[serde(rename = "type")]
    pub message_type: MessageType,

    /// 消息优先级
    pub priority: MessagePriority,

    /// 消息内容
    pub content: MessageContent,

    /// 是否已投递
    pub delivered: bool,

    /// 是否已读
    pub read: bool,

    /// 时间戳
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// 元数据
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

impl AgentMessage {
    /// 创建新消息
    pub fn new(
        sender: String,
        recipient: String,
        message_type: MessageType,
        content: MessageContent,
    ) -> Self {
        let now = chrono::Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            sender,
            recipient,
            message_type,
            priority: MessagePriority::Normal,
            content,
            delivered: false,
            read: false,
            timestamp: now,
            metadata: None,
        }
    }

    /// 设置优先级
    pub fn with_priority(mut self, priority: MessagePriority) -> Self {
        self.priority = priority;
        self
    }

    /// 设置元数据
    pub fn with_metadata(mut self, metadata: HashMap<String, serde_json::Value>) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// 创建指令消息
    pub fn instruction(
        sender: String,
        recipient: String,
        instruction: String,
        context: Option<serde_json::Value>,
    ) -> Self {
        Self::new(
            sender,
            recipient,
            MessageType::Instruction,
            MessageContent::Instruction { instruction, context },
        )
    }

    /// 创建完成报告消息
    pub fn completion_report(
        sender: String,
        recipient: String,
        result: serde_json::Value,
        findings: usize,
    ) -> Self {
        Self::new(
            sender,
            recipient,
            MessageType::CompletionReport,
            MessageContent::CompletionReport { result, findings },
        )
    }

    /// 创建状态更新消息
    pub fn status_update(
        sender: String,
        recipient: String,
        status: String,
        progress: Option<f32>,
    ) -> Self {
        Self::new(
            sender,
            recipient,
            MessageType::StatusUpdate,
            MessageContent::StatusUpdate {
                status,
                progress,
                details: None,
            },
        )
    }

    /// 创建任务交接消息
    pub fn task_handoff(
        sender: String,
        recipient: String,
        task_description: String,
        handover_data: serde_json::Value,
    ) -> Self {
        Self::new(
            sender,
            recipient,
            MessageType::TaskHandoff,
            MessageContent::TaskHandoff {
                task_description,
                handover_data,
            },
        )
    }
}

/// 消息内容
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "content_type", rename_all = "snake_case")]
pub enum MessageContent {
    /// 信息
    Information {
        /// 信息文本
        message: String,
        /// 附加数据
        data: Option<serde_json::Value>,
    },
    /// 指令
    Instruction {
        /// 指令内容
        instruction: String,
        /// 执行上下文
        context: Option<serde_json::Value>,
    },
    /// 完成报告
    CompletionReport {
        /// 结果数据
        result: serde_json::Value,
        /// 发现的漏洞数
        findings: usize,
    },
    /// 错误
    Error {
        /// 错误消息
        error: String,
        /// 错误代码
        code: Option<String>,
        /// 堆栈信息
        stack: Option<String>,
    },
    /// 任务交接
    TaskHandoff {
        /// 任务描述
        task_description: String,
        /// 交接数据
        handover_data: serde_json::Value,
    },
    /// 状态更新
    StatusUpdate {
        /// 状态描述
        status: String,
        /// 进度百分比 (0-100)
        progress: Option<f32>,
        /// 详细信息
        details: Option<String>,
    },
    /// 思考消息
    Thinking {
        /// 思考内容
        thought: String,
        /// 累计思考
        accumulated_thought: Option<String>,
        /// 当前计划
        planned_action: Option<String>,
    },
}

impl MessageContent {
    /// 获取内容的文本描述
    pub fn as_text(&self) -> String {
        match self {
            MessageContent::Information { message, .. } => message.clone(),
            MessageContent::Instruction { instruction, .. } => instruction.clone(),
            MessageContent::CompletionReport { .. } => "任务完成".to_string(),
            MessageContent::Error { error, .. } => format!("错误: {}", error),
            MessageContent::TaskHandoff { task_description, .. } => {
                format!("任务交接: {}", task_description)
            }
            MessageContent::StatusUpdate { status, .. } => format!("状态更新: {}", status),
            MessageContent::Thinking { thought, .. } => format!("思考: {}", thought),
        }
    }
}

/// 消息统计
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageStats {
    /// 总消息数
    pub total_messages: usize,

    /// 已投递消息数
    pub delivered_messages: usize,

    /// 待投递消息数
    pub pending_messages: usize,

    /// 已读消息数
    pub read_messages: usize,

    /// 按类型统计
    pub by_type: HashMap<String, usize>,

    /// 按优先级统计
    pub by_priority: HashMap<String, usize>,
}

impl Default for MessageStats {
    fn default() -> Self {
        Self {
            total_messages: 0,
            delivered_messages: 0,
            pending_messages: 0,
            read_messages: 0,
            by_type: HashMap::new(),
            by_priority: HashMap::new(),
        }
    }
}
