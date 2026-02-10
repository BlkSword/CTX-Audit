// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 对话历史和上下文管理
//!
//! 管理与 LLM 的对话历史，支持持久化和上下文压缩

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};

use crate::database::Database;
use ctx_audit_llm::{LLMMessage, MessageRole};

/// 对话会话
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conversation {
    /// 会话 ID
    pub id: String,

    /// 会话标题
    pub title: String,

    /// 项目路径
    pub project_path: Option<String>,

    /// 创建时间
    pub created_at: DateTime<Utc>,

    /// 更新时间
    pub updated_at: DateTime<Utc>,

    /// 消息数量
    pub message_count: usize,

    /// Token 使用量
    pub tokens_used: u64,
}

/// 对话消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationMessage {
    /// 消息 ID
    pub id: String,

    /// 会话 ID
    pub conversation_id: String,

    /// 角色
    pub role: String,

    /// 内容
    pub content: String,

    /// 是否是工具调用
    pub is_tool_call: bool,

    /// 工具名称
    pub tool_name: Option<String>,

    /// 时间戳
    pub timestamp: DateTime<Utc>,

    /// Token 数量（估算）
    pub tokens: u32,
}

impl ConversationMessage {
    /// 转换为 LLM 消息
    pub fn to_llm_message(&self) -> LLMMessage {
        let role = match self.role.as_str() {
            "user" => MessageRole::User,
            "assistant" => MessageRole::Assistant,
            "system" => MessageRole::System,
            _ => MessageRole::User,
        };

        LLMMessage {
            role,
            content: vec![ctx_audit_llm::MessageContent::Text {
                text: self.content.clone()
            }],
            cache_control: None,
        }
    }

    /// 从 LLM 消息创建
    pub fn from_llm_message(
        conversation_id: String,
        msg: &LLMMessage,
        is_tool_call: bool,
    ) -> Self {
        let role = match msg.role {
            MessageRole::User => "user".to_string(),
            MessageRole::Assistant => "assistant".to_string(),
            MessageRole::System => "system".to_string(),
        };

        let content = msg.get_text();

        // 估算 token 数量 (粗略估算: 1 token ≈ 4 字符)
        let tokens = ((content.len() / 4) + 1) as u32;

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            conversation_id,
            role,
            content,
            is_tool_call,
            tool_name: None,
            timestamp: Utc::now(),
            tokens,
        }
    }
}

/// 对话管理器
pub struct ConversationManager {
    /// 数据库
    db: Arc<Database>,

    /// 当前会话 ID
    current_conversation: Arc<RwLock<Option<String>>>,

    /// 内存中的消息缓存（用于快速访问）
    message_cache: Arc<RwLock<std::collections::HashMap<String, Vec<ConversationMessage>>>>,

    /// 配置
    config: ConversationConfig,
}

/// 对话配置
#[derive(Debug, Clone)]
pub struct ConversationConfig {
    /// 最大消息数量
    pub max_messages: usize,

    /// 最大 token 数量
    pub max_tokens: usize,

    /// 是否启用持久化
    pub enable_persistence: bool,

    /// 历史文件路径
    pub history_path: PathBuf,
}

impl Default for ConversationConfig {
    fn default() -> Self {
        Self {
            max_messages: 100,
            max_tokens: 32000,
            enable_persistence: true,
            history_path: dirs::config_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("ctx-audit")
                .join("conversations"),
        }
    }
}

impl ConversationManager {
    /// 创建新的对话管理器
    pub fn new(db: Arc<Database>) -> Self {
        let config = ConversationConfig::default();

        Self {
            db,
            current_conversation: Arc::new(RwLock::new(None)),
            message_cache: Arc::new(RwLock::new(std::collections::HashMap::new())),
            config,
        }
    }

    /// 设置配置
    pub fn with_config(mut self, config: ConversationConfig) -> Self {
        self.config = config;
        self
    }

    /// 创建新会话
    pub async fn create_conversation(
        &self,
        title: String,
        project_path: Option<String>,
    ) -> Result<Conversation, String> {
        let conversation = Conversation {
            id: uuid::Uuid::new_v4().to_string(),
            title,
            project_path,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            message_count: 0,
            tokens_used: 0,
        };

        // 保存到数据库
        if self.config.enable_persistence {
            // TODO: 实现数据库持久化
        }

        Ok(conversation)
    }

    /// 获取当前会话
    pub async fn get_current_conversation(&self) -> Option<String> {
        self.current_conversation.read().await.clone()
    }

    /// 设置当前会话
    pub async fn set_current_conversation(&self, id: String) {
        let mut current = self.current_conversation.write().await;
        *current = Some(id);
    }

    /// 添加消息
    pub async fn add_message(
        &self,
        conversation_id: &str,
        message: ConversationMessage,
    ) -> Result<(), String> {
        // 添加到缓存
        let mut cache = self.message_cache.write().await;
        cache.entry(conversation_id.to_string())
            .or_insert_with(Vec::new)
            .push(message.clone());

        // 保存到数据库
        if self.config.enable_persistence {
            // TODO: 实现数据库持久化
        }

        Ok(())
    }

    /// 获取会话消息
    pub async fn get_messages(&self, conversation_id: &str) -> Vec<ConversationMessage> {
        let cache = self.message_cache.read().await;

        if let Some(messages) = cache.get(conversation_id) {
            return messages.clone();
        }

        // 从数据库加载
        // TODO: 实现数据库加载
        Vec::new()
    }

    /// 获取 LLM 格式的消息历史（已压缩）
    pub async fn get_llm_messages(&self, conversation_id: &str) -> Vec<LLMMessage> {
        let messages = self.get_messages(conversation_id).await;

        // 转换为 LLM 格式
        let llm_messages: Vec<LLMMessage> = messages.iter()
            .map(|m| m.to_llm_message())
            .collect();

        // 应用上下文压缩
        self.compress_context(&llm_messages)
    }

    /// 压缩上下文
    fn compress_context(&self, messages: &[LLMMessage]) -> Vec<LLMMessage> {
        if messages.len() <= self.config.max_messages {
            return messages.to_vec();
        }

        // 保留最近的 N 条消息
        let recent_messages = &messages[messages.len() - self.config.max_messages..];

        // 如果还是太多，可以使用摘要
        // TODO: 实现更智能的压缩策略

        recent_messages.to_vec()
    }

    /// 列出所有会话
    pub async fn list_conversations(&self) -> Vec<Conversation> {
        // TODO: 从数据库加载
        Vec::new()
    }

    /// 删除会话
    pub async fn delete_conversation(&self, id: &str) -> Result<(), String> {
        // 从缓存移除
        let mut cache = self.message_cache.write().await;
        cache.remove(id);

        // 从数据库删除
        if self.config.enable_persistence {
            // TODO: 实现数据库删除
        }

        Ok(())
    }

    /// 清空当前会话
    pub async fn clear_current(&self) -> Result<(), String> {
        if let Some(ref id) = *self.current_conversation.read().await {
            let mut cache = self.message_cache.write().await;
            cache.remove(id);
        }

        Ok(())
    }

    /// 搜索消息
    pub async fn search_messages(&self, query: &str) -> Vec<ConversationMessage> {
        let cache = self.message_cache.read().await;
        let mut results = Vec::new();

        for messages in cache.values() {
            for msg in messages {
                if msg.content.contains(query) {
                    results.push(msg.clone());
                }
            }
        }

        results
    }

    /// 获取统计信息
    pub async fn get_stats(&self) -> ConversationStats {
        let cache = self.message_cache.read().await;

        let total_conversations = cache.len();
        let total_messages: usize = cache.values().map(|v| v.len()).sum();

        ConversationStats {
            total_conversations,
            total_messages,
            active_conversation: self.current_conversation.read().await.is_some(),
        }
    }
}

/// 对话统计
#[derive(Debug, Clone)]
pub struct ConversationStats {
    /// 会话总数
    pub total_conversations: usize,

    /// 消息总数
    pub total_messages: usize,

    /// 是否有活动会话
    pub active_conversation: bool,
}

/// 项目上下文注入器
pub struct ProjectContextInjector {
    /// 数据库
    db: Arc<Database>,
}

impl ProjectContextInjector {
    /// 创建新的注入器
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// 构建项目上下文
    pub async fn build_context(
        &self,
        project_path: &str,
    ) -> Result<String, String> {
        // 获取项目信息
        let project = self.db.projects()
            .await
            .get_by_path(project_path)
            .await
            .map_err(|e| format!("获取项目失败: {}", e))?;

        // 获取项目统计
        let stats = self.db.projects()
            .await
            .get_stats(project.id)
            .await
            .map_err(|e| format!("获取统计失败: {}", e))?;

        // 获取最近的漏洞
        let recent_findings = self.db.findings()
            .await
            .list_findings(
                Some(project.id),
                None,
                None,
                5,
            )
            .await
            .map_err(|e| format!("获取漏洞失败: {}", e))?;

        let mut context = format!(
            "项目: {}\n路径: {}\n\n统计:\n  文件数: {}\n  代码行数: {}\n  漏洞数: {}\n\n",
            project.name,
            project_path,
            stats.file_count.unwrap_or(0),
            stats.line_count.unwrap_or(0),
            stats.finding_count.unwrap_or(0),
        );

        if !recent_findings.is_empty() {
            context.push_str("最近发现的漏洞:\n");
            for finding in recent_findings {
                context.push_str(&format!(
                    "  [{}] {} - {}:{}\n",
                    finding.severity,
                    finding.title.unwrap_or_default(),
                    finding.file_path,
                    finding.line_number
                ));
            }
        }

        Ok(context)
    }

    /// 构建文件上下文
    pub async fn build_file_context(
        &self,
        file_path: &str,
    ) -> Result<String, String> {
        // 获取文件的符号信息
        let symbols = self.db.symbol_queries()
            .await
            .get_file_symbols(file_path)
            .await
            .map_err(|e| format!("获取符号失败: {}", e))?;

        if symbols.is_empty() {
            return Ok(format!("文件: {}\n\n此文件尚未索引。", file_path));
        }

        let mut context = format!("文件: {}\n\n符号定义:\n", file_path);

        // 按类型分组
        let mut classes = Vec::new();
        let mut functions = Vec::new();
        let mut other = Vec::new();

        for symbol in symbols {
            match symbol.symbol_type.as_str() {
                "class" | "interface" | "struct" => {
                    classes.push(symbol);
                }
                "function" | "method" => {
                    functions.push(symbol);
                }
                _ => {
                    other.push(symbol);
                }
            }
        }

        if !classes.is_empty() {
            context.push_str("  类/接口:\n");
            for cls in classes {
                context.push_str(&format!(
                    "    • {} (行 {})\n",
                    cls.symbol_name,
                    cls.line_number
                ));
            }
        }

        if !functions.is_empty() {
            context.push_str("  函数/方法:\n");
            for func in functions {
                context.push_str(&format!(
                    "    • {} (行 {})\n",
                    func.symbol_name,
                    func.line_number
                ));
            }
        }

        Ok(context)
    }
}
