// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 对话历史和上下文管理
//!
//! 管理与 LLM 的对话历史，支持持久化和上下文压缩

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};

use crate::database::{Database, DbConversation, DbConversationMessage, CreateConversation, CreateConversationMessage, ConversationQueries};
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

impl From<DbConversation> for Conversation {
    fn from(db: DbConversation) -> Self {
        let created_at = DateTime::parse_from_rfc3339(&db.created_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        let updated_at = DateTime::parse_from_rfc3339(&db.updated_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        Self {
            id: db.id,
            title: db.title,
            project_path: db.project_path,
            created_at,
            updated_at,
            message_count: db.message_count as usize,
            tokens_used: db.tokens_used as u64,
        }
    }
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

impl From<DbConversationMessage> for ConversationMessage {
    fn from(db: DbConversationMessage) -> Self {
        let timestamp = DateTime::parse_from_rfc3339(&db.timestamp)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        Self {
            id: db.id,
            conversation_id: db.conversation_id,
            role: db.role,
            content: db.content,
            is_tool_call: db.is_tool_call,
            tool_name: db.tool_name,
            timestamp,
            tokens: db.tokens as u32,
        }
    }
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
        let id = uuid::Uuid::new_v4().to_string();
        let create = CreateConversation {
            id: id.clone(),
            title,
            project_path,
        };

        // 保存到数据库
        if self.config.enable_persistence {
            match ConversationQueries::create(self.db.pool(), &create).await {
                Ok(db_conv) => {
                    let conv: Conversation = db_conv.into();
                    return Ok(conv);
                }
                Err(e) => {
                    return Err(format!("创建会话失败: {}", e));
                }
            }
        }

        // 返回基本会话信息（不启用持久化时）
        Ok(Conversation {
            id: create.id,
            title: create.title,
            project_path: create.project_path,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            message_count: 0,
            tokens_used: 0,
        })
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
            let create_msg = CreateConversationMessage {
                id: message.id.clone(),
                conversation_id: conversation_id.to_string(),
                role: message.role.clone(),
                content: message.content.clone(),
                is_tool_call: message.is_tool_call,
                tool_name: message.tool_name.clone(),
                tokens: message.tokens as i32,
            };

            if let Err(e) = ConversationQueries::add_message(self.db.pool(), &create_msg).await {
                return Err(format!("保存消息失败: {}", e));
            }

            // 更新会话统计
            let (msg_count, total_tokens) = match ConversationQueries::get_stats(self.db.pool(), conversation_id).await {
                Ok(stats) => stats,
                Err(e) => {
                    tracing::error!("获取会话统计失败: {}", e);
                    (0, 0)
                }
            };

            if let Err(e) = ConversationQueries::update(
                self.db.pool(),
                conversation_id,
                msg_count,
                total_tokens,
            ).await {
                tracing::error!("更新会话统计失败: {}", e);
            }
        }

        Ok(())
    }

    /// 获取会话消息
    pub async fn get_messages(&self, conversation_id: &str) -> Vec<ConversationMessage> {
        // 先检查缓存
        {
            let cache = self.message_cache.read().await;
            if let Some(messages) = cache.get(conversation_id) {
                return messages.clone();
            }
        }

        // 从数据库加载
        if self.config.enable_persistence {
            match ConversationQueries::get_messages(self.db.pool(), conversation_id).await {
                Ok(db_messages) => {
                    let messages: Vec<ConversationMessage> = db_messages
                        .into_iter()
                        .map(|m| m.into())
                        .collect();

                    // 更新缓存
                    let mut cache = self.message_cache.write().await;
                    cache.insert(conversation_id.to_string(), messages.clone());

                    return messages;
                }
                Err(e) => {
                    tracing::error!("加载消息失败: {}", e);
                    return Vec::new();
                }
            }
        }

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

        // 智能压缩策略：
        // 1. 保留系统消息
        // 2. 保留最近的用户消息
        // 3. 如果有太多中间消息，使用摘要
        let mut result = Vec::new();

        // 首先添加系统消息
        for msg in messages {
            if matches!(msg.role, MessageRole::System) {
                result.push(msg.clone());
            }
        }

        // 然后添加最近的用户/助手消息
        for msg in recent_messages {
            if !matches!(msg.role, MessageRole::System) {
                result.push(msg.clone());
            }
        }

        // 估算总 token 数量
        let total_tokens: usize = result.iter()
            .map(|m| m.get_text().len() / 4)
            .sum();

        // 如果仍然超过限制，进一步裁剪
        if total_tokens > self.config.max_tokens {
            // 移除最早的非系统消息
            let mut i = 0;
            while i < result.len() {
                if !matches!(result[i].role, MessageRole::System) {
                    result.remove(i);
                    let current_total: usize = result.iter()
                        .map(|m| m.get_text().len() / 4)
                        .sum();
                    if current_total <= self.config.max_tokens {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
        }

        result
    }

    /// 列出所有会话
    pub async fn list_conversations(&self) -> Vec<Conversation> {
        if !self.config.enable_persistence {
            return Vec::new();
        }

        match ConversationQueries::list(self.db.pool(), Some(50)).await {
            Ok(db_convs) => db_convs.into_iter().map(|c| c.into()).collect(),
            Err(e) => {
                tracing::error!("加载会话列表失败: {}", e);
                Vec::new()
            }
        }
    }

    /// 根据项目路径列出会话
    pub async fn list_conversations_by_project(&self, project_path: &str) -> Vec<Conversation> {
        if !self.config.enable_persistence {
            return Vec::new();
        }

        match ConversationQueries::list_by_project(self.db.pool(), project_path).await {
            Ok(db_convs) => db_convs.into_iter().map(|c| c.into()).collect(),
            Err(e) => {
                tracing::error!("加载会话列表失败: {}", e);
                Vec::new()
            }
        }
    }

    /// 获取会话详情
    pub async fn get_conversation(&self, id: &str) -> Option<Conversation> {
        if !self.config.enable_persistence {
            return None;
        }

        match ConversationQueries::get_by_id(self.db.pool(), id).await {
            Ok(Some(db_conv)) => Some(db_conv.into()),
            Ok(None) => None,
            Err(e) => {
                tracing::error!("加载会话失败: {}", e);
                None
            }
        }
    }

    /// 删除会话
    pub async fn delete_conversation(&self, id: &str) -> Result<(), String> {
        // 从缓存移除
        let mut cache = self.message_cache.write().await;
        cache.remove(id);

        // 从数据库删除
        if self.config.enable_persistence {
            ConversationQueries::delete(self.db.pool(), id)
                .await
                .map_err(|e| format!("删除会话失败: {}", e))?;
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
        if !self.config.enable_persistence {
            // 仅搜索缓存
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
        } else {
            // 搜索数据库
            match ConversationQueries::search_messages(self.db.pool(), query).await {
                Ok(db_messages) => db_messages.into_iter().map(|m| m.into()).collect(),
                Err(e) => {
                    tracing::error!("搜索消息失败: {}", e);
                    Vec::new()
                }
            }
        }
    }

    /// 获取统计信息
    pub async fn get_stats(&self) -> ConversationStats {
        let cache = self.message_cache.read().await;

        let total_conversations = if self.config.enable_persistence {
            match ConversationQueries::list(self.db.pool(), None).await {
                Ok(convs) => convs.len(),
                Err(_) => 0,
            }
        } else {
            cache.len()
        };

        let total_messages: usize = cache.values().map(|v| v.len()).sum();

        ConversationStats {
            total_conversations,
            total_messages,
            active_conversation: self.current_conversation.read().await.is_some(),
        }
    }

    /// 从数据库加载并缓存所有会话的消息
    pub async fn load_all_to_cache(&self) -> Result<(), String> {
        if !self.config.enable_persistence {
            return Ok(());
        }

        let conversations = ConversationQueries::list(self.db.pool(), None)
            .await
            .map_err(|e| format!("加载会话失败: {}", e))?;

        for conv in conversations {
            let messages = ConversationQueries::get_messages(self.db.pool(), &conv.id)
                .await
                .map_err(|e| format!("加载消息失败: {}", e))?;

            let conv_messages: Vec<ConversationMessage> = messages
                .into_iter()
                .map(|m| m.into())
                .collect();

            let mut cache = self.message_cache.write().await;
            cache.insert(conv.id, conv_messages);
        }

        Ok(())
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
            .search(1, file_path)
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
