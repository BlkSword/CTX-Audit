// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 消息系统 (Mailbox)
//!
//! 实现 Coordinator-Specialist 架构中的 Peer-to-Peer 消息传递。

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{mpsc, broadcast};

/// 消息 ID
pub type MessageId = String;

/// 消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    /// 点对点消息
    Direct {
        from: String,
        to: String,
        content: MessageContent,
    },

    /// 广播消息
    Broadcast {
        from: String,
        content: MessageContent,
    },

    /// 协调器指令
    CoordinatorCommand {
        to: String,
        command: CoordinatorDirective,
    },
}

/// 消息内容
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageContent {
    /// 发现共享
    FindingShared {
        finding: InternalFinding,
        context: String,
    },

    /// 请求协助
    AssistanceRequest {
        task_id: String,
        reason: String,
        suggested_specialty: Option<String>,
    },

    /// 质疑发现
    FindingChallenge {
        finding_id: String,
        challenge_reason: String,
    },

    /// 进度更新
    ProgressUpdate {
        task_id: String,
        progress: f32,
        notes: String,
    },

    /// 任务完成通知
    TaskCompleted {
        task_id: String,
        success: bool,
        summary: String,
    },

    /// 自定义消息
    Custom {
        message_type: String,
        data: serde_json::Value,
    },
}

/// 内部发现数据（用于 P2P 消息传递）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalFinding {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub confidence: f32,
    pub location: String,
    pub description: String,
    pub evidence: Option<String>,
}

/// 协调器指令
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CoordinatorDirective {
    /// 切换阶段
    PhaseTransition(AuditPhase),

    /// 重新分配任务
    ReassignTask {
        task_id: String,
        new_specialist: String,
    },

    /// 暂停任务
    SuspendTask(String),

    /// 恢复任务
    ResumeTask(String),

    /// 请求状态报告
    RequestStatusReport,

    /// 计划批准请求回复
    PlanApprovalResponse {
        approved: bool,
        feedback: Option<String>,
    },

    /// 调整任务优先级
    AdjustPriority {
        task_id: String,
        new_priority: String,
    },
}

/// 审计阶段
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AuditPhase {
    Initialization,
    DeterministicScan,
    DeepAnalysis,
    Verification,
    Reporting,
}

/// 消息系统 (Mailbox)
///
/// 核心特性：
/// - Peer-to-Peer 直接消息
/// - Broadcast 广播消息
/// - 自动消息传递
/// - 消息优先级
#[derive(Clone)]
pub struct Mailbox {
    /// 各 Specialist 的消息队列
    queues: Arc<tokio::sync::RwLock<HashMap<String, mpsc::Sender<Message>>>>,

    /// 消息总线 (广播)
    broadcast_tx: broadcast::Sender<Message>,

    /// 消息历史 (可选，用于调试)
    message_history: Arc<tokio::sync::RwLock<VecDeque<Message>>>,
}

impl Mailbox {
    /// 创建新的消息系统
    pub fn new() -> Self {
        let (broadcast_tx, _) = broadcast::channel(100);

        Self {
            queues: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            broadcast_tx,
            message_history: Arc::new(tokio::sync::RwLock::new(VecDeque::new())),
        }
    }

    /// 注册 Specialist
    pub async fn register_specialist(&self, specialist_id: &str) -> mpsc::Receiver<Message> {
        let (tx, rx) = mpsc::channel(100);
        self.queues.write().await.insert(specialist_id.to_string(), tx);
        rx
    }

    /// 注销 Specialist
    pub async fn unregister_specialist(&self, specialist_id: &str) {
        self.queues.write().await.remove(specialist_id);
    }

    /// Specialist 发送直接消息
    pub async fn send_direct(&self, from: &str, to: &str, content: MessageContent) -> anyhow::Result<()> {
        let msg = Message::Direct {
            from: from.to_string(),
            to: to.to_string(),
            content,
        };

        // 记录历史
        self.record_message(msg.clone()).await;

        let queues = self.queues.read().await;
        if let Some(tx) = queues.get(to) {
            tx.send(msg).await
                .map_err(|_| anyhow::anyhow!("发送消息失败: Specialist {} 可能已离线", to))?;
            Ok(())
        } else {
            Err(anyhow::anyhow!("Specialist {} 不存在", to))
        }
    }

    /// Specialist 发送广播
    pub async fn broadcast(&self, from: &str, content: MessageContent) {
        let msg = Message::Broadcast {
            from: from.to_string(),
            content,
        };

        // 记录历史
        self.record_message(msg.clone()).await;

        let _ = self.broadcast_tx.send(msg);
    }

    /// Coordinator 发送指令
    pub async fn send_command(&self, to: &str, command: CoordinatorDirective) -> anyhow::Result<()> {
        let msg = Message::CoordinatorCommand {
            to: to.to_string(),
            command,
        };

        // 记录历史
        self.record_message(msg.clone()).await;

        let queues = self.queues.read().await;
        if let Some(tx) = queues.get(to) {
            tx.send(msg).await
                .map_err(|_| anyhow::anyhow!("发送指令失败: Specialist {} 可能已离线", to))?;
            Ok(())
        } else {
            Err(anyhow::anyhow!("Specialist {} 不存在", to))
        }
    }

    /// 订阅广播消息
    pub fn subscribe(&self) -> broadcast::Receiver<Message> {
        self.broadcast_tx.subscribe()
    }

    /// 记录消息历史
    async fn record_message(&self, msg: Message) {
        let mut history = self.message_history.write().await;
        history.push_back(msg);

        // 限制历史大小
        if history.len() > 1000 {
            history.pop_front(); // O(1) 操作
        }
    }

    /// 获取消息历史
    pub async fn get_message_history(&self) -> Vec<Message> {
        self.message_history.read().await.iter().cloned().collect()
    }

    /// 获取已注册的 Specialist 列表
    pub async fn get_registered_specialists(&self) -> Vec<String> {
        self.queues.read().await.keys().cloned().collect()
    }
}

impl Default for Mailbox {
    fn default() -> Self {
        Self::new()
    }
}

/// 消息处理器 Trait
#[async_trait::async_trait]
pub trait MessageHandler: Send + Sync {
    /// 处理直接消息
    async fn handle_direct_message(
        &mut self,
        from: &str,
        content: &MessageContent,
    ) -> anyhow::Result<()>;

    /// 处理广播消息
    async fn handle_broadcast_message(
        &mut self,
        from: &str,
        content: &MessageContent,
    ) -> anyhow::Result<()>;

    /// 处理协调器指令
    async fn handle_coordinator_command(
        &mut self,
        command: &CoordinatorDirective,
    ) -> anyhow::Result<()>;
}

/// 便捷的消息处理宏
#[macro_export]
macro_rules! impl_message_handler {
    ($struct_name:ty) => {
        #[async_trait::async_trait]
        impl MessageHandler for $struct_name {
            async fn handle_direct_message(
                &mut self,
                from: &str,
                content: &MessageContent,
            ) -> anyhow::Result<()> {
                match content {
                    MessageContent::FindingShared { finding, context } => {
                        tracing::info!("[{}] 来自 {} 的发现共享: {}", stringify!($struct_name), from, finding.title);
                        // 处理发现共享
                    }
                    MessageContent::AssistanceRequest { task_id, reason, suggested_specialty } => {
                        tracing::info!("[{}] 来自 {} 的协助请求: {} - {}", stringify!($struct_name), from, task_id, reason);
                        // 处理协助请求
                    }
                    MessageContent::FindingChallenge { finding_id, challenge_reason } => {
                        tracing::warn!("[{}] 来自 {} 的质疑: {} - {}", stringify!($struct_name), from, finding_id, challenge_reason);
                        // 处理质疑
                    }
                    MessageContent::ProgressUpdate { task_id, progress, notes } => {
                        tracing::info!("[{}] {} 进度: {}% - {}", stringify!($struct_name), task_id, (progress * 100.0) as u32, notes);
                        // 处理进度更新
                    }
                    MessageContent::TaskCompleted { task_id, success, summary } => {
                        tracing::info!("[{}] 任务完成: {} - {} - {}", stringify!($struct_name), task_id, success, summary);
                        // 处理任务完成
                    }
                    MessageContent::Custom { message_type, data } => {
                        tracing::debug!("[{}] 自定义消息: {}", stringify!($struct_name), message_type);
                        // 处理自定义消息
                    }
                }
                Ok(())
            }

            async fn handle_broadcast_message(
                &mut self,
                from: &str,
                content: &MessageContent,
            ) -> anyhow::Result<()> {
                self.handle_direct_message(from, content).await
            }

            async fn handle_coordinator_command(
                &mut self,
                command: &CoordinatorDirective,
            ) -> anyhow::Result<()> {
                match command {
                    CoordinatorDirective::PhaseTransition(phase) => {
                        tracing::info!("[{}] 切换阶段: {:?}", stringify!($struct_name), phase);
                        // 处理阶段切换
                    }
                    CoordinatorDirective::ReassignTask { task_id, new_specialist } => {
                        tracing::info!("[{}] 重新分配: {} -> {}", stringify!($struct_name), task_id, new_specialist);
                        // 处理任务重分配
                    }
                    CoordinatorDirective::SuspendTask(task_id) => {
                        tracing::warn!("[{}] 暂停任务: {}", stringify!($struct_name), task_id);
                        // 处理任务暂停
                    }
                    CoordinatorDirective::ResumeTask(task_id) => {
                        tracing::info!("[{}] 恢复任务: {}", stringify!($struct_name), task_id);
                        // 处理任务恢复
                    }
                    CoordinatorDirective::RequestStatusReport => {
                        tracing::debug!("[{}] 请求状态报告", stringify!($struct_name));
                        // 处理状态报告请求
                    }
                    CoordinatorDirective::PlanApprovalResponse { approved, feedback } => {
                        tracing::info!("[{}] 计划批准: {} - {:?}", stringify!($struct_name), approved, feedback);
                        // 处理计划批准响应
                    }
                    CoordinatorDirective::AdjustPriority { task_id, new_priority } => {
                        tracing::info!("[{}] 调整优先级: {} -> {}", stringify!($struct_name), task_id, new_priority);
                        // 处理优先级调整
                    }
                }
                Ok(())
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mailbox_direct_message() {
        let mailbox = Mailbox::new();

        // 注册两个 Specialist
        let mut rx1 = mailbox.register_specialist("specialist-1").await;
        let mut rx2 = mailbox.register_specialist("specialist-2").await;

        // 发送直接消息
        let content = MessageContent::ProgressUpdate {
            task_id: "task-1".to_string(),
            progress: 0.5,
            notes: "进行中".to_string(),
        };

        mailbox.send_direct("specialist-1", "specialist-2", content).await.unwrap();

        // 接收消息
        let msg = rx2.recv().await.unwrap();
        match msg {
            Message::Direct { from, to, .. } => {
                assert_eq!(from, "specialist-1");
                assert_eq!(to, "specialist-2");
            }
            _ => panic!("期望直接消息"),
        }
    }

    #[tokio::test]
    async fn test_mailbox_broadcast() {
        let mailbox = Mailbox::new();

        // 注册两个 Specialist
        let _rx1 = mailbox.register_specialist("specialist-1").await;
        let _rx2 = mailbox.register_specialist("specialist-2").await;

        // 订阅广播
        let mut sub1 = mailbox.subscribe();
        let mut sub2 = mailbox.subscribe();

        // 发送广播
        let content = MessageContent::TaskCompleted {
            task_id: "task-1".to_string(),
            success: true,
            summary: "完成".to_string(),
        };

        mailbox.broadcast("specialist-1", content).await;

        // 两个订阅者都应该收到
        let msg1 = sub1.recv().await.unwrap();
        let msg2 = sub2.recv().await.unwrap();

        match (&msg1, &msg2) {
            (Message::Broadcast { from, .. }, Message::Broadcast { from: from2, .. }) => {
                assert_eq!(from, "specialist-1");
                assert_eq!(from2, "specialist-1");
            }
            _ => panic!("期望广播消息"),
        }
    }

    #[tokio::test]
    async fn test_coordinator_command() {
        let mailbox = Mailbox::new();

        let mut rx = mailbox.register_specialist("specialist-1").await;

        // 发送协调器指令
        let command = CoordinatorDirective::PhaseTransition(AuditPhase::DeepAnalysis);
        mailbox.send_command("specialist-1", command).await.unwrap();

        // 接收指令
        let msg = rx.recv().await.unwrap();
        match msg {
            Message::CoordinatorCommand { command, .. } => {
                assert!(matches!(command, CoordinatorDirective::PhaseTransition(_)));
            }
            _ => panic!("期望协调器指令"),
        }
    }
}
