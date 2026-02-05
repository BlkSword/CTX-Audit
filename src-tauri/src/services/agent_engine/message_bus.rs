//! 消息总线
//!
//! 实现 Agent 之间的消息传递

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

use crate::models::message::{AgentMessage, MessagePriority, MessageType};

/// 消息总线
pub struct MessageBus {
    /// 广播通道（用于事件通知）
    event_tx: broadcast::Sender<AgentMessage>,

    /// 按接收者分组的有界队列
    queues: Arc<RwLock<HashMap<String, Arc<MessageQueue>>>>,

    /// 消息历史（用于调试和重放）
    history: Arc<RwLock<VecDeque<AgentMessage>>>,

    /// 历史记录最大数量
    max_history: usize,
}

impl MessageBus {
    /// 创建新的消息总线
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(1000);

        Self {
            event_tx,
            queues: Arc::new(RwLock::new(HashMap::new())),
            history: Arc::new(RwLock::new(VecDeque::with_capacity(1000))),
            max_history: 1000,
        }
    }

    /// 发送消息
    pub async fn send(&self, message: AgentMessage) -> Result<(), String> {
        // 1. 添加到接收者的队列
        let queues = self.queues.read().await;
        if let Some(queue) = queues.get(&message.recipient) {
            queue.push(message.clone()).await?;
        }

        // 2. 广播事件
        let _ = self.event_tx.send(message.clone());

        // 3. 添加到历史
        self.add_to_history(message).await;

        Ok(())
    }

    /// 接收消息（阻塞）
    pub async fn receive(&self, recipient: &str) -> Result<AgentMessage, String> {
        // 获取或创建队列
        let queue = self.get_or_create_queue(recipient).await;
        queue.pop().await
    }

    /// 尝试接收消息（非阻塞）
    pub async fn try_receive(&self, recipient: &str) -> Option<AgentMessage> {
        let queues = self.queues.read().await;
        if let Some(queue) = queues.get(recipient) {
            queue.try_pop().await
        } else {
            None
        }
    }

    /// 订阅消息事件
    pub fn subscribe(&self) -> broadcast::Receiver<AgentMessage> {
        self.event_tx.subscribe()
    }

    /// 获取消息历史
    pub async fn get_history(&self) -> Vec<AgentMessage> {
        let history = self.history.read().await;
        history.iter().cloned().collect()
    }

    /// 获取特定 Agent 的消息历史
    pub async fn get_agent_history(&self, agent_id: &str) -> Vec<AgentMessage> {
        let history = self.history.read().await;
        history
            .iter()
            .filter(|m| m.sender == agent_id || m.recipient == agent_id)
            .cloned()
            .collect()
    }

    /// 清空消息队列
    pub async fn clear_queue(&self, recipient: &str) {
        let queues = self.queues.read().await;
        if let Some(queue) = queues.get(recipient) {
            queue.clear().await;
        }
    }

    /// 获取队列统计信息
    pub async fn get_queue_stats(&self, recipient: &str) -> Option<QueueStats> {
        let queues = self.queues.read().await;
        if let Some(queue) = queues.get(recipient) {
            Some(queue.get_stats().await)
        } else {
            None
        }
    }

    /// 添加到历史
    async fn add_to_history(&self, message: AgentMessage) {
        let mut history = self.history.write().await;
        history.push_back(message);

        // 限制历史大小
        while history.len() > self.max_history {
            history.pop_front();
        }
    }

    /// 获取或创建队列
    async fn get_or_create_queue(&self, recipient: &str) -> Arc<MessageQueue> {
        // 先尝试读取
        {
            let queues = self.queues.read().await;
            if let Some(queue) = queues.get(recipient) {
                return queue.clone();
            }
        }

        // 不存在则创建
        let mut queues = self.queues.write().await;
        let queue = Arc::new(MessageQueue::new(recipient.to_string()));
        queues.insert(recipient.to_string(), queue.clone());
        queue
    }
}

impl Default for MessageBus {
    fn default() -> Self {
        Self::new()
    }
}

/// 消息队列
///
/// 基于优先级的消息队列
pub struct MessageQueue {
    agent_id: String,

    /// 高优先级队列
    high_priority: Arc<RwLock<VecDeque<AgentMessage>>>,

    /// 普通优先级队列
    normal_priority: Arc<RwLock<VecDeque<AgentMessage>>>,

    /// 低优先级队列
    low_priority: Arc<RwLock<VecDeque<AgentMessage>>>,

    /// 通知通道
    notify: tokio::sync::Notify,
}

impl MessageQueue {
    /// 创建新的消息队列
    pub fn new(agent_id: String) -> Self {
        Self {
            agent_id,
            high_priority: Arc::new(RwLock::new(VecDeque::new())),
            normal_priority: Arc::new(RwLock::new(VecDeque::new())),
            low_priority: Arc::new(RwLock::new(VecDeque::new())),
            notify: tokio::sync::Notify::new(),
        }
    }

    /// 推送消息
    pub async fn push(&self, message: AgentMessage) -> Result<(), String> {
        let queue = match message.priority {
            MessagePriority::Urgent | MessagePriority::High => &self.high_priority,
            MessagePriority::Normal => &self.normal_priority,
            MessagePriority::Low => &self.low_priority,
        };

        queue.write().await.push_back(message);
        self.notify.notify_one();
        Ok(())
    }

    /// 弹出消息（阻塞等待）
    pub async fn pop(&self) -> Result<AgentMessage, String> {
        loop {
            // 尝试从高到低获取消息
            if let Some(msg) = self.try_pop().await {
                return Ok(msg);
            }

            // 等待通知
            self.notify.notified().await;
        }
    }

    /// 尝试弹出消息（非阻塞）
    pub async fn try_pop(&self) -> Option<AgentMessage> {
        // 优先从高优先级队列获取
        if let Some(msg) = self.high_priority.write().await.pop_front() {
            return Some(msg);
        }

        // 然后从普通优先级队列获取
        if let Some(msg) = self.normal_priority.write().await.pop_front() {
            return Some(msg);
        }

        // 最后从低优先级队列获取
        self.low_priority.write().await.pop_front()
    }

    /// 清空队列
    pub async fn clear(&self) {
        self.high_priority.write().await.clear();
        self.normal_priority.write().await.clear();
        self.low_priority.write().await.clear();
    }

    /// 获取队列大小
    pub async fn size(&self) -> usize {
        let high = self.high_priority.read().await.len();
        let normal = self.normal_priority.read().await.len();
        let low = self.low_priority.read().await.len();
        high + normal + low
    }

    /// 获取统计信息
    pub async fn get_stats(&self) -> QueueStats {
        QueueStats {
            agent_id: self.agent_id.clone(),
            total_messages: self.size().await,
            high_priority: self.high_priority.read().await.len(),
            normal_priority: self.normal_priority.read().await.len(),
            low_priority: self.low_priority.read().await.len(),
        }
    }
}

/// 队列统计信息
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QueueStats {
    /// Agent ID
    pub agent_id: String,

    /// 总消息数
    pub total_messages: usize,

    /// 高优先级消息数
    pub high_priority: usize,

    /// 普通优先级消息数
    pub normal_priority: usize,

    /// 低优先级消息数
    pub low_priority: usize,
}

/// 消息总线统计信息
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MessageBusStats {
    /// 总消息数
    pub total_messages: usize,

    /// 队列统计
    pub queue_stats: Vec<QueueStats>,

    /// 历史消息数
    pub history_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_message_bus_send_receive() {
        let bus = MessageBus::new();

        let message = AgentMessage::new(
            "agent1".to_string(),
            "agent2".to_string(),
            MessageType::Information,
            crate::models::message::MessageContent::Information {
                message: "Hello".to_string(),
                data: None,
            },
        );

        bus.send(message).await.unwrap();

        let received = bus.receive("agent2").await.unwrap();
        assert_eq!(received.sender, "agent1");
        assert_eq!(received.recipient, "agent2");
    }

    #[tokio::test]
    async fn test_message_queue_priority() {
        let queue = MessageQueue::new("test".to_string());

        // 发送不同优先级的消息
        let low = AgentMessage::new(
            "sender".to_string(),
            "test".to_string(),
            MessageType::Information,
            crate::models::message::MessageContent::Information {
                message: "low".to_string(),
                data: None,
            },
        )
        .with_priority(MessagePriority::Low);

        let high = AgentMessage::new(
            "sender".to_string(),
            "test".to_string(),
            MessageType::Information,
            crate::models::message::MessageContent::Information {
                message: "high".to_string(),
                data: None,
            },
        )
        .with_priority(MessagePriority::High);

        queue.push(low).await.unwrap();
        queue.push(high).await.unwrap();

        // 高优先级应该先出来
        let msg1 = queue.try_pop().await.unwrap();
        assert_eq!(msg1.get_text(), "high");

        let msg2 = queue.try_pop().await.unwrap();
        assert_eq!(msg2.get_text(), "low");
    }
}
