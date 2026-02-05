//! 事件总线 V2
//!
//! 为每个审计任务提供独立的事件队列

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

use crate::models::events::AgentEvent;

/// 事件总线 V2 配置
#[derive(Debug, Clone)]
pub struct EventBusV2Config {
    /// 队列容量
    pub queue_capacity: usize,

    /// 启用持久化
    pub enable_persistence: bool,
}

impl Default for EventBusV2Config {
    fn default() -> Self {
        Self {
            queue_capacity: 1000,
            enable_persistence: true,
        }
    }
}

/// 事件总线 V2
///
/// 为每个审计任务提供独立的事件队列
pub struct EventBusV2 {
    /// 每个任务的独立队列
    queues: Arc<Mutex<HashMap<String, broadcast::Sender<AgentEvent>>>>,

    /// 序列号计数器（每个任务独立）
    sequences: Arc<Mutex<HashMap<String, i64>>>,

    /// 订阅者计数
    subscribers: Arc<Mutex<HashMap<String, usize>>>,

    /// 配置
    config: EventBusV2Config,
}

impl EventBusV2 {
    /// 创建新的事件总线
    pub fn new(config: EventBusV2Config) -> Self {
        Self {
            queues: Arc::new(Mutex::new(HashMap::new())),
            sequences: Arc::new(Mutex::new(HashMap::new())),
            subscribers: Arc::new(Mutex::new(HashMap::new())),
            config,
        }
    }

    /// 创建或获取队列
    async fn get_or_create_queue(&self, audit_id: &str) -> broadcast::Sender<AgentEvent> {
        let mut queues = self.queues.lock().await;

        if let Some(tx) = queues.get(audit_id) {
            tx.clone()
        } else {
            let (tx, _) = broadcast::channel(self.config.queue_capacity);
            queues.insert(audit_id.to_string(), tx.clone());
            tx
        }
    }

    /// 发布事件
    pub async fn publish(&self, audit_id: &str, mut event: AgentEvent) {
        // 更新序列号
        event.sequence = self.next_sequence(audit_id).await;

        // 推送到队列
        if let Some(tx) = self.queues.lock().await.get(audit_id) {
            let _ = tx.send(event.clone());
        }

        tracing::trace!("[{}] Event published: {:?}", audit_id, event.event_type);
    }

    /// 订阅事件
    pub async fn subscribe(&self, audit_id: &str) -> broadcast::Receiver<AgentEvent> {
        let tx = self.get_or_create_queue(audit_id).await;
        let rx = tx.subscribe();

        // 增加订阅者计数
        let mut subscribers = self.subscribers.lock().await;
        *subscribers.entry(audit_id.to_string()).or_insert(0) += 1;

        rx
    }

    /// 取消订阅
    pub async fn unsubscribe(&self, audit_id: &str) {
        let mut subscribers = self.subscribers.lock().await;
        if let Some(count) = subscribers.get_mut(audit_id) {
            if *count > 0 {
                *count -= 1;
            }

            // 如果没有订阅者了，可以清理队列
            if *count == 0 {
                subscribers.remove(audit_id);
                // 可选：清理队列
                // self.queues.lock().await.remove(audit_id);
            }
        }
    }

    /// 获取下一个序列号
    async fn next_sequence(&self, audit_id: &str) -> i64 {
        let mut sequences = self.sequences.lock().await;
        let seq = sequences.entry(audit_id.to_string()).or_insert(0);
        *seq += 1;
        *seq
    }

    /// 获取当前序列号
    pub async fn current_sequence(&self, audit_id: &str) -> i64 {
        let sequences = self.sequences.lock().await;
        sequences.get(audit_id).copied().unwrap_or(0)
    }

    /// 重置序列号
    pub async fn reset_sequence(&self, audit_id: &str) {
        let mut sequences = self.sequences.lock().await;
        sequences.insert(audit_id.to_string(), 0);
    }

    /// 获取订阅者数量
    pub async fn subscriber_count(&self, audit_id: &str) -> usize {
        let subscribers = self.subscribers.lock().await;
        subscribers.get(audit_id).copied().unwrap_or(0)
    }

    /// 清理任务相关的所有数据
    pub async fn cleanup(&self, audit_id: &str) {
        self.queues.lock().await.remove(audit_id);
        self.sequences.lock().await.remove(audit_id);
        self.subscribers.lock().await.remove(audit_id);

        tracing::debug!("[{}] Event bus cleaned up", audit_id);
    }

    /// 获取统计信息
    pub async fn stats(&self, audit_id: &str) -> EventBusStats {
        let queues = self.queues.lock().await;
        let subscribers = self.subscribers.lock().await;
        let sequences = self.sequences.lock().await;

        EventBusStats {
            audit_id: audit_id.to_string(),
            has_queue: queues.contains_key(audit_id),
            subscriber_count: subscribers.get(audit_id).copied().unwrap_or(0),
            current_sequence: sequences.get(audit_id).copied().unwrap_or(0),
        }
    }

    /// 清空所有数据
    pub async fn clear_all(&self) {
        self.queues.lock().await.clear();
        self.sequences.lock().await.clear();
        self.subscribers.lock().await.clear();
    }
}

impl Default for EventBusV2 {
    fn default() -> Self {
        Self::new(EventBusV2Config::default())
    }
}

/// 事件总线统计信息
#[derive(Debug, Clone, serde::Serialize)]
pub struct EventBusStats {
    /// 审计 ID
    pub audit_id: String,

    /// 是否有队列
    pub has_queue: bool,

    /// 订阅者数量
    pub subscriber_count: usize,

    /// 当前序列号
    pub current_sequence: i64,
}

/// 全局事件总线单例
pub fn global_event_bus() -> &'static EventBusV2 {
    use std::sync::OnceLock;
    static BUS: OnceLock<EventBusV2> = OnceLock::new();
    BUS.get_or_init(|| EventBusV2::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::events::EventType;

    #[tokio::test]
    async fn test_event_bus() {
        let bus = EventBusV2::default();
        let audit_id = "test-audit";

        // 订阅
        let mut rx = bus.subscribe(audit_id).await;

        // 发布事件
        let event = AgentEvent::new(audit_id.to_string(), "task1".to_string(), EventType::Info);
        bus.publish(audit_id, event).await;

        // 接收事件
        let received = rx.recv().await.unwrap();
        assert_eq!(received.audit_id, audit_id);
        assert_eq!(received.sequence, 1);
    }

    #[tokio::test]
    async fn test_sequence_numbers() {
        let bus = EventBusV2::default();
        let audit_id = "test-audit";

        assert_eq!(bus.current_sequence(audit_id).await, 0);

        bus.publish(
            audit_id,
            AgentEvent::new(audit_id.to_string(), "task1".to_string(), EventType::Info),
        )
        .await;

        assert_eq!(bus.current_sequence(audit_id).await, 1);

        bus.publish(
            audit_id,
            AgentEvent::new(audit_id.to_string(), "task1".to_string(), EventType::Info),
        )
        .await;

        assert_eq!(bus.current_sequence(audit_id).await, 2);
    }

    #[tokio::test]
    async fn test_subscriber_count() {
        let bus = EventBusV2::default();
        let audit_id = "test-audit";

        assert_eq!(bus.subscriber_count(audit_id).await, 0);

        let _rx1 = bus.subscribe(audit_id).await;
        assert_eq!(bus.subscriber_count(audit_id).await, 1);

        let _rx2 = bus.subscribe(audit_id).await;
        assert_eq!(bus.subscriber_count(audit_id).await, 2);

        drop(_rx1);
        // 注意：由于 drop 是异步的，计数可能不会立即减少
        // 实际使用中可以通过显式调用 unsubscribe 来管理
    }
}
