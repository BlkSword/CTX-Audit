//! 事件管理器
//!
//! 提供事件节流、批处理和去重功能

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::models::events::{AgentEvent, EventFilter, EventType};

/// 事件发射器 trait
#[async_trait::async_trait]
pub trait EventEmitter: Send + Sync {
    /// 发射事件
    async fn emit(&self, event: &AgentEvent) -> Result<(), String>;
}

/// 事件管理器配置
#[derive(Debug, Clone)]
pub struct EventManagerConfig {
    /// 启用节流
    pub enable_throttle: bool,

    /// 节流间隔（毫秒）
    pub throttle_ms: u64,

    /// 启用去重
    pub enable_dedup: bool,

    /// 去重时间窗口（秒）
    pub dedup_window_seconds: u64,

    /// 启用批处理
    pub enable_batch: bool,

    /// 批处理大小
    pub batch_size: usize,

    /// 批处理超时（毫秒）
    pub batch_timeout_ms: u64,
}

impl Default for EventManagerConfig {
    fn default() -> Self {
        Self {
            enable_throttle: true,
            throttle_ms: 100,
            enable_dedup: true,
            dedup_window_seconds: 5,
            enable_batch: false,
            batch_size: 10,
            batch_timeout_ms: 1000,
        }
    }
}

/// 事件管理器
///
/// 提供事件的节流、去重和批处理功能
pub struct EventManager {
    /// 底层发射器
    emitter: Arc<dyn EventEmitter>,

    /// 配置
    config: EventManagerConfig,

    /// 节流状态（每个事件类型）
    throttle_state: Arc<Mutex<HashMap<String, Instant>>>,

    /// 去重缓存（事件哈希 -> 时间戳）
    dedup_cache: Arc<Mutex<HashMap<u64, Instant>>>,

    /// 批处理缓冲区
    batch_buffer: Arc<Mutex<Vec<AgentEvent>>>,
}

impl EventManager {
    /// 创建新的事件管理器
    pub fn new(emitter: Arc<dyn EventEmitter>, config: EventManagerConfig) -> Self {
        // 启动批处理任务
        let manager = Self {
            emitter,
            config,
            throttle_state: Arc::new(Mutex::new(HashMap::new())),
            dedup_cache: Arc::new(Mutex::new(HashMap::new())),
            batch_buffer: Arc::new(Mutex::new(Vec::new())),
        };

        if manager.config.enable_batch {
            manager.start_batch_task();
        }

        // 启动清理任务
        manager.start_cleanup_task();

        manager
    }

    /// 发射事件
    pub async fn emit(&self, event: AgentEvent) -> Result<(), String> {
        // 检查去重
        if self.config.enable_dedup {
            if self.is_duplicate(&event) {
                return Ok(());
            }
        }

        // 检查节流
        if self.config.enable_throttle {
            if self.should_throttle(&event) {
                // 添加到批处理缓冲区
                if self.config.enable_batch {
                    self.add_to_batch(event).await;
                }
                return Ok(());
            }
        }

        // 发射事件
        self.emitter.emit(&event).await?;

        // 记录发射时间（用于节流）
        if self.config.enable_throttle {
            self.record_emission(&event).await;
        }

        Ok(())
    }

    /// 批量发射事件
    pub async fn emit_batch(&self, events: Vec<AgentEvent>) -> Result<(), String> {
        for event in events {
            self.emit(event).await?;
        }
        Ok(())
    }

    /// 过滤并发射事件
    pub async fn emit_filtered(
        &self,
        events: Vec<AgentEvent>,
        filter: &EventFilter,
    ) -> Result<(), String> {
        for event in events {
            if self.matches_filter(&event, filter) {
                self.emit(event).await?;
            }
        }
        Ok(())
    }

    /// 检查是否是重复事件
    fn is_duplicate(&self, event: &AgentEvent) -> bool {
        let hash = self.event_hash(event);
        let now = Instant::now();

        let mut cache = self.dedup_cache.blocking_lock();
        let window = Duration::from_secs(self.config.dedup_window_seconds);

        if let Some(&timestamp) = cache.get(&hash) {
            if now.duration_since(timestamp) < window {
                return true;
            }
        }

        cache.insert(hash, now);
        false
    }

    /// 计算事件哈希（用于去重）
    fn event_hash(&self, event: &AgentEvent) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();

        event.audit_id.hash(&mut hasher);
        event.event_type.as_str().hash(&mut hasher);
        event.agent_type.hash(&mut hasher);
        event.message.hash(&mut hasher);
        event.thought.hash(&mut hasher);

        hasher.finish()
    }

    /// 检查是否应该节流
    fn should_throttle(&self, event: &AgentEvent) -> bool {
        // 某些事件类型不节流
        if matches!(
            event.event_type,
            EventType::Start | EventType::Complete | EventType::Error | EventType::AgentFailed
        ) {
            return false;
        }

        let key = format!("{}:{}", event.audit_id, event.event_type.as_str());
        let state = self.throttle_state.blocking_lock();

        if let Some(&last_time) = state.get(&key) {
            let elapsed = last_time.elapsed();
            elapsed.as_millis() < self.config.throttle_ms as u128
        } else {
            false
        }
    }

    /// 记录发射时间
    async fn record_emission(&self, event: &AgentEvent) {
        let key = format!("{}:{}", event.audit_id, event.event_type.as_str());
        let mut state = self.throttle_state.lock().await;
        state.insert(key, Instant::now());
    }

    /// 添加到批处理缓冲区
    async fn add_to_batch(&self, event: AgentEvent) {
        let mut buffer = self.batch_buffer.lock().await;
        buffer.push(event);

        // 如果达到批处理大小，立即发送
        if buffer.len() >= self.config.batch_size {
            let events = buffer.drain(..).collect::<Vec<_>>();
            drop(buffer);

            for event in events {
                let _ = self.emitter.emit(&event).await;
            }
        }
    }

    /// 启动批处理任务
    fn start_batch_task(&self) {
        let buffer = self.batch_buffer.clone();
        let emitter = self.emitter.clone();
        let timeout = Duration::from_millis(self.config.batch_timeout_ms);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(timeout);
            loop {
                interval.tick().await;

                let events = {
                    let mut buffer = buffer.lock().await;
                    if buffer.is_empty() {
                        continue;
                    }
                    buffer.drain(..).collect::<Vec<_>>()
                };

                for event in events {
                    let _ = emitter.emit(&event).await;
                }
            }
        });
    }

    /// 启动清理任务（定期清理过期的去重缓存）
    fn start_cleanup_task(&self) {
        let cache = self.dedup_cache.clone();
        let window = Duration::from_secs(self.config.dedup_window_seconds * 2);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(window);
            loop {
                interval.tick().await;

                let now = Instant::now();
                let mut cache = cache.lock().await;
                cache.retain(|_, &mut timestamp| {
                    now.duration_since(timestamp) < window
                });
            }
        });
    }

    /// 检查事件是否匹配过滤器
    fn matches_filter(&self, event: &AgentEvent, filter: &EventFilter) -> bool {
        // 检查事件类型
        if let Some(ref types) = filter.event_types {
            if !types.contains(&event.event_type) {
                return false;
            }
        }

        // 检查 Agent 类型
        if let Some(ref agent_types) = filter.agent_types {
            if let Some(ref agent_type) = event.agent_type {
                if !agent_types.contains(agent_type) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // 检查 Agent ID
        if let Some(ref agent_ids) = filter.agent_ids {
            if let Some(ref agent_id) = event.agent_id {
                if !agent_ids.contains(agent_id) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // 检查序列号范围
        if let Some(after) = filter.after_sequence {
            if event.sequence <= after {
                return false;
            }
        }

        if let Some(before) = filter.before_sequence {
            if event.sequence >= before {
                return false;
            }
        }

        true
    }

    /// 获取统计信息
    pub async fn stats(&self) -> EventManagerStats {
        let throttle_size = self.throttle_state.lock().await.len();
        let dedup_size = self.dedup_cache.lock().await.len();
        let batch_size = self.batch_buffer.lock().await.len();

        EventManagerStats {
            throttle_cache_size: throttle_size,
            dedup_cache_size: dedup_size,
            batch_buffer_size: batch_size,
        }
    }
}

/// 事件管理器统计信息
#[derive(Debug, Clone, serde::Serialize)]
pub struct EventManagerStats {
    /// 节流缓存大小
    pub throttle_cache_size: usize,

    /// 去重缓存大小
    pub dedup_cache_size: usize,

    /// 批处理缓冲区大小
    pub batch_buffer_size: usize,
}

/// Agent 事件发射器（简单的日志实现）
pub struct LogEmitter;

#[async_trait::async_trait]
impl EventEmitter for LogEmitter {
    async fn emit(&self, event: &AgentEvent) -> Result<(), String> {
        tracing::info!(
            "[{}] {:?}: {}",
            event.audit_id,
            event.event_type,
            event.message.as_deref().unwrap_or("")
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_event_manager() {
        let emitter = Arc::new(LogEmitter);
        let config = EventManagerConfig {
            enable_throttle: true,
            throttle_ms: 100,
            ..Default::default()
        };

        let manager = EventManager::new(emitter, config);

        let event = AgentEvent::new("test".to_string(), "task1".to_string(), EventType::Info);

        // 第一个事件应该发射
        assert!(manager.emit(event.clone()).await.is_ok());

        // 第二个相同的事件应该被去重
        assert!(manager.emit(event.clone()).await.is_ok());
    }

    #[test]
    fn test_event_hash() {
        let manager = EventManager::new(
            Arc::new(LogEmitter),
            EventManagerConfig::default(),
        );

        let event1 = AgentEvent::new("test".to_string(), "task1".to_string(), EventType::Info);
        let event2 = AgentEvent::new("test".to_string(), "task1".to_string(), EventType::Info);

        assert_eq!(manager.event_hash(&event1), manager.event_hash(&event2));
    }
}
