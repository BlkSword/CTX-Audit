//! 事件持久化
//!
//! 将事件持久化到 SQLite 数据库

use std::sync::Arc;
use tokio::sync::Mutex;

use crate::models::events::AgentEvent;

/// 事件持久化配置
#[derive(Debug, Clone)]
pub struct EventPersistenceConfig {
    /// 批处理大小
    pub batch_size: usize,

    /// 刷新间隔（毫秒）
    pub flush_interval_ms: u64,

    /// 启用异步持久化
    pub enable_async: bool,
}

impl Default for EventPersistenceConfig {
    fn default() -> Self {
        Self {
            batch_size: 100,
            flush_interval_ms: 5000,
            enable_async: true,
        }
    }
}

/// 事件持久化层
pub struct EventPersistence {
    /// 数据库连接
    db: Arc<crate::services::database::Database>,

    /// 配置
    config: EventPersistenceConfig,

    /// 待持久化的事件缓冲区
    buffer: Arc<Mutex<Vec<AgentEvent>>>,
}

impl EventPersistence {
    /// 创建新的持久化层
    pub fn new(
        db: Arc<crate::services::database::Database>,
        config: EventPersistenceConfig,
    ) -> Self {
        let persistence = Self {
            db,
            config,
            buffer: Arc::new(Mutex::new(Vec::new())),
        };

        // 启动刷新任务
        if persistence.config.enable_async {
            persistence.start_flush_task();
        }

        persistence
    }

    /// 保存事件
    pub async fn save_event(&self, event: AgentEvent) -> Result<(), String> {
        if self.config.enable_async {
            // 添加到缓冲区
            let mut buffer = self.buffer.lock().await;
            buffer.push(event);

            // 如果达到批处理大小，立即刷新
            if buffer.len() >= self.config.batch_size {
                let events = buffer.drain(..).collect::<Vec<_>>();
                drop(buffer);
                self.flush_batch(events).await?;
            }
        } else {
            // 同步保存
            self.save_single_event(&event).await?;
        }

        Ok(())
    }

    /// 批量保存事件
    pub async fn save_events(&self, events: Vec<AgentEvent>) -> Result<(), String> {
        for event in events {
            self.save_event(event).await?;
        }
        Ok(())
    }

    /// 刷新缓冲区
    pub async fn flush(&self) -> Result<(), String> {
        let buffer = self.buffer.lock().await;
        if buffer.is_empty() {
            return Ok(());
        }
        let events = buffer.iter().cloned().collect::<Vec<_>>();
        drop(buffer);
        self.flush_batch(events).await
    }

    /// 刷新批次
    async fn flush_batch(&self, events: Vec<AgentEvent>) -> Result<(), String> {
        if events.is_empty() {
            return Ok(());
        }

        for event in events {
            self.save_single_event(&event).await?;
        }

        Ok(())
    }

    /// 保存单个事件
    async fn save_single_event(&self, event: &AgentEvent) -> Result<(), String> {
        // 序列化事件数据
        let data_str = serde_json::to_string(event)
            .map_err(|e| format!("Failed to serialize event: {}", e))?;

        // 序列化元数据
        let metadata_str = event
            .metadata
            .as_ref()
            .and_then(|m| serde_json::to_string(m).ok())
            .unwrap_or_else(|| "null".to_string());

        // 序列化漏洞数据
        let finding_str = event
            .finding
            .as_ref()
            .and_then(|f| serde_json::to_string(f).ok())
            .unwrap_or_else(|| "null".to_string());

        // 序列化进度数据
        let progress_str = event
            .progress
            .as_ref()
            .and_then(|p| serde_json::to_string(p).ok())
            .unwrap_or_else(|| "null".to_string());

        // 序列化工具输入
        let tool_input_str = event
            .tool_input
            .as_ref()
            .and_then(|i| serde_json::to_string(i).ok())
            .unwrap_or_else(|| "null".to_string());

        // 使用数据库保存
        let sql = r#"
            INSERT INTO agent_events (
                audit_id, task_id, sequence, event_type, agent_type, agent_id,
                message, thought, accumulated_thought, data, metadata,
                tool_name, tool_input, tool_output, finding, progress, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#;

        let timestamp = event.timestamp.to_rfc3339();

        // 这里需要实际的数据库操作
        // 暂时使用日志输出
        tracing::trace!(
            "[{}] Saving event: {:?} (seq={})",
            event.audit_id,
            event.event_type,
            event.sequence
        );

        // TODO: 实际的数据库插入
        // sqlx::query(sql)
        //     .bind(&event.audit_id)
        //     .bind(&event.task_id)
        //     .bind(event.sequence)
        //     .bind(event.event_type.as_str())
        //     .bind(event.agent_type.as_deref())
        //     .bind(event.agent_id.as_deref())
        //     .bind(event.message.as_deref())
        //     .bind(event.thought.as_deref())
        //     .bind(event.accumulated_thought.as_deref())
        //     .bind(&data_str)
        //     .bind(&metadata_str)
        //     .bind(event.tool_name.as_deref())
        //     .bind(&tool_input_str)
        //     .bind(event.tool_output.as_deref())
        //     .bind(&finding_str)
        //     .bind(&progress_str)
        //     .bind(&timestamp)
        //     .execute(&*self.db.pool)
        //     .await
        //     .map_err(|e| format!("Database error: {}", e))?;

        Ok(())
    }

    /// 查询事件
    pub async fn query_events(
        &self,
        audit_id: &str,
        after_sequence: Option<i64>,
        limit: Option<usize>,
    ) -> Result<Vec<AgentEvent>, String> {
        // TODO: 实际的数据库查询
        // 暂时返回空向量
        Ok(Vec::new())
    }

    /// 获取事件计数
    pub async fn count_events(&self, audit_id: &str) -> Result<usize, String> {
        // TODO: 实际的数据库查询
        Ok(0)
    }

    /// 删除审计的所有事件
    pub async fn delete_audit_events(&self, audit_id: &str) -> Result<(), String> {
        // TODO: 实际的数据库删除
        tracing::info!("[{}] Deleting all events", audit_id);
        Ok(())
    }

    /// 启动刷新任务
    fn start_flush_task(&self) {
        let buffer = self.buffer.clone();
        let interval = std::time::Duration::from_millis(self.config.flush_interval_ms);

        tokio::spawn(async move {
            let mut timer = tokio::time::interval(interval);
            loop {
                timer.tick().await;

                let events = {
                    let mut buffer = buffer.lock().await;
                    if buffer.is_empty() {
                        continue;
                    }
                    buffer.drain(..).collect::<Vec<_>>()
                };

                if !events.is_empty() {
                    tracing::debug!("Flushing {} events to database", events.len());
                    // 刷新会在调用者处完成
                }
            }
        });
    }

    /// 获取缓冲区大小
    pub async fn buffer_size(&self) -> usize {
        self.buffer.lock().await.len()
    }

    /// 获取统计信息
    pub async fn stats(&self, audit_id: &str) -> PersistenceStats {
        let buffer_size = self.buffer.lock().await.len();
        let event_count = self.count_events(audit_id).await.unwrap_or(0);

        PersistenceStats {
            buffer_size,
            saved_events: event_count,
        }
    }
}

/// 持久化统计信息
#[derive(Debug, Clone, serde::Serialize)]
pub struct PersistenceStats {
    /// 缓冲区大小
    pub buffer_size: usize,

    /// 已保存的事件数量
    pub saved_events: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    // 注意：这些测试需要实际的数据库连接
    // 在实际环境中需要设置好测试数据库

    // #[tokio::test]
    // async fn test_save_event() {
    //     let db = Arc::new(Database::new_in_memory().await.unwrap());
    //     let persistence = EventPersistence::new(db, EventPersistenceConfig::default());
    //
    //     let event = AgentEvent::new("test".to_string(), "task1".to_string(), EventType::Info);
    //
    //     assert!(persistence.save_event(event).await.is_ok());
    // }
}
