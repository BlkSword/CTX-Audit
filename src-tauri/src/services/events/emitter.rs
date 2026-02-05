//! Tauri 事件发射器
//!
//! 将事件发射到 Tauri 前端

use std::sync::Arc;
use tokio::sync::Mutex;
use tauri::{AppHandle, Emitter};

use crate::models::events::{AgentEvent, EventType};

/// Tauri 事件发射器
///
/// 负责将 Agent 事件发射到前端
pub struct TauriEventEmitter {
    /// Tauri 应用句柄
    app_handle: Arc<Mutex<Option<AppHandle>>>,

    /// 是否启用
    enabled: Arc<Mutex<bool>>,
}

impl TauriEventEmitter {
    /// 创建新的发射器
    pub fn new() -> Self {
        Self {
            app_handle: Arc::new(Mutex::new(None)),
            enabled: Arc::new(Mutex::new(true)),
        }
    }

    /// 设置应用句柄
    pub async fn set_app_handle(&self, handle: AppHandle) {
        *self.app_handle.lock().await = Some(handle);
    }

    /// 发射事件到前端
    pub async fn emit(&self, event: &AgentEvent) -> Result<(), String> {
        // 检查是否启用
        if !*self.enabled.lock().await {
            return Ok(());
        }

        let app_handle = self.app_handle.lock().await;
        let handle = app_handle
            .as_ref()
            .ok_or_else(|| "AppHandle not set".to_string())?;

        // 发射事件
        handle
            .emit("audit-event", event)
            .map_err(|e| format!("Failed to emit event: {}", e))?;

        Ok(())
    }

    /// 发射特定类型的事件
    pub async fn emit_type(
        &self,
        event_type: EventType,
        audit_id: &str,
        data: serde_json::Value,
    ) -> Result<(), String> {
        let event = AgentEvent {
            id: None,
            audit_id: audit_id.to_string(),
            task_id: "system".to_string(),
            sequence: 0,
            event_type,
            agent_type: None,
            agent_id: None,
            message: None,
            thought: None,
            accumulated_thought: None,
            data: Some(data),
            metadata: None,
            tool_name: None,
            tool_input: None,
            tool_output: None,
            finding: None,
            progress: None,
            timestamp: chrono::Utc::now(),
        };

        self.emit(&event).await
    }

    /// 发射进度更新
    pub async fn emit_progress(
        &self,
        audit_id: &str,
        stage: &str,
        percentage: u8,
    ) -> Result<(), String> {
        self.emit_type(
            EventType::ProgressUpdate,
            audit_id,
            serde_json::json!({
                "stage": stage,
                "percentage": percentage
            }),
        )
        .await
    }

    /// 发射错误事件
    pub async fn emit_error(&self, audit_id: &str, error: &str) -> Result<(), String> {
        self.emit_type(
            EventType::Error,
            audit_id,
            serde_json::json!({"error": error}),
        )
        .await
    }

    /// 发射心跳事件
    pub async fn emit_heartbeat(&self, audit_id: &str) -> Result<(), String> {
        self.emit_type(
            EventType::Heartbeat,
            audit_id,
            serde_json::json!({"timestamp": chrono::Utc::now().to_rfc3339()}),
        )
        .await
    }

    /// 启用/禁用发射器
    pub async fn set_enabled(&self, enabled: bool) {
        *self.enabled.lock().await = enabled;
    }

    /// 检查是否启用
    pub async fn is_enabled(&self) -> bool {
        *self.enabled.lock().await
    }
}

impl Default for TauriEventEmitter {
    fn default() -> Self {
        Self::new()
    }
}

/// Agent 事件发射器（带节流）
///
/// 自动节流高频事件，避免阻塞前端
pub struct ThrottledEmitter {
    /// 内部发射器
    inner: TauriEventEmitter,

    /// 节流间隔（毫秒）
    throttle_ms: u64,

    /// 上次发射时间（每个事件类型）
    last_emit: Arc<Mutex<std::collections::HashMap<String, chrono::DateTime<chrono::Utc>>>>,
}

impl ThrottledEmitter {
    /// 创建新的节流发射器
    pub fn new(inner: TauriEventEmitter, throttle_ms: u64) -> Self {
        Self {
            inner,
            throttle_ms,
            last_emit: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// 发射事件（带节流）
    pub async fn emit(&self, event: &AgentEvent) -> Result<(), String> {
        let event_key = format!("{}:{}", event.audit_id, event.event_type.as_str());

        // 检查是否需要节流
        let should_emit = {
            let mut last_emit = self.last_emit.lock().await;
            let now = chrono::Utc::now();

            if let Some(&last_time) = last_emit.get(&event_key) {
                let elapsed = now.signed_duration_since(last_time).num_milliseconds() as u64;
                if elapsed >= self.throttle_ms {
                    last_emit.insert(event_key, now);
                    true
                } else {
                    false
                }
            } else {
                last_emit.insert(event_key, now);
                true
            }
        };

        if should_emit {
            self.inner.emit(event).await
        } else {
            Ok(())
        }
    }

    /// 强制发射（忽略节流）
    pub async fn emit_force(&self, event: &AgentEvent) -> Result<(), String> {
        self.inner.emit(event).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tauri_event_emitter() {
        let emitter = TauriEventEmitter::new();
        // 测试创建和基本状态
        assert!(emitter.is_enabled().await);
    }

    #[tokio::test]
    async fn test_enable_disable() {
        let emitter = TauriEventEmitter::new();

        emitter.set_enabled(false).await;
        assert!(!emitter.is_enabled().await);

        emitter.set_enabled(true).await;
        assert!(emitter.is_enabled().await);
    }
}
