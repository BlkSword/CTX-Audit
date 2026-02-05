//! 工具执行器
//!
//! 负责执行工具调用，处理超时和错误

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use crate::models::tools::{ToolError, ToolResult};

use super::registry::Tool;

/// 工具执行器
pub struct ToolExecutor {
    /// 工具注册表引用
    registry: Arc<crate::services::tools::registry::ToolRegistry>,

    /// 默认超时时间（秒）
    default_timeout: u64,

    /// 执行统计
    stats: Arc<Mutex<ExecutionStats>>,
}

/// 执行统计
#[derive(Debug, Clone, Default)]
struct ExecutionStats {
    total_executions: u64,
    successful_executions: u64,
    failed_executions: u64,
    total_duration_ms: u64,
}

impl ToolExecutor {
    /// 创建新的执行器
    pub fn new(
        registry: Arc<crate::services::tools::registry::ToolRegistry>,
        default_timeout: u64,
    ) -> Self {
        Self {
            registry,
            default_timeout,
            stats: Arc::new(Mutex::new(ExecutionStats::default())),
        }
    }

    /// 执行工具
    pub async fn execute(
        &self,
        tool_name: &str,
        input: serde_json::Value,
    ) -> Result<ToolResult, ToolError> {
        self.execute_with_timeout(tool_name, input, self.default_timeout)
            .await
    }

    /// 执行工具（带超时）
    pub async fn execute_with_timeout(
        &self,
        tool_name: &str,
        input: serde_json::Value,
        timeout_seconds: u64,
    ) -> Result<ToolResult, ToolError> {
        let start_time = std::time::Instant::now();

        // 获取工具
        let tool = self
            .registry
            .get_tool(tool_name)
            .await
            .ok_or_else(|| ToolError::not_found(format!("工具不存在: {}", tool_name)))?;

        // 执行工具（带超时）
        let result = tokio::time::timeout(
            Duration::from_secs(timeout_seconds),
            tool.execute(input.clone()),
        )
        .await
        .map_err(|_| ToolError::timeout(format!("工具执行超时: {}", tool_name)))??;

        // 记录统计
        let duration = start_time.elapsed().as_millis() as u64;
        self.record_execution(result.is_ok(), duration).await;

        // 添加执行时长到结果
        let result = result.with_duration(duration);

        Ok(result)
    }

    /// 批量执行工具
    pub async fn execute_batch(
        &self,
        requests: Vec<ToolRequest>,
    ) -> Vec<Result<ToolResult, ToolError>> {
        use futures::stream::{self, StreamExt};

        let registry = self.registry.clone();
        stream::iter(requests)
            .map(move |req| {
                let registry = registry.clone();
                async move {
                    let tool = registry.get_tool(&req.tool_name).await.unwrap();
                    tokio::time::timeout(
                        std::time::Duration::from_secs(req.timeout_seconds),
                        tool.execute(req.input.clone()),
                    )
                    .await
                    .map_err(|_| ToolError::timeout(format!("工具执行超时: {}", req.tool_name)))?
                }
            })
            .buffer_unordered(5) // 最多并发 5 个工具
            .collect()
            .await
    }

    /// 尝试执行工具（不抛出异常）
    pub async fn try_execute(
        &self,
        tool_name: &str,
        input: serde_json::Value,
    ) -> ToolResult {
        match self.execute(tool_name, input).await {
            Ok(result) => result,
            Err(e) => ToolResult::error(e.to_string(), Some(e.code.to_string())),
        }
    }

    /// 记录执行统计
    async fn record_execution(&self, success: bool, duration_ms: u64) {
        let mut stats = self.stats.lock().await;
        stats.total_executions += 1;
        stats.total_duration_ms += duration_ms;

        if success {
            stats.successful_executions += 1;
        } else {
            stats.failed_executions += 1;
        }
    }

    /// 获取统计信息
    pub async fn stats(&self) -> ExecutorStats {
        let stats = self.stats.lock().await;

        ExecutorStats {
            total_executions: stats.total_executions,
            successful_executions: stats.successful_executions,
            failed_executions: stats.failed_executions,
            total_duration_ms: stats.total_duration_ms,
            success_rate: if stats.total_executions > 0 {
                (stats.successful_executions as f64 / stats.total_executions as f64) * 100.0
            } else {
                0.0
            },
        }
    }
}

/// 工具执行请求
pub struct ToolRequest {
    /// 工具名称
    pub tool_name: String,

    /// 工具输入
    pub input: serde_json::Value,

    /// 超时时间（秒）
    pub timeout_seconds: u64,
}

impl ToolRequest {
    /// 创建新的请求
    pub fn new(tool_name: impl Into<String>, input: serde_json::Value) -> Self {
        Self {
            tool_name: tool_name.into(),
            input,
            timeout_seconds: 60, // 默认 60 秒
        }
    }

    /// 设置超时时间
    pub fn with_timeout(mut self, timeout: u64) -> Self {
        self.timeout_seconds = timeout;
        self
    }
}

/// 执行器统计信息
#[derive(Debug, Clone, serde::Serialize)]
pub struct ExecutorStats {
    /// 总执行次数
    pub total_executions: u64,

    /// 成功次数
    pub successful_executions: u64,

    /// 失败次数
    pub failed_executions: u64,

    /// 总耗时（毫秒）
    pub total_duration_ms: u64,

    /// 成功率（百分比）
    pub success_rate: f64,
}

/// 工具执行上下文
///
/// 提供给工具执行时的额外信息
#[derive(Debug, Clone)]
pub struct ToolContext {
    /// 审计 ID
    pub audit_id: String,

    /// Agent ID
    pub agent_id: String,

    /// 项目路径
    pub project_path: String,

    /// 额外元数据
    pub metadata: serde_json::Value,
}

impl ToolContext {
    /// 创建新的上下文
    pub fn new(audit_id: String, agent_id: String, project_path: String) -> Self {
        Self {
            audit_id,
            agent_id,
            project_path,
            metadata: serde_json::json!({}),
        }
    }

    /// 添加元数据
    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        if let Some(obj) = self.metadata.as_object_mut() {
            obj.insert(key.into(), value);
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tool_executor() {
        let registry = Arc::new(crate::services::tools::registry::ToolRegistry::new());
        let executor = ToolExecutor::new(registry.clone(), 5);

        // 测试执行不存在的工具
        let result = executor
            .execute("nonexistent", serde_json::json!({}))
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err().code,
            crate::models::tools::ToolErrorCode::NotFound
        ));
    }
}
