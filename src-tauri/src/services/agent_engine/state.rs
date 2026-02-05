//! Agent 状态管理
//!
//! 管理Agent的执行状态、迭代控制和超时处理

use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{timeout, Duration};

use crate::models::agent::{AgentStatus, AgentType};

/// Agent 状态
#[derive(Debug, Clone)]
pub struct AgentState {
    /// Agent ID
    pub agent_id: String,

    /// Agent 名称
    pub agent_name: String,

    /// Agent 类型
    pub agent_type: AgentType,

    /// 父 Agent ID
    pub parent_id: Option<String>,

    /// 当前状态
    pub status: AgentStatus,

    /// 当前迭代次数
    pub iteration: usize,

    /// 最大迭代次数
    pub max_iterations: usize,

    /// 任务描述
    pub task: String,

    /// 执行开始时间
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,

    /// 执行完成时间
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,

    /// 是否请求停止
    pub stop_requested: bool,

    /// 错误信息
    pub error: Option<String>,

    /// 最后更新时间
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

impl AgentState {
    /// 创建新的 Agent 状态
    pub fn new(agent_id: String, agent_name: String, agent_type: AgentType) -> Self {
        let now = chrono::Utc::now();
        Self {
            agent_id,
            agent_name,
            agent_type,
            parent_id: None,
            status: AgentStatus::Created,
            iteration: 0,
            max_iterations: 50,
            task: String::new(),
            started_at: None,
            finished_at: None,
            stop_requested: false,
            error: None,
            last_updated: now,
        }
    }

    /// 设置父 Agent
    pub fn with_parent(mut self, parent_id: String) -> Self {
        self.parent_id = Some(parent_id);
        self
    }

    /// 设置最大迭代次数
    pub fn with_max_iterations(mut self, max: usize) -> Self {
        self.max_iterations = max;
        self
    }

    /// 开始执行
    pub fn start(&mut self) {
        self.status = AgentStatus::Running;
        self.started_at = Some(chrono::Utc::now());
        self.last_updated = chrono::Utc::now();
    }

    /// 增加迭代
    pub fn increment_iteration(&mut self) -> Result<(), String> {
        if self.iteration >= self.max_iterations {
            return Err(format!(
                "达到最大迭代次数限制: {}",
                self.max_iterations
            ));
        }
        self.iteration += 1;
        self.last_updated = chrono::Utc::now();
        Ok(())
    }

    /// 检查是否应该停止
    pub fn should_stop(&self) -> bool {
        self.stop_requested
            || self.status == AgentStatus::Stopped
            || self.status == AgentStatus::Failed
            || self.status == AgentStatus::Completed
    }

    /// 检查是否达到最大迭代次数
    pub fn is_at_max_iterations(&self) -> bool {
        self.iteration >= self.max_iterations
    }

    /// 请求停止
    pub fn request_stop(&mut self) {
        self.stop_requested = true;
        self.status = AgentStatus::Stopping;
        self.last_updated = chrono::Utc::now();
    }

    /// 标记为完成
    pub fn mark_completed(&mut self) {
        self.status = AgentStatus::Completed;
        self.finished_at = Some(chrono::Utc::now());
        self.last_updated = chrono::Utc::now();
    }

    /// 标记为失败
    pub fn mark_failed(&mut self, error: String) {
        self.status = AgentStatus::Failed;
        self.error = Some(error);
        self.finished_at = Some(chrono::Utc::now());
        self.last_updated = chrono::Utc::now();
    }

    /// 标记为停止
    pub fn mark_stopped(&mut self) {
        self.status = AgentStatus::Stopped;
        self.finished_at = Some(chrono::Utc::now());
        self.last_updated = chrono::Utc::now();
    }

    /// 设置为等待状态
    pub fn set_waiting(&mut self) {
        self.status = AgentStatus::Waiting;
        self.last_updated = chrono::Utc::now();
    }

    /// 恢复运行
    pub fn resume(&mut self) {
        if self.status == AgentStatus::Waiting || self.status == AgentStatus::Paused {
            self.status = AgentStatus::Running;
            self.last_updated = chrono::Utc::now();
        }
    }

    /// 暂停
    pub fn pause(&mut self) {
        self.status = AgentStatus::Paused;
        self.last_updated = chrono::Utc::now();
    }

    /// 检查是否已完成（包括失败和停止状态）
    pub fn is_completed(&self) -> bool {
        matches!(
            self.status,
            AgentStatus::Completed | AgentStatus::Failed | AgentStatus::Stopped
        )
    }
}

/// Agent 状态句柄
///
/// 提供线程安全的状态访问
#[derive(Clone)]
pub struct AgentStateHandle {
    inner: Arc<Mutex<AgentState>>,
}

impl AgentStateHandle {
    /// 创建新的状态句柄
    pub fn new(state: AgentState) -> Self {
        Self {
            inner: Arc::new(Mutex::new(state)),
        }
    }

    /// 获取当前状态的克隆
    pub async fn get(&self) -> AgentState {
        self.inner.lock().await.clone()
    }

    /// 更新状态
    pub async fn update<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut AgentState) -> R,
    {
        let mut state = self.inner.lock().await;
        f(&mut state)
    }

    /// 开始执行
    pub async fn start(&self) {
        self.update(|s| s.start()).await;
    }

    /// 增加迭代
    pub async fn increment_iteration(&self) -> Result<(), String> {
        self.update(|s| s.increment_iteration()).await
    }

    /// 检查是否应该停止
    pub async fn should_stop(&self) -> bool {
        self.update(|s| s.should_stop()).await
    }

    /// 请求停止
    pub async fn request_stop(&self) {
        self.update(|s| s.request_stop()).await;
    }

    /// 标记为完成
    pub async fn mark_completed(&self) {
        self.update(|s| s.mark_completed()).await;
    }

    /// 标记为失败
    pub async fn mark_failed(&self, error: String) {
        self.update(|s| s.mark_failed(error)).await;
    }

    /// 获取迭代次数
    pub async fn iteration(&self) -> usize {
        self.update(|s| s.iteration).await
    }

    /// 获取状态
    pub async fn status(&self) -> AgentStatus {
        self.update(|s| s.status).await
    }
}

/// 迭代控制器
///
/// 控制Agent的迭代和超时
pub struct IterationController {
    state: AgentStateHandle,
    timeout: Duration,
}

impl IterationController {
    /// 创建新的迭代控制器
    pub fn new(state: AgentStateHandle, timeout_seconds: u64) -> Self {
        Self {
            state,
            timeout: Duration::from_secs(timeout_seconds),
        }
    }

    /// 执行一次迭代
    pub async fn iterate<F, T>(&self, f: F) -> Result<T, String>
    where
        F: std::future::Future<Output = Result<T, String>>,
    {
        // 检查是否应该停止
        if self.state.should_stop().await {
            return Err("Agent 已请求停止".to_string());
        }

        // 增加迭代计数
        self.state.increment_iteration().await?;

        // 检查是否达到最大迭代次数
        let current_state = self.state.get().await;
        if current_state.is_at_max_iterations() {
            return Err(format!(
                "达到最大迭代次数: {}",
                current_state.max_iterations
            ));
        }

        // 执行迭代逻辑（带超时）
        timeout(self.timeout, f)
            .await
            .map_err(|_| "迭代执行超时".to_string())?
    }

    /// 获取当前迭代次数
    pub async fn current_iteration(&self) -> usize {
        self.state.iteration().await
    }

    /// 获取剩余迭代次数
    pub async fn remaining_iterations(&self) -> usize {
        let state = self.state.get().await;
        state.max_iterations.saturating_sub(state.iteration)
    }

    /// 检查是否可以继续
    pub async fn can_continue(&self) -> bool {
        !self.state.should_stop().await && self.remaining_iterations().await > 0
    }

    /// 请求停止
    pub async fn stop(&self) {
        self.state.request_stop().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_agent_state() {
        let state = AgentState::new(
            "test-agent".to_string(),
            "Test Agent".to_string(),
            AgentType::Analysis,
        );

        assert_eq!(state.status, AgentStatus::Created);
        assert_eq!(state.iteration, 0);
        assert!(!state.should_stop());
    }

    #[tokio::test]
    async fn test_state_handle() {
        let state = AgentState::new(
            "test-agent".to_string(),
            "Test Agent".to_string(),
            AgentType::Analysis,
        );
        let handle = AgentStateHandle::new(state);

        handle.start().await;
        assert_eq!(handle.status().await, AgentStatus::Running);

        let result = handle.increment_iteration().await;
        assert!(result.is_ok());
        assert_eq!(handle.iteration().await, 1);
    }

    #[tokio::test]
    async fn test_max_iterations() {
        let state = AgentState::new(
            "test-agent".to_string(),
            "Test Agent".to_string(),
            AgentType::Analysis,
        )
        .with_max_iterations(3);
        let handle = AgentStateHandle::new(state);

        handle.start().await;

        // 前3次迭代应该成功
        for _ in 0..3 {
            assert!(handle.increment_iteration().await.is_ok());
        }

        // 第4次应该失败
        assert!(handle.increment_iteration().await.is_err());
    }

    #[tokio::test]
    async fn test_iteration_controller() {
        let state = AgentState::new(
            "test-agent".to_string(),
            "Test Agent".to_string(),
            AgentType::Analysis,
        );
        let handle = AgentStateHandle::new(state);
        let controller = IterationController::new(handle, 5);

        // 简单的迭代测试
        let result = controller
            .iterate(async { Ok::<_, String>("success") })
            .await;
        assert!(result.is_ok());
        assert_eq!(controller.current_iteration().await, 1);
    }
}
