// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Agent 状态管理

use crate::base::{AgentStatus, AgentType};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Agent 状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentState {
    /// Agent ID
    pub agent_id: String,

    /// Agent 类型
    pub agent_type: AgentType,

    /// 当前状态
    pub status: AgentStatus,

    /// 开始时间
    pub started_at: DateTime<Utc>,

    /// 更新时间
    pub updated_at: DateTime<Utc>,

    /// 进度百分比 (0-100)
    pub progress: u8,

    /// 当前活动描述
    pub current_activity: Option<String>,
}

impl AgentState {
    /// 创建新的状态
    pub fn new(agent_id: String, agent_type: AgentType) -> Self {
        let now = Utc::now();
        Self {
            agent_id,
            agent_type,
            status: AgentStatus::Initializing,
            started_at: now,
            updated_at: now,
            progress: 0,
            current_activity: None,
        }
    }

    /// 更新状态
    pub fn update(&mut self, status: AgentStatus, activity: Option<String>) {
        self.status = status;
        self.current_activity = activity;
        self.updated_at = Utc::now();
    }

    /// 更新进度
    pub fn set_progress(&mut self, progress: u8) {
        self.progress = progress.min(100);
        self.updated_at = Utc::now();
    }
}

/// Agent 状态管理器
#[derive(Clone)]
pub struct AgentStateManager {
    states: Arc<RwLock<std::collections::HashMap<String, AgentState>>>,
}

impl AgentStateManager {
    /// 创建新的管理器
    pub fn new() -> Self {
        Self {
            states: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// 添加或更新状态
    pub async fn upsert(&self, state: AgentState) {
        let mut states = self.states.write().await;
        states.insert(state.agent_id.clone(), state);
    }

    /// 获取状态
    pub async fn get(&self, agent_id: &str) -> Option<AgentState> {
        let states = self.states.read().await;
        states.get(agent_id).cloned()
    }

    /// 列出所有状态
    pub async fn list(&self) -> Vec<AgentState> {
        let states = self.states.read().await;
        states.values().cloned().collect()
    }

    /// 删除状态
    pub async fn remove(&self, agent_id: &str) {
        let mut states = self.states.write().await;
        states.remove(agent_id);
    }
}

impl Default for AgentStateManager {
    fn default() -> Self {
        Self::new()
    }
}
