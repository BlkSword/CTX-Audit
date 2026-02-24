// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 动态任务优先级调整
//!
//! 实现 Coordinator-Specialist 架构中的动态任务优先级调整机制。

use crate::multi_agent::task::{AuditTask, TaskPriority, TaskStatus};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::Result;

/// 优先级调整原因
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum PriorityAdjustmentReason {
    /// 用户请求
    UserRequest,

    /// 依赖解除
    DependencyUnblocked,

    /// 发现高风险漏洞
    HighRiskFinding,

    /// 任务即将超时
    NearTimeout,

    /// 资源可用
    ResourceAvailable,

    /// 协调器决定
    CoordinatorDecision,

    /// 专家建议
    SpecialistRecommendation,

    /// 自动调整
    Automatic,

    /// 其他
    Other { reason: String },
}

/// 优先级调整记录
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PriorityAdjustment {
    /// 任务 ID
    pub task_id: String,

    /// 原优先级
    pub old_priority: TaskPriority,

    /// 新优先级
    pub new_priority: TaskPriority,

    /// 调整原因
    pub reason: PriorityAdjustmentReason,

    /// 调整时间
    pub adjusted_at: chrono::DateTime<chrono::Utc>,

    /// 调整者
    pub adjusted_by: String,
}

/// 优先级调整策略
#[derive(Debug, Clone, Copy)]
pub enum PriorityAdjustmentStrategy {
    /// 保守策略 (不轻易提升优先级)
    Conservative,

    /// 平衡策略
    Balanced,

    /// 激进策略 (快速响应高风险任务)
    Aggressive,
}

impl Default for PriorityAdjustmentStrategy {
    fn default() -> Self {
        Self::Balanced
    }
}

/// 动态优先级管理器
#[derive(Clone)]
pub struct DynamicPriorityManager {
    /// 任务优先级 (task_id -> priority)
    priorities: Arc<RwLock<HashMap<String, TaskPriority>>>,

    /// 调整历史 (task_id -> adjustments)
    adjustment_history: Arc<RwLock<HashMap<String, Vec<PriorityAdjustment>>>>,

    /// 任务创建时间 (task_id -> created_at)
    task_creation_times: Arc<RwLock<HashMap<String, chrono::DateTime<chrono::Utc>>>>,

    /// 任务超时时间 (秒)
    task_timeout_secs: u64,

    /// 调整策略
    strategy: PriorityAdjustmentStrategy,
}

impl DynamicPriorityManager {
    /// 创建新的优先级管理器
    pub fn new(task_timeout_secs: u64) -> Self {
        Self {
            priorities: Arc::new(RwLock::new(HashMap::new())),
            adjustment_history: Arc::new(RwLock::new(HashMap::new())),
            task_creation_times: Arc::new(RwLock::new(HashMap::new())),
            task_timeout_secs,
            strategy: PriorityAdjustmentStrategy::default(),
        }
    }

    /// 设置调整策略
    pub fn with_strategy(mut self, strategy: PriorityAdjustmentStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// 注册任务
    pub async fn register_task(&self, task_id: String, priority: TaskPriority) {
        let now = chrono::Utc::now();
        self.priorities.write().await.insert(task_id.clone(), priority);
        self.task_creation_times.write().await.insert(task_id, now);
    }

    /// 调整任务优先级
    pub async fn adjust_priority(
        &self,
        task_id: &str,
        new_priority: TaskPriority,
        reason: PriorityAdjustmentReason,
        adjusted_by: String,
    ) -> Result<()> {
        let mut priorities = self.priorities.write().await;
        let old_priority = priorities.get(task_id)
            .copied()
            .unwrap_or(TaskPriority::Medium);

        // 根据策略验证调整
        if !self.should_allow_adjustment(&old_priority, &new_priority) {
            return Err(anyhow::anyhow!("优先级调整被策略拒绝"));
        }

        // 应用调整
        priorities.insert(task_id.to_string(), new_priority);

        // 记录历史
        let adjustment = PriorityAdjustment {
            task_id: task_id.to_string(),
            old_priority,
            new_priority,
            reason: reason.clone(),
            adjusted_at: chrono::Utc::now(),
            adjusted_by: adjusted_by.clone(),
        };

        let mut history = self.adjustment_history.write().await;
        history.entry(task_id.to_string())
            .or_insert_with(Vec::new)
            .push(adjustment);

        // 限制历史大小
        if let Some(adjustments) = history.get_mut(task_id) {
            if adjustments.len() > 10 {
                adjustments.remove(0);
            }
        }

        tracing::debug!(
            "[PriorityManager] 调整优先级: {} {:?} -> {:?} ({:?})",
            task_id, old_priority, new_priority, reason
        );

        Ok(())
    }

    /// 获取任务优先级
    pub async fn get_priority(&self, task_id: &str) -> Option<TaskPriority> {
        self.priorities.read().await.get(task_id).copied()
    }

    /// 批量提升优先级 (基于依赖解除)
    pub async fn boost_on_dependency_unblocked(
        &self,
        task_ids: Vec<String>,
        adjusted_by: String,
    ) -> usize {
        let mut boosted_count = 0;

        for task_id in task_ids {
            if let Some(current) = self.get_priority(&task_id).await {
                let new_priority = match current {
                    TaskPriority::Low => TaskPriority::Medium,
                    TaskPriority::Medium => TaskPriority::High,
                    TaskPriority::High => TaskPriority::High,
                    TaskPriority::Critical => TaskPriority::Critical,
                };

                if new_priority != current {
                    let _ = self.adjust_priority(
                        &task_id,
                        new_priority,
                        PriorityAdjustmentReason::DependencyUnblocked,
                        adjusted_by.clone(),
                    ).await;
                    boosted_count += 1;
                }
            }
        }

        boosted_count
    }

    /// 检查并调整即将超时的任务优先级
    pub async fn check_and_boost_near_timeout(&self, timeout_threshold_secs: u64) -> Vec<String> {
        let mut boosted = Vec::new();
        let now = chrono::Utc::now();
        let creation_times = self.task_creation_times.read().await;
        let priorities = self.priorities.read().await;

        // 先收集需要提升的任务 ID
        let mut to_boost = Vec::new();
        for (task_id, created_at) in creation_times.iter() {
            let elapsed = now.signed_duration_since(*created_at).num_seconds() as u64;
            let remaining = self.task_timeout_secs.saturating_sub(elapsed);

            if remaining <= timeout_threshold_secs {
                if let Some(current) = priorities.get(task_id) {
                    if *current != TaskPriority::Critical {
                        to_boost.push(task_id.clone());
                    }
                }
            }
        }

        // 释放读锁后再调整优先级
        drop(creation_times);
        drop(priorities);

        for task_id in to_boost {
            if self.adjust_priority(
                &task_id,
                TaskPriority::Critical,
                PriorityAdjustmentReason::NearTimeout,
                "priority-manager".to_string(),
            ).await.is_ok() {
                boosted.push(task_id);
            }
        }

        boosted
    }

    /// 根据发现提升相关任务优先级
    pub async fn boost_on_finding(
        &self,
        task_id: &str,
        finding_severity: &str,
        adjusted_by: String,
    ) -> Result<()> {
        let new_priority = match finding_severity {
            "Critical" => TaskPriority::Critical,
            "High" => TaskPriority::High,
            "Medium" => TaskPriority::Medium,
            _ => TaskPriority::Low,
        };

        self.adjust_priority(
            task_id,
            new_priority,
            PriorityAdjustmentReason::HighRiskFinding,
            adjusted_by,
        ).await
    }

    /// 获取调整历史
    pub async fn get_adjustment_history(&self, task_id: &str) -> Vec<PriorityAdjustment> {
        self.adjustment_history.read().await
            .get(task_id)
            .cloned()
            .unwrap_or_default()
    }

    /// 移除任务
    pub async fn remove_task(&self, task_id: &str) {
        self.priorities.write().await.remove(task_id);
        self.task_creation_times.write().await.remove(task_id);
        self.adjustment_history.write().await.remove(task_id);
    }

    /// 获取所有待处理任务的优先级排序
    pub async fn get_sorted_pending_tasks(&self, tasks: &[AuditTask]) -> Vec<AuditTask> {
        let priorities = self.priorities.read().await;

        let mut sorted = tasks.to_vec();
        sorted.sort_by(|a, b| {
            let priority_a = priorities.get(&a.id).copied().unwrap_or(a.priority);
            let priority_b = priorities.get(&b.id).copied().unwrap_or(b.priority);
            priority_b.cmp(&priority_a) // 降序排列 (高优先级在前)
                .then_with(|| a.id.cmp(&b.id)) // 相同优先级按 ID 排序
        });

        sorted
    }

    /// 检查是否应该允许调整 (基于策略)
    fn should_allow_adjustment(
        &self,
        old: &TaskPriority,
        new: &TaskPriority,
    ) -> bool {
        match self.strategy {
            PriorityAdjustmentStrategy::Conservative => {
                // 保守策略：只允许提升到下一级
                let is_conservative_upgrade = matches!(
                    (old, new),
                    (TaskPriority::Low, TaskPriority::Medium)
                        | (TaskPriority::Medium, TaskPriority::High)
                        | (TaskPriority::High, TaskPriority::Critical)
                );
                // 允许同级调整
                is_conservative_upgrade || old == new
            }
            PriorityAdjustmentStrategy::Balanced => {
                // 平衡策略：允许任何提升，不允许降级
                *new >= *old
            }
            PriorityAdjustmentStrategy::Aggressive => {
                // 激进策略：允许任何调整
                true
            }
        }
    }

    /// 获取统计信息
    pub async fn get_stats(&self) -> PriorityManagerStats {
        let priorities = self.priorities.read().await;
        let mut stats = PriorityManagerStats::default();

        for priority in priorities.values() {
            match priority {
                TaskPriority::Critical => stats.critical += 1,
                TaskPriority::High => stats.high += 1,
                TaskPriority::Medium => stats.medium += 1,
                TaskPriority::Low => stats.low += 1,
            }
        }

        stats.total_tasks = priorities.len();
        stats
    }
}

/// 优先级管理器统计
#[derive(Debug, Clone, Default)]
pub struct PriorityManagerStats {
    pub total_tasks: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_priority_registration() {
        let manager = DynamicPriorityManager::new(300);

        manager.register_task("task-1".to_string(), TaskPriority::High).await;
        assert_eq!(
            manager.get_priority("task-1").await,
            Some(TaskPriority::High)
        );
    }

    #[tokio::test]
    async fn test_priority_adjustment() {
        let manager = DynamicPriorityManager::new(300);

        manager.register_task("task-1".to_string(), TaskPriority::Low).await;

        let result = manager.adjust_priority(
            "task-1",
            TaskPriority::High,
            PriorityAdjustmentReason::UserRequest,
            "coordinator".to_string(),
        ).await;

        assert!(result.is_ok());
        assert_eq!(
            manager.get_priority("task-1").await,
            Some(TaskPriority::High)
        );
    }

    #[tokio::test]
    async fn test_conservative_strategy() {
        let manager = DynamicPriorityManager::new(300)
            .with_strategy(PriorityAdjustmentStrategy::Conservative);

        manager.register_task("task-1".to_string(), TaskPriority::Low).await;

        // 允许提升到下一级
        assert!(manager.adjust_priority(
            "task-1",
            TaskPriority::Medium,
            PriorityAdjustmentReason::Automatic,
            "system".to_string(),
        ).await.is_ok());

        // 不允许跳级提升
        assert!(manager.adjust_priority(
            "task-1",
            TaskPriority::Critical,
            PriorityAdjustmentReason::Automatic,
            "system".to_string(),
        ).await.is_err());
    }

    #[tokio::test]
    async fn test_boost_on_dependency_unblocked() {
        let manager = DynamicPriorityManager::new(300);

        manager.register_task("task-1".to_string(), TaskPriority::Low).await;
        manager.register_task("task-2".to_string(), TaskPriority::Medium).await;

        let boosted = manager.boost_on_dependency_unblocked(
            vec!["task-1".to_string(), "task-2".to_string()],
            "coordinator".to_string(),
        ).await;

        assert_eq!(boosted, 2);
        assert_eq!(
            manager.get_priority("task-1").await,
            Some(TaskPriority::Medium)
        );
        // task-2 从 Medium 提升到 High
        assert_eq!(
            manager.get_priority("task-2").await,
            Some(TaskPriority::High)
        );
    }

    #[tokio::test]
    async fn test_adjustment_history() {
        let manager = DynamicPriorityManager::new(300);

        manager.register_task("task-1".to_string(), TaskPriority::Low).await;

        manager.adjust_priority(
            "task-1",
            TaskPriority::High,
            PriorityAdjustmentReason::UserRequest,
            "coordinator".to_string(),
        ).await.unwrap();

        let history = manager.get_adjustment_history("task-1").await;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].old_priority, TaskPriority::Low);
        assert_eq!(history[0].new_priority, TaskPriority::High);
    }

    #[tokio::test]
    async fn test_get_stats() {
        let manager = DynamicPriorityManager::new(300);

        manager.register_task("task-1".to_string(), TaskPriority::Critical).await;
        manager.register_task("task-2".to_string(), TaskPriority::High).await;
        manager.register_task("task-3".to_string(), TaskPriority::Medium).await;

        let stats = manager.get_stats().await;
        assert_eq!(stats.total_tasks, 3);
        assert_eq!(stats.critical, 1);
        assert_eq!(stats.high, 1);
        assert_eq!(stats.medium, 1);
    }
}
