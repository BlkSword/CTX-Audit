// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 智能任务调度系统
//!
//! 管理分析任务优先级，避免重复分析，追踪进度

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

use crate::audit_state::{AnalysisTarget, TargetPriority, TargetStatus};

/// 调度任务
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledTask {
    /// 任务 ID
    pub id: String,

    /// 关联的分析目标
    pub target_id: String,

    /// 任务类型
    pub task_type: TaskType,

    /// 优先级分数 (0-100)
    pub priority_score: u32,

    /// 状态
    pub status: TaskStatus,

    /// 依赖的任务 ID
    pub dependencies: Vec<String>,

    /// 重试次数
    pub retry_count: u32,

    /// 最大重试次数
    pub max_retries: u32,

    /// 创建时间
    pub created_at: DateTime<Utc>,

    /// 开始时间
    pub started_at: Option<DateTime<Utc>>,

    /// 完成时间
    pub completed_at: Option<DateTime<Utc>>,

    /// 结果摘要
    pub result_summary: Option<String>,
}

/// 任务类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskType {
    /// 污点分析
    TaintAnalysis,
    /// 模式检测
    PatternDetection,
    /// 深度代码审查
    DeepCodeReview,
    /// 漏洞验证
    VulnerabilityVerification,
    /// 跨文件分析
    CrossFileAnalysis,
    /// 误报分析
    FalsePositiveAnalysis,
}

/// 任务状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskStatus {
    /// 等待依赖
    WaitingForDependencies,
    /// 就绪
    Ready,
    /// 执行中
    InProgress,
    /// 已完成
    Completed,
    /// 失败
    Failed,
    /// 已跳过
    Skipped,
}

/// 任务调度器
pub struct TaskScheduler {
    /// 待处理队列（按优先级排序）
    pending: VecDeque<ScheduledTask>,

    /// 正在执行的任务
    in_progress: HashMap<String, ScheduledTask>,

    /// 已完成的任务
    completed: Vec<ScheduledTask>,

    /// 失败的任务
    failed: Vec<ScheduledTask>,

    /// 已处理的文件（避免重复）
    processed_files: HashSet<String>,

    /// 已处理的候选漏洞
    processed_candidates: HashSet<String>,

    /// 任务依赖图
    dependency_graph: HashMap<String, Vec<String>>,

    /// 配置
    config: SchedulerConfig,
}

/// 调度器配置
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// 最大并发任务数
    pub max_concurrent: usize,

    /// 默认最大重试次数
    pub default_max_retries: u32,

    /// 是否允许重复分析
    pub allow_reanalysis: bool,

    /// 高优先级阈值
    pub high_priority_threshold: u32,

    /// 跳过低优先级阈值
    pub skip_below_threshold: u32,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 4,
            default_max_retries: 2,
            allow_reanalysis: false,
            high_priority_threshold: 70,
            skip_below_threshold: 20,
        }
    }
}

impl TaskScheduler {
    /// 创建新的任务调度器
    pub fn new(config: SchedulerConfig) -> Self {
        Self {
            pending: VecDeque::new(),
            in_progress: HashMap::new(),
            completed: Vec::new(),
            failed: Vec::new(),
            processed_files: HashSet::new(),
            processed_candidates: HashSet::new(),
            dependency_graph: HashMap::new(),
            config,
        }
    }

    /// 使用默认配置创建
    pub fn with_defaults() -> Self {
        Self::new(SchedulerConfig::default())
    }

    /// 添加任务
    pub fn add_task(&mut self, mut task: ScheduledTask) {
        // 检查优先级（先检查优先级，低优先级直接跳过）
        if task.priority_score < self.config.skip_below_threshold {
            task.status = TaskStatus::Skipped;
            self.completed.push(task);
            return;
        }

        // 检查是否已处理（只有当有依赖时才检查）
        if !self.config.allow_reanalysis && !task.dependencies.is_empty() {
            // 如果任务关联的所有候选都已处理，跳过
            if task.dependencies.iter().all(|d| self.processed_candidates.contains(d)) {
                task.status = TaskStatus::Skipped;
                self.completed.push(task);
                return;
            }
        }

        // 检查依赖是否完成
        let all_deps_completed = task.dependencies.is_empty() || task.dependencies.iter().all(|dep_id| {
            self.completed.iter().any(|t| &t.id == dep_id) ||
            self.failed.iter().any(|t| &t.id == dep_id)
        });

        if all_deps_completed {
            task.status = TaskStatus::Ready;
        } else {
            task.status = TaskStatus::WaitingForDependencies;
        }

        // 按优先级插入
        let insert_pos = self.pending
            .iter()
            .position(|t| t.priority_score < task.priority_score)
            .unwrap_or(self.pending.len());

        self.pending.insert(insert_pos, task);
    }

    /// 从分析目标创建任务
    pub fn create_task_from_target(&self, target: &AnalysisTarget, task_type: TaskType) -> ScheduledTask {
        let priority_score = self.calculate_priority_score(target);

        ScheduledTask {
            id: uuid::Uuid::new_v4().to_string(),
            target_id: target.id.clone(),
            task_type,
            priority_score,
            status: TaskStatus::Ready,
            dependencies: target.candidate_vulnerabilities.clone(),
            retry_count: 0,
            max_retries: self.config.default_max_retries,
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            result_summary: None,
        }
    }

    /// 计算优先级分数
    fn calculate_priority_score(&self, target: &AnalysisTarget) -> u32 {
        let mut score = 0u32;

        // 基础优先级
        score += match target.priority {
            TargetPriority::Critical => 40,
            TargetPriority::High => 30,
            TargetPriority::Medium => 20,
            TargetPriority::Low => 10,
        };

        // 关联的候选漏洞加分
        score += (target.candidate_vulnerabilities.len() as u32).min(20) * 2;

        // 入口点加分
        if matches!(target.target_type, crate::audit_state::TargetType::EntryPoint | crate::audit_state::TargetType::ApiEndpoint) {
            score += 15;
        }

        score.min(100)
    }

    /// 获取下一个待执行任务
    pub fn get_next_task(&mut self) -> Option<ScheduledTask> {
        // 检查并发限制
        if self.in_progress.len() >= self.config.max_concurrent {
            return None;
        }

        // 找到第一个就绪的任务
        while let Some(mut task) = self.pending.pop_front() {
            // 检查依赖
            if task.status == TaskStatus::WaitingForDependencies {
                let all_deps_completed = task.dependencies.iter().all(|dep_id| {
                    self.completed.iter().any(|t| &t.id == dep_id)
                });

                if all_deps_completed {
                    task.status = TaskStatus::Ready;
                } else {
                    // 放回队列末尾
                    self.pending.push_back(task);
                    continue;
                }
            }

            task.status = TaskStatus::InProgress;
            task.started_at = Some(Utc::now());
            let task_id = task.id.clone();
            self.in_progress.insert(task_id, task.clone());
            return Some(task);
        }

        None
    }

    /// 标记任务完成
    pub fn complete_task(&mut self, task_id: &str, result_summary: Option<String>) {
        if let Some(mut task) = self.in_progress.remove(task_id) {
            task.status = TaskStatus::Completed;
            task.completed_at = Some(Utc::now());
            task.result_summary = result_summary;
            self.completed.push(task);
        }
    }

    /// 标记任务失败
    pub fn fail_task(&mut self, task_id: &str, error: &str) {
        if let Some(mut task) = self.in_progress.remove(task_id) {
            task.retry_count += 1;

            if task.retry_count < task.max_retries {
                // 重试
                task.status = TaskStatus::Ready;
                task.started_at = None;
                self.pending.push_back(task);
            } else {
                // 最终失败
                task.status = TaskStatus::Failed;
                task.completed_at = Some(Utc::now());
                task.result_summary = Some(error.to_string());
                self.failed.push(task);
            }
        }
    }

    /// 标记文件已处理
    pub fn mark_file_processed(&mut self, file_path: &str) {
        self.processed_files.insert(file_path.to_string());
    }

    /// 标记候选已处理
    pub fn mark_candidate_processed(&mut self, candidate_id: &str) {
        self.processed_candidates.insert(candidate_id.to_string());
    }

    /// 检查文件是否已处理
    pub fn is_file_processed(&self, file_path: &str) -> bool {
        self.processed_files.contains(file_path)
    }

    /// 获取统计信息
    pub fn get_stats(&self) -> SchedulerStats {
        SchedulerStats {
            pending: self.pending.len(),
            in_progress: self.in_progress.len(),
            completed: self.completed.len(),
            failed: self.failed.len(),
            files_processed: self.processed_files.len(),
            candidates_processed: self.processed_candidates.len(),
        }
    }

    /// 获取高优先级任务数
    pub fn high_priority_count(&self) -> usize {
        self.pending.iter()
            .filter(|t| t.priority_score >= self.config.high_priority_threshold)
            .count()
    }

    /// 检查是否所有任务都已完成
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty() && self.in_progress.is_empty()
    }

    /// 获取下一个批次的任务
    pub fn get_batch(&mut self, batch_size: usize) -> Vec<ScheduledTask> {
        let mut batch = Vec::with_capacity(batch_size);

        while batch.len() < batch_size && self.in_progress.len() + batch.len() < self.config.max_concurrent {
            if let Some(task) = self.get_next_task() {
                batch.push(task);
            } else {
                break;
            }
        }

        batch
    }
}

/// 调度器统计
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulerStats {
    pub pending: usize,
    pub in_progress: usize,
    pub completed: usize,
    pub failed: usize,
    pub files_processed: usize,
    pub candidates_processed: usize,
}

impl std::fmt::Display for SchedulerStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "待处理: {}, 执行中: {}, 已完成: {}, 失败: {}, 文件: {}, 候选: {}",
            self.pending, self.in_progress, self.completed, self.failed,
            self.files_processed, self.candidates_processed
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduler_creation() {
        let scheduler = TaskScheduler::with_defaults();
        let stats = scheduler.get_stats();
        assert_eq!(stats.pending, 0);
        assert_eq!(stats.in_progress, 0);
    }

    #[test]
    fn test_add_task() {
        let mut scheduler = TaskScheduler::with_defaults();

        let task = ScheduledTask {
            id: "test-1".to_string(),
            target_id: "target-1".to_string(),
            task_type: TaskType::TaintAnalysis,
            priority_score: 80,
            status: TaskStatus::Ready,
            dependencies: vec![],
            retry_count: 0,
            max_retries: 2,
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            result_summary: None,
        };

        scheduler.add_task(task);
        assert_eq!(scheduler.get_stats().pending, 1);
    }

    #[test]
    fn test_priority_ordering() {
        let mut scheduler = TaskScheduler::with_defaults();

        // 添加低优先级任务
        let mut task1 = ScheduledTask {
            id: "low".to_string(),
            target_id: "t1".to_string(),
            task_type: TaskType::PatternDetection,
            priority_score: 30,
            status: TaskStatus::Ready,
            dependencies: vec![],
            retry_count: 0,
            max_retries: 2,
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            result_summary: None,
        };
        task1.id = "low".to_string();

        // 添加高优先级任务
        let mut task2 = task1.clone();
        task2.id = "high".to_string();
        task2.priority_score = 90;

        scheduler.add_task(task1);
        scheduler.add_task(task2);

        // 高优先级应该先被取出
        let next = scheduler.get_next_task().unwrap();
        assert_eq!(next.id, "high");
    }
}
