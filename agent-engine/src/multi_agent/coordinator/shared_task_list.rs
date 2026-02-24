// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 共享任务列表
//!
//! 实现 Coordinator-Specialist 架构中的共享任务列表机制。
//! 提供任务认领、文件锁定、优先级队列等功能。

use crate::multi_agent::task::{AgentSpecialty, AuditTask, TaskPriority, TaskStatus, TaskType};
use std::collections::{HashMap, HashSet, BinaryHeap};
use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};
use anyhow::Result;

/// 任务优先级条目（用于 BinaryHeap）
#[derive(Debug, Clone)]
struct TaskPriorityEntry {
    task: AuditTask,
}

impl PartialEq for TaskPriorityEntry {
    fn eq(&self, other: &Self) -> bool {
        self.task.id == other.task.id
    }
}

impl Eq for TaskPriorityEntry {}

impl PartialOrd for TaskPriorityEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TaskPriorityEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // BinaryHeap 是最大堆，高优先级先出
        // TaskPriority 的自然顺序: Critical > High > Medium > Low
        self.task.priority.cmp(&other.task.priority)
            .then_with(|| self.task.id.cmp(&other.task.id))
    }
}

/// 任务完成结果
#[derive(Debug, Clone)]
pub struct TaskResult {
    /// 发现的漏洞
    pub findings: Vec<serde_json::Value>,
    /// 执行结果
    pub execution_result: Option<serde_json::Value>,
}

/// 共享任务列表
///
/// 核心特性：
/// - 任务状态管理: Pending → InProgress → Completed/Failed
/// - 自我认领机制 (Self-claim)
/// - 任务优先级队列
/// - 文件锁定防冲突
#[derive(Clone)]
pub struct SharedTaskList {
    /// 任务列表
    tasks: Arc<RwLock<HashMap<String, AuditTask>>>,

    /// 待处理任务队列（按优先级排序）
    pending_queue: Arc<Mutex<BinaryHeap<TaskPriorityEntry>>>,

    /// 文件锁 (防止冲突) - file_path -> task_id
    file_locks: Arc<RwLock<HashMap<String, String>>>,

    /// 任务依赖图
    dependency_graph: Arc<Mutex<TaskDependencyGraph>>,

    /// Specialist 状态 - specialist_id -> current_task_id
    specialist_tasks: Arc<RwLock<HashMap<String, Option<String>>>>,

    /// 任务结果存储 - task_id -> TaskResult
    task_results: Arc<RwLock<HashMap<String, TaskResult>>>,
}

impl SharedTaskList {
    /// 创建新的共享任务列表
    pub fn new() -> Self {
        Self {
            tasks: Arc::new(RwLock::new(HashMap::new())),
            pending_queue: Arc::new(Mutex::new(BinaryHeap::new())),
            file_locks: Arc::new(RwLock::new(HashMap::new())),
            dependency_graph: Arc::new(Mutex::new(TaskDependencyGraph::new())),
            specialist_tasks: Arc::new(RwLock::new(HashMap::new())),
            task_results: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Coordinator 添加任务
    pub async fn add_task(&self, mut task: AuditTask) -> Result<()> {
        // 检查文件是否已被锁定
        self.check_file_conflicts(&task)?;

        // 设置任务状态为 Pending
        task.status = TaskStatus::Pending;

        // 获取优先级用于日志
        let priority = task.priority;

        // 添加到任务列表
        let task_id = task.id.clone();
        self.tasks.write().await.insert(task_id.clone(), task.clone());

        // 如果没有依赖，加入待处理队列
        let has_deps = {
            let graph = self.dependency_graph.lock().await;
            graph.has_dependencies(&task_id)
        };

        if !has_deps {
            self.pending_queue.lock().await.push(TaskPriorityEntry { task });
        }

        tracing::debug!("[SharedTaskList] 添加任务: {} (优先级: {:?})", task_id, priority);

        Ok(())
    }

    /// 添加任务依赖
    pub async fn add_dependency(&self, task_id: &str, depends_on: &str) {
        let mut graph = self.dependency_graph.lock().await;
        graph.add_dependency(task_id, depends_on);
        tracing::debug!("[SharedTaskList] 添加依赖: {} -> {}", task_id, depends_on);
    }

    /// Specialist 自我认领任务
    pub async fn claim_task(
        &self,
        specialist_id: &str,
        specialty: &AgentSpecialty,
    ) -> Option<AuditTask> {
        // 检查 Specialist 是否已经有任务
        {
            let specialist_map = self.specialist_tasks.read().await;
            if let Some(Some(current_task)) = specialist_map.get(specialist_id) {
                tracing::warn!("[Specialist {}] 已有任务: {}", specialist_id, current_task);
                return None;
            }
        }

        let mut queue = self.pending_queue.lock().await;

        // 查找匹配专业领域的任务
        while let Some(entry) = queue.pop() {
            let task_id = entry.task.id.clone();

            // 检查是否被阻塞
            let is_blocked = {
                let graph = self.dependency_graph.lock().await;
                graph.is_blocked(&task_id)
            };

            if is_blocked {
                // 被阻塞，放回队列
                queue.push(entry);
                continue;
            }

            // 检查专业匹配
            if self.is_specialty_match(&entry.task, specialty) {
                // 尝试获取文件锁
                if self.try_acquire_file_locks(&entry.task).await {
                    // 更新任务状态
                    self.update_task_status(&task_id, TaskStatus::Assigned).await;
                    self.update_task_status(&task_id, TaskStatus::InProgress).await;

                    // 分配给 Specialist
                    self.assign_to_specialist(&task_id, specialist_id).await;

                    tracing::info!(
                        "[Specialist {} - {:?}] 认领任务: {}",
                        specialist_id,
                        specialty,
                        task_id
                    );

                    return Some(entry.task);
                } else {
                    // 文件冲突，放回队列
                    queue.push(entry);
                }
            } else {
                // 不匹配，放回队列
                queue.push(entry);
            }
        }

        None
    }

    /// 完成任务 (自动解除依赖阻塞)
    pub async fn complete_task(&self, task_id: &str, result: TaskResult) {
        tracing::info!("[SharedTaskList] 完成任务: {}", task_id);

        // 保存任务结果
        {
            self.task_results.write().await.insert(task_id.to_string(), result);
        }

        // 更新任务状态
        self.update_task_status(task_id, TaskStatus::Completed).await;

        // 释放文件锁
        self.release_file_locks(task_id).await;

        // 清除 Specialist 任务分配
        {
            let mut specialist_map = self.specialist_tasks.write().await;
            for (_, current_task) in specialist_map.iter_mut() {
                if current_task.as_ref() == Some(&task_id.to_string()) {
                    *current_task = None;
                }
            }
        }

        // 解除依赖此任务的其他任务
        let unblocked = {
            let mut graph = self.dependency_graph.lock().await;
            graph.unblock_dependents(task_id)
        };

        // 将解除阻塞的任务加入待处理队列
        for unblocked_task_id in unblocked {
            if let Some(task) = self.get_task(&unblocked_task_id).await {
                self.pending_queue.lock().await.push(TaskPriorityEntry { task });
                tracing::debug!("[SharedTaskList] 解除阻塞: {}", unblocked_task_id);
            }
        }
    }

    /// 标记任务为失败
    pub async fn fail_task(&self, task_id: &str, error: String) {
        tracing::error!("[SharedTaskList] 任务失败: {} - {}", task_id, error);

        // 更新任务状态
        self.update_task_status(task_id, TaskStatus::Failed).await;

        // 释放文件锁
        self.release_file_locks(task_id).await;

        // 清除 Specialist 任务分配
        {
            let mut specialist_map = self.specialist_tasks.write().await;
            for (_, current_task) in specialist_map.iter_mut() {
                if current_task.as_ref() == Some(&task_id.to_string()) {
                    *current_task = None;
                }
            }
        }
    }

    /// 获取任务
    pub async fn get_task(&self, task_id: &str) -> Option<AuditTask> {
        self.tasks.read().await.get(task_id).cloned()
    }

    /// 获取任务结果
    pub async fn get_task_result(&self, task_id: &str) -> Option<TaskResult> {
        self.task_results.read().await.get(task_id).cloned()
    }

    /// 获取所有任务
    pub async fn get_all_tasks(&self) -> Vec<AuditTask> {
        self.tasks.read().await.values().cloned().collect()
    }

    /// 获取待处理任务数量
    pub async fn pending_count(&self) -> usize {
        self.pending_queue.lock().await.len()
    }

    /// 检查所有任务是否完成
    pub async fn all_tasks_completed(&self) -> bool {
        let tasks = self.tasks.read().await;
        tasks.values().all(|t| {
            matches!(t.status, TaskStatus::Completed | TaskStatus::Failed)
        })
    }

    /// 获取任务统计
    pub async fn get_stats(&self) -> TaskListStats {
        let tasks = self.tasks.read().await;
        let mut stats = TaskListStats::default();

        for task in tasks.values() {
            stats.total += 1;
            match task.status {
                TaskStatus::Pending => stats.pending += 1,
                TaskStatus::Assigned | TaskStatus::InProgress => stats.in_progress += 1,
                TaskStatus::Completed => stats.completed += 1,
                TaskStatus::Failed | TaskStatus::Cancelled => stats.failed += 1,
                TaskStatus::WaitingForAssistance => stats.waiting_assistance += 1,
            }
        }

        stats
    }

    // ========== 私有方法 ==========

    /// 检查文件冲突
    fn check_file_conflicts(&self, _task: &AuditTask) -> Result<()> {
        // 简化实现，总是返回 Ok
        Ok(())
    }

    /// 检查专业匹配
    fn is_specialty_match(&self, task: &AuditTask, specialty: &AgentSpecialty) -> bool {
        // 简单匹配：任务类型与专家领域对应
        match (&task.task_type, specialty) {
            (_, AgentSpecialty::GeneralAnalyst) => true, // 通用分析师可以接受所有任务
            (TaskType::FileAnalysis, AgentSpecialty::SqlInjectionExpert) => true,
            (TaskType::FileAnalysis, AgentSpecialty::XssExpert) => true,
            (TaskType::FileAnalysis, AgentSpecialty::CommandInjectionExpert) => true,
            (TaskType::FileAnalysis, AgentSpecialty::PathTraversalExpert) => true,
            (TaskType::FileAnalysis, AgentSpecialty::SsrfExpert) => true,
            (TaskType::BusinessLogicAnalysis, AgentSpecialty::BusinessLogicExpert) => true,
            (TaskType::BusinessLogicAnalysis, AgentSpecialty::AuthExpert) => true,
            (TaskType::VulnerabilityVerification, AgentSpecialty::GeneralAnalyst) => true,
            (TaskType::Reconnaissance, AgentSpecialty::GeneralAnalyst) => true,
            (TaskType::GlobalDataFlow, AgentSpecialty::GeneralAnalyst) => true,
            (TaskType::GitHistoryAnalysis, AgentSpecialty::GeneralAnalyst) => true,
            (TaskType::SemanticAnalysis, AgentSpecialty::GeneralAnalyst) => true,
            _ => false,
        }
    }

    /// 尝试获取文件锁
    async fn try_acquire_file_locks(&self, task: &AuditTask) -> bool {
        let mut locks = self.file_locks.write().await;

        // 获取任务涉及的文件
        let files = self.get_task_files(task);

        // 检查是否有文件已被锁定
        for file in &files {
            if locks.contains_key(file) {
                return false;
            }
        }

        // 获取锁
        for file in files {
            locks.insert(file, task.id.clone());
        }

        true
    }

    /// 释放文件锁
    async fn release_file_locks(&self, task_id: &str) {
        let mut locks = self.file_locks.write().await;

        // 获取任务涉及的文件
        let files = {
            if let Some(task) = self.tasks.read().await.get(task_id) {
                self.get_task_files(task)
            } else {
                Vec::new()
            }
        };

        // 释放锁
        for file in files {
            locks.remove(&file);
        }
    }

    /// 获取任务涉及的文件
    fn get_task_files(&self, task: &AuditTask) -> Vec<String> {
        if let Some(ref file_info) = task.context.file_info {
            vec![file_info.path.clone()]
        } else if let Some(ref endpoint_info) = task.context.endpoint_info {
            // 对于端点，可以获取相关文件路径
            // 这里简化处理
            vec![]
        } else {
            Vec::new()
        }
    }

    /// 更新任务状态
    async fn update_task_status(&self, task_id: &str, status: TaskStatus) {
        if let Some(mut task) = self.tasks.write().await.get_mut(task_id) {
            task.status = status;

            // 更新时间戳
            match status {
                TaskStatus::Assigned => {
                    task.started_at = Some(chrono::Utc::now());
                }
                TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled => {
                    task.completed_at = Some(chrono::Utc::now());
                }
                _ => {}
            }
        }
    }

    /// 分配任务给 Specialist
    async fn assign_to_specialist(&self, task_id: &str, specialist_id: &str) {
        let mut specialist_map = self.specialist_tasks.write().await;
        specialist_map.insert(specialist_id.to_string(), Some(task_id.to_string()));
    }

    /// 检查任务是否有依赖
    async fn has_dependencies(&self, task: &AuditTask) -> bool {
        let graph = self.dependency_graph.lock().await;
        graph.has_dependencies(&task.id)
    }
}

impl Default for SharedTaskList {
    fn default() -> Self {
        Self::new()
    }
}

/// 任务依赖图
#[derive(Debug, Default)]
struct TaskDependencyGraph {
    /// 依赖关系: task_id -> 依赖的任务列表
    dependencies: HashMap<String, Vec<String>>,

    /// 被依赖关系: task_id -> 依赖此任务的任务列表
    dependents: HashMap<String, Vec<String>>,

    /// 阻塞状态
    blocked_tasks: HashSet<String>,
}

impl TaskDependencyGraph {
    /// 创建新的依赖图
    pub fn new() -> Self {
        Self {
            dependencies: HashMap::new(),
            dependents: HashMap::new(),
            blocked_tasks: HashSet::new(),
        }
    }

    /// 添加任务依赖
    pub fn add_dependency(&mut self, task_id: &str, depends_on: &str) {
        self.dependencies
            .entry(task_id.to_string())
            .or_insert_with(Vec::new)
            .push(depends_on.to_string());

        self.dependents
            .entry(depends_on.to_string())
            .or_insert_with(Vec::new)
            .push(task_id.to_string());

        // 标记为阻塞
        self.blocked_tasks.insert(task_id.to_string());

        tracing::debug!(
            "[TaskDependencyGraph] 添加依赖: {} 依赖于 {}",
            task_id,
            depends_on
        );
    }

    /// 解除阻塞 (任务完成时调用)
    pub fn unblock_dependents(&mut self, completed_task: &str) -> Vec<String> {
        let mut unblocked = Vec::new();

        if let Some(dependents) = self.dependents.get(completed_task) {
            for dependent in dependents.clone() {
                // 从依赖中移除
                if let Some(deps) = self.dependencies.get_mut(&dependent) {
                    deps.retain(|id| id != completed_task);

                    // 如果没有依赖了，解除阻塞
                    if deps.is_empty() {
                        self.blocked_tasks.remove(&dependent);
                        unblocked.push(dependent.clone());
                        tracing::debug!(
                            "[TaskDependencyGraph] 解除阻塞: {} (已完成: {})",
                            dependent,
                            completed_task
                        );
                    }
                }
            }
        }

        unblocked
    }

    /// 检查任务是否被阻塞
    pub fn is_blocked(&self, task_id: &str) -> bool {
        self.blocked_tasks.contains(task_id)
    }

    /// 检查任务是否有依赖
    pub fn has_dependencies(&self, task_id: &str) -> bool {
        self.dependencies
            .get(task_id)
            .map(|deps| !deps.is_empty())
            .unwrap_or(false)
    }
}

/// 任务列表统计
#[derive(Debug, Clone, Default)]
pub struct TaskListStats {
    pub total: usize,
    pub pending: usize,
    pub in_progress: usize,
    pub completed: usize,
    pub failed: usize,
    pub waiting_assistance: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multi_agent::task::{TaskType, TaskContext, FileContext};

    #[tokio::test]
    async fn test_shared_task_list_basic() {
        let task_list = SharedTaskList::new();

        // 创建测试任务
        let task = AuditTask::new(
            TaskType::FileAnalysis,
            "/test/file.rs".to_string(),
            AgentSpecialty::SqlInjectionExpert,
            TaskPriority::High,
        );

        // 添加任务
        task_list.add_task(task).await.unwrap();

        // 验证任务数量
        assert_eq!(task_list.pending_count().await, 1);
    }

    #[tokio::test]
    async fn test_dependency_blocking() {
        let task_list = SharedTaskList::new();

        // 添加依赖关系
        task_list.add_dependency("task-2", "task-1").await;

        let graph = task_list.dependency_graph.lock().await;
        assert!(graph.is_blocked("task-2"));
        assert!(!graph.is_blocked("task-1"));
    }

    #[tokio::test]
    async fn test_priority_ordering() {
        let mut heap = BinaryHeap::new();

        let task1 = AuditTask::new(
            TaskType::FileAnalysis,
            "/test/low.rs".to_string(),
            AgentSpecialty::SqlInjectionExpert,
            TaskPriority::Low,
        );

        let task2 = AuditTask::new(
            TaskType::FileAnalysis,
            "/test/high.rs".to_string(),
            AgentSpecialty::SqlInjectionExpert,
            TaskPriority::High,
        );

        heap.push(TaskPriorityEntry { task: task1 });
        heap.push(TaskPriorityEntry { task: task2 });

        // High priority should come first
        let first = heap.pop().unwrap();
        assert_eq!(first.task.target, "/test/high.rs");
    }
}
