// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! ReAct 循环状态管理

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// ReAct 循环状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactState {
    /// 当前迭代次数
    pub iteration: u32,

    /// 是否完成
    pub completed: bool,

    /// 是否失败
    pub failed: bool,

    /// 失败原因
    pub error: Option<String>,

    /// 思考链
    pub thought_chain: Vec<ThoughtEntry>,

    /// 累积的上下文
    pub accumulated_context: String,

    /// 当前工作内存
    pub working_memory: HashMap<String, serde_json::Value>,

    /// 最后的观察结果
    pub last_observation: Option<Observation>,

    /// 待处理的目标
    pub pending_goals: Vec<String>,

    /// 已完成的目标
    pub completed_goals: Vec<String>,

    /// 开始时间
    pub started_at: DateTime<Utc>,

    /// 最后更新时间
    pub updated_at: DateTime<Utc>,
}

impl ReactState {
    /// 创建新的 ReAct 状态
    pub fn new() -> Self {
        let now = Utc::now();
        Self {
            iteration: 0,
            completed: false,
            failed: false,
            error: None,
            thought_chain: Vec::new(),
            accumulated_context: String::new(),
            working_memory: HashMap::new(),
            last_observation: None,
            pending_goals: Vec::new(),
            completed_goals: Vec::new(),
            started_at: now,
            updated_at: now,
        }
    }

    /// 增加迭代次数
    pub fn next_iteration(&mut self) {
        self.iteration += 1;
        self.updated_at = Utc::now();
    }

    /// 添加思考条目
    pub fn add_thought(&mut self, thought: ThoughtEntry) {
        self.thought_chain.push(thought);
        self.updated_at = Utc::now();
    }

    /// 设置观察结果
    pub fn set_observation(&mut self, observation: Observation) {
        self.last_observation = Some(observation);
        self.updated_at = Utc::now();
    }

    /// 追加上下文
    pub fn append_context(&mut self, context: &str) {
        self.accumulated_context.push_str("\n\n");
        self.accumulated_context.push_str(context);
        self.updated_at = Utc::now();
    }

    /// 设置工作记忆
    pub fn set_memory(&mut self, key: String, value: serde_json::Value) {
        self.working_memory.insert(key, value);
        self.updated_at = Utc::now();
    }

    /// 获取工作记忆
    pub fn get_memory(&self, key: &str) -> Option<&serde_json::Value> {
        self.working_memory.get(key)
    }

    /// 添加待处理目标
    pub fn add_goal(&mut self, goal: String) {
        self.pending_goals.push(goal);
        self.updated_at = Utc::now();
    }

    /// 完成目标
    pub fn complete_goal(&mut self, goal: &str) {
        if let Some(pos) = self.pending_goals.iter().position(|g| g == goal) {
            self.pending_goals.remove(pos);
            self.completed_goals.push(goal.to_string());
        }
        self.updated_at = Utc::now();
    }

    /// 标记完成
    pub fn mark_completed(&mut self) {
        self.completed = true;
        self.updated_at = Utc::now();
    }

    /// 标记失败
    pub fn mark_failed(&mut self, error: String) {
        self.failed = true;
        self.error = Some(error);
        self.updated_at = Utc::now();
    }

    /// 是否应该继续
    pub fn should_continue(&self, max_iterations: u32) -> bool {
        !self.completed && !self.failed && self.iteration < max_iterations
    }

    /// 获取上下文摘要（用于 LLM 提示）
    pub fn get_context_summary(&self) -> String {
        let mut summary = String::new();

        // 当前状态
        summary.push_str(&format!("迭代: {}/{}\n", self.iteration, self.started_at.format("%H:%M:%S")));

        // 待处理目标
        if !self.pending_goals.is_empty() {
            summary.push_str(&format!("待处理目标: {}\n", self.pending_goals.join(", ")));
        }

        // 已完成目标
        if !self.completed_goals.is_empty() {
            summary.push_str(&format!("已完成: {}\n", self.completed_goals.join(", ")));
        }

        // 最后观察
        if let Some(ref obs) = self.last_observation {
            summary.push_str(&format!("最后观察: {}\n", obs.summary));
        }

        // 工作记忆键
        if !self.working_memory.is_empty() {
            let keys: Vec<_> = self.working_memory.keys().map(|k| k.as_str()).collect();
            summary.push_str(&format!("工作记忆: {}\n", keys.join(", ")));
        }

        summary
    }

    /// 获取完整历史（用于调试）
    pub fn get_full_history(&self) -> String {
        let mut history = String::new();

        for (i, thought) in self.thought_chain.iter().enumerate() {
            history.push_str(&format!(
                "=== 迭代 {} ===\n时间: {}\n思考: {}\n",
                i + 1,
                thought.timestamp.format("%H:%M:%S"),
                thought.thought
            ));

            if let Some(ref action) = thought.action {
                history.push_str(&format!("操作: {}\n", action));
            }

            if let Some(ref observation) = thought.observation {
                history.push_str(&format!("观察: {}\n", observation.summary));
            }

            history.push_str("\n");
        }

        history
    }
}

impl Default for ReactState {
    fn default() -> Self {
        Self::new()
    }
}

/// 思考条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThoughtEntry {
    /// 迭代次数
    pub iteration: u32,

    /// 思考内容
    pub thought: String,

    /// 计划的操作
    pub action: Option<String>,

    /// 操作参数
    pub action_input: Option<serde_json::Value>,

    /// 观察结果
    pub observation: Option<Observation>,

    /// 置信度
    pub confidence: f32,

    /// 时间戳
    pub timestamp: DateTime<Utc>,
}

impl ThoughtEntry {
    /// 创建新的思考条目
    pub fn new(iteration: u32, thought: String) -> Self {
        Self {
            iteration,
            thought,
            action: None,
            action_input: None,
            observation: None,
            confidence: 0.5,
            timestamp: Utc::now(),
        }
    }

    /// 设置操作
    pub fn with_action(mut self, action: String) -> Self {
        self.action = Some(action);
        self
    }

    /// 设置操作参数
    pub fn with_input(mut self, input: serde_json::Value) -> Self {
        self.action_input = Some(input);
        self
    }

    /// 设置观察结果
    pub fn with_observation(mut self, observation: Observation) -> Self {
        self.observation = Some(observation);
        self
    }

    /// 设置置信度
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence;
        self
    }
}

/// 观察结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    /// 结果摘要
    pub summary: String,

    /// 完整数据
    pub data: Option<serde_json::Value>,

    /// 是否成功
    pub success: bool,

    /// 错误信息
    pub error: Option<String>,

    /// 工具名称
    pub tool_name: Option<String>,

    /// 执行时长（毫秒）
    pub duration_ms: u64,
}

impl Observation {
    /// 创建成功的观察
    pub fn success(summary: String) -> Self {
        Self {
            summary,
            data: None,
            success: true,
            error: None,
            tool_name: None,
            duration_ms: 0,
        }
    }

    /// 创建带数据的观察
    pub fn with_data(summary: String, data: serde_json::Value) -> Self {
        Self {
            summary,
            data: Some(data),
            success: true,
            error: None,
            tool_name: None,
            duration_ms: 0,
        }
    }

    /// 创建工具执行结果
    pub fn from_tool(
        tool_name: String,
        result: String,
        duration_ms: u64,
    ) -> Self {
        Self {
            summary: result.clone(),
            data: Some(serde_json::json!({ "result": result })),
            success: true,
            error: None,
            tool_name: Some(tool_name),
            duration_ms,
        }
    }

    /// 创建失败的观察
    pub fn error(error: String) -> Self {
        Self {
            summary: "执行失败".to_string(),
            data: None,
            success: false,
            error: Some(error),
            tool_name: None,
            duration_ms: 0,
        }
    }

    /// 设置时长
    pub fn with_duration(mut self, duration_ms: u64) -> Self {
        self.duration_ms = duration_ms;
        self
    }
}
