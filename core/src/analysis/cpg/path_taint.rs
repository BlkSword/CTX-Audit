// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 路径敏感污点状态（属性路径版）
//!
//! 使用 `AccessPath`（如 `req.body.name`）作为污点状态的 key，
//! 替代简单变量名 String。支持前缀匹配：如果 `req.body` 被污染，
//! 使用 `req.body.name` 时也会被检测到。

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::analysis::alias::AccessPath;
use crate::analysis::enhanced_dataflow::EdgeType;
use crate::analysis::taint::{PropagationStep, PropagationStepType};

/// 路径条件 — 描述当前执行到某个分支的原因
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathCondition {
    /// 产生分支的条件节点 ID
    pub condition_node_id: usize,
    /// 当前在哪条分支上
    pub branch: EdgeType,
    /// 条件表达式文本
    pub expr: String,
}

/// 变量在路径敏感状态下的污点信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VarTaintState {
    /// 污点来源行号
    pub source_line: usize,
    /// 污点来源变量名
    pub source_var: String,
    /// 是否在任何路径上被净化
    pub sanitized: bool,
    /// 净化函数名
    pub sanitizer: Option<String>,
    /// 传播路径
    pub propagation_steps: Vec<PropagationStep>,
    /// 在哪些路径条件下被净化
    pub sanitized_on: Vec<PathCondition>,
    /// 在哪些路径条件下仍被污染
    pub tainted_on: Vec<PathCondition>,
}

impl VarTaintState {
    /// 从基本污点信息创建（默认全部路径上被污染）
    pub fn from_taint(
        source_line: usize,
        source_var: String,
        propagation_steps: Vec<PropagationStep>,
    ) -> Self {
        Self {
            source_line,
            source_var,
            sanitized: false,
            sanitizer: None,
            propagation_steps,
            sanitized_on: vec![],
            tainted_on: vec![],
        }
    }

    /// 在指定分支上标记为净化
    pub fn mark_sanitized_on_branch(&mut self, condition: &PathCondition) {
        self.sanitized_on.push(condition.clone());
    }

    /// 在指定分支上标记为仍被污染
    pub fn mark_tainted_on_branch(&mut self, condition: &PathCondition) {
        self.tainted_on.push(condition.clone());
    }

    /// 计算最终置信度
    pub fn confidence(&self) -> f64 {
        if self.sanitized && self.sanitized_on.is_empty() {
            return 0.3;
        }

        let s = self.sanitized_on.len();
        let t = self.tainted_on.len();

        if s == 0 && t == 0 {
            if self.sanitized {
                0.3
            } else {
                0.85
            }
        } else if t == 0 && s > 0 {
            0.3
        } else if s == 0 && t > 0 {
            0.85
        } else {
            0.5
        }
    }

    /// 该变量在当前路径条件下是否应该被视为污染
    pub fn is_tainted(&self) -> bool {
        if self.sanitized && self.sanitized_on.is_empty() {
            return false;
        }
        !self.sanitized_on.is_empty() && self.tainted_on.is_empty() && self.sanitized
    }

    /// 克隆污点信息，替换为目标路径
    pub fn clone_for_target(&self, target: &AccessPath) -> Self {
        Self {
            source_line: self.source_line,
            source_var: self.source_var.clone(),
            sanitized: self.sanitized,
            sanitizer: self.sanitizer.clone(),
            propagation_steps: self.propagation_steps.clone(),
            sanitized_on: self.sanitized_on.clone(),
            tainted_on: self.tainted_on.clone(),
        }
    }
}

/// 路径敏感污点状态（以 AccessPath 为 key）
#[derive(Debug, Clone, Default)]
pub struct PathSensitiveState {
    /// 当前活跃的路径条件栈
    pub path_conditions: Vec<PathCondition>,
    /// 以 AccessPath 为 key 的污点状态
    access_taint: HashMap<AccessPath, VarTaintState>,
}

impl PathSensitiveState {
    /// 创建空状态
    pub fn new() -> Self {
        Self::default()
    }

    /// 在指定路径条件下创建状态
    pub fn with_conditions(conditions: Vec<PathCondition>) -> Self {
        Self {
            path_conditions: conditions,
            access_taint: HashMap::new(),
        }
    }

    // ── 简单变量接口（兼容旧代码） ──

    /// 用简单变量名获取污点状态
    pub fn get_var(&self, var: &str) -> Option<&VarTaintState> {
        let path = AccessPath::simple(var);
        self.find_taint_for_path(&path)
    }

    /// 用简单变量名获取可变污点状态（精确匹配）
    pub fn get_var_mut(&mut self, var: &str) -> Option<&mut VarTaintState> {
        let path = AccessPath::simple(var);
        self.access_taint.get_mut(&path)
    }

    /// 用简单变量名插入污点状态
    pub fn insert_var(&mut self, var: String, state: VarTaintState) {
        self.access_taint.insert(AccessPath::simple(&var), state);
    }

    /// 用 AccessPath 插入污点状态
    pub fn insert_path(&mut self, path: AccessPath, state: VarTaintState) {
        self.access_taint.insert(path, state);
    }

    /// 标记变量在当前分支上被净化
    pub fn mark_sanitized(&mut self, var: &str, sanitizer: Option<String>) {
        let path = AccessPath::simple(var);
        if let Some(vt) = self.access_taint.get_mut(&path) {
            vt.sanitizer = sanitizer;
            if let Some(pc) = self.path_conditions.last() {
                vt.mark_sanitized_on_branch(pc);
            } else {
                vt.sanitized = true;
            }
        }
    }

    /// 标记变量在当前分支上仍被污染
    pub fn mark_tainted(&mut self, var: &str) {
        let path = AccessPath::simple(var);
        if let Some(vt) = self.access_taint.get_mut(&path) {
            if let Some(pc) = self.path_conditions.last() {
                vt.mark_tainted_on_branch(pc);
            }
        }
    }

    // ── AccessPath 查询接口 ──

    /// 查询 access path 的污点状态（支持前缀匹配）
    ///
    /// 1. 精确匹配: `req.body.name` → 找到 `req.body.name` 上的污点
    /// 2. 前缀匹配: 查 `req.body.name` → 找到 `req.body` 上的污点（保守策略）
    /// 3. 反向前缀: 查 `req.body` → 找到 `req.body.name` 上的污点（保守）
    pub fn find_taint_for_path(&self, path: &AccessPath) -> Option<&VarTaintState> {
        // 精确匹配
        if let Some(vt) = self.access_taint.get(path) {
            return Some(vt);
        }

        // 前缀匹配: 查找是否有更短的路径是 query 的前缀
        // 例: 查 req.body.name → 找到 req.body 上有污点
        let mut best_match: Option<&VarTaintState> = None;
        let mut best_depth = usize::MAX;
        for (stored_path, vt) in &self.access_taint {
            if stored_path.is_prefix_of(path) && stored_path.depth() < best_depth {
                best_depth = stored_path.depth();
                best_match = Some(vt);
            }
        }
        if best_match.is_some() {
            return best_match;
        }

        // 反向前缀: 查找是否有更长的路径以 query 为前缀
        // 例: 查 req.body → 找到 req.body.name 上有污点
        for (stored_path, vt) in &self.access_taint {
            if path.is_prefix_of(stored_path) && !vt.sanitized {
                return Some(vt);
            }
        }

        None
    }

    /// 精确获取 AccessPath 的污点状态（不做前缀匹配）
    pub fn get_exact(&self, path: &AccessPath) -> Option<&VarTaintState> {
        self.access_taint.get(path)
    }

    /// 检查变量（简单名）是否被污染
    pub fn is_var_tainted(&self, var: &str) -> bool {
        let path = AccessPath::simple(var);
        self.find_taint_for_path(&path)
            .map(|vt| !vt.sanitized || !vt.sanitized_on.is_empty())
            .unwrap_or(false)
    }

    /// 检查 AccessPath 是否被污染
    pub fn is_path_tainted(&self, path: &AccessPath) -> bool {
        self.find_taint_for_path(path)
            .map(|vt| !vt.sanitized || !vt.sanitized_on.is_empty())
            .unwrap_or(false)
    }

    /// 获取所有污点条目（用于 merge）
    pub fn all_entries(&self) -> impl Iterator<Item = (&AccessPath, &VarTaintState)> {
        self.access_taint.iter()
    }

    /// 是否为空
    pub fn is_empty(&self) -> bool {
        self.access_taint.is_empty()
    }

    /// 条目数量
    pub fn len(&self) -> usize {
        self.access_taint.len()
    }

    // ── 合并操作 ──

    /// 合并两个分支的状态（用于 merge 节点）
    pub fn merge_branches(
        true_state: &PathSensitiveState,
        false_state: &PathSensitiveState,
    ) -> PathSensitiveState {
        let mut merged = PathSensitiveState::new();

        // 收集所有 AccessPath
        let mut all_paths: Vec<AccessPath> = true_state
            .access_taint
            .keys()
            .chain(false_state.access_taint.keys())
            .cloned()
            .collect();
        all_paths.sort_by(|a, b| a.as_dotted().cmp(&b.as_dotted()));
        all_paths.dedup();

        for path in all_paths {
            let true_vt = true_state.access_taint.get(&path);
            let false_vt = false_state.access_taint.get(&path);

            match (true_vt, false_vt) {
                (Some(tv), Some(fv)) => {
                    let mut merged_vt = tv.clone();
                    for pc in &fv.sanitized_on {
                        if !merged_vt.sanitized_on.iter().any(|p| {
                            p.condition_node_id == pc.condition_node_id && p.branch == pc.branch
                        }) {
                            merged_vt.sanitized_on.push(pc.clone());
                        }
                    }
                    for pc in &fv.tainted_on {
                        if !merged_vt.tainted_on.iter().any(|p| {
                            p.condition_node_id == pc.condition_node_id && p.branch == pc.branch
                        }) {
                            merged_vt.tainted_on.push(pc.clone());
                        }
                    }
                    if !tv.sanitized || !fv.sanitized {
                        merged_vt.sanitized = false;
                    } else {
                        merged_vt.sanitized = true;
                    }
                    for step in &fv.propagation_steps {
                        if !merged_vt
                            .propagation_steps
                            .iter()
                            .any(|s| s.line == step.line && s.step_type == step.step_type)
                        {
                            merged_vt.propagation_steps.push(step.clone());
                        }
                    }
                    merged.access_taint.insert(path, merged_vt);
                }
                (Some(tv), None) => {
                    merged.access_taint.insert(path, tv.clone());
                }
                (None, Some(fv)) => {
                    merged.access_taint.insert(path, fv.clone());
                }
                _ => {}
            }
        }

        merged
    }

    /// 将另一个状态的变量合并到当前状态（union join）
    pub fn union_with(&mut self, other: &PathSensitiveState) {
        for (path, vt) in &other.access_taint {
            match self.access_taint.get(path) {
                None => {
                    self.access_taint.insert(path.clone(), vt.clone());
                }
                Some(existing) => {
                    if existing.sanitized && !vt.sanitized {
                        self.access_taint.insert(path.clone(), vt.clone());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pc(node_id: usize, branch: EdgeType, expr: &str) -> PathCondition {
        PathCondition {
            condition_node_id: node_id,
            branch,
            expr: expr.to_string(),
        }
    }

    #[test]
    fn test_var_taint_confidence_unsanitized() {
        let vt = VarTaintState::from_taint(1, "input".into(), vec![]);
        assert!((vt.confidence() - 0.85).abs() < 0.01);
    }

    #[test]
    fn test_var_taint_confidence_fully_sanitized() {
        let mut vt = VarTaintState::from_taint(1, "input".into(), vec![]);
        vt.sanitized = true;
        assert!((vt.confidence() - 0.3).abs() < 0.01);
    }

    #[test]
    fn test_var_taint_confidence_partial_sanitization() {
        let mut vt = VarTaintState::from_taint(1, "input".into(), vec![]);
        vt.sanitized_on
            .push(make_pc(5, EdgeType::TrueBranch, "isSafe(x)"));
        vt.tainted_on
            .push(make_pc(5, EdgeType::FalseBranch, "isSafe(x)"));
        assert!((vt.confidence() - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_merge_branches_preserves_unsanitized() {
        let mut true_state = PathSensitiveState::new();
        let mut true_vt = VarTaintState::from_taint(1, "x".into(), vec![]);
        true_vt.sanitized = true;
        true_vt
            .sanitized_on
            .push(make_pc(5, EdgeType::TrueBranch, "isSafe(x)"));
        true_state.insert_var("x".into(), true_vt);

        let mut false_state = PathSensitiveState::new();
        let false_vt = VarTaintState::from_taint(1, "x".into(), vec![]);
        false_state.insert_var("x".into(), false_vt);

        let merged = PathSensitiveState::merge_branches(&true_state, &false_state);
        let merged_vt = merged.get_var("x").unwrap();
        assert!(!merged_vt.sanitized);
        assert!(!merged_vt.sanitized_on.is_empty());
    }

    #[test]
    fn test_merge_branches_both_sanitized() {
        let mut true_state = PathSensitiveState::new();
        let mut true_vt = VarTaintState::from_taint(1, "x".into(), vec![]);
        true_vt.sanitized = true;
        true_state.insert_var("x".into(), true_vt);

        let mut false_state = PathSensitiveState::new();
        let mut false_vt = VarTaintState::from_taint(1, "x".into(), vec![]);
        false_vt.sanitized = true;
        false_state.insert_var("x".into(), false_vt);

        let merged = PathSensitiveState::merge_branches(&true_state, &false_state);
        let merged_vt = merged.get_var("x").unwrap();
        assert!(merged_vt.sanitized);
    }

    #[test]
    fn test_mark_sanitized_with_path_condition() {
        let mut state = PathSensitiveState::with_conditions(vec![make_pc(
            5,
            EdgeType::TrueBranch,
            "isSafe(x)",
        )]);
        state.insert_var("x".into(), VarTaintState::from_taint(1, "x".into(), vec![]));

        state.mark_sanitized("x", Some("isSafe".into()));

        let vt = state.get_var("x").unwrap();
        assert!(!vt.sanitized_on.is_empty());
    }

    // ── AccessPath-specific tests ──

    #[test]
    fn test_prefix_match_taint() {
        let mut state = PathSensitiveState::new();
        // Taint req.body
        state.insert_path(
            AccessPath::from_dotted("req.body"),
            VarTaintState::from_taint(1, "req.body".into(), vec![]),
        );

        // Query req.body.name should find taint from req.body
        let result = state.find_taint_for_path(&AccessPath::from_dotted("req.body.name"));
        assert!(result.is_some());
    }

    #[test]
    fn test_exact_match_taint() {
        let mut state = PathSensitiveState::new();
        state.insert_path(
            AccessPath::from_dotted("req.body.name"),
            VarTaintState::from_taint(1, "req.body.name".into(), vec![]),
        );

        // Exact match
        let result = state.find_taint_for_path(&AccessPath::from_dotted("req.body.name"));
        assert!(result.is_some());
    }

    #[test]
    fn test_no_false_positive_different_property() {
        let mut state = PathSensitiveState::new();
        state.insert_path(
            AccessPath::from_dotted("req.body.name"),
            VarTaintState::from_taint(1, "req.body.name".into(), vec![]),
        );

        // req.body.email should NOT be tainted by req.body.name (not a prefix)
        let result = state.find_taint_for_path(&AccessPath::from_dotted("req.body.email"));
        assert!(result.is_none());
    }

    #[test]
    fn test_simple_var_backward_compat() {
        let mut state = PathSensitiveState::new();
        state.insert_var(
            "input".into(),
            VarTaintState::from_taint(1, "input".into(), vec![]),
        );

        assert!(state.get_var("input").is_some());
        assert!(state.is_var_tainted("input"));
    }

    #[test]
    fn test_reverse_prefix_taint() {
        let mut state = PathSensitiveState::new();
        // Taint req.body.name
        state.insert_path(
            AccessPath::from_dotted("req.body.name"),
            VarTaintState::from_taint(1, "req.body.name".into(), vec![]),
        );

        // Query req.body — reverse prefix should find it (conservative)
        let result = state.find_taint_for_path(&AccessPath::from_dotted("req.body"));
        assert!(result.is_some());
    }
}
