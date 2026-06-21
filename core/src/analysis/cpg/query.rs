// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! CPG 查询 API
//!
//! 提供统一的跨图查询能力：到达定义、调用者查询、分支上下文、别名解析。

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::analysis::alias::AccessPath;
use crate::analysis::cross_file::{CallGraph, CallGraphNode};
use crate::analysis::enhanced_dataflow::EdgeType;

use super::{FunctionCPG, FunctionSignature};

/// 分支上下文 — 描述节点相对于最近条件分支的位置
#[derive(Debug, Clone)]
pub struct BranchContext {
    /// 支配该节点的条件节点 ID
    pub condition_node_id: Option<usize>,
    /// 节点在哪个分支上（TrueBranch / FalseBranch / None）
    pub branch_side: Option<EdgeType>,
    /// 条件表达式文本
    pub condition_expr: Option<String>,
}

/// 项目级 CPG — 多函数 CPG + 跨过程调用图
#[derive(Debug, Clone)]
pub struct CodePropertyGraph {
    /// "file:func:start_line" → FunctionCPG
    functions: HashMap<String, FunctionCPG>,
    /// 跨过程调用图
    call_graph: Arc<CallGraph>,
    /// 已索引的文件路径
    file_paths: HashSet<String>,
}

impl CodePropertyGraph {
    /// 创建空 CPG
    pub fn new(call_graph: CallGraph) -> Self {
        Self {
            functions: HashMap::new(),
            call_graph: Arc::new(call_graph),
            file_paths: HashSet::new(),
        }
    }

    /// 添加函数 CPG
    pub fn add_function(&mut self, func_cpg: FunctionCPG) {
        self.file_paths.insert(func_cpg.signature.file_path.clone());
        self.functions.insert(func_cpg.signature.id(), func_cpg);
    }

    /// 获取函数 CPG
    pub fn get_function(&self, func_id: &str) -> Option<&FunctionCPG> {
        self.functions.get(func_id)
    }

    /// 获取所有函数 ID
    pub fn function_ids(&self) -> Vec<&String> {
        self.functions.keys().collect()
    }

    /// 获取引用的调用图
    pub fn call_graph(&self) -> &CallGraph {
        &self.call_graph
    }

    /// 查询：哪些函数调用了 func_id？
    pub fn callers_of(&self, func_id: &str) -> Vec<&CallGraphNode> {
        self.call_graph
            .get_all_callers(func_id)
            .iter()
            .filter_map(|id| self.call_graph.nodes.get(id))
            .collect()
    }

    /// 查询：func_id 调用了哪些函数？
    pub fn callees_of(&self, func_id: &str) -> Vec<&CallGraphNode> {
        self.call_graph
            .get_all_callees(func_id)
            .iter()
            .filter_map(|id| self.call_graph.nodes.get(id))
            .collect()
    }

    /// 查询：变量 var 在 node_id 处的到达定义
    pub fn reaching_definitions(&self, func_id: &str, var: &str, node_id: usize) -> Vec<usize> {
        if let Some(func_cpg) = self.functions.get(func_id) {
            return func_cpg.cfg.get_reaching_definitions(var, node_id);
        }
        vec![]
    }

    /// 查询：节点相对于最近条件分支的上下文
    pub fn branch_context(&self, func_id: &str, node_id: usize) -> BranchContext {
        if let Some(func_cpg) = self.functions.get(func_id) {
            return Self::compute_branch_context(func_cpg, node_id);
        }
        BranchContext {
            condition_node_id: None,
            branch_side: None,
            condition_expr: None,
        }
    }

    /// 查询：变量的别名 AccessPath 集合
    pub fn resolve_aliases(&self, func_id: &str, var: &str) -> HashSet<AccessPath> {
        if let Some(func_cpg) = self.functions.get(func_id) {
            return func_cpg.alias_map.resolve(var);
        }
        HashSet::new()
    }

    /// 计算节点相对于最近条件分支的位置
    ///
    /// 向前遍历支配者链，找到第一个 ConditionHeader 节点，
    /// 然后检查该节点到目标节点的路径上的第一条边类型。
    fn compute_branch_context(func_cpg: &FunctionCPG, node_id: usize) -> BranchContext {
        let cfg = &func_cpg.cfg;

        // 向前查找最近的 ConditionHeader 支配者
        for pred_id in &cfg
            .nodes
            .get(node_id)
            .map(|n| n.predecessors.clone())
            .unwrap_or_default()
        {
            if let Some(ctx) =
                Self::find_condition_context(cfg, func_cpg, node_id, *pred_id, &mut HashSet::new())
            {
                return ctx;
            }
        }

        BranchContext {
            condition_node_id: None,
            branch_side: None,
            condition_expr: None,
        }
    }

    /// 递归查找条件上下文（限制搜索深度）
    fn find_condition_context(
        cfg: &crate::analysis::enhanced_dataflow::EnhancedFlowGraph,
        func_cpg: &FunctionCPG,
        original_node: usize,
        current: usize,
        visited: &mut HashSet<usize>,
    ) -> Option<BranchContext> {
        if visited.contains(&current) || visited.len() > 20 {
            return None;
        }
        visited.insert(current);

        let node = cfg.nodes.get(current)?;

        // 如果是 ConditionHeader，检查边类型
        if node.node_type == crate::analysis::enhanced_dataflow::EnhancedNodeType::ConditionHeader {
            // 查找从 current 到 original_node 路径上的第一条边类型
            if let Some(edge_type) =
                Self::find_edge_type_to(cfg, current, original_node, &mut HashSet::new())
            {
                let condition_expr = func_cpg
                    .node_meta
                    .get(&current)
                    .and_then(|m| m.condition.as_ref())
                    .map(|c| c.expr.clone());
                return Some(BranchContext {
                    condition_node_id: Some(current),
                    branch_side: Some(edge_type),
                    condition_expr,
                });
            }
        }

        // 继续向前搜索
        for pred_id in &node.predecessors {
            if let Some(ctx) =
                Self::find_condition_context(cfg, func_cpg, original_node, *pred_id, visited)
            {
                return Some(ctx);
            }
        }

        None
    }

    /// 从 start 节点查找到 target 的第一条边类型（BFS，深度限制 10）
    fn find_edge_type_to(
        cfg: &crate::analysis::enhanced_dataflow::EnhancedFlowGraph,
        start: usize,
        target: usize,
        visited: &mut HashSet<usize>,
    ) -> Option<EdgeType> {
        use std::collections::VecDeque;
        let mut queue: VecDeque<(usize, Option<EdgeType>, usize)> = VecDeque::new();
        queue.push_back((start, None, 0));

        while let Some((current, first_edge, depth)) = queue.pop_front() {
            if depth > 10 {
                continue;
            }
            if current == target {
                return first_edge;
            }
            if visited.contains(&current) {
                continue;
            }
            visited.insert(current);

            let node = cfg.nodes.get(current)?;
            for edge in &node.successors {
                let edge_type = first_edge.unwrap_or(edge.edge_type);
                queue.push_back((edge.target, Some(edge_type), depth + 1));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_cpg() {
        let cg = CallGraph::new();
        let cpg = CodePropertyGraph::new(cg);
        assert!(cpg.function_ids().is_empty());
        assert!(cpg.callers_of("nonexistent").is_empty());
    }
}
