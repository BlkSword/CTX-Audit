// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 数据流分析框架
//!
//! 提供通用的前向和后向数据流分析能力

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// 流图节点
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowNode {
    /// 节点 ID
    pub id: usize,

    /// 节点类型
    pub node_type: FlowNodeType,

    /// 代码内容
    pub code: String,

    /// 行号
    pub line: usize,

    /// 前驱节点
    pub predecessors: Vec<usize>,

    /// 后继节点
    pub successors: Vec<usize>,

    /// 定义的变量
    pub defs: Vec<String>,

    /// 使用的变量
    pub uses: Vec<String>,
}

/// 流图节点类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FlowNodeType {
    /// 入口节点
    Entry,
    /// 出口节点
    Exit,
    /// 赋值语句
    Assignment,
    /// 条件分支
    Condition,
    /// 函数调用
    Call,
    /// 返回语句
    Return,
    /// 循环头
    LoopHeader,
    /// 普通语句
    Statement,
}

/// 流图
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowGraph {
    /// 节点列表
    pub nodes: Vec<FlowNode>,

    /// 入口节点 ID
    pub entry: usize,

    /// 出口节点 ID
    pub exit: usize,

    /// 文件路径
    pub file_path: String,

    /// 函数/方法名
    pub function_name: String,
}

impl FlowGraph {
    /// 创建新的流图
    pub fn new(file_path: &str, function_name: &str) -> Self {
        let entry = FlowNode {
            id: 0,
            node_type: FlowNodeType::Entry,
            code: "ENTRY".to_string(),
            line: 0,
            predecessors: vec![],
            successors: vec![1],
            defs: vec![],
            uses: vec![],
        };

        let exit = FlowNode {
            id: 1,
            node_type: FlowNodeType::Exit,
            code: "EXIT".to_string(),
            line: 0,
            predecessors: vec![0],
            successors: vec![],
            defs: vec![],
            uses: vec![],
        };

        Self {
            nodes: vec![entry, exit],
            entry: 0,
            exit: 1,
            file_path: file_path.to_string(),
            function_name: function_name.to_string(),
        }
    }

    /// 添加节点
    pub fn add_node(&mut self, node: FlowNode) -> usize {
        let id = node.id;
        self.nodes.push(node);
        id
    }

    /// 添加边
    pub fn add_edge(&mut self, from: usize, to: usize) {
        if let Some(from_node) = self.nodes.get_mut(from) {
            if !from_node.successors.contains(&to) {
                from_node.successors.push(to);
            }
        }
        if let Some(to_node) = self.nodes.get_mut(to) {
            if !to_node.predecessors.contains(&from) {
                to_node.predecessors.push(from);
            }
        }
    }

    /// 获取节点
    pub fn get_node(&self, id: usize) -> Option<&FlowNode> {
        self.nodes.get(id)
    }

    /// 获取前驱节点
    pub fn predecessors(&self, id: usize) -> Vec<usize> {
        self.nodes
            .get(id)
            .map(|n| n.predecessors.clone())
            .unwrap_or_default()
    }

    /// 获取后继节点
    pub fn successors(&self, id: usize) -> Vec<usize> {
        self.nodes
            .get(id)
            .map(|n| n.successors.clone())
            .unwrap_or_default()
    }

    /// 从代码构建流图
    pub fn from_code(code: &str, file_path: &str, function_name: &str) -> Self {
        let mut graph = Self::new(file_path, function_name);
        let lines: Vec<&str> = code.lines().collect();

        let mut prev_node = 0usize;

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let (node_type, defs, uses) = Self::analyze_line(trimmed);

            let node = FlowNode {
                id: graph.nodes.len(),
                node_type,
                code: trimmed.to_string(),
                line: idx + 1,
                predecessors: vec![prev_node],
                successors: vec![],
                defs,
                uses,
            };

            let node_id = node.id;
            graph.add_node(node);
            graph.add_edge(prev_node, node_id);

            // 连接到出口节点
            graph.add_edge(node_id, graph.exit);

            prev_node = node_id;
        }

        // 如果没有添加任何节点，直接连接入口和出口
        if graph.nodes.len() == 2 {
            graph.add_edge(graph.entry, graph.exit);
        }

        graph
    }

    /// 分析单行代码
    fn analyze_line(line: &str) -> (FlowNodeType, Vec<String>, Vec<String>) {
        let mut defs = Vec::new();
        let mut uses = Vec::new();

        // 简单的分析逻辑
        let node_type =
            if line.contains("if ") || line.contains("else if ") || line.contains("switch") {
                FlowNodeType::Condition
            } else if line.contains("for ") || line.contains("while ") || line.contains("loop") {
                FlowNodeType::LoopHeader
            } else if line.contains("return ") {
                FlowNodeType::Return
            } else if line.contains("(") && line.contains(")") && !line.contains("=") {
                FlowNodeType::Call
            } else if line.contains("=") || line.contains(":=") {
                // 提取定义的变量
                if let Some(eq_pos) = line.find('=') {
                    let left = &line[..eq_pos];
                    for word in left.split_whitespace() {
                        let word =
                            word.trim_matches(&['*', '&', 'm', 'u', 't', 'l', 'e', ' '] as &[_]);
                        if !word.is_empty() && word.chars().next().unwrap().is_alphabetic() {
                            defs.push(word.to_string());
                        }
                    }
                }
                // 提取使用的变量
                let right = if let Some(eq_pos) = line.find('=') {
                    &line[eq_pos + 1..]
                } else {
                    line
                };
                for word in right.split(&[' ', '(', ')', '+', '-', '*', '/', ',', ';']) {
                    let word = word.trim();
                    if !word.is_empty()
                        && word.chars().next().unwrap().is_alphabetic()
                        && !defs.contains(&word.to_string())
                        && ![
                            "if", "else", "for", "while", "return", "let", "var", "const",
                        ]
                        .contains(&word)
                    {
                        uses.push(word.to_string());
                    }
                }
                FlowNodeType::Assignment
            } else {
                FlowNodeType::Statement
            };

        (node_type, defs, uses)
    }
}

/// 流事实 - 数据流分析中的抽象值
pub trait FlowFact: Clone + Eq + std::fmt::Debug {
    /// 获取顶部元素（最大元素）
    fn top() -> Self;

    /// 获取底部元素（最小元素）
    fn bottom() -> Self;

    /// 合并两个事实
    fn join(&self, other: &Self) -> Self;

    /// 是否小于等于另一个事实
    fn less_equal(&self, other: &Self) -> bool;
}

/// 可用变量分析的事实
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailableExpressionsFact {
    /// 可用表达式集合
    expressions: HashSet<String>,
}

impl AvailableExpressionsFact {
    /// 创建新的事实
    pub fn new() -> Self {
        Self {
            expressions: HashSet::new(),
        }
    }

    /// 从表达式集合创建
    pub fn from_set(expressions: HashSet<String>) -> Self {
        Self { expressions }
    }

    /// 添加表达式
    pub fn add(&mut self, expr: &str) {
        self.expressions.insert(expr.to_string());
    }

    /// 移除表达式
    pub fn remove(&mut self, expr: &str) {
        self.expressions.remove(expr);
    }

    /// 检查是否包含表达式
    pub fn contains(&self, expr: &str) -> bool {
        self.expressions.contains(expr)
    }

    /// 获取所有表达式
    pub fn expressions(&self) -> &HashSet<String> {
        &self.expressions
    }
}

impl FlowFact for AvailableExpressionsFact {
    fn top() -> Self {
        Self {
            expressions: HashSet::new(),
        }
    }

    fn bottom() -> Self {
        Self {
            expressions: HashSet::new(), // 实际上应该是全集
        }
    }

    fn join(&self, other: &Self) -> Self {
        Self {
            expressions: self
                .expressions
                .intersection(&other.expressions)
                .cloned()
                .collect(),
        }
    }

    fn less_equal(&self, other: &Self) -> bool {
        self.expressions.is_subset(&other.expressions)
    }
}

impl Default for AvailableExpressionsFact {
    fn default() -> Self {
        Self::new()
    }
}

/// 活跃变量分析的事实
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveVariablesFact {
    /// 活跃变量集合
    variables: HashSet<String>,
}

impl LiveVariablesFact {
    /// 创建新的事实
    pub fn new() -> Self {
        Self {
            variables: HashSet::new(),
        }
    }

    /// 从变量集合创建
    pub fn from_set(variables: HashSet<String>) -> Self {
        Self { variables }
    }

    /// 添加变量
    pub fn add(&mut self, var: &str) {
        self.variables.insert(var.to_string());
    }

    /// 移除变量
    pub fn remove(&mut self, var: &str) {
        self.variables.remove(var);
    }

    /// 检查变量是否活跃
    pub fn is_live(&self, var: &str) -> bool {
        self.variables.contains(var)
    }

    /// 获取所有活跃变量
    pub fn variables(&self) -> &HashSet<String> {
        &self.variables
    }
}

impl FlowFact for LiveVariablesFact {
    fn top() -> Self {
        Self {
            variables: HashSet::new(),
        }
    }

    fn bottom() -> Self {
        Self {
            variables: HashSet::new(),
        }
    }

    fn join(&self, other: &Self) -> Self {
        Self {
            variables: self.variables.union(&other.variables).cloned().collect(),
        }
    }

    fn less_equal(&self, other: &Self) -> bool {
        self.variables.is_subset(&other.variables)
    }
}

impl Default for LiveVariablesFact {
    fn default() -> Self {
        Self::new()
    }
}

/// 到达定值分析的事实
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachingDefinitionsFact {
    /// 定值集合 (variable, node_id)
    definitions: HashSet<(String, usize)>,
}

impl ReachingDefinitionsFact {
    /// 创建新的事实
    pub fn new() -> Self {
        Self {
            definitions: HashSet::new(),
        }
    }

    /// 添加定值
    pub fn add(&mut self, var: &str, node_id: usize) {
        self.definitions.insert((var.to_string(), node_id));
    }

    /// 移除变量的所有定值
    pub fn kill(&mut self, var: &str) {
        self.definitions.retain(|(v, _)| v != var);
    }

    /// 获取变量的定值
    pub fn get_definitions(&self, var: &str) -> Vec<usize> {
        self.definitions
            .iter()
            .filter(|(v, _)| v == var)
            .map(|(_, id)| *id)
            .collect()
    }
}

impl FlowFact for ReachingDefinitionsFact {
    fn top() -> Self {
        Self {
            definitions: HashSet::new(),
        }
    }

    fn bottom() -> Self {
        Self {
            definitions: HashSet::new(),
        }
    }

    fn join(&self, other: &Self) -> Self {
        Self {
            definitions: self
                .definitions
                .union(&other.definitions)
                .cloned()
                .collect(),
        }
    }

    fn less_equal(&self, other: &Self) -> bool {
        self.definitions.is_subset(&other.definitions)
    }
}

impl Default for ReachingDefinitionsFact {
    fn default() -> Self {
        Self::new()
    }
}

/// 数据流分析 Trait
pub trait DataFlowAnalysis {
    /// 事实类型
    type Fact: FlowFact;

    /// 方向：前向或后向
    fn direction(&self) -> AnalysisDirection;

    /// 传递函数
    fn transfer(&self, node: &FlowNode, fact: &Self::Fact) -> Self::Fact;

    /// 分析流图
    fn analyze(&self, graph: &FlowGraph) -> HashMap<usize, Self::Fact> {
        let mut in_facts: HashMap<usize, Self::Fact> = HashMap::new();
        let mut out_facts: HashMap<usize, Self::Fact> = HashMap::new();

        // 初始化
        for node in &graph.nodes {
            in_facts.insert(node.id, Self::Fact::top());
            out_facts.insert(node.id, Self::Fact::top());
        }

        // 设置入口/出口初始值
        match self.direction() {
            AnalysisDirection::Forward => {
                in_facts.insert(graph.entry, Self::Fact::top());
            }
            AnalysisDirection::Backward => {
                out_facts.insert(graph.exit, Self::Fact::top());
            }
        }

        // 迭代直到收敛
        let mut changed = true;
        let max_iterations = 100;
        let mut iterations = 0;

        while changed && iterations < max_iterations {
            changed = false;
            iterations += 1;

            let node_order: Vec<usize> = match self.direction() {
                AnalysisDirection::Forward => (0..graph.nodes.len()).collect(),
                AnalysisDirection::Backward => (0..graph.nodes.len()).rev().collect(),
            };

            for node_id in node_order {
                let node = &graph.nodes[node_id];

                // 计算入事实
                let new_in = match self.direction() {
                    AnalysisDirection::Forward => {
                        let preds = graph.predecessors(node_id);
                        if preds.is_empty() {
                            Self::Fact::top()
                        } else {
                            preds
                                .iter()
                                .filter_map(|p| out_facts.get(p))
                                .fold(Self::Fact::top(), |acc, f| acc.join(f))
                        }
                    }
                    AnalysisDirection::Backward => {
                        let succs = graph.successors(node_id);
                        if succs.is_empty() {
                            Self::Fact::top()
                        } else {
                            succs
                                .iter()
                                .filter_map(|s| in_facts.get(s))
                                .fold(Self::Fact::top(), |acc, f| acc.join(f))
                        }
                    }
                };

                // 应用传递函数
                let new_out = self.transfer(node, &new_in);

                // 检查是否变化
                let old_out = out_facts
                    .get(&node_id)
                    .cloned()
                    .unwrap_or_else(Self::Fact::top);
                if !new_out.less_equal(&old_out) || !old_out.less_equal(&new_out) {
                    changed = true;
                }

                in_facts.insert(node_id, new_in);
                out_facts.insert(node_id, new_out);
            }
        }

        match self.direction() {
            AnalysisDirection::Forward => out_facts,
            AnalysisDirection::Backward => in_facts,
        }
    }
}

/// 分析方向
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisDirection {
    /// 前向分析
    Forward,
    /// 后向分析
    Backward,
}

/// 活跃变量分析
pub struct LiveVariableAnalysis;

impl DataFlowAnalysis for LiveVariableAnalysis {
    type Fact = LiveVariablesFact;

    fn direction(&self) -> AnalysisDirection {
        AnalysisDirection::Backward
    }

    fn transfer(&self, node: &FlowNode, fact: &Self::Fact) -> Self::Fact {
        let mut result = fact.clone();

        // kill: 移除在此节点定义的变量
        for def in &node.defs {
            result.remove(def);
        }

        // gen: 添加在此节点使用的变量
        for use_var in &node.uses {
            result.add(use_var);
        }

        result
    }
}

/// 到达定值分析
pub struct ReachingDefinitionsAnalysis;

impl DataFlowAnalysis for ReachingDefinitionsAnalysis {
    type Fact = ReachingDefinitionsFact;

    fn direction(&self) -> AnalysisDirection {
        AnalysisDirection::Forward
    }

    fn transfer(&self, node: &FlowNode, fact: &Self::Fact) -> Self::Fact {
        let mut result = fact.clone();

        // kill: 移除被重新定义的变量
        for def in &node.defs {
            result.kill(def);
        }

        // gen: 添加新的定值
        for def in &node.defs {
            result.add(def, node.id);
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_graph_creation() {
        let graph = FlowGraph::new("test.py", "main");
        assert_eq!(graph.nodes.len(), 2);
        assert_eq!(graph.entry, 0);
        assert_eq!(graph.exit, 1);
    }

    #[test]
    fn test_flow_graph_from_code() {
        let code = "x = 1\ny = x + 2\nreturn y";
        let graph = FlowGraph::from_code(code, "test.py", "main");
        assert!(graph.nodes.len() > 2);
    }

    #[test]
    fn test_available_expressions_fact() {
        let mut fact = AvailableExpressionsFact::new();
        fact.add("x + y");
        assert!(fact.contains("x + y"));

        let other = AvailableExpressionsFact::new();
        let joined = fact.join(&other);
        assert!(!joined.contains("x + y")); // 交集为空
    }

    #[test]
    fn test_live_variables_fact() {
        let mut fact = LiveVariablesFact::new();
        fact.add("x");
        assert!(fact.is_live("x"));

        fact.remove("x");
        assert!(!fact.is_live("x"));
    }

    #[test]
    fn test_reaching_definitions_fact() {
        let mut fact = ReachingDefinitionsFact::new();
        fact.add("x", 1);
        fact.add("x", 2);

        let defs = fact.get_definitions("x");
        assert_eq!(defs.len(), 2);

        fact.kill("x");
        assert!(fact.get_definitions("x").is_empty());
    }

    #[test]
    fn test_live_variable_analysis() {
        let code = "x = 1\ny = x\nreturn y";
        let graph = FlowGraph::from_code(code, "test.py", "main");
        let analysis = LiveVariableAnalysis;
        let results = analysis.analyze(&graph);

        // 应该有分析结果
        assert!(!results.is_empty());
    }
}
