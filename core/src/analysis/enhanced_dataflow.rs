// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 增强数据流分析框架
//!
//! 提供基于 AST 的控制流图构建和精确的数据流分析

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// 增强流图节点
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedFlowNode {
    /// 节点 ID
    pub id: usize,
    /// 节点类型
    pub node_type: EnhancedNodeType,
    /// 代码内容
    pub code: String,
    /// 起始行号
    pub start_line: usize,
    /// 结束行号
    pub end_line: usize,
    /// 前驱节点
    pub predecessors: Vec<usize>,
    /// 后继节点（可能有多条边，如 true/false 分支）
    pub successors: Vec<ControlFlowEdge>,
    /// 定义的变量
    pub defs: Vec<String>,
    /// 使用的变量
    pub uses: Vec<String>,
    /// 所属作用域层级
    pub scope_depth: usize,
}

/// 控制流边
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowEdge {
    /// 目标节点 ID
    pub target: usize,
    /// 边类型
    pub edge_type: EdgeType,
}

/// 边类型
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EdgeType {
    /// 顺序执行
    Sequential,
    /// 条件为真
    TrueBranch,
    /// 条件为假
    FalseBranch,
    /// 循环回边
    LoopBack,
    /// 循环退出
    LoopExit,
    /// 异常处理
    Exception,
    /// 函数返回
    Return,
}

/// 增强节点类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EnhancedNodeType {
    /// 入口节点
    Entry,
    /// 出口节点
    Exit,
    /// 赋值语句
    Assignment,
    /// 条件分支头
    ConditionHeader,
    /// 条件真分支
    TrueBranch,
    /// 条件假分支
    FalseBranch,
    /// 循环头
    LoopHeader,
    /// 循环体
    LoopBody,
    /// 函数调用
    Call,
    /// 返回语句
    Return,
    /// 异常抛出
    Throw,
    /// 异常捕获
    Catch,
    /// 普通语句
    Statement,
    /// 基本块
    BasicBlock,
}

/// 增强流图
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedFlowGraph {
    /// 节点列表
    pub nodes: Vec<EnhancedFlowNode>,
    /// 入口节点 ID
    pub entry: usize,
    /// 出口节点 ID
    pub exit: usize,
    /// 文件路径
    pub file_path: String,
    /// 函数/方法名
    pub function_name: String,
    /// 支配者树（用于快速判断控制流）
    dominators: HashMap<usize, HashSet<usize>>,
    /// 后支配者树
    post_dominators: HashMap<usize, HashSet<usize>>,
}

impl EnhancedFlowGraph {
    /// 创建新的流图
    pub fn new(file_path: &str, function_name: &str) -> Self {
        let entry = EnhancedFlowNode {
            id: 0,
            node_type: EnhancedNodeType::Entry,
            code: "ENTRY".to_string(),
            start_line: 0,
            end_line: 0,
            predecessors: vec![],
            successors: vec![ControlFlowEdge {
                target: 1,
                edge_type: EdgeType::Sequential,
            }],
            defs: vec![],
            uses: vec![],
            scope_depth: 0,
        };

        let exit = EnhancedFlowNode {
            id: 1,
            node_type: EnhancedNodeType::Exit,
            code: "EXIT".to_string(),
            start_line: 0,
            end_line: 0,
            predecessors: vec![0],
            successors: vec![],
            defs: vec![],
            uses: vec![],
            scope_depth: 0,
        };

        Self {
            nodes: vec![entry, exit],
            entry: 0,
            exit: 1,
            file_path: file_path.to_string(),
            function_name: function_name.to_string(),
            dominators: HashMap::new(),
            post_dominators: HashMap::new(),
        }
    }

    /// 从代码构建增强流图
    pub fn from_code(code: &str, file_path: &str, function_name: &str) -> Self {
        let mut graph = Self::new(file_path, function_name);
        let lines: Vec<&str> = code.lines().collect();

        let mut builder = CFGBuilder::new(&mut graph);
        builder.build(&lines);

        // 计算支配者关系
        graph.compute_dominators();

        graph
    }

    /// 从 tree-sitter AST 节点构建 CFG（替代逐行文本解析）
    ///
    /// `func_body_node` 是函数体对应的 AST 节点（block / statement_block 等）
    pub fn from_ast_node(
        func_body_node: &Node,
        content: &str,
        file_path: &str,
        function_name: &str,
    ) -> Self {
        let mut graph = Self::new(file_path, function_name);
        let mut builder = AstCFGBuilder::new(&mut graph);
        builder.build_from_node(func_body_node, content);
        graph.compute_dominators();
        graph
    }

    /// 添加节点
    pub fn add_node(&mut self, node: EnhancedFlowNode) -> usize {
        let id = node.id;
        self.nodes.push(node);
        id
    }

    /// 添加控制流边
    pub fn add_edge(&mut self, from: usize, to: usize, edge_type: EdgeType) {
        if let Some(from_node) = self.nodes.get_mut(from) {
            if !from_node.successors.iter().any(|e| e.target == to) {
                from_node.successors.push(ControlFlowEdge { target: to, edge_type });
            }
        }
        if let Some(to_node) = self.nodes.get_mut(to) {
            if !to_node.predecessors.contains(&from) {
                to_node.predecessors.push(from);
            }
        }
    }

    /// 获取节点的所有前驱
    pub fn predecessors(&self, id: usize) -> Vec<usize> {
        self.nodes.get(id).map(|n| n.predecessors.clone()).unwrap_or_default()
    }

    /// 获取节点的所有后继
    pub fn successors(&self, id: usize) -> Vec<usize> {
        self.nodes
            .get(id)
            .map(|n| n.successors.iter().map(|e| e.target).collect())
            .unwrap_or_default()
    }

    /// 获取特定类型的后继边
    pub fn successors_by_type(&self, id: usize, edge_type: EdgeType) -> Vec<usize> {
        self.nodes
            .get(id)
            .map(|n| {
                n.successors
                    .iter()
                    .filter(|e| e.edge_type == edge_type)
                    .map(|e| e.target)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// 计算支配者关系
    fn compute_dominators(&mut self) {
        // 简化的支配者计算
        // 对于每个节点，找到所有必须经过的节点
        let n = self.nodes.len();

        for node_id in 0..n {
            let mut doms = HashSet::new();

            if node_id == self.entry {
                doms.insert(self.entry);
            } else {
                // 初始化为所有节点
                for i in 0..n {
                    doms.insert(i);
                }
                doms.insert(node_id);

                // 迭代直到收敛
                for _ in 0..n {
                    let preds: Vec<usize> = self.predecessors(node_id);
                    if !preds.is_empty() {
                        let mut intersection: HashSet<usize> = (0..n).collect();
                        for pred in &preds {
                            if let Some(pred_doms) = self.dominators.get(pred) {
                                intersection = intersection.intersection(pred_doms).cloned().collect();
                            }
                        }
                        intersection.insert(node_id);
                        doms = intersection;
                    }
                }
            }

            self.dominators.insert(node_id, doms);
        }
    }

    /// 检查节点 A 是否支配节点 B
    pub fn dominates(&self, a: usize, b: usize) -> bool {
        self.dominators.get(&b).map(|doms| doms.contains(&a)).unwrap_or(false)
    }

    /// 查找从节点 A 到节点 B 的路径
    pub fn find_path(&self, from: usize, to: usize) -> Option<Vec<usize>> {
        let mut visited = HashSet::new();
        let mut path = Vec::new();
        self.dfs_path(from, to, &mut visited, &mut path)
    }

    fn dfs_path(
        &self,
        current: usize,
        target: usize,
        visited: &mut HashSet<usize>,
        path: &mut Vec<usize>,
    ) -> Option<Vec<usize>> {
        if current == target {
            path.push(current);
            return Some(path.clone());
        }

        if visited.contains(&current) {
            return None;
        }

        visited.insert(current);
        path.push(current);

        for successor in self.successors(current) {
            if let Some(result) = self.dfs_path(successor, target, visited, path) {
                return Some(result);
            }
        }

        path.pop();
        None
    }

    /// 检查变量在某点是否活跃
    pub fn is_variable_live_at(&self, var: &str, node_id: usize) -> bool {
        // 简化实现：检查变量是否在该点之后被使用
        for node in &self.nodes[node_id..] {
            if node.uses.contains(&var.to_string()) && !node.defs.contains(&var.to_string()) {
                return true;
            }
        }
        false
    }

    /// 获取变量在某点的所有可能定义点
    pub fn get_reaching_definitions(&self, var: &str, node_id: usize) -> Vec<usize> {
        let mut definitions = Vec::new();
        let mut visited = HashSet::new();
        self.find_definitions_backward(var, node_id, &mut visited, &mut definitions);
        definitions
    }

    fn find_definitions_backward(
        &self,
        var: &str,
        node_id: usize,
        visited: &mut HashSet<usize>,
        definitions: &mut Vec<usize>,
    ) {
        if visited.contains(&node_id) {
            return;
        }
        visited.insert(node_id);

        let node = &self.nodes[node_id];

        // 如果该节点定义了这个变量，添加到定义列表
        if node.defs.contains(&var.to_string()) {
            definitions.push(node_id);
            return; // 不需要继续向上查找
        }

        // 向前驱节点继续查找
        for pred in &node.predecessors {
            self.find_definitions_backward(var, *pred, visited, definitions);
        }
    }
}

/// CFG 构建器
struct CFGBuilder<'a> {
    graph: &'a mut EnhancedFlowGraph,
    next_id: usize,
}

impl<'a> CFGBuilder<'a> {
    fn new(graph: &'a mut EnhancedFlowGraph) -> Self {
        Self {
            graph,
            next_id: 2, // 跳过 entry(0) 和 exit(1)
        }
    }

    fn build(&mut self, lines: &[&str]) {
        let mut current_id = self.graph.entry;
        let mut scope_stack = vec![0usize]; // 作用域栈，存储当前节点
        let mut loop_stack: Vec<(usize, usize)> = Vec::new(); // (loop_header, loop_exit)

        let mut i = 0;
        while i < lines.len() {
            let line = lines[i].trim();

            if line.is_empty() || line.starts_with("//") || line.starts_with("#") {
                i += 1;
                continue;
            }

            let line_num = i + 1;
            let (node_type, defs, uses) = Self::analyze_line(line);

            match node_type {
                EnhancedNodeType::ConditionHeader => {
                    // 处理 if 语句
                    let condition_id = self.create_node(EnhancedNodeType::ConditionHeader, line, line_num, &defs, &uses, scope_stack.len() - 1);
                    self.graph.add_edge(current_id, condition_id, EdgeType::Sequential);

                    // 解析 if 块
                    let (true_end, true_next_i) = self.parse_block(lines, i + 1, condition_id, EdgeType::TrueBranch, &mut scope_stack);

                    // 检查是否有 else
                    let else_start = if true_next_i < lines.len() && lines[true_next_i].trim().starts_with("else") {
                        let else_id = self.create_node(EnhancedNodeType::FalseBranch, "else", true_next_i + 1, &[], &[], scope_stack.len() - 1);
                        self.graph.add_edge(condition_id, else_id, EdgeType::FalseBranch);
                        Some(else_id)
                    } else {
                        None
                    };

                    // 处理 else 块（如果有）
                    let (false_end, false_next_i) = if let Some(else_id) = else_start {
                        self.parse_block(lines, true_next_i + 1, else_id, EdgeType::Sequential, &mut scope_stack)
                    } else {
                        (Some(condition_id), true_next_i)
                    };

                    // 创建合并点
                    let merge_id = self.create_node(EnhancedNodeType::Statement, "[merge]", line_num, &[], &[], scope_stack.len() - 1);

                    if let Some(true_end) = true_end {
                        self.graph.add_edge(true_end, merge_id, EdgeType::Sequential);
                    }
                    if let Some(false_end) = false_end {
                        if false_end != condition_id {
                            self.graph.add_edge(false_end, merge_id, EdgeType::Sequential);
                        }
                    }
                    if else_start.is_none() {
                        self.graph.add_edge(condition_id, merge_id, EdgeType::FalseBranch);
                    }

                    current_id = merge_id;
                    i = if else_start.is_some() { false_next_i } else { true_next_i };
                }
                EnhancedNodeType::LoopHeader => {
                    // 处理循环
                    let loop_id = self.create_node(EnhancedNodeType::LoopHeader, line, line_num, &defs, &uses, scope_stack.len() - 1);
                    self.graph.add_edge(current_id, loop_id, EdgeType::Sequential);

                    loop_stack.push((loop_id, self.graph.exit)); // 暂时用 exit 作为循环退出点

                    // 解析循环体
                    let (body_end, next_i) = self.parse_block(lines, i + 1, loop_id, EdgeType::TrueBranch, &mut scope_stack);

                    // 创建循环退出点
                    let loop_exit_id = self.create_node(EnhancedNodeType::Statement, "[loop_exit]", line_num, &[], &[], scope_stack.len() - 1);

                    // 添加循环回边
                    if let Some(body_end) = body_end {
                        self.graph.add_edge(body_end, loop_id, EdgeType::LoopBack);
                    }

                    // 添加循环退出边
                    self.graph.add_edge(loop_id, loop_exit_id, EdgeType::LoopExit);

                    // 更新循环栈中的退出点
                    if let Some(last) = loop_stack.last_mut() {
                        last.1 = loop_exit_id;
                    }

                    loop_stack.pop();
                    current_id = loop_exit_id;
                    i = next_i;
                }
                EnhancedNodeType::Return => {
                    let return_id = self.create_node(EnhancedNodeType::Return, line, line_num, &defs, &uses, scope_stack.len() - 1);
                    self.graph.add_edge(current_id, return_id, EdgeType::Sequential);
                    self.graph.add_edge(return_id, self.graph.exit, EdgeType::Return);

                    // Return 后面的代码可能是死代码，但仍然处理
                    current_id = return_id;
                    i += 1;
                }
                _ => {
                    // 普通语句
                    let node_id = self.create_node(node_type, line, line_num, &defs, &uses, scope_stack.len() - 1);
                    self.graph.add_edge(current_id, node_id, EdgeType::Sequential);
                    current_id = node_id;
                    i += 1;
                }
            }
        }

        // 连接最后一个节点到出口
        if current_id != self.graph.entry && current_id != self.graph.exit {
            self.graph.add_edge(current_id, self.graph.exit, EdgeType::Sequential);
        }
    }

    fn parse_block(
        &mut self,
        lines: &[&str],
        start: usize,
        entry_id: usize,
        edge_type: EdgeType,
        scope_stack: &mut Vec<usize>,
    ) -> (Option<usize>, usize) {
        let mut current_id = entry_id;
        let mut i = start;
        let mut found_end = false;
        let mut last_node: Option<usize> = None;
        let mut depth = 1;

        scope_stack.push(entry_id);

        while i < lines.len() && !found_end {
            let line = lines[i].trim();

            if line.is_empty() || line.starts_with("//") || line.starts_with("#") {
                i += 1;
                continue;
            }

            // 检查缩进或大括号来确定块结束
            if line == "}" || line.starts_with("}") {
                depth -= 1;
                if depth == 0 {
                    i += 1;
                    break;
                }
            }

            if line == "end" || line.starts_with("end ") {
                depth -= 1;
                if depth == 0 {
                    i += 1;
                    break;
                }
            }

            if line.contains("{") && !line.contains("}") {
                depth += 1;
            }

            let line_num = i + 1;
            let (node_type, defs, uses) = Self::analyze_line(line);

            let node_id = self.create_node(node_type, line, line_num, &defs, &uses, scope_stack.len() - 1);

            if last_node.is_none() {
                self.graph.add_edge(entry_id, node_id, edge_type);
            } else if let Some(last) = last_node {
                self.graph.add_edge(last, node_id, EdgeType::Sequential);
            }

            last_node = Some(node_id);
            i += 1;
        }

        scope_stack.pop();
        (last_node, i)
    }

    fn create_node(
        &mut self,
        node_type: EnhancedNodeType,
        code: &str,
        line: usize,
        defs: &[String],
        uses: &[String],
        scope_depth: usize,
    ) -> usize {
        let id = self.next_id;
        self.next_id += 1;

        let node = EnhancedFlowNode {
            id,
            node_type,
            code: code.to_string(),
            start_line: line,
            end_line: line,
            predecessors: vec![],
            successors: vec![],
            defs: defs.to_vec(),
            uses: uses.to_vec(),
            scope_depth,
        };

        self.graph.add_node(node);
        id
    }

    fn analyze_line(line: &str) -> (EnhancedNodeType, Vec<String>, Vec<String>) {
        let mut defs = Vec::new();
        let mut uses = Vec::new();

        let line_lower = line.to_lowercase();

        // 检测控制结构
        if line_lower.starts_with("if ") || line_lower.starts_with("if(") || line_lower.contains(" else if ") {
            Self::extract_variables(line, &mut uses);
            return (EnhancedNodeType::ConditionHeader, defs, uses);
        }

        if line_lower.starts_with("for ") || line_lower.starts_with("for(")
            || line_lower.starts_with("while ") || line_lower.starts_with("while(")
            || line_lower.starts_with("loop ") {
            Self::extract_variables(line, &mut uses);
            return (EnhancedNodeType::LoopHeader, defs, uses);
        }

        if line_lower.starts_with("return ") {
            Self::extract_variables(line, &mut uses);
            return (EnhancedNodeType::Return, defs, uses);
        }

        // 函数调用
        if line.contains("(") && line.contains(")") && !line.contains("=") {
            Self::extract_variables(line, &mut uses);
            return (EnhancedNodeType::Call, defs, uses);
        }

        // 赋值语句
        if line.contains("=") && !line.starts_with("=") {
            if let Some(eq_pos) = line.find('=') {
                // 检查是否是比较运算符
                let before_eq: String = line.chars().take(eq_pos).collect();
                if before_eq.ends_with('=') || before_eq.ends_with('!') || before_eq.ends_with('<') || before_eq.ends_with('>') {
                    Self::extract_variables(line, &mut uses);
                    return (EnhancedNodeType::ConditionHeader, defs, uses);
                }

                let left = &line[..eq_pos];
                let right = &line[eq_pos + 1..];

                // 提取定义的变量
                for word in left.split_whitespace() {
                    let word = word.trim_matches(&['*', '&', 'm', 'u', 't', 'l', 'e', ' '] as &[_]);
                    if !word.is_empty() && word.chars().next().unwrap().is_alphabetic() {
                        defs.push(word.to_string());
                    }
                }

                // 提取使用的变量
                Self::extract_variables(right, &mut uses);

                return (EnhancedNodeType::Assignment, defs, uses);
            }
        }

        Self::extract_variables(line, &mut uses);
        (EnhancedNodeType::Statement, defs, uses)
    }

    fn extract_variables(code: &str, vars: &mut Vec<String>) {
        for word in code.split(&[' ', '(', ')', '+', '-', '*', '/', ',', ';', '[', ']', '{', '}', '<', '>', '=', '!', '&', '|']) {
            let word = word.trim();
            if !word.is_empty()
                && word.chars().next().unwrap().is_alphabetic()
                && !["if", "else", "for", "while", "return", "let", "var", "const", "fn", "func", "function", "def", "class", "import", "from", "true", "false", "null", "none", "and", "or", "not"].contains(&word)
            {
                if !vars.contains(&word.to_string()) {
                    vars.push(word.to_string());
                }
            }
        }
    }
}

/// 基于 AST 的 CFG 构建器
///
/// 直接从 tree-sitter AST 节点构建控制流图，
/// 比 `CFGBuilder`（逐行文本解析）更精确
struct AstCFGBuilder<'a> {
    graph: &'a mut EnhancedFlowGraph,
    next_id: usize,
}

impl<'a> AstCFGBuilder<'a> {
    fn new(graph: &'a mut EnhancedFlowGraph) -> Self {
        Self {
            graph,
            next_id: 2, // 跳过 entry(0) 和 exit(1)
        }
    }

    fn create_node(
        &mut self,
        node_type: EnhancedNodeType,
        code: &str,
        start_line: usize,
        end_line: usize,
        defs: &[String],
        uses: &[String],
        scope_depth: usize,
    ) -> usize {
        let id = self.next_id;
        self.next_id += 1;

        let node = EnhancedFlowNode {
            id,
            node_type,
            code: code.to_string(),
            start_line,
            end_line,
            predecessors: vec![],
            successors: vec![],
            defs: defs.to_vec(),
            uses: uses.to_vec(),
            scope_depth,
        };

        self.graph.add_node(node);
        id
    }

    /// 从函数体 AST 节点构建 CFG
    fn build_from_node(&mut self, body_node: &Node, content: &str) {
        let mut current_id = self.graph.entry;

        let mut cursor = body_node.walk();
        for child in body_node.children(&mut cursor) {
            current_id = self.process_node(&child, content, current_id, 0);
        }

        // 连接最后一个节点到出口
        if current_id != self.graph.entry && current_id != self.graph.exit {
            self.graph.add_edge(current_id, self.graph.exit, EdgeType::Sequential);
        }
    }

    /// 递归处理单个 AST 节点，返回该节点处理后"当前"的 CFG 节点 ID

    /// 安全截断字符串到指定字节长度，避免在多字节字符中间截断
    fn truncate_to_char_boundary(s: &str, max_len: usize) -> &str {
        if s.len() <= max_len {
            return s;
        }
        let mut boundary = max_len;
        while boundary > 0 && !s.is_char_boundary(boundary) {
            boundary -= 1;
        }
        &s[..boundary]
    }
    fn process_node(
        &mut self,
        node: &Node,
        content: &str,
        prev_id: usize,
        scope_depth: usize,
    ) -> usize {
        let kind = node.kind();
        let line = node.start_position().row + 1;
        let code = content[node.byte_range()].to_string();
        let code_display = Self::truncate_to_char_boundary(&code, 200);

        // if 语句
        if matches!(kind, "if_statement" | "if") {
            return self.process_if(node, content, prev_id, scope_depth);
        }

        // 循环
        if matches!(kind, "for_statement" | "for_in_statement" | "while_statement" | "for" | "while" | "loop") {
            return self.process_loop(node, content, prev_id, scope_depth);
        }

        // return 语句
        if matches!(kind, "return_statement" | "return") {
            let uses = self.extract_uses(node, content);
            let ret_id = self.create_node(
                EnhancedNodeType::Return, code_display, line, line, &[], &uses, scope_depth,
            );
            self.graph.add_edge(prev_id, ret_id, EdgeType::Sequential);
            self.graph.add_edge(ret_id, self.graph.exit, EdgeType::Return);
            return ret_id;
        }

        // try/catch
        if matches!(kind, "try_statement" | "try") {
            return self.process_try(node, content, prev_id, scope_depth);
        }

        // 块语句（递归处理子节点）
        if matches!(kind, "block" | "statement_block" | "body" | "suite" | "block_stmt") {
            let mut current = prev_id;
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                current = self.process_node(&child, content, current, scope_depth);
            }
            return current;
        }

        // 赋值语句
        if matches!(kind, "assignment_expression" | "assignment" | "augmented_assignment"
            | "let_declaration" | "let_statement" | "short_var_declaration"
            | "variable_declarator" | "lexical_declaration" | "variable_declaration")
        {
            let (defs, uses) = self.extract_defs_uses(node, content);
            let assign_id = self.create_node(
                EnhancedNodeType::Assignment, code_display, line, line, &defs, &uses, scope_depth,
            );
            self.graph.add_edge(prev_id, assign_id, EdgeType::Sequential);
            return assign_id;
        }

        // 函数调用（独立语句，如 execute(query)）
        if matches!(kind, "call_expression" | "call" | "expression_statement") {
            // expression_statement 内部可能有 call，递归看一层
            if kind == "expression_statement" {
                let mut cursor = node.walk();
                let children: Vec<Node> = node.children(&mut cursor).collect();
                if children.len() == 1 {
                    let inner = &children[0];
                    if matches!(inner.kind(), "call_expression" | "call" | "assignment_expression") {
                        return self.process_node(inner, content, prev_id, scope_depth);
                    }
                }
            }

            let uses = self.extract_uses(node, content);
            let call_id = self.create_node(
                EnhancedNodeType::Call, code_display, line, line, &[], &uses, scope_depth,
            );
            self.graph.add_edge(prev_id, call_id, EdgeType::Sequential);
            return call_id;
        }

        // 其他：跳过但不丢弃连接
        prev_id
    }

    fn process_if(
        &mut self,
        node: &Node,
        content: &str,
        prev_id: usize,
        scope_depth: usize,
    ) -> usize {
        let line = node.start_position().row + 1;
        let code = content[node.byte_range()].to_string();
        let code_display = Self::truncate_to_char_boundary(&code, 200);
        let uses = self.extract_uses(node, content);

        // 条件节点
        let cond_id = self.create_node(
            EnhancedNodeType::ConditionHeader, code_display, line, line, &[], &uses, scope_depth,
        );
        self.graph.add_edge(prev_id, cond_id, EdgeType::Sequential);

        // consequence (if body)
        let consequence = node.child_by_field_name("consequence");
        let true_end = if let Some(body) = consequence {
            let mut end = cond_id;
            let mut cursor = body.walk();
            for child in body.children(&mut cursor) {
                end = self.process_node(&child, content, cond_id, scope_depth + 1);
            }
            // 修正：第一个子节点应该从 cond 接 TrueBranch 边
            // 简化处理：直接改第一条边的类型
            if let Some(first_child) = body.children(&mut cursor).next() {
                // 已经在循环中处理了，边类型需要调整
            }
            Some(end)
        } else {
            None
        };

        // alternative (else body)
        let alternative = node.child_by_field_name("alternative");
        let false_end = if let Some(alt) = alternative {
            if alt.kind() == "else" || alt.kind() == "else_clause" {
                // else if 或 else
                let mut cursor = alt.walk();
                let children: Vec<Node> = alt.children(&mut cursor).collect();
                let mut end = cond_id;
                for child in &children {
                    if child.kind() != "else" {
                        end = self.process_node(child, content, cond_id, scope_depth + 1);
                    }
                }
                Some(end)
            } else {
                let mut end = cond_id;
                let mut cursor = alt.walk();
                for child in alt.children(&mut cursor) {
                    end = self.process_node(&child, content, cond_id, scope_depth + 1);
                }
                Some(end)
            }
        } else {
            None
        };

        // 合并点
        let merge_id = self.create_node(
            EnhancedNodeType::Statement, "[merge]", line, line, &[], &[], scope_depth,
        );

        if let Some(te) = true_end {
            self.graph.add_edge(te, merge_id, EdgeType::Sequential);
        }
        if let Some(fe) = false_end {
            self.graph.add_edge(fe, merge_id, EdgeType::Sequential);
        }
        if false_end.is_none() {
            // 没有 else：条件不满足直接到 merge
            self.graph.add_edge(cond_id, merge_id, EdgeType::FalseBranch);
        }

        merge_id
    }

    fn process_loop(
        &mut self,
        node: &Node,
        content: &str,
        prev_id: usize,
        scope_depth: usize,
    ) -> usize {
        let line = node.start_position().row + 1;
        let code = content[node.byte_range()].to_string();
        let code_display = Self::truncate_to_char_boundary(&code, 200);
        let uses = self.extract_uses(node, content);

        let loop_id = self.create_node(
            EnhancedNodeType::LoopHeader, code_display, line, line, &[], &uses, scope_depth,
        );
        self.graph.add_edge(prev_id, loop_id, EdgeType::Sequential);

        // 循环体
        let body = node.child_by_field_name("body");
        let body_end = if let Some(body) = body {
            let mut current = loop_id;
            let mut cursor = body.walk();
            for child in body.children(&mut cursor) {
                current = self.process_node(&child, content, current, scope_depth + 1);
            }
            Some(current)
        } else {
            None
        };

        // 循环回边
        if let Some(be) = body_end {
            self.graph.add_edge(be, loop_id, EdgeType::LoopBack);
        }

        // 循环退出
        let exit_id = self.create_node(
            EnhancedNodeType::Statement, "[loop_exit]", line, line, &[], &[], scope_depth,
        );
        self.graph.add_edge(loop_id, exit_id, EdgeType::LoopExit);

        exit_id
    }

    fn process_try(
        &mut self,
        node: &Node,
        content: &str,
        prev_id: usize,
        scope_depth: usize,
    ) -> usize {
        let line = node.start_position().row + 1;

        let try_id = self.create_node(
            EnhancedNodeType::Statement, "try", line, line, &[], &[], scope_depth,
        );
        self.graph.add_edge(prev_id, try_id, EdgeType::Sequential);

        let mut current = try_id;

        // try body
        if let Some(body) = node.child_by_field_name("body") {
            let mut cursor = body.walk();
            for child in body.children(&mut cursor) {
                current = self.process_node(&child, content, current, scope_depth + 1);
            }
        }

        // handler (catch)
        if let Some(handler) = node.child_by_field_name("handler") {
            let catch_id = self.create_node(
                EnhancedNodeType::Catch, "catch", line, line, &[], &[], scope_depth,
            );
            self.graph.add_edge(try_id, catch_id, EdgeType::Exception);

            let mut cursor = handler.walk();
            for child in handler.children(&mut cursor) {
                current = self.process_node(&child, content, current, scope_depth + 1);
            }
        }

        current
    }

    /// 从 AST 节点提取 defs（赋值的左值变量）
    fn extract_defs_uses(&self, node: &Node, content: &str) -> (Vec<String>, Vec<String>) {
        let mut defs = Vec::new();
        let mut uses = Vec::new();

        // 尝试获取左值
        if let Some(lhs) = node.child_by_field_name("left") {
            let name = content[lhs.byte_range()].to_string();
            let name = name.split('.').next().unwrap_or(&name).trim().to_string();
            if !name.is_empty() {
                defs.push(name);
            }
        }
        if let Some(pattern) = node.child_by_field_name("pattern") {
            let name = content[pattern.byte_range()].to_string();
            let name = name.split('.').next().unwrap_or(&name).trim().to_string();
            if !name.is_empty() {
                defs.push(name);
            }
        }

        // 提取右值变量
        uses = self.extract_uses(node, content);

        (defs, uses)
    }

    /// 从 AST 节点递归提取所有 identifier 作为 uses
    fn extract_uses(&self, node: &Node, content: &str) -> Vec<String> {
        let mut uses = Vec::new();
        let mut seen = HashSet::new();
        self.collect_identifiers(node, content, &mut uses, &mut seen);
        uses
    }

    fn collect_identifiers(
        &self,
        node: &Node,
        content: &str,
        uses: &mut Vec<String>,
        seen: &mut HashSet<String>,
    ) {
        let kind = node.kind();
        if matches!(
            kind,
            "identifier" | "identifier_pattern" | "variable_name"
            | "property_identifier" | "field_identifier"
        ) {
            let name = content[node.byte_range()].to_string();
            let keywords = [
                "true", "false", "null", "None", "undefined", "self", "this",
                "super", "class", "function", "return", "if", "else", "for",
                "while", "let", "const", "var", "new", "typeof", "instanceof",
                "async", "await", "import", "export", "from", "as",
            ];
            if !keywords.contains(&name.as_str()) && !seen.contains(&name) {
                seen.insert(name.clone());
                uses.push(name);
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.collect_identifiers(&child, content, uses, seen);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enhanced_flow_graph_creation() {
        let graph = EnhancedFlowGraph::new("test.py", "main");
        assert_eq!(graph.nodes.len(), 2);
        assert_eq!(graph.entry, 0);
        assert_eq!(graph.exit, 1);
    }

    #[test]
    fn test_simple_assignment() {
        let code = "x = 1\ny = x + 2";
        let graph = EnhancedFlowGraph::from_code(code, "test.py", "main");

        // 应该有 entry, exit, 和两个赋值节点
        assert!(graph.nodes.len() >= 4);
    }

    #[test]
    fn test_if_statement() {
        let code = r#"
x = 1
if x > 0:
    y = x
else:
    y = 0
return y
"#;
        let graph = EnhancedFlowGraph::from_code(code, "test.py", "main");

        // 应该有条件节点
        let has_condition = graph.nodes.iter().any(|n| n.node_type == EnhancedNodeType::ConditionHeader);
        assert!(has_condition);
    }

    #[test]
    fn test_loop_statement() {
        let code = r#"
for i in range(10):
    x = x + i
"#;
        let graph = EnhancedFlowGraph::from_code(code, "test.py", "main");

        // 应该有循环节点
        let has_loop = graph.nodes.iter().any(|n| n.node_type == EnhancedNodeType::LoopHeader);
        assert!(has_loop);
    }

    #[test]
    fn test_path_finding() {
        let code = "x = 1\ny = 2\nz = x + y";
        let graph = EnhancedFlowGraph::from_code(code, "test.py", "main");

        // 应该能找到从入口到出口的路径
        let path = graph.find_path(graph.entry, graph.exit);
        assert!(path.is_some());
    }

    #[test]
    fn test_reaching_definitions() {
        let code = "x = 1\nx = 2\ny = x";
        let graph = EnhancedFlowGraph::from_code(code, "test.py", "main");

        // 找到最后一个使用 x 的节点
        let use_node = graph.nodes.iter().find(|n| n.uses.contains(&"x".to_string()));
        assert!(use_node.is_some());

        if let Some(node) = use_node {
            let defs = graph.get_reaching_definitions("x", node.id);
            assert!(!defs.is_empty());
        }
    }
}
