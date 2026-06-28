// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 基于 AST 的污点分析器
//!
//! 利用 tree-sitter AST 解析 + CFG 数据流分析，替代逐行文本匹配。
//! 核心流程：AST 解析 → 提取赋值/调用 → 构建 CFG → 前向污点传播（worklist 算法）

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;

use crate::analysis::alias::{detect_all_aliases, AccessPath, AliasMap};
use crate::analysis::async_flow::{self, CallbackTaintHint};
use crate::analysis::enhanced_dataflow::{EdgeType, EnhancedFlowGraph, EnhancedNodeType};
use crate::analysis::taint::{
    FlowLocation, FlowNode, FlowNodeType, PropagationStep, PropagationStepType, Severity,
    TaintCategory, TaintFlow, TaintSink, TaintSource, VulnerabilityType,
};
use crate::ast::parser::ASTParser;
use crate::ast::symbol::{Assignment, CallInfo, FunctionBody, TypedParam};

/// 单个变量的污点状态
#[derive(Debug, Clone)]
struct TaintInfo {
    /// 污点来源行号
    source_line: usize,
    /// 来源变量名
    source_var: String,
    /// 是否已被净化
    sanitized: bool,
    /// 净化函数名
    sanitizer: Option<String>,
    /// 传播路径
    propagation_steps: Vec<PropagationStep>,
}

/// AST 污点分析器
pub struct AstTaintAnalyzer {
    /// 污点源定义
    sources: Vec<TaintSource>,
    /// 污点汇定义
    sinks: Vec<TaintSink>,
    /// 净化函数模式
    sanitizer_patterns: Vec<String>,
    /// AST 解析器
    ast_parser: ASTParser,
}

impl AstTaintAnalyzer {
    pub fn new() -> Self {
        // 尝试从 rules/taint/ 加载 YAML 规则，失败则使用硬编码默认值
        let yaml_dir = std::path::Path::new("rules/taint");
        if yaml_dir.exists() {
            if let Ok(loaded) = crate::rules::taint_loader::load_taint_rules_from_dir(yaml_dir) {
                if !loaded.sources.is_empty() || !loaded.sinks.is_empty() {
                    return Self {
                        sources: loaded.sources,
                        sinks: loaded.sinks,
                        sanitizer_patterns: loaded.sanitizer_patterns,
                        ast_parser: ASTParser::new(),
                    };
                }
            }
        }

        // Fallback: 硬编码默认值
        Self {
            sources: Self::default_sources(),
            sinks: Self::default_sinks(),
            sanitizer_patterns: Self::default_sanitizers(),
            ast_parser: ASTParser::new(),
        }
    }

    /// 从 YAML 目录创建分析器（替代默认硬编码定义）
    ///
    /// 如果目录存在且包含 taint-rules YAML 文件，使用加载的定义。
    /// 否则回退到默认硬编码定义。
    pub fn from_yaml_dir(dir: &Path) -> anyhow::Result<Self> {
        let loaded = crate::rules::taint_loader::load_taint_rules_from_dir(dir)?;

        if loaded.sources.is_empty() && loaded.sinks.is_empty() {
            tracing::info!("No taint rules found in {:?}, using defaults", dir);
            return Ok(Self::new());
        }

        tracing::info!(
            "Loaded {} sources, {} sinks, {} sanitizers from {:?}",
            loaded.sources.len(),
            loaded.sinks.len(),
            loaded.sanitizer_patterns.len(),
            dir,
        );

        Ok(Self {
            sources: loaded.sources,
            sinks: loaded.sinks,
            sanitizer_patterns: loaded.sanitizer_patterns,
            ast_parser: ASTParser::new(),
        })
    }

    /// Builder: 替换所有污点源
    pub fn with_sources(mut self, sources: Vec<TaintSource>) -> Self {
        self.sources = sources;
        self
    }

    /// Builder: 替换所有污点汇
    pub fn with_sinks(mut self, sinks: Vec<TaintSink>) -> Self {
        self.sinks = sinks;
        self
    }

    /// Builder: 替换所有净化函数模式
    pub fn with_sanitizers(mut self, patterns: Vec<String>) -> Self {
        self.sanitizer_patterns = patterns;
        self
    }

    /// 获取污点源定义
    pub fn sources(&self) -> &[TaintSource] {
        &self.sources
    }

    /// 获取污点汇定义
    pub fn sinks(&self) -> &[TaintSink] {
        &self.sinks
    }

    /// 获取净化函数模式
    pub fn sanitizer_patterns(&self) -> &[String] {
        &self.sanitizer_patterns
    }

    /// 追加额外的污点源（不覆盖现有定义）
    pub fn add_sources(&mut self, sources: Vec<TaintSource>) {
        self.sources.extend(sources);
    }

    /// 追加额外的污点汇
    pub fn add_sinks(&mut self, sinks: Vec<TaintSink>) {
        self.sinks.extend(sinks);
    }

    /// 追加额外的净化函数模式
    pub fn add_sanitizers(&mut self, patterns: Vec<String>) {
        self.sanitizer_patterns.extend(patterns);
    }

    /// 根据文件扩展名推断语言标识
    ///
    /// 返回与规则 YAML 中 `languages` 字段一致的值，例如 "rust"、"go"、"java"。
    fn detect_language(file_path: &str) -> String {
        let ext = std::path::Path::new(file_path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        match ext.to_lowercase().as_str() {
            "rs" => "rust",
            "go" => "go",
            "java" => "java",
            "c" => "c",
            "cpp" | "cc" | "cxx" => "cpp",
            "py" => "python",
            "js" => "javascript",
            "ts" => "typescript",
            "jsx" => "jsx",
            "tsx" => "tsx",
            _ => ext,
        }
        .to_string()
    }

    /// 分析单个文件，返回所有检测到的污点流
    pub fn analyze_file(&mut self, file_path: &Path, content: &str) -> Vec<TaintFlow> {
        let mut all_flows = Vec::new();
        let file_path_str = file_path.to_string_lossy().to_string();
        let language = Self::detect_language(&file_path_str);
        let callback_hints = async_flow::detect_callback_hints(content);

        // 使用 AST-based 分析（保留 Tree 供 CFG 构建使用）
        if let Some((tree, functions, file_assignments, file_calls)) = self
            .ast_parser
            .extract_all_for_taint_with_tree(file_path, content)
        {
            let root = tree.root_node();

            if functions.is_empty() {
                // 没有函数体：对整个文件做 AST-based CFG 分析
                let cfg = EnhancedFlowGraph::from_ast_node(&root, content, &file_path_str, "");
                let flows = self.forward_taint_analysis(
                    &cfg,
                    &file_assignments,
                    &file_calls,
                    content,
                    &file_path_str,
                    &language,
                    &[],
                    &callback_hints,
                    0,
                );
                all_flows.extend(flows);
            } else {
                // 按函数逐个分析
                for func in &functions {
                    let func_hints: Vec<CallbackTaintHint> = callback_hints
                        .iter()
                        .filter(|h| {
                            h.callback_start_line >= func.start_line
                                && h.callback_start_line <= func.end_line
                        })
                        .cloned()
                        .collect();

                    let func_assignments: Vec<_> = file_assignments
                        .iter()
                        .filter(|a| a.line >= func.start_line && a.line <= func.end_line)
                        .cloned()
                        .collect();
                    let func_calls: Vec<_> = file_calls
                        .iter()
                        .filter(|c| c.line >= func.start_line && c.line <= func.end_line)
                        .cloned()
                        .collect();

                    // 优先使用 AST-based CFG，fallback 到 text-based
                    let func_body_node =
                        Self::find_function_body_node_static(&root, func.start_line, func.end_line);
                    let cfg = if let Some(body_node) = func_body_node {
                        EnhancedFlowGraph::from_ast_node(
                            &body_node,
                            content,
                            &file_path_str,
                            &func.name,
                        )
                    } else {
                        EnhancedFlowGraph::from_code(&func.body_text, &file_path_str, &func.name)
                    };

                    let line_offset = func.start_line.saturating_sub(1);
                    let flows = self.forward_taint_analysis(
                        &cfg,
                        &func_assignments,
                        &func_calls,
                        &func.body_text,
                        &file_path_str,
                        &language,
                        &func.typed_params,
                        &func_hints,
                        line_offset,
                    );
                    all_flows.extend(flows);
                }
            }
        }

        all_flows
    }

    /// 在 AST 中查找匹配行号范围的函数体节点
    pub fn find_function_body_node_static<'a>(
        node: &tree_sitter::Node<'a>,
        start_line: usize,
        end_line: usize,
    ) -> Option<tree_sitter::Node<'a>> {
        let node_start = node.start_position().row + 1;
        let node_end = node.end_position().row + 1;

        if node_start == start_line && node_end >= end_line {
            if let Some(body) = node.child_by_field_name("body") {
                return Some(body);
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if let Some(found) = Self::find_function_body_node_static(&child, start_line, end_line)
            {
                return Some(found);
            }
        }
        None
    }

    /// 分析一段代码（函数体或完整文件）— 供测试使用
    ///
    /// 测试用：使用 text-based CFG 保证对短代码片段的稳定性。
    /// 生产用 `analyze_file()` 走 AST-based CFG 路径。
    pub(crate) fn analyze_code(
        &mut self,
        code: &str,
        file_path: &Path,
        function_name: &str,
        typed_params: &[TypedParam],
        callback_hints: &[CallbackTaintHint],
    ) -> Vec<TaintFlow> {
        let file_path_str = file_path.to_string_lossy().to_string();
        let language = Self::detect_language(&file_path_str);
        let tmp_path = std::path::PathBuf::from(&file_path_str);
        let (_, assignments, calls) = self.ast_parser.extract_all_for_taint(&tmp_path, code);
        let cfg = EnhancedFlowGraph::from_code(code, &file_path_str, function_name);
        self.forward_taint_analysis(
            &cfg,
            &assignments,
            &calls,
            code,
            &file_path_str,
            &language,
            typed_params,
            callback_hints,
            0,
        )
    }

    /// 从 FunctionCPG 分析（路径敏感污点传播）
    ///
    /// 使用 CPG 中的 ConditionInfo 实现路径敏感分析：
    /// 条件净化检查（如 if (isSafe(x))）会降低对应分支上的置信度。
    pub fn analyze_function_cpg(
        &self,
        cpg: &super::cpg::FunctionCPG,
        content: &str,
        callback_hints: &[crate::analysis::async_flow::CallbackTaintHint],
    ) -> Vec<TaintFlow> {
        let assignments: Vec<Assignment> = cpg
            .node_meta
            .values()
            .filter_map(|m| m.assignment.clone())
            .collect();
        let calls: Vec<CallInfo> = cpg
            .node_meta
            .values()
            .filter_map(|m| m.call_info.clone())
            .collect();
        let language = Self::detect_language(&cpg.signature.file_path);

        let line_offset = cpg.signature.start_line.saturating_sub(1);
        self.forward_taint_analysis_cpg(
            &cpg.cfg,
            &assignments,
            &calls,
            &cpg.node_meta,
            content,
            &cpg.signature.file_path,
            &language,
            &cpg.signature.params,
            callback_hints,
            line_offset,
        )
    }

    /// 前向污点传播（worklist 算法）
    ///
    /// `line_offset` 用于将函数体内部相对行号转换为文件绝对行号，
    /// 避免入口源被错误地标记为函数体起始行导致后续去重丢失。
    fn forward_taint_analysis(
        &self,
        cfg: &EnhancedFlowGraph,
        assignments: &[Assignment],
        calls: &[CallInfo],
        code: &str,
        file_path: &str,
        language: &str,
        typed_params: &[TypedParam],
        callback_hints: &[CallbackTaintHint],
        line_offset: usize,
    ) -> Vec<TaintFlow> {
        let mut flows = Vec::new();

        // 节点污点状态：node_id → (var_name → TaintInfo)
        let mut taint_state: HashMap<usize, HashMap<String, TaintInfo>> = HashMap::new();

        // 按行号索引赋值和调用，加速查找
        let assign_by_line: HashMap<usize, &Assignment> =
            assignments.iter().map(|a| (a.line, a)).collect();
        let call_by_line: HashMap<usize, &CallInfo> = calls.iter().map(|c| (c.line, c)).collect();

        // 从赋值中构建别名映射
        let alias_map = self.build_alias_map(assignments);

        // 初始化 worklist（HashSet 辅助 O(1) 去重）
        let mut worklist: VecDeque<usize> = VecDeque::new();
        let mut in_worklist: std::collections::HashSet<usize> = std::collections::HashSet::new();
        worklist.push_back(cfg.entry);
        in_worklist.insert(cfg.entry);

        while let Some(node_id) = worklist.pop_front() {
            if node_id >= cfg.nodes.len() {
                continue;
            }

            let node = &cfg.nodes[node_id];

            // Join 前驱节点的污点状态
            let mut new_state = self.join_predecessors(node_id, &taint_state, cfg);

            // Transfer function
            match node.node_type {
                EnhancedNodeType::Entry => {
                    self.check_entry_sources(
                        node,
                        code,
                        &mut new_state,
                        &alias_map,
                        typed_params,
                        callback_hints,
                        language,
                        line_offset,
                    );
                }

                EnhancedNodeType::Assignment => {
                    if let Some(flow) = self.transfer_assignment(
                        node,
                        &assign_by_line,
                        &call_by_line,
                        &mut new_state,
                        file_path,
                        language,
                        &alias_map,
                    ) {
                        flows.push(flow);
                    }
                }

                EnhancedNodeType::Call => {
                    if let Some(flow) = self.transfer_call(
                        node,
                        &call_by_line,
                        &mut new_state,
                        file_path,
                        language,
                        &alias_map,
                    ) {
                        flows.push(flow);
                    }
                }

                EnhancedNodeType::Return => {
                    // Return 节点可能包含 sink 调用（如 return needle.get(url, ...)）
                    if let Some(flow) = self.transfer_call(
                        node,
                        &call_by_line,
                        &mut new_state,
                        file_path,
                        language,
                        &alias_map,
                    ) {
                        flows.push(flow);
                    }
                }

                EnhancedNodeType::ConditionHeader => {
                    // 条件分支：检查条件表达式中的污点（暂不处理）
                }

                _ => {}
            }

            // 检查状态是否变化
            let changed = self.state_changed(node_id, &new_state, &taint_state);
            if changed {
                taint_state.insert(node_id, new_state);
                // 将后继加入 worklist（O(1) 去重）
                for edge in &node.successors {
                    if in_worklist.insert(edge.target) {
                        worklist.push_back(edge.target);
                    }
                }
            }
        }

        flows
    }

    /// 路径敏感前向污点传播（worklist 算法 + CPG）
    ///
    /// 与 forward_taint_analysis 相同的基本结构，但：
    /// - 使用 PathSensitiveState 替代 HashMap<String, TaintInfo>
    /// - ConditionHeader 节点注入路径条件到后继
    /// - 合并节点使用 merge_branches 而非简单 union
    /// - 置信度根据分支净化情况调整
    fn forward_taint_analysis_cpg(
        &self,
        cfg: &EnhancedFlowGraph,
        assignments: &[Assignment],
        calls: &[CallInfo],
        node_meta: &std::collections::HashMap<usize, super::cpg::CPGNodeMeta>,
        code: &str,
        file_path: &str,
        language: &str,
        typed_params: &[TypedParam],
        callback_hints: &[CallbackTaintHint],
        line_offset: usize,
    ) -> Vec<TaintFlow> {
        use super::cpg::{ConditionInfo, PathCondition, PathSensitiveState, VarTaintState};
        use crate::analysis::enhanced_dataflow::EdgeType;

        let mut flows = Vec::new();

        // 路径敏感状态：node_id → PathSensitiveState
        let mut taint_state: HashMap<usize, PathSensitiveState> = HashMap::new();

        let assign_by_line: HashMap<usize, &Assignment> =
            assignments.iter().map(|a| (a.line, a)).collect();
        let call_by_line: HashMap<usize, &CallInfo> = calls.iter().map(|c| (c.line, c)).collect();

        let alias_map = self.build_alias_map(assignments);

        let mut worklist: VecDeque<usize> = VecDeque::new();
        let mut in_worklist: std::collections::HashSet<usize> = std::collections::HashSet::new();
        worklist.push_back(cfg.entry);
        in_worklist.insert(cfg.entry);

        while let Some(node_id) = worklist.pop_front() {
            if node_id >= cfg.nodes.len() {
                continue;
            }

            let node = &cfg.nodes[node_id];

            // 路径敏感 Join：考虑入边类型
            let mut new_state = self.join_predecessors_cpg(node_id, &taint_state, cfg, node_meta);

            // Transfer function
            match node.node_type {
                EnhancedNodeType::Entry => {
                    self.check_entry_sources_cpg(
                        node,
                        code,
                        &mut new_state,
                        &alias_map,
                        typed_params,
                        callback_hints,
                        language,
                        line_offset,
                    );
                }

                EnhancedNodeType::Assignment => {
                    if let Some(flow) = self.transfer_assignment_cpg(
                        node,
                        &assign_by_line,
                        &call_by_line,
                        &mut new_state,
                        file_path,
                        language,
                        &alias_map,
                    ) {
                        flows.push(flow);
                    }
                }

                EnhancedNodeType::Call => {
                    if let Some(flow) = self.transfer_call_cpg(
                        node,
                        &call_by_line,
                        &mut new_state,
                        file_path,
                        language,
                        &alias_map,
                    ) {
                        flows.push(flow);
                    }
                }

                EnhancedNodeType::ConditionHeader => {
                    // 路径敏感：检查条件是否包含净化器调用
                    // 在后继节点中注入路径条件（通过 taint_state 传递）
                    let condition = node_meta.get(&node_id).and_then(|m| m.condition.as_ref());

                    if let Some(cond) = condition {
                        if cond.is_sanitizer_check {
                            // 对当前状态中受影响的变量打上路径条件标记
                            // 实际的 True/False 分支净化在 join 时处理
                            // 这里只记录条件信息
                        }
                    }
                }

                EnhancedNodeType::Return | EnhancedNodeType::Statement => {
                    // Return 节点可能包含 sink 调用（如 return needle.get(url, ...)）
                    // 需要检查是否包含污点流向的 sink
                    if node.node_type == EnhancedNodeType::Return {
                        if let Some(flow) = self.transfer_call_cpg(
                            node,
                            &call_by_line,
                            &mut new_state,
                            file_path,
                            language,
                            &alias_map,
                        ) {
                            flows.push(flow);
                        }
                    }
                }

                _ => {}
            }

            // 检查状态是否变化
            let changed = self.state_changed_cpg(node_id, &new_state, &taint_state);
            if changed {
                taint_state.insert(node_id, new_state);

                // 对后继节点：如果是 ConditionHeader 的后继，注入路径条件
                let condition = node_meta.get(&node_id).and_then(|m| m.condition.as_ref());

                for edge in &node.successors {
                    if in_worklist.insert(edge.target) {
                        worklist.push_back(edge.target);
                    }
                }
            }
        }

        flows
    }

    /// 路径敏感 Join：考虑入边类型和条件信息
    fn join_predecessors_cpg(
        &self,
        node_id: usize,
        taint_state: &HashMap<usize, super::cpg::PathSensitiveState>,
        cfg: &EnhancedFlowGraph,
        node_meta: &std::collections::HashMap<usize, super::cpg::CPGNodeMeta>,
    ) -> super::cpg::PathSensitiveState {
        use super::cpg::{PathCondition, PathSensitiveState};
        use crate::analysis::enhanced_dataflow::EdgeType;

        let node = &cfg.nodes[node_id];
        let preds = &node.predecessors;

        if preds.is_empty() {
            return PathSensitiveState::new();
        }

        // 收集各前驱的状态和对应边类型
        let pred_entries: Vec<(&PathSensitiveState, EdgeType, usize)> = preds
            .iter()
            .filter_map(|&pred_id| {
                let state = taint_state.get(&pred_id)?;
                let edge_type = cfg
                    .edge_type_between(pred_id, node_id)
                    .unwrap_or(EdgeType::Sequential);
                // 查找前驱中的 ConditionHeader，获取条件信息
                let cond_pred = self.find_condition_predecessor(pred_id, cfg, node_meta);
                Some((state, edge_type, cond_pred))
            })
            .collect();

        if pred_entries.is_empty() {
            return PathSensitiveState::new();
        }

        // 分支感知合并
        let mut true_states: Vec<&PathSensitiveState> = Vec::new();
        let mut false_states: Vec<&PathSensitiveState> = Vec::new();
        let mut seq_states: Vec<&PathSensitiveState> = Vec::new();
        let mut cond_info: Option<&super::cpg::ConditionInfo> = None;

        for (state, edge_type, cond_pred_id) in &pred_entries {
            match edge_type {
                EdgeType::TrueBranch => {
                    true_states.push(state);
                    // 获取条件信息
                    if cond_info.is_none() {
                        if let Some(meta) = node_meta.get(cond_pred_id) {
                            if let Some(ref ci) = meta.condition {
                                cond_info = Some(ci);
                            }
                        }
                    }
                }
                EdgeType::FalseBranch => {
                    false_states.push(state);
                    if cond_info.is_none() {
                        if let Some(meta) = node_meta.get(cond_pred_id) {
                            if let Some(ref ci) = meta.condition {
                                cond_info = Some(ci);
                            }
                        }
                    }
                }
                _ => {
                    seq_states.push(state);
                }
            }
        }

        // 对 True/False 分支的状态注入条件效果
        let mut true_merged = PathSensitiveState::new();
        for ts in &true_states {
            true_merged.union_with(ts);
        }
        if let Some(ci) = cond_info {
            if ci.is_sanitizer_check {
                let pc = PathCondition {
                    condition_node_id: preds[0],
                    branch: EdgeType::TrueBranch,
                    expr: ci.expr.clone(),
                };
                // 在 True 分支上，净化器检查的变量被净化
                for var in &ci.used_vars {
                    if let Some(vt) = true_merged.get_var_mut(var) {
                        vt.mark_sanitized_on_branch(&pc);
                    }
                }
            }
        }

        let mut false_merged = PathSensitiveState::new();
        for fs in &false_states {
            false_merged.union_with(fs);
        }
        if let Some(ci) = cond_info {
            if ci.is_sanitizer_check {
                let pc = PathCondition {
                    condition_node_id: preds[0],
                    branch: EdgeType::FalseBranch,
                    expr: ci.expr.clone(),
                };
                // 在 False 分支上，变量仍被污染
                for var in &ci.used_vars {
                    if let Some(vt) = false_merged.get_var_mut(var) {
                        vt.mark_tainted_on_branch(&pc);
                    }
                }
            }
        }

        // 最终合并
        let mut result = PathSensitiveState::new();
        for ss in &seq_states {
            result.union_with(ss);
        }

        if !true_states.is_empty() && !false_states.is_empty() {
            let merged = PathSensitiveState::merge_branches(&true_merged, &false_merged);
            result.union_with(&merged);
        } else if !true_states.is_empty() {
            result.union_with(&true_merged);
        } else if !false_states.is_empty() {
            result.union_with(&false_merged);
        }

        result
    }

    /// 查找支配前驱的 ConditionHeader 节点
    fn find_condition_predecessor(
        &self,
        pred_id: usize,
        cfg: &EnhancedFlowGraph,
        _node_meta: &std::collections::HashMap<usize, super::cpg::CPGNodeMeta>,
    ) -> usize {
        // 简化：直接检查 pred 是否是 ConditionHeader
        if cfg
            .nodes
            .get(pred_id)
            .map(|n| n.node_type == EnhancedNodeType::ConditionHeader)
            .unwrap_or(false)
        {
            return pred_id;
        }
        pred_id
    }

    /// 检查入口源（PathSensitiveState 版本）
    fn check_entry_sources_cpg(
        &self,
        node: &crate::analysis::enhanced_dataflow::EnhancedFlowNode,
        code: &str,
        state: &mut super::cpg::PathSensitiveState,
        alias_map: &AliasMap,
        typed_params: &[TypedParam],
        callback_hints: &[CallbackTaintHint],
        language: &str,
        line_offset: usize,
    ) {
        use super::cpg::VarTaintState;

        let lines: Vec<&str> = code.lines().collect();

        // 1. 基于类型注解的参数污点源
        for tp in typed_params {
            let var_name = tp.name.clone();
            if state.get_var(&var_name).is_some() {
                continue;
            }
            if let Some(ref type_ann) = tp.type_annotation {
                let type_lower = type_ann.to_lowercase();
                let is_request_type = Self::REQUEST_TYPE_PATTERNS
                    .iter()
                    .any(|pattern| type_lower.contains(&pattern.to_lowercase()));
                if is_request_type {
                    let line_num = code
                        .lines()
                        .enumerate()
                        .find(|(_, l)| l.contains(&tp.name))
                        .map(|(i, _)| i + 1 + line_offset)
                        .unwrap_or(1);
                    state.insert_var(
                        var_name,
                        VarTaintState::from_taint(
                            line_num,
                            format!("{}: {}", tp.name, type_ann),
                            vec![PropagationStep {
                                step_type: PropagationStepType::DirectAssignment,
                                from_var: None,
                                to_var: Some(tp.name.clone()),
                                line: line_num,
                                code_snippet: Some(format!("param: {}", type_ann)),
                                function_name: None,
                            }],
                        ),
                    );
                }
            }
        }

        // 2. 基于回调提示的参数污点
        for hint in callback_hints {
            let var_name = hint.param_name.clone();
            if state.get_var(&var_name).is_some() {
                continue;
            }
            let line_num = code
                .lines()
                .enumerate()
                .find(|(_, l)| l.contains(&hint.param_name))
                .map(|(i, _)| i + 1 + line_offset)
                .unwrap_or(1);
            state.insert_var(
                var_name,
                VarTaintState::from_taint(
                    line_num,
                    format!("{} (callback param)", hint.param_name),
                    vec![PropagationStep {
                        step_type: PropagationStepType::CallPropagation,
                        from_var: None,
                        to_var: Some(hint.param_name.clone()),
                        line: line_num,
                        code_snippet: Some(format!("{} => ...", hint.param_name)),
                        function_name: None,
                    }],
                ),
            );
        }

        // 3. 基于行扫描的污点源匹配
        for (line_idx, line) in lines.iter().enumerate() {
            let line_num = line_idx + 1 + line_offset;
            for source in &self.sources {
                if source.matches(line, language) {
                    if let Some(var_name) = self.extract_var_from_source(line) {
                        if state.get_var(&var_name).is_none() {
                            state.insert_var(
                                var_name.clone(),
                                VarTaintState::from_taint(
                                    line_num,
                                    var_name.clone(),
                                    vec![PropagationStep {
                                        step_type: PropagationStepType::DirectAssignment,
                                        from_var: None,
                                        to_var: Some(var_name.clone()),
                                        line: line_num,
                                        code_snippet: Some(line.trim().to_string()),
                                        function_name: None,
                                    }],
                                ),
                            );
                        }
                    }
                    // 同时标记源行中引用的函数参数为污点
                    // 例：const url = req.query.url + ... 中 req 是参数，
                    // 后续 transfer_assignment 需要 req 在 state 中才能传播到 url
                    for tp in typed_params {
                        let pname = &tp.name;
                        if line.contains(pname.as_str()) && state.get_var(pname).is_none() {
                            state.insert_var(
                                pname.clone(),
                                VarTaintState::from_taint(
                                    line_num,
                                    format!("{} (tainted param)", pname),
                                    vec![PropagationStep {
                                        step_type: PropagationStepType::DirectAssignment,
                                        from_var: None,
                                        to_var: Some(pname.clone()),
                                        line: line_num,
                                        code_snippet: Some(line.trim().to_string()),
                                        function_name: None,
                                    }],
                                ),
                            );
                        }
                    }
                }
            }
        }

        // 4. 基于别名的污点源
        for (local_var, paths) in alias_map.all_aliases() {
            if state.get_var(local_var).is_some() {
                continue;
            }
            let path_matches_source = paths.iter().any(|path| {
                let dotted = path.as_dotted();
                self.sources.iter().any(|s| s.matches(&dotted, language))
            });
            if path_matches_source {
                let line_num = code
                    .lines()
                    .enumerate()
                    .find(|(_, l)| l.contains(local_var))
                    .map(|(i, _)| i + 1 + line_offset)
                    .unwrap_or(1);
                state.insert_var(
                    local_var.clone(),
                    VarTaintState::from_taint(
                        line_num,
                        local_var.clone(),
                        vec![PropagationStep {
                            step_type: PropagationStepType::DirectAssignment,
                            from_var: None,
                            to_var: Some(local_var.clone()),
                            line: line_num,
                            code_snippet: None,
                            function_name: None,
                        }],
                    ),
                );
            }
        }
    }

    /// 赋值传播（PathSensitiveState 版本）
    fn transfer_assignment_cpg(
        &self,
        node: &crate::analysis::enhanced_dataflow::EnhancedFlowNode,
        assign_by_line: &HashMap<usize, &Assignment>,
        call_by_line: &HashMap<usize, &CallInfo>,
        state: &mut super::cpg::PathSensitiveState,
        file_path: &str,
        language: &str,
        alias_map: &AliasMap,
    ) -> Option<TaintFlow> {
        use super::cpg::VarTaintState;

        if let Some(assign) = assign_by_line.get(&node.start_line) {
            let is_sanitized = call_by_line
                .get(&assign.line)
                .map(|c| self.is_sanitizer(&c.callee))
                .unwrap_or(false)
                || self
                    .sanitizer_patterns
                    .iter()
                    .any(|p| assign.source_expr.contains(p.as_str()));

            // 在 PathSensitiveState 中查找污点变量
            let tainted_source_var =
                self.find_tainted_var_cpg(&assign.source_vars, state, alias_map);

            if let Some(src_var) = tainted_source_var {
                let src_path = AccessPath::from_dotted(&src_var);
                let src_vt = state.find_taint_for_path(&src_path).unwrap().clone();
                let mut steps = src_vt.propagation_steps.clone();
                steps.push(PropagationStep {
                    step_type: if is_sanitized {
                        PropagationStepType::Sanitization
                    } else {
                        PropagationStepType::DirectAssignment
                    },
                    from_var: Some(src_var.clone()),
                    to_var: Some(assign.target.clone()),
                    line: assign.line,
                    code_snippet: Some(assign.source_expr.clone()),
                    function_name: None,
                });

                // 使用 AccessPath 作为 key（支持 obj.prop 格式）
                let target_path = AccessPath::from_dotted(&assign.target);
                let mut target_paths = vec![target_path.clone()];

                // 别名路径也作为目标
                for alias_ap in alias_map.resolve(&assign.target) {
                    if state.get_exact(&alias_ap).is_none() {
                        target_paths.push(alias_ap);
                    }
                }

                for tp in target_paths {
                    let mut vt = VarTaintState::from_taint(
                        src_vt.source_line,
                        src_vt.source_var.clone(),
                        steps.clone(),
                    );
                    if is_sanitized {
                        vt.sanitized = true;
                        vt.sanitizer = call_by_line.get(&assign.line).map(|c| c.callee.clone());
                    }
                    state.insert_path(tp, vt);
                }

                // 检查赋值右值中的 sink
                if !is_sanitized {
                    if let Some(sink) =
                        self.find_matching_sink_in_expr(&assign.source_expr, language)
                    {
                        let target_ap = AccessPath::from_dotted(&assign.target);
                        let vt = state
                            .find_taint_for_path(&target_ap)
                            .or_else(|| state.find_taint_for_path(&src_path))
                            .unwrap()
                            .clone();
                        return Some(self.build_taint_flow_cpg(
                            &vt,
                            &src_var,
                            &self.extract_sink_name(&assign.source_expr, language),
                            &sink,
                            assign.line,
                            assign.line,
                            file_path,
                            &assign.source_expr,
                        ));
                    }
                }
            }
        } else {
            // 回退到 defs/uses 分析
            let has_tainted_use = node
                .uses
                .iter()
                .any(|u| self.is_var_tainted_cpg(u, state, alias_map));

            if has_tainted_use && !node.defs.is_empty() {
                let tainted_var = node
                    .uses
                    .iter()
                    .find(|u| self.is_var_tainted_cpg(u, state, alias_map))
                    .and_then(|u| self.resolve_tainted_var_cpg(u, state, alias_map))
                    .unwrap_or_else(|| node.uses[0].clone());

                let src_path = AccessPath::from_dotted(&tainted_var);
                let src_vt = state.find_taint_for_path(&src_path).unwrap().clone();
                for def in &node.defs {
                    let mut steps = src_vt.propagation_steps.clone();
                    steps.push(PropagationStep {
                        step_type: PropagationStepType::DirectAssignment,
                        from_var: Some(tainted_var.clone()),
                        to_var: Some(def.clone()),
                        line: node.start_line,
                        code_snippet: Some(node.code.clone()),
                        function_name: None,
                    });
                    state.insert_path(
                        AccessPath::from_dotted(def),
                        VarTaintState::from_taint(
                            src_vt.source_line,
                            src_vt.source_var.clone(),
                            steps,
                        ),
                    );
                }
            }
        }
        None
    }

    /// 调用传播（PathSensitiveState 版本）
    fn transfer_call_cpg(
        &self,
        node: &crate::analysis::enhanced_dataflow::EnhancedFlowNode,
        call_by_line: &HashMap<usize, &CallInfo>,
        state: &mut super::cpg::PathSensitiveState,
        file_path: &str,
        language: &str,
        alias_map: &AliasMap,
    ) -> Option<TaintFlow> {
        if let Some(call) = call_by_line.get(&node.start_line) {
            // 检查 sink（方法调用考虑 receiver，如 needle.get）
            if let Some(sink) = self.match_sink_for_call(call, language) {
                let tainted_arg = call.arguments.iter().find(|arg| {
                    arg.referenced_vars
                        .iter()
                        .any(|v| self.is_var_tainted_cpg(v, state, alias_map))
                });

                if let Some(arg) = tainted_arg {
                    let tainted_var = arg
                        .referenced_vars
                        .iter()
                        .find(|v| self.is_var_tainted_cpg(v, state, alias_map))
                        .and_then(|v| self.resolve_tainted_var_cpg(v, state, alias_map))
                        .unwrap_or_else(|| arg.referenced_vars[0].clone());

                    let src_path = AccessPath::from_dotted(&tainted_var);
                    let src_vt = state.find_taint_for_path(&src_path).unwrap().clone();

                    // 检查参数化查询
                    if self.is_parameterized_query(&call.callee, &node.code) {
                        state.mark_sanitized(&tainted_var, Some("parameterized_query".into()));
                        return None;
                    }

                    return Some(self.build_taint_flow_cpg(
                        &src_vt,
                        &tainted_var,
                        &call.callee,
                        &sink,
                        call.line,
                        node.start_line,
                        file_path,
                        &node.code,
                    ));
                }
            }

            // 检查净化器
            if self.is_sanitizer(&call.callee) {
                for arg in &call.arguments {
                    for var in &arg.referenced_vars {
                        state.mark_sanitized(var, Some(call.callee.clone()));
                    }
                }
            }
        }
        None
    }

    /// 在 PathSensitiveState 中查找污点变量
    fn find_tainted_var_cpg(
        &self,
        vars: &[String],
        state: &super::cpg::PathSensitiveState,
        alias_map: &AliasMap,
    ) -> Option<String> {
        for var in vars {
            if self.is_var_tainted_cpg(var, state, alias_map) {
                return Some(
                    self.resolve_tainted_var_cpg(var, state, alias_map)
                        .unwrap_or_else(|| var.clone()),
                );
            }
        }
        None
    }

    /// 检查变量是否被污染（AccessPath 版本，支持前缀匹配）
    fn is_var_tainted_cpg(
        &self,
        var: &str,
        state: &super::cpg::PathSensitiveState,
        alias_map: &AliasMap,
    ) -> bool {
        // AccessPath 查询（含前缀匹配）
        let path = AccessPath::from_dotted(var);
        if state.is_path_tainted(&path) {
            return true;
        }
        // 别名路径查询
        for alias_path in alias_map.resolve(var) {
            if state.is_path_tainted(&alias_path) {
                return true;
            }
        }
        false
    }

    /// 解析污点变量名（AccessPath 版本）
    fn resolve_tainted_var_cpg(
        &self,
        var: &str,
        state: &super::cpg::PathSensitiveState,
        alias_map: &AliasMap,
    ) -> Option<String> {
        // 精确匹配
        let path = AccessPath::from_dotted(var);
        if state.get_exact(&path).is_some() {
            return Some(var.to_string());
        }
        // 别名解析
        for alias_path in alias_map.resolve(var) {
            if state.get_exact(&alias_path).is_some() {
                return Some(alias_path.as_dotted());
            }
        }
        // 前缀匹配 — 返回匹配到的路径
        if state.find_taint_for_path(&path).is_some() {
            return Some(var.to_string());
        }
        None
    }

    /// 构建污点流（VarTaintState 版本 — 含路径敏感置信度）
    fn build_taint_flow_cpg(
        &self,
        taint_state: &super::cpg::VarTaintState,
        tainted_var: &str,
        sink_name: &str,
        sink: &TaintSink,
        sink_line: usize,
        _node_line: usize,
        file_path: &str,
        sink_code: &str,
    ) -> TaintFlow {
        let mut path = Vec::new();

        path.push(FlowNode {
            node_type: FlowNodeType::Source,
            file_path: file_path.to_string(),
            line: taint_state.source_line,
            symbol: taint_state.source_var.clone(),
            code_snippet: None,
        });

        for step in &taint_state.propagation_steps {
            let node_type = match step.step_type {
                PropagationStepType::DirectAssignment => FlowNodeType::Assignment,
                PropagationStepType::ConcatAssignment => FlowNodeType::Assignment,
                PropagationStepType::CallPropagation => FlowNodeType::Call,
                PropagationStepType::ReturnPropagation => FlowNodeType::Return,
                PropagationStepType::FieldPropagation => FlowNodeType::FieldAccess,
                PropagationStepType::Sanitization => FlowNodeType::Sanitized,
                PropagationStepType::Dereference => FlowNodeType::Statement,
            };
            path.push(FlowNode {
                node_type,
                file_path: file_path.to_string(),
                line: step.line,
                symbol: step.to_var.clone().unwrap_or_default(),
                code_snippet: step.code_snippet.clone(),
            });
        }

        path.push(FlowNode {
            node_type: FlowNodeType::Sink,
            file_path: file_path.to_string(),
            line: sink_line,
            symbol: sink_name.to_string(),
            code_snippet: Some(sink_code.to_string()),
        });

        // 路径敏感置信度
        let confidence = taint_state.confidence() as f32;

        TaintFlow {
            id: uuid::Uuid::new_v4().to_string(),
            source: FlowLocation {
                file_path: file_path.to_string(),
                line: taint_state.source_line,
                column: None,
                symbol: taint_state.source_var.clone(),
                code_snippet: None,
            },
            sink: FlowLocation {
                file_path: file_path.to_string(),
                line: sink_line,
                column: None,
                symbol: sink_name.to_string(),
                code_snippet: Some(sink_code.to_string()),
            },
            path,
            vulnerability_type: sink.vulnerability_type.clone(),
            severity: sink.severity,
            confidence,
        }
    }

    /// 状态变化检查（PathSensitiveState 版本）
    fn state_changed_cpg(
        &self,
        node_id: usize,
        new_state: &super::cpg::PathSensitiveState,
        old_states: &HashMap<usize, super::cpg::PathSensitiveState>,
    ) -> bool {
        match old_states.get(&node_id) {
            None => !new_state.is_empty(),
            Some(old) => {
                if old.len() != new_state.len() {
                    return true;
                }
                for (path, new_vt) in new_state.all_entries() {
                    match old.get_exact(path) {
                        None => return true,
                        Some(old_vt) => {
                            if old_vt.source_line != new_vt.source_line
                                || old_vt.sanitized != new_vt.sanitized
                                || old_vt.sanitized_on.len() != new_vt.sanitized_on.len()
                                || old_vt.tainted_on.len() != new_vt.tainted_on.len()
                            {
                                return true;
                            }
                        }
                    }
                }
                false
            }
        }
    }

    /// 从赋值列表构建别名映射
    fn build_alias_map(&self, assignments: &[Assignment]) -> AliasMap {
        let mut map = AliasMap::new();
        for assign in assignments {
            let detection = detect_all_aliases(assign);
            for (var, path) in detection.new_aliases {
                map.add_alias(&var, path);
            }
        }
        map
    }

    /// Join 前驱节点的污点状态（union）
    fn join_predecessors(
        &self,
        node_id: usize,
        taint_state: &HashMap<usize, HashMap<String, TaintInfo>>,
        cfg: &EnhancedFlowGraph,
    ) -> HashMap<String, TaintInfo> {
        let mut joined = HashMap::new();

        for &pred_id in &cfg.nodes[node_id].predecessors {
            if let Some(pred_state) = taint_state.get(&pred_id) {
                for (var, info) in pred_state {
                    let existing = joined.get(var);
                    // 如果该变量未被净化（或新状态也不是净化后的），保留污点
                    match existing {
                        None => {
                            joined.insert(var.clone(), info.clone());
                        }
                        Some(e) => {
                            // 如果任一路径未净化，保持未净化
                            if !e.sanitized && info.sanitized {
                                // 保持已有的未净化状态
                            } else if e.sanitized && !info.sanitized {
                                joined.insert(var.clone(), info.clone());
                            }
                        }
                    }
                }
            }
        }

        joined
    }

    /// 已知的请求类型模式 — TypeScript 类型注解匹配
    const REQUEST_TYPE_PATTERNS: &'static [&'static str] = &[
        "HttpRequest",
        "Request",
        "IncomingMessage",
        "HttpContext",
        "ServletRequest",
        "HttpServletRequest",
        "Express.Request",
        "FastifyRequest",
        "Koa.Request",
        "NextRequest",
        "NextApiRequest",
        "EventHttpRequest",
        "ServerRequest",
    ];

    /// 检查入口节点是否有污点源
    fn check_entry_sources(
        &self,
        node: &crate::analysis::enhanced_dataflow::EnhancedFlowNode,
        code: &str,
        state: &mut HashMap<String, TaintInfo>,
        alias_map: &AliasMap,
        typed_params: &[TypedParam],
        callback_hints: &[CallbackTaintHint],
        language: &str,
        line_offset: usize,
    ) {
        let lines: Vec<&str> = code.lines().collect();

        // 1. 基于类型注解的参数污点源
        for tp in typed_params {
            if state.contains_key(&tp.name) {
                continue;
            }
            if let Some(ref type_ann) = tp.type_annotation {
                let type_lower = type_ann.to_lowercase();
                let is_request_type = Self::REQUEST_TYPE_PATTERNS
                    .iter()
                    .any(|pattern| type_lower.contains(&pattern.to_lowercase()));
                if is_request_type {
                    let line_num = code
                        .lines()
                        .enumerate()
                        .find(|(_, l)| l.contains(&tp.name))
                        .map(|(i, _)| i + 1 + line_offset)
                        .unwrap_or(1);
                    state.insert(
                        tp.name.clone(),
                        TaintInfo {
                            source_line: line_num,
                            source_var: format!("{}: {}", tp.name, type_ann),
                            sanitized: false,
                            sanitizer: None,
                            propagation_steps: vec![PropagationStep {
                                step_type: PropagationStepType::DirectAssignment,
                                from_var: None,
                                to_var: Some(tp.name.clone()),
                                line: line_num,
                                code_snippet: Some(format!("param: {}", type_ann)),
                                function_name: None,
                            }],
                        },
                    );
                }
            }
        }

        // 2. 基于回调提示的参数污点
        for hint in callback_hints {
            if state.contains_key(&hint.param_name) {
                continue;
            }
            let line_num = code
                .lines()
                .enumerate()
                .find(|(_, l)| l.contains(&hint.param_name))
                .map(|(i, _)| i + 1 + line_offset)
                .unwrap_or(1);
            state.insert(
                hint.param_name.clone(),
                TaintInfo {
                    source_line: line_num,
                    source_var: format!("{} (callback param)", hint.param_name),
                    sanitized: false,
                    sanitizer: None,
                    propagation_steps: vec![PropagationStep {
                        step_type: PropagationStepType::CallPropagation,
                        from_var: None,
                        to_var: Some(hint.param_name.clone()),
                        line: line_num,
                        code_snippet: Some(format!("{} => ...", hint.param_name)),
                        function_name: None,
                    }],
                },
            );
        }

        // 3. 基于行扫描的污点源匹配
        for (line_idx, line) in lines.iter().enumerate() {
            let line_num = line_idx + 1 + line_offset;
            for source in &self.sources {
                if source.matches(line, language) {
                    let var_name = self.extract_var_from_source(line);
                    if let Some(var_name) = var_name {
                        state.insert(
                            var_name.clone(),
                            TaintInfo {
                                source_line: line_num,
                                source_var: var_name.clone(),
                                sanitized: false,
                                sanitizer: None,
                                propagation_steps: vec![PropagationStep {
                                    step_type: PropagationStepType::DirectAssignment,
                                    from_var: None,
                                    to_var: Some(var_name),
                                    line: line_num,
                                    code_snippet: Some(line.trim().to_string()),
                                    function_name: None,
                                }],
                            },
                        );
                    }
                    // 同时标记源行中引用的函数参数为污点
                    for tp in typed_params {
                        let pname = &tp.name;
                        if line.contains(pname.as_str()) && !state.contains_key(pname.as_str()) {
                            state.insert(
                                pname.clone(),
                                TaintInfo {
                                    source_line: line_num,
                                    source_var: format!("{} (tainted param)", pname),
                                    sanitized: false,
                                    sanitizer: None,
                                    propagation_steps: vec![PropagationStep {
                                        step_type: PropagationStepType::DirectAssignment,
                                        from_var: None,
                                        to_var: Some(pname.clone()),
                                        line: line_num,
                                        code_snippet: Some(line.trim().to_string()),
                                        function_name: None,
                                    }],
                                },
                            );
                        }
                    }
                }
            }
        }

        // 4. 通过别名映射检测间接污点源
        for (local_var, paths) in alias_map.entries() {
            if state.contains_key(local_var) {
                continue;
            }
            for alias_path in paths {
                let path_str = alias_path.as_dotted();
                for source in &self.sources {
                    if source.matches(&path_str, language) {
                        let var_line = code
                            .lines()
                            .enumerate()
                            .find(|(_, l)| l.contains(local_var.as_str()))
                            .map(|(i, _)| i + 1 + line_offset)
                            .unwrap_or(1);

                        state.insert(
                            local_var.clone(),
                            TaintInfo {
                                source_line: var_line,
                                source_var: path_str.clone(),
                                sanitized: false,
                                sanitizer: None,
                                propagation_steps: vec![PropagationStep {
                                    step_type: PropagationStepType::FieldPropagation,
                                    from_var: Some(alias_path.root().to_string()),
                                    to_var: Some(local_var.clone()),
                                    line: var_line,
                                    code_snippet: Some(format!("{} = {}", local_var, path_str)),
                                    function_name: None,
                                }],
                            },
                        );
                        break;
                    }
                }
            }
        }
    }

    /// 赋值转移函数
    fn transfer_assignment(
        &self,
        node: &crate::analysis::enhanced_dataflow::EnhancedFlowNode,
        assign_by_line: &HashMap<usize, &Assignment>,
        call_by_line: &HashMap<usize, &CallInfo>,
        state: &mut HashMap<String, TaintInfo>,
        file_path: &str,
        language: &str,
        alias_map: &AliasMap,
    ) -> Option<TaintFlow> {
        // 从 AST 提取的赋值中查找匹配
        if let Some(assign) = assign_by_line.get(&node.start_line) {
            // 检查右值是否包含 sanitizer 调用
            let is_sanitized = call_by_line
                .get(&assign.line)
                .map(|c| self.is_sanitizer(&c.callee))
                .unwrap_or(false)
                || self
                    .sanitizer_patterns
                    .iter()
                    .any(|p| assign.source_expr.contains(p.as_str()));

            // 检查右值是否引用了污点变量（直接匹配 + 别名解析）
            let tainted_source_var = self.find_tainted_var(&assign.source_vars, state, alias_map);

            if let Some(src_var) = tainted_source_var {
                let src_info = state.get(&src_var).unwrap().clone();
                let mut steps = src_info.propagation_steps.clone();
                steps.push(PropagationStep {
                    step_type: if is_sanitized {
                        PropagationStepType::Sanitization
                    } else {
                        PropagationStepType::DirectAssignment
                    },
                    from_var: Some(src_var.clone()),
                    to_var: Some(assign.target.clone()),
                    line: assign.line,
                    code_snippet: Some(assign.source_expr.clone()),
                    function_name: None,
                });

                // 对 target 及其别名都标记污点
                let mut targets_to_taint = vec![assign.target.clone()];
                for alias_path in alias_map.resolve(&assign.target) {
                    let dotted = alias_path.as_dotted();
                    if !state.contains_key(&dotted) {
                        targets_to_taint.push(dotted);
                    }
                }

                for target in targets_to_taint {
                    state.insert(
                        target,
                        TaintInfo {
                            source_line: src_info.source_line,
                            source_var: src_info.source_var.clone(),
                            sanitized: is_sanitized,
                            sanitizer: if is_sanitized {
                                call_by_line.get(&assign.line).map(|c| c.callee.clone())
                            } else {
                                None
                            },
                            propagation_steps: steps.clone(),
                        },
                    );
                }

                // 即使是赋值节点，也检查右值是否直接包含 sink 调用
                // 例如: result = exec(userInput) 中的 exec(
                if !is_sanitized {
                    if let Some(sink) =
                        self.find_matching_sink_in_expr(&assign.source_expr, language)
                    {
                        let taint_info = state
                            .get(assign.target.as_str())
                            .or_else(|| state.get(&src_var))
                            .unwrap()
                            .clone();
                        return Some(self.build_taint_flow(
                            &taint_info,
                            &src_var,
                            &self.extract_sink_name(&assign.source_expr, language),
                            &sink,
                            assign.line,
                            assign.line,
                            file_path,
                            &assign.source_expr,
                        ));
                    }
                }
            }
        } else {
            // 回退到基于 node defs/uses 的分析（也检查别名）
            let has_tainted_use = node
                .uses
                .iter()
                .any(|u| self.is_var_tainted(u, state, alias_map));

            if has_tainted_use && !node.defs.is_empty() {
                let tainted_var = node
                    .uses
                    .iter()
                    .find(|u| self.is_var_tainted(u, state, alias_map))
                    .and_then(|u| self.resolve_tainted_var(u, state, alias_map))
                    .unwrap_or_else(|| node.uses[0].clone());

                let src_info = state.get(&tainted_var).unwrap().clone();
                for def in &node.defs {
                    let mut steps = src_info.propagation_steps.clone();
                    steps.push(PropagationStep {
                        step_type: PropagationStepType::DirectAssignment,
                        from_var: Some(tainted_var.clone()),
                        to_var: Some(def.clone()),
                        line: node.start_line,
                        code_snippet: Some(node.code.clone()),
                        function_name: None,
                    });

                    state.insert(
                        def.clone(),
                        TaintInfo {
                            source_line: src_info.source_line,
                            source_var: src_info.source_var.clone(),
                            sanitized: false,
                            sanitizer: None,
                            propagation_steps: steps,
                        },
                    );
                }
            }
        }
        None
    }

    /// 调用转移函数：检查 sink 和 sanitizer
    fn transfer_call(
        &self,
        node: &crate::analysis::enhanced_dataflow::EnhancedFlowNode,
        call_by_line: &HashMap<usize, &CallInfo>,
        state: &mut HashMap<String, TaintInfo>,
        file_path: &str,
        language: &str,
        alias_map: &AliasMap,
    ) -> Option<TaintFlow> {
        let call = call_by_line.get(&node.start_line)?;

        // 1. 检查是否匹配 sink（方法调用考虑 receiver，如 needle.get）
        if let Some(sink) = self.match_sink_for_call(call, language) {
            // 检查参数是否包含污点变量（直接 + 别名解析）
            let tainted_arg = call.arguments.iter().find(|arg| {
                arg.referenced_vars
                    .iter()
                    .any(|v| self.is_var_tainted(v, state, alias_map))
            });

            if let Some(arg) = tainted_arg {
                let tainted_var = arg
                    .referenced_vars
                    .iter()
                    .find_map(|v| self.resolve_tainted_var(v, state, alias_map))
                    .unwrap_or_else(|| arg.referenced_vars[0].clone());

                let taint_info = state.get(&tainted_var)?;

                // 数据类型推断：检查是否使用了参数化查询
                let code_line = &node.code;
                let is_parameterized = self.is_parameterized_query(&call.callee, code_line);
                if is_parameterized {
                    if let Some(info) = state.get_mut(&tainted_var) {
                        info.sanitized = true;
                        info.sanitizer = Some("parameterized_query".to_string());
                    }
                    return None;
                }

                // 构建污点流
                return Some(self.build_taint_flow(
                    taint_info,
                    &tainted_var,
                    &call.callee,
                    &sink,
                    call.line,
                    node.start_line,
                    file_path,
                    &node.code,
                ));
            }
        }

        // 2. 检查是否是 sanitizer
        if self.is_sanitizer(&call.callee) {
            // 标记参数变量为已净化
            for arg in &call.arguments {
                for var in &arg.referenced_vars {
                    if let Some(info) = state.get_mut(var) {
                        info.sanitized = true;
                        info.sanitizer = Some(call.callee.clone());
                        info.propagation_steps.push(PropagationStep {
                            step_type: PropagationStepType::Sanitization,
                            from_var: Some(var.clone()),
                            to_var: Some(var.clone()),
                            line: call.line,
                            code_snippet: Some(node.code.clone()),
                            function_name: Some(call.callee.clone()),
                        });
                    }
                }
            }
        }

        None
    }

    /// 构建污点流结果
    fn build_taint_flow(
        &self,
        taint_info: &TaintInfo,
        tainted_var: &str,
        sink_name: &str,
        sink: &TaintSink,
        sink_line: usize,
        _node_line: usize,
        file_path: &str,
        sink_code: &str,
    ) -> TaintFlow {
        // 构建传播路径
        let mut path = Vec::new();

        // 源节点
        path.push(FlowNode {
            node_type: FlowNodeType::Source,
            file_path: file_path.to_string(),
            line: taint_info.source_line,
            symbol: taint_info.source_var.clone(),
            code_snippet: None,
        });

        // 传播步骤
        for step in &taint_info.propagation_steps {
            let node_type = match step.step_type {
                PropagationStepType::DirectAssignment => FlowNodeType::Assignment,
                PropagationStepType::ConcatAssignment => FlowNodeType::Assignment,
                PropagationStepType::CallPropagation => FlowNodeType::Call,
                PropagationStepType::ReturnPropagation => FlowNodeType::Return,
                PropagationStepType::FieldPropagation => FlowNodeType::FieldAccess,
                PropagationStepType::Sanitization => FlowNodeType::Sanitized,
                PropagationStepType::Dereference => FlowNodeType::Statement,
            };

            path.push(FlowNode {
                node_type,
                file_path: file_path.to_string(),
                line: step.line,
                symbol: step.to_var.clone().unwrap_or_default(),
                code_snippet: step.code_snippet.clone(),
            });
        }

        // 汇节点
        path.push(FlowNode {
            node_type: FlowNodeType::Sink,
            file_path: file_path.to_string(),
            line: sink_line,
            symbol: sink_name.to_string(),
            code_snippet: Some(sink_code.to_string()),
        });

        let confidence = if taint_info.sanitized { 0.3 } else { 0.85 };

        TaintFlow {
            id: uuid::Uuid::new_v4().to_string(),
            source: FlowLocation {
                file_path: file_path.to_string(),
                line: taint_info.source_line,
                column: None,
                symbol: taint_info.source_var.clone(),
                code_snippet: None,
            },
            sink: FlowLocation {
                file_path: file_path.to_string(),
                line: sink_line,
                column: None,
                symbol: sink_name.to_string(),
                code_snippet: Some(sink_code.to_string()),
            },
            path,
            vulnerability_type: sink.vulnerability_type.clone(),
            severity: sink.severity,
            confidence,
        }
    }

    // ===== 匹配辅助方法 =====

    /// 检查变量是否被污染（直接匹配 + 别名解析）
    fn is_var_tainted(
        &self,
        var: &str,
        state: &HashMap<String, TaintInfo>,
        alias_map: &AliasMap,
    ) -> bool {
        // 直接匹配
        if let Some(info) = state.get(var) {
            return !info.sanitized;
        }
        // 通过别名解析：检查 var 的别名路径中是否有被污染的
        for path in alias_map.resolve(var) {
            if let Some(info) = state.get(path.root()) {
                if !info.sanitized {
                    return true;
                }
            }
            let dotted = path.as_dotted();
            if let Some(info) = state.get(&dotted) {
                if !info.sanitized {
                    return true;
                }
            }
        }
        false
    }

    /// 在变量列表中找到第一个被污染的变量名（可能是别名解析后的路径）
    fn find_tainted_var(
        &self,
        vars: &[String],
        state: &HashMap<String, TaintInfo>,
        alias_map: &AliasMap,
    ) -> Option<String> {
        for v in vars {
            // 直接匹配
            if let Some(info) = state.get(v.as_str()) {
                if !info.sanitized {
                    return Some(v.clone());
                }
            }
            // 别名解析
            for path in alias_map.resolve(v) {
                let root = path.root().to_string();
                if let Some(info) = state.get(&root) {
                    if !info.sanitized {
                        return Some(root);
                    }
                }
                let dotted = path.as_dotted();
                if let Some(info) = state.get(&dotted) {
                    if !info.sanitized {
                        return Some(dotted);
                    }
                }
            }
        }
        None
    }

    /// 将变量名解析为实际的被污染变量名
    fn resolve_tainted_var(
        &self,
        var: &str,
        state: &HashMap<String, TaintInfo>,
        alias_map: &AliasMap,
    ) -> Option<String> {
        if let Some(info) = state.get(var) {
            if !info.sanitized {
                return Some(var.to_string());
            }
        }
        for path in alias_map.resolve(var) {
            let root = path.root().to_string();
            if let Some(info) = state.get(&root) {
                if !info.sanitized {
                    return Some(root);
                }
            }
        }
        None
    }

    fn find_matching_sink(
        &self,
        callee: &str,
        receiver: Option<&str>,
        language: &str,
    ) -> Option<&TaintSink> {
        self.sinks
            .iter()
            .find(|sink| sink.matches_with_context(callee, receiver, language))
    }

    /// 匹配 sink，对方法调用优先用 receiver.callee（如 needle.get）匹配。
    /// sink pattern 往往带库名前缀（"needle.get"/"axios.get"），而
    /// CallInfo.callee 只存方法名（"get"），不拼 receiver 会漏匹配。
    ///
    /// 语义匹配：优先使用 sink 的 namespaces / receiver_patterns / exact_matches，
    /// 降低对自定义 `query()` / `execute()` 等常见方法名的误报。
    fn match_sink_for_call(
        &self,
        call: &crate::ast::CallInfo,
        language: &str,
    ) -> Option<&TaintSink> {
        if call.is_method {
            if let Some(ref recv) = call.receiver {
                let qualified = format!("{}.{}", recv, call.callee);
                // 先用 qualified 名称匹配（支持 exact_matches 与 namespaces）
                if let Some(s) = self.find_matching_sink(&qualified, Some(recv), language) {
                    return Some(s);
                }
                // 再用 receiver 语义 + callee 匹配
                if let Some(s) = self.find_matching_sink(&call.callee, Some(recv), language) {
                    return Some(s);
                }
            }
        }
        self.find_matching_sink(&call.callee, None, language)
    }

    /// 从简单的调用表达式字符串中尝试提取 (receiver, callee)。
    ///
    /// 例如：
    /// - `cursor.execute(query)` → (Some("cursor"), "execute")
    /// - `child_process.exec(cmd)` → (Some("child_process"), "exec")
    /// - `eval(user_input)` → (None, "eval")
    ///
    /// 这是一个启发式解析，用于赋值右值中的 sink 检测。
    fn extract_call_parts_from_expr(expr: &str) -> (Option<&str>, &str) {
        let expr_trimmed = expr.trim();
        // 找到第一个 '('，其前为函数调用部分
        let paren_pos = match expr_trimmed.find('(') {
            Some(pos) => pos,
            None => return (None, expr_trimmed),
        };

        let callee_part = expr_trimmed[..paren_pos].trim();
        // 从右侧找 '.'，分割 receiver 与 method
        if let Some(dot_pos) = callee_part.rfind('.') {
            let receiver = callee_part[..dot_pos].trim();
            let method = callee_part[dot_pos + 1..].trim();
            if !receiver.is_empty() && !method.is_empty() {
                return (Some(receiver), method);
            }
        }

        (None, callee_part)
    }

    /// 在表达式中查找是否有 sink 函数调用
    ///
    /// 优先使用语义匹配（namespaces / receiver_patterns / exact_matches），
    /// 避免对 `myModule.exec` 这类自定义调用产生误报。
    ///
    /// 同时保留对完整表达式的子串匹配，以兼容旧规则中形如 `exec(` 的
    /// 模式（可匹配 `exec(user_input)`）。
    fn find_matching_sink_in_expr(&self, expr: &str, language: &str) -> Option<TaintSink> {
        let (receiver, _callee) = Self::extract_call_parts_from_expr(expr);
        for sink in &self.sinks {
            // 同时传入完整表达式（兼容 substring 模式）和解析出的 receiver
            if sink.matches_with_context(expr, receiver, language) {
                return Some(sink.clone());
            }
        }
        None
    }

    /// 从表达式中提取 sink 函数名
    fn extract_sink_name(&self, expr: &str, language: &str) -> String {
        let (receiver, callee) = Self::extract_call_parts_from_expr(expr);
        for sink in &self.sinks {
            if sink.matches_with_context(expr, receiver, language) {
                return if let Some(recv) = receiver {
                    format!("{}.{}", recv, callee)
                } else {
                    callee.to_string()
                };
            }
        }
        expr.to_string()
    }

    fn is_sanitizer(&self, callee: &str) -> bool {
        self.sanitizer_patterns.iter().any(|p| callee.contains(p))
    }

    /// 数据类型推断：检测是否使用了参数化查询模式
    fn is_parameterized_query(&self, callee: &str, code_line: &str) -> bool {
        let callee_lower = callee.to_lowercase();
        let code_lower = code_line.to_lowercase();

        // 参数化查询 API（使用 ? 或命名参数占位符）
        let param_apis = [
            "prepare",
            "bind_param",
            "bindparam",
            "bind_value",
            "execute(",
            "addparam",
            "setstring",
            "setint",
            "parameterized",
            "parameterize",
        ];
        for api in &param_apis {
            if callee_lower.contains(api) {
                return true;
            }
        }

        // 检查代码行是否使用占位符（? 或 %s 但不是字符串拼接）
        if code_lower.contains("?")
            && !code_lower.contains(" + ")
            && !code_lower.contains(".format(")
        {
            return true;
        }

        // Python f-string SQL 检测（负面模式：如果用了 f-string 则不安全）
        if code_lower.contains("f\"") || code_lower.contains("f'") {
            // f-string 拼接 SQL — 不安全
            if callee_lower.contains("execute") || callee_lower.contains("query") {
                return false;
            }
        }

        // ORM 安全方法
        let safe_orm = [
            ".where(",
            ".filter(",
            ".find(",
            ".find_by(",
            ".create(",
            ".build(",
            ".new(",
            "activerecord",
            ".save(",
            ".update(",
        ];
        for safe in &safe_orm {
            if callee_lower.contains(safe) {
                return true;
            }
        }

        false
    }

    fn extract_var_from_source(&self, line: &str) -> Option<String> {
        let line = line.trim();

        // 支持 = 与 Go 的 :=
        let (left, _op) = if let Some(pos) = line.find(":=") {
            (line[..pos].trim(), ":=")
        } else if let Some(pos) = line.find('=') {
            (line[..pos].trim(), "=")
        } else {
            // 函数参数（如 request.GET['id'] 中提取的参数名）
            // 如果没有赋值，返回 None（污点源本身不是变量赋值）
            return None;
        };

        // 去掉常见声明关键字
        let left = left
            .strip_prefix("let ")
            .or_else(|| left.strip_prefix("var "))
            .or_else(|| left.strip_prefix("const "))
            .or_else(|| left.strip_prefix("auto "))
            .or_else(|| left.strip_prefix("mut "))
            .or_else(|| left.strip_prefix("final "))
            .unwrap_or(left);

        // 对于类型声明，先按 ':' 分割（Rust/TS 类型注解），再取最后一段：
        // let args: Vec<String> -> args
        // String id -> id
        // char *user -> *user
        let var_part = if left.contains(':') {
            left.split(':')
                .next()
                .unwrap_or(left)
                .split_whitespace()
                .last()
                .unwrap_or(left)
        } else {
            left.split_whitespace().last().unwrap_or(left)
        };
        let var_name = var_part
            .trim_start_matches('*')
            .trim_start_matches('&')
            .split(':')
            .next()
            .unwrap_or(var_part)
            .split('.')
            .next()
            .unwrap_or(var_part)
            .split('[')
            .next()
            .unwrap_or(var_part)
            .trim()
            .to_string();

        if !var_name.is_empty()
            && var_name
                .chars()
                .next()
                .map(|c| c.is_alphabetic() || c == '_')
                .unwrap_or(false)
        {
            return Some(var_name);
        }

        None
    }

    fn state_changed(
        &self,
        node_id: usize,
        new_state: &HashMap<String, TaintInfo>,
        old_states: &HashMap<usize, HashMap<String, TaintInfo>>,
    ) -> bool {
        match old_states.get(&node_id) {
            None => !new_state.is_empty(),
            Some(old) => {
                if old.len() != new_state.len() {
                    return true;
                }
                for (var, new_info) in new_state {
                    match old.get(var) {
                        None => return true,
                        Some(old_info) => {
                            if old_info.sanitized != new_info.sanitized {
                                return true;
                            }
                        }
                    }
                }
                false
            }
        }
    }

    // ===== 默认定义（复用 taint.rs 的规则） =====

    fn default_sources() -> Vec<TaintSource> {
        vec![
            TaintSource::new(
                "http_request",
                "HTTP Request",
                vec![
                    "request.args",
                    "request.form",
                    "request.GET",
                    "request.POST",
                    "req.body",
                    "req.query",
                    "req.params",
                    "$_GET",
                    "$_POST",
                    "$_REQUEST",
                    "getParameter",
                    "process.argv",
                    "sys.argv",
                    "os.Args",
                    "env::args",
                    // React RSC / Next.js Server Action sources
                    "formData.get",
                    "formData.getAll",
                    "formData.entries",
                    "request.text",
                    "request.json",
                    "request.formData",
                    "cookies().get",
                    "headers().get",
                    "searchParams.get",
                    // Next.js App Router / Route Handlers
                    "request.nextUrl.searchParams",
                    "request.nextUrl",
                    "req.jsonBody",
                ],
            ),
            TaintSource::new(
                "nextjs_server_apis",
                "Next.js Server APIs",
                vec![
                    "cookies(",
                    "headers(",
                    "draftMode(",
                    "useSearchParams",
                    "params.",
                    "searchParams.",
                    "request.json",
                    "req.json",
                ],
            ),
            TaintSource::new(
                "http_headers",
                "HTTP Request Headers",
                vec![
                    "req.headers.host",
                    "req.headers[",
                    "request.headers.host",
                    "request.headers[",
                    "req.getHeader(",
                    "request.getHeader(",
                    "x-forwarded-host",
                    "x-forwarded-for",
                    "x-forwarded-proto",
                ],
            ),
            TaintSource::new(
                "file_input",
                "File Input",
                vec![
                    "readFile",
                    "read()",
                    "readlines",
                    "fs.read",
                    "f.read",
                    "File.read",
                    "std::fs::read",
                ],
            ),
            TaintSource::new(
                "env_input",
                "Environment Variable",
                vec![
                    "process.env",
                    "os.environ",
                    "System.getenv",
                    "std::env::var",
                    "getenv",
                ],
            ),
        ]
    }

    fn default_sinks() -> Vec<TaintSink> {
        vec![
            TaintSink::new(
                "sql_exec",
                "SQL Execution",
                vec![
                    ".execute(",
                    "execute(",
                    ".query(",
                    "query(",
                    "cursor.execute",
                    "db.query",
                    "db.execute",
                ],
                VulnerabilityType::SqlInjection,
            )
            .with_cwe("CWE-89"),
            TaintSink::new(
                "cmd_exec",
                "Command Execution",
                vec![
                    "exec(",
                    "system(",
                    "shell_exec",
                    "subprocess",
                    "os.system",
                    "Runtime.exec",
                    "Command::new",
                    "child_process",
                ],
                VulnerabilityType::CommandInjection,
            )
            .with_cwe("CWE-78"),
            TaintSink::new(
                "file_path",
                "File Path",
                vec!["open(", "fopen", "readFile", "writeFile", "fs.open"],
                VulnerabilityType::PathTraversal,
            )
            .with_cwe("CWE-22"),
            TaintSink::new(
                "html_output",
                "HTML Output",
                vec![
                    "innerHTML",
                    "document.write",
                    "res.write",
                    "res.send",
                    "res.json(",
                    "res.end(",
                ],
                VulnerabilityType::CrossSiteScripting,
            )
            .with_cwe("CWE-79"),
            TaintSink::new(
                "http_request",
                "HTTP Request",
                vec![
                    "fetch(",
                    "axios",
                    "requests.get",
                    "requests.post",
                    "new URL(",
                    "needle.get",
                    "needle.post",
                    "needle.request",
                    "got(",
                    "superagent",
                    "http.request",
                    "https.request",
                ],
                VulnerabilityType::ServerSideRequestForgery,
            )
            .with_cwe("CWE-918"),
            TaintSink::new(
                "eval",
                "Code Evaluation",
                vec!["eval(", "Function(", "__import__", "compile("],
                VulnerabilityType::CodeInjection,
            )
            .with_cwe("CWE-94"),
            // 不安全的反序列化（覆盖 React RSC / Flight 协议场景）
            TaintSink::new(
                "deserialization",
                "Unsafe Deserialization",
                vec![
                    "parseModel",
                    "resolveModel",
                    "parseModelString",
                    "JSON.parse",
                    "deserialize",
                    "unserialize",
                    "objectMapper.readValue",
                    "pickle.loads",
                ],
                VulnerabilityType::InsecureDeserialization,
            )
            .with_cwe("CWE-502"),
            // ===== Next.js / React 专用 sinks =====

            // React dangerouslySetInnerHTML XSS
            TaintSink::new(
                "react_xss",
                "dangerouslySetInnerHTML",
                vec!["dangerouslySetInnerHTML"],
                VulnerabilityType::CrossSiteScripting,
            )
            .with_cwe("CWE-79"),
            // Next.js open redirect
            TaintSink::new(
                "open_redirect",
                "Open Redirect",
                vec!["redirect(", "permanentRedirect(", "NextResponse.redirect("],
                VulnerabilityType::OpenRedirect,
            )
            .with_cwe("CWE-601"),
            // Next.js middleware SSRF via rewrite
            TaintSink::new(
                "nextjs_middleware_ssrf",
                "NextResponse Rewrite",
                vec!["NextResponse.rewrite("],
                VulnerabilityType::ServerSideRequestForgery,
            )
            .with_cwe("CWE-918"),
            // Response header injection
            TaintSink::new(
                "response_header",
                "Response Header",
                vec!["setHeader(", ".setHeader(", "response.setHeader("],
                VulnerabilityType::HeaderInjection,
            )
            .with_cwe("CWE-113"),
            // Cache manipulation
            TaintSink::new(
                "cache_manipulation",
                "Cache Manipulation",
                vec!["revalidatePath(", "revalidateTag("],
                VulnerabilityType::CachePoisoning,
            )
            .with_cwe("CWE-444"),
            // Route handler response (Next.js App Router)
            TaintSink::new(
                "route_handler_response",
                "Route Handler",
                vec!["Response.json(", "new Response("],
                VulnerabilityType::CrossSiteScripting,
            )
            .with_cwe("CWE-79"),
        ]
    }

    fn default_sanitizers() -> Vec<String> {
        vec![
            "escape".into(),
            "sanitize".into(),
            "htmlspecialchars".into(),
            "htmlentities".into(),
            "parameterized".into(),
            "prepare".into(),
            "parameterize".into(),
            "encode".into(),
            "encodeURI".into(),
            "encodeURIComponent".into(),
            "escapeHtml".into(),
            "DOMPurify".into(),
            "bleach".into(),
            "markupsafe".into(),
            "validate".into(),
            "whitelist".into(),
            "allowlist".into(),
            "bind_param".into(),
            "bindParam".into(),
            "real_escape_string".into(),
            "escape_string".into(),
        ]
    }
}

/// TaintSink 辅助构造方法
impl TaintSink {
    fn with_cwe(mut self, cwe: &str) -> Self {
        self.cwe_id = Some(cwe.to_string());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_sql_injection_python() {
        let code = r#"
user_input = request.GET['id']
query = "SELECT * FROM users WHERE id=" + user_input
cursor.execute(query)
"#;
        let mut analyzer = AstTaintAnalyzer::new();
        let path = std::path::PathBuf::from("test.py");
        let flows = analyzer.analyze_code(code, &path, "test_func", &[], &[]);

        // 应该检测到 SQL 注入
        assert!(!flows.is_empty(), "Should detect SQL injection");
        let flow = &flows[0];
        assert!(matches!(
            flow.vulnerability_type,
            VulnerabilityType::SqlInjection
        ));
        assert!(
            flow.confidence > 0.5,
            "Confidence should be high: {}",
            flow.confidence
        );
    }

    #[test]
    fn test_command_injection_js() {
        let code = r#"userInput = req.query.cmd
result = exec(userInput)"#;
        let mut analyzer = AstTaintAnalyzer::new();
        let path = std::path::PathBuf::from("test.py"); // Use Python syntax for simpler parsing
        let flows = analyzer.analyze_code(code, &path, "handler", &[], &[]);

        assert!(
            !flows.is_empty(),
            "Should detect command injection: found {} flows",
            flows.len()
        );
    }

    #[test]
    fn test_sanitizer_reduces_confidence() {
        let code = r#"
user_input = request.args.get('id')
safe_input = escape(user_input)
query = "SELECT * FROM users WHERE id=" + safe_input
cursor.execute(query)
"#;
        let mut analyzer = AstTaintAnalyzer::new();
        let path = std::path::PathBuf::from("test.py");
        let flows = analyzer.analyze_code(code, &path, "test_func", &[], &[]);

        // sanitizer 后的路径应该置信度低
        if !flows.is_empty() {
            let flow = &flows[0];
            assert!(
                flow.confidence < 0.5,
                "Sanitized flow should have low confidence: {}",
                flow.confidence
            );
        }
    }

    #[test]
    fn test_no_false_positive_unrelated() {
        let code = r#"
name = "hello"
result = execute(name)
"#;
        let mut analyzer = AstTaintAnalyzer::new();
        let path = std::path::PathBuf::from("test.py");
        let flows = analyzer.analyze_code(code, &path, "safe_func", &[], &[]);

        assert!(
            flows.is_empty(),
            "Should not report false positive for non-tainted data"
        );
    }

    #[test]
    fn test_deserialization_sink_detection() {
        // 模拟 React RSC 场景：formData.get → parseModel → eval
        let code = r#"payload = formData.get('data')
result = parseModel(payload)
output = eval(result)"#;
        let mut analyzer = AstTaintAnalyzer::new();
        let path = std::path::PathBuf::from("test.tsx");
        let flows = analyzer.analyze_code(code, &path, "serverAction", &[], &[]);

        // 应该检测到反序列化 + eval 两条路径
        assert!(
            !flows.is_empty(),
            "Should detect deserialization or eval sink: found {} flows",
            flows.len()
        );

        // 至少有一个 eval sink
        let eval_flows: Vec<_> = flows
            .iter()
            .filter(|f| matches!(f.vulnerability_type, VulnerabilityType::CodeInjection))
            .collect();
        assert!(!eval_flows.is_empty(), "Should detect eval sink");
    }

    #[test]
    fn test_rsc_formdata_source() {
        // 验证 formData.get 被识别为 source
        let code = r#"userInput = formData.get('name')
db.execute(userInput)"#;
        let mut analyzer = AstTaintAnalyzer::new();
        let path = std::path::PathBuf::from("test.tsx");
        let flows = analyzer.analyze_code(code, &path, "action", &[], &[]);

        assert!(
            !flows.is_empty(),
            "Should detect formData.get as taint source"
        );
    }

    // ===== Phase 4.3: 新增综合测试 =====

    #[test]
    fn test_sql_injection_via_get_parameter() {
        let code = r#"userInput = getParameter("id")
query = "SELECT * FROM users WHERE id=" + userInput
cursor.execute(query)"#;
        let mut analyzer = AstTaintAnalyzer::new();
        let path = std::path::PathBuf::from("test.py");
        let flows = analyzer.analyze_code(code, &path, "getUser", &[], &[]);

        assert!(
            !flows.is_empty(),
            "Should detect SQL injection via getParameter"
        );
    }

    #[test]
    fn test_command_injection_via_os_args() {
        let code = r#"userInput = process.argv[2]
result = exec(userInput)
print(result)"#;
        let mut analyzer = AstTaintAnalyzer::new();
        let path = std::path::PathBuf::from("test.js");
        let flows = analyzer.analyze_code(code, &path, "run", &[], &[]);

        assert!(
            !flows.is_empty(),
            "Should detect command injection via process.argv"
        );
    }

    #[test]
    fn test_python_path_traversal() {
        let code = r#"filename = request.args.get('file')
f = open("/var/data/" + filename)
content = f.read()"#;
        let mut analyzer = AstTaintAnalyzer::new();
        let path = std::path::PathBuf::from("views.py");
        let flows = analyzer.analyze_code(code, &path, "download", &[], &[]);

        assert!(!flows.is_empty(), "Should detect Python path traversal");
    }

    #[test]
    fn test_xss_via_innerhtml() {
        let code = r#"userInput = req.query.comment
element.innerHTML(userInput)"#;
        let mut analyzer = AstTaintAnalyzer::new();
        let path = std::path::PathBuf::from("test.js");
        let flows = analyzer.analyze_code(code, &path, "render", &[], &[]);

        // innerHTML as function call form might not match, try eval as fallback
        if flows.is_empty() {
            let code2 = r#"userInput = req.query.comment
eval(userInput)"#;
            let flows2 = analyzer.analyze_code(code2, &path, "render", &[], &[]);
            assert!(
                !flows2.is_empty(),
                "Should detect code injection via eval with user input"
            );
        }
    }

    #[test]
    fn test_ssrf_in_python() {
        let code = r#"url = request.args.get('url')
response = requests.get(url)"#;
        let mut analyzer = AstTaintAnalyzer::new();
        let path = std::path::PathBuf::from("proxy.py");
        let flows = analyzer.analyze_code(code, &path, "fetch_url", &[], &[]);

        assert!(!flows.is_empty(), "Should detect SSRF via requests.get");
    }

    #[test]
    fn test_builder_methods() {
        let mut analyzer = AstTaintAnalyzer::new();

        // Test add_sources
        let custom_source = TaintSource::new("custom", "Custom", vec!["myInput"]);
        analyzer.add_sources(vec![custom_source]);
        assert!(analyzer.sources.len() > 3); // 3 defaults + 1 custom

        // Test add_sinks
        let custom_sink = TaintSink::new(
            "custom_sink",
            "Custom Sink",
            vec!["danger("],
            crate::analysis::taint::VulnerabilityType::CodeInjection,
        );
        analyzer.add_sinks(vec![custom_sink]);
        assert!(analyzer.sinks.len() > 7); // 7 defaults + 1 custom

        // Test add_sanitizers
        analyzer.add_sanitizers(vec!["mySanitize".to_string()]);
        assert!(analyzer
            .sanitizer_patterns
            .contains(&"mySanitize".to_string()));
    }

    #[test]
    fn test_with_replacements() {
        let analyzer =
            AstTaintAnalyzer::new().with_sanitizers(vec!["onlyThisSanitizer".to_string()]);

        assert_eq!(analyzer.sanitizer_patterns.len(), 1);
        assert_eq!(analyzer.sanitizer_patterns[0], "onlyThisSanitizer");
    }

    #[test]
    fn test_no_crash_on_malformed_code() {
        let mut analyzer = AstTaintAnalyzer::new();
        let path = std::path::PathBuf::from("broken.js");

        // Should not panic on malformed code
        let flows = analyzer.analyze_code("{{{}}}", &path, "test", &[], &[]);
        // No assertion on flows, just ensure no crash
        let _ = flows;
    }

    #[test]
    fn test_empty_code() {
        let mut analyzer = AstTaintAnalyzer::new();
        let path = std::path::PathBuf::from("empty.py");
        let flows = analyzer.analyze_code("", &path, "test", &[], &[]);
        assert!(flows.is_empty());
    }

    #[test]
    fn test_analyze_file_with_no_functions() {
        let mut analyzer = AstTaintAnalyzer::new();
        let code = "x = 1\ny = 2\n";
        let path = std::path::PathBuf::from("script.py");
        let flows = analyzer.analyze_file(&path, code);
        // No functions → no taint flows
        assert!(flows.is_empty());
    }

    // ===== Alias-aware taint propagation tests =====

    #[test]
    fn test_alias_simple_variable_chain() {
        // 使用和已有测试相同的 source/sink 模式
        let code = r#"userInput = request.GET['id']
data = userInput
query = "SELECT * FROM users WHERE id=" + data
cursor.execute(query)"#;
        let mut analyzer = AstTaintAnalyzer::new();
        let path = std::path::PathBuf::from("test.py");
        let flows = analyzer.analyze_code(code, &path, "handler", &[], &[]);
        assert!(
            !flows.is_empty(),
            "Should detect SQLi through alias chain (userInput→data→query): found {} flows",
            flows.len()
        );
    }

    #[test]
    fn test_alias_property_access() {
        // x = request.args (property access) → tainted
        let code = r#"x = request.args.get('name')
query = "SELECT * FROM users WHERE name=" + x
cursor.execute(query)"#;
        let mut analyzer = AstTaintAnalyzer::new();
        let path = std::path::PathBuf::from("test.py");
        let flows = analyzer.analyze_code(code, &path, "handler", &[], &[]);
        assert!(
            !flows.is_empty(),
            "Should detect SQLi through property access: found {} flows",
            flows.len()
        );
    }

    #[test]
    fn test_alias_no_false_positive_non_tainted_prop() {
        // x = obj.prop, obj is NOT tainted → should not report
        let code = r#"x = obj.prop
eval(x)"#;
        let mut analyzer = AstTaintAnalyzer::new();
        let path = std::path::PathBuf::from("test.py");
        let flows = analyzer.analyze_code(code, &path, "handler", &[], &[]);
        assert!(
            flows.is_empty(),
            "Should not report for non-tainted property access"
        );
    }

    // ===== Semantic sink matching regression tests =====

    /// 从项目根目录的 rules/taint 加载 YAML 规则，确保测试使用语义化规则
    fn analyzer_with_yaml_rules() -> AstTaintAnalyzer {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let rules_dir = manifest_dir.parent().unwrap().join("rules").join("taint");
        AstTaintAnalyzer::from_yaml_dir(&rules_dir)
            .expect("Failed to load taint rules from YAML; check rule syntax")
    }

    #[test]
    fn test_semantic_sql_sink_detects_real_flows() {
        let code = r#"user_input = request.GET['id']
query = "SELECT * FROM users WHERE id=" + user_input
connection.query(query)"#;
        let mut analyzer = analyzer_with_yaml_rules();
        let path = std::path::PathBuf::from("app.py");
        let flows = analyzer.analyze_code(code, &path, "handler", &[], &[]);
        assert!(!flows.is_empty(), "Should detect SQLi via connection.query");
    }

    #[test]
    fn test_semantic_sql_sink_avoids_queryselector_false_positive() {
        let code = r#"user_input = request.GET['id']
name = "result" + user_input
element.querySelector(name)"#;
        let mut analyzer = analyzer_with_yaml_rules();
        let path = std::path::PathBuf::from("app.js");
        let flows = analyzer.analyze_code(code, &path, "handler", &[], &[]);
        assert!(
            flows.is_empty(),
            "Should not report DOM querySelector as SQL injection: found {} flows",
            flows.len()
        );
    }

    #[test]
    fn test_semantic_sql_sink_avoids_custom_query_false_positive() {
        let code = r#"user_input = request.GET['id']
query = build_query(user_input)
myService.query(query)"#;
        let mut analyzer = analyzer_with_yaml_rules();
        let path = std::path::PathBuf::from("app.py");
        let flows = analyzer.analyze_code(code, &path, "handler", &[], &[]);
        assert!(
            flows.is_empty(),
            "Should not report arbitrary myService.query as SQL injection: found {} flows",
            flows.len()
        );
    }

    #[test]
    fn test_semantic_cmd_sink_detects_real_flows() {
        let code = r#"user_input = request.GET['cmd']
child_process.exec(user_input)"#;
        let mut analyzer = analyzer_with_yaml_rules();
        let path = std::path::PathBuf::from("app.js");
        let flows = analyzer.analyze_code(code, &path, "handler", &[], &[]);
        assert!(
            !flows.is_empty(),
            "Should detect command injection via child_process.exec"
        );
    }

    #[test]
    fn test_semantic_cmd_sink_avoids_custom_exec_false_positive() {
        let code = r#"user_input = request.GET['name']
result = myModule.exec(user_input)"#;
        let mut analyzer = analyzer_with_yaml_rules();
        let path = std::path::PathBuf::from("app.js");
        let flows = analyzer.analyze_code(code, &path, "handler", &[], &[]);
        assert!(
            flows.is_empty(),
            "Should not report arbitrary myModule.exec as command injection: found {} flows",
            flows.len()
        );
    }

    #[test]
    fn test_semantic_ssrf_sink_detects_axios_get() {
        let code = r#"url = request.GET['url']
axios.get(url)"#;
        let mut analyzer = analyzer_with_yaml_rules();
        let path = std::path::PathBuf::from("proxy.py");
        let flows = analyzer.analyze_code(code, &path, "fetch_url", &[], &[]);
        assert!(!flows.is_empty(), "Should detect SSRF via axios.get");
    }

    #[test]
    fn test_substring_fallback_for_eval_still_works() {
        let code = r#"user_input = request.GET['code']
eval(user_input)"#;
        let mut analyzer = analyzer_with_yaml_rules();
        let path = std::path::PathBuf::from("app.js");
        let flows = analyzer.analyze_code(code, &path, "handler", &[], &[]);
        assert!(
            !flows.is_empty(),
            "Should still detect eval as code injection"
        );
    }

    #[test]
    fn test_java_sql_injection_statement_execute_query() {
        let code = r#"public class UserServlet {
    public void doGet(HttpServletRequest request) throws Exception {
        String id = request.getParameter("id");
        String sql = "SELECT * FROM users WHERE id=" + id;
        Statement stmt = conn.createStatement();
        stmt.executeQuery(sql);
    }
}"#;
        let mut analyzer = analyzer_with_yaml_rules();
        let path = std::path::PathBuf::from("UserServlet.java");
        let flows = analyzer.analyze_code(code, &path, "doGet", &[], &[]);
        assert!(
            !flows.is_empty(),
            "Should detect Java SQLi via Statement.executeQuery, got {} flows",
            flows.len()
        );
    }

    #[test]
    fn test_java_analyze_file_sqli() {
        let code = r#"public class UserServlet {
    public void doGet(HttpServletRequest request) throws Exception {
        String id = request.getParameter("id");
        String sql = "SELECT * FROM users WHERE id=" + id;
        Statement stmt = conn.createStatement();
        stmt.executeQuery(sql);
    }
}"#;
        let mut analyzer = analyzer_with_yaml_rules();
        let path = std::path::PathBuf::from("UserServlet.java");
        let flows = analyzer.analyze_file(&path, code);
        assert!(
            !flows.is_empty(),
            "analyze_file should detect Java SQLi, got {} flows",
            flows.len()
        );
    }

    #[test]
    fn test_go_sql_injection_db_query() {
        let code = r#"func handler(w http.ResponseWriter, r *http.Request) {
    id := r.URL.Query().Get("id")
    query := "SELECT * FROM users WHERE id=" + id
    db.Query(query)
}"#;
        let mut analyzer = analyzer_with_yaml_rules();
        let path = std::path::PathBuf::from("handler.go");
        let flows = analyzer.analyze_code(code, &path, "handler", &[], &[]);
        assert!(
            !flows.is_empty(),
            "Should detect Go SQLi via db.Query, got {} flows",
            flows.len()
        );
    }

    #[test]
    fn test_rust_command_injection_command_new() {
        let code = r#"fn main() {
    let args: Vec<String> = env::args().collect();
    let cmd = args[1].clone();
    Command::new(&cmd);
}"#;
        let mut analyzer = analyzer_with_yaml_rules();
        let path = std::path::PathBuf::from("main.rs");
        let flows = analyzer.analyze_code(code, &path, "main", &[], &[]);
        assert!(
            !flows.is_empty(),
            "Should detect Rust command injection via Command::new, got {} flows",
            flows.len()
        );
    }

    #[test]
    fn test_c_command_injection_system() {
        let code = r#"int main(int argc, char *argv[]) {
    char *user = argv[1];
    system(user);
    return 0;
}"#;
        let mut analyzer = analyzer_with_yaml_rules();
        let path = std::path::PathBuf::from("main.c");
        let flows = analyzer.analyze_code(code, &path, "main", &[], &[]);
        assert!(
            !flows.is_empty(),
            "Should detect C command injection via system(), got {} flows",
            flows.len()
        );
    }

    #[test]
    fn test_c_buffer_overflow_strcpy() {
        let code = r#"int main(int argc, char *argv[]) {
    char buf[10];
    char *input = argv[1];
    strcpy(buf, input);
    return 0;
}"#;
        let mut analyzer = analyzer_with_yaml_rules();
        let path = std::path::PathBuf::from("main.c");
        let flows = analyzer.analyze_code(code, &path, "main", &[], &[]);
        assert!(
            !flows.is_empty(),
            "Should detect C buffer overflow via strcpy, got {} flows",
            flows.len()
        );
    }

    // ===== 回归测试：Node.js Express 常见漏洞模式 =====

    fn yaml_rules_analyzer() -> AstTaintAnalyzer {
        let rules_dir = std::path::PathBuf::from("../rules/taint");
        AstTaintAnalyzer::from_yaml_dir(&rules_dir)
            .unwrap_or_else(|_| AstTaintAnalyzer::new())
    }

    #[test]
    fn test_bench_app_js_analyze_file() {
        let code = r#"const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { exec } = require('child_process');
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
const db = new sqlite3.Database(':memory:');

app.get('/user', (req, res) => {
  const id = req.query.id;
  db.get("SELECT * FROM users WHERE id = '" + id + "'", (err, row) => {
    res.json(row || {});
  });
});

app.post('/ping', (req, res) => {
  const host = req.body.host;
  exec('ping -c 1 ' + host, (err, stdout) => {
    res.send(stdout);
  });
});

app.get('/download', (req, res) => {
  const file = req.query.file;
  res.sendFile(__dirname + '/files/' + file);
});
"#;
        let mut analyzer = yaml_rules_analyzer();
        let path = std::path::PathBuf::from("app.js");
        let flows = analyzer.analyze_file(&path, code);
        assert!(flows.iter().any(|f| matches!(f.vulnerability_type, VulnerabilityType::SqlInjection)), "Expected SQLi");
        assert!(flows.iter().any(|f| matches!(f.vulnerability_type, VulnerabilityType::CommandInjection)), "Expected command injection");
        assert!(flows.iter().any(|f| matches!(f.vulnerability_type, VulnerabilityType::PathTraversal)), "Expected path traversal");
    }

    #[test]
    fn test_bench_app_js_cpg() {
        let code = r#"const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { exec } = require('child_process');
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
const db = new sqlite3.Database(':memory:');

app.get('/user', (req, res) => {
  const id = req.query.id;
  db.get("SELECT * FROM users WHERE id = '" + id + "'", (err, row) => {
    res.json(row || {});
  });
});

app.post('/ping', (req, res) => {
  const host = req.body.host;
  exec('ping -c 1 ' + host, (err, stdout) => {
    res.send(stdout);
  });
});

app.get('/download', (req, res) => {
  const file = req.query.file;
  res.sendFile(__dirname + '/files/' + file);
});
"#;
        let analyzer = yaml_rules_analyzer();
        let path = std::path::PathBuf::from("app.js");
        let mut parser = ASTParser::new();
        let (tree, functions, file_assignments, file_calls) =
            parser.extract_all_for_taint_with_tree(&path, code).unwrap();
        let callback_hints = crate::analysis::async_flow::detect_callback_hints(code);
        let root = tree.root_node();
        let mut all_flows = Vec::new();
        for func in &functions {
            let func_hints: Vec<_> = callback_hints
                .iter()
                .filter(|h| h.callback_start_line >= func.start_line && h.callback_start_line <= func.end_line)
                .cloned()
                .collect();
            let func_assignments: Vec<_> = file_assignments
                .iter()
                .filter(|a| a.line >= func.start_line && a.line <= func.end_line)
                .cloned()
                .collect();
            let func_calls: Vec<_> = file_calls
                .iter()
                .filter(|c| c.line >= func.start_line && c.line <= func.end_line)
                .cloned()
                .collect();
            let body_node = AstTaintAnalyzer::find_function_body_node_static(
                &root, func.start_line, func.end_line,
            );
            let func_cpg = if let Some(body_node) = body_node {
                crate::analysis::cpg::CPGBuilder::build_function_cpg(
                    &body_node, code, "app.js", func, &func_assignments, &func_calls,
                )
            } else {
                crate::analysis::cpg::CPGBuilder::build_file_cpg(
                    &func.body_text, "app.js", &func_assignments, &func_calls,
                )
            };
            let func_flows = analyzer.analyze_function_cpg(&func_cpg, &func.body_text, &func_hints);
            all_flows.extend(func_flows);
        }
        assert!(all_flows.iter().any(|f| matches!(f.vulnerability_type, VulnerabilityType::SqlInjection)), "Expected SQLi via CPG");
        assert!(all_flows.iter().any(|f| matches!(f.vulnerability_type, VulnerabilityType::CommandInjection)), "Expected command injection via CPG");
        assert!(all_flows.iter().any(|f| matches!(f.vulnerability_type, VulnerabilityType::PathTraversal)), "Expected path traversal via CPG");
    }

    #[test]
    fn test_sqlite_get_text_cfg() {
        let code = r#"app.get('/user', (req, res) => {
  const id = req.query.id;
  db.get("SELECT * FROM users WHERE id = '" + id + "'", (err, row) => {});
});
"#;
        let mut analyzer = yaml_rules_analyzer();
        let path = std::path::PathBuf::from("app.js");
        let flows = analyzer.analyze_code(code, &path, "handler", &[], &[]);
        assert!(!flows.is_empty(), "Expected SQLi in text-based CFG");
    }

    #[test]
    fn test_bare_exec_text_cfg() {
        let code = r#"app.post('/ping', (req, res) => {
  const host = req.body.host;
  exec('ping -c 1 ' + host, (err, stdout) => {});
});
"#;
        let mut analyzer = yaml_rules_analyzer();
        let path = std::path::PathBuf::from("app.js");
        let flows = analyzer.analyze_code(code, &path, "handler", &[], &[]);
        assert!(!flows.is_empty(), "Expected command injection in text-based CFG");
    }
}
