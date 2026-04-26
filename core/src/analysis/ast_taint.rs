// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 基于 AST 的污点分析器
//!
//! 利用 tree-sitter AST 解析 + CFG 数据流分析，替代逐行文本匹配。
//! 核心流程：AST 解析 → 提取赋值/调用 → 构建 CFG → 前向污点传播（worklist 算法）

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;

use crate::ast::parser::ASTParser;
use crate::ast::symbol::{Assignment, CallInfo, FunctionBody};
use crate::analysis::enhanced_dataflow::{EdgeType, EnhancedFlowGraph, EnhancedNodeType};
use crate::analysis::taint::{
    FlowLocation, FlowNode, FlowNodeType, PropagationStep, PropagationStepType, Severity,
    TaintCategory, TaintFlow, TaintSink, TaintSource, VulnerabilityType,
};

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
        Self {
            sources: Self::default_sources(),
            sinks: Self::default_sinks(),
            sanitizer_patterns: Self::default_sanitizers(),
            ast_parser: ASTParser::new(),
        }
    }

    /// 分析单个文件，返回所有检测到的污点流
    pub fn analyze_file(&mut self, file_path: &Path, content: &str) -> Vec<TaintFlow> {
        let mut all_flows = Vec::new();

        // 1. 提取函数体（按函数粒度分析）
        let functions = self.ast_parser.extract_function_bodies(file_path, content);

        if functions.is_empty() {
            // 如果没有提取到函数，对整个文件做分析
            let flows = self.analyze_code(content, file_path, "");
            all_flows.extend(flows);
        } else {
            // 按函数逐个分析
            for func in &functions {
                let flows = self.analyze_code(&func.body_text, file_path, &func.name);
                all_flows.extend(flows);
            }
        }

        all_flows
    }

    /// 分析一段代码（函数体或完整文件）
    fn analyze_code(
        &mut self,
        code: &str,
        file_path: &Path,
        function_name: &str,
    ) -> Vec<TaintFlow> {
        let file_path_str = file_path.to_string_lossy().to_string();

        // 2. 用 AST 提取赋值和调用信息
        // 为提取信息，创建临时文件
        let tmp_path = std::path::PathBuf::from(&file_path_str);
        let assignments = self.ast_parser.extract_assignments(&tmp_path, code);
        let calls = self.ast_parser.extract_calls(&tmp_path, code);

        // 3. 构建基于 AST 的 CFG
        let cfg = EnhancedFlowGraph::from_code(code, &file_path_str, function_name);

        // 4. 前向污点传播
        self.forward_taint_analysis(&cfg, &assignments, &calls, code, &file_path_str)
    }

    /// 前向污点传播（worklist 算法）
    fn forward_taint_analysis(
        &self,
        cfg: &EnhancedFlowGraph,
        assignments: &[Assignment],
        calls: &[CallInfo],
        code: &str,
        file_path: &str,
    ) -> Vec<TaintFlow> {
        let mut flows = Vec::new();

        // 节点污点状态：node_id → (var_name → TaintInfo)
        let mut taint_state: HashMap<usize, HashMap<String, TaintInfo>> = HashMap::new();

        // 按行号索引赋值和调用，加速查找
        let assign_by_line: HashMap<usize, &Assignment> = assignments
            .iter()
            .map(|a| (a.line, a))
            .collect();
        let call_by_line: HashMap<usize, &CallInfo> = calls
            .iter()
            .map(|c| (c.line, c))
            .collect();

        // 初始化 worklist
        let mut worklist: VecDeque<usize> = VecDeque::new();
        worklist.push_back(cfg.entry);

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
                    // 入口节点：检查是否在函数参数中有污点源
                    self.check_entry_sources(node, code, &mut new_state);
                }

                EnhancedNodeType::Assignment => {
                    if let Some(flow) = self.transfer_assignment(node, &assign_by_line, &call_by_line, &mut new_state, file_path) {
                        flows.push(flow);
                    }
                }

                EnhancedNodeType::Call => {
                    if let Some(flow) = self.transfer_call(
                        node, &call_by_line, &mut new_state, file_path,
                    ) {
                        flows.push(flow);
                    }
                }

                EnhancedNodeType::Return => {
                    // 返回语句不需要特殊处理（函数摘要场景用）
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
                // 将后继加入 worklist
                for edge in &node.successors {
                    if !worklist.contains(&edge.target) {
                        worklist.push_back(edge.target);
                    }
                }
            }
        }

        flows
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

    /// 检查入口节点是否有污点源
    fn check_entry_sources(
        &self,
        node: &crate::analysis::enhanced_dataflow::EnhancedFlowNode,
        code: &str,
        state: &mut HashMap<String, TaintInfo>,
    ) {
        let lines: Vec<&str> = code.lines().collect();

        // 在整个代码中查找污点源
        for (line_idx, line) in lines.iter().enumerate() {
            let line_num = line_idx + 1;
            for source in &self.sources {
                if source.matches(line, "") {
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
    ) -> Option<TaintFlow> {
        // 从 AST 提取的赋值中查找匹配
        if let Some(assign) = assign_by_line.get(&node.start_line) {
            // 检查右值是否包含 sanitizer 调用
            let is_sanitized = call_by_line.get(&assign.line)
                .map(|c| self.is_sanitizer(&c.callee))
                .unwrap_or(false)
                || self.sanitizer_patterns.iter().any(|p| assign.source_expr.contains(p.as_str()));

            // 检查右值是否引用了污点变量
            let tainted_source_var = assign.source_vars.iter().find(|v| {
                let info = state.get(v.as_str());
                info.is_some() && !info.unwrap().sanitized
            });

            if let Some(src_var) = tainted_source_var {
                let src_info = state.get(src_var.as_str()).unwrap().clone();
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

                state.insert(
                    assign.target.clone(),
                    TaintInfo {
                        source_line: src_info.source_line,
                        source_var: src_info.source_var.clone(),
                        sanitized: is_sanitized,
                        sanitizer: if is_sanitized {
                            call_by_line.get(&assign.line).map(|c| c.callee.clone())
                        } else {
                            None
                        },
                        propagation_steps: steps,
                    },
                );

                // 即使是赋值节点，也检查右值是否直接包含 sink 调用
                // 例如: result = exec(userInput) 中的 exec(
                if !is_sanitized {
                    if let Some(sink) = self.find_matching_sink_in_expr(&assign.source_expr) {
                        let taint_info = state.get(assign.target.as_str())
                            .or_else(|| state.get(src_var.as_str()))
                            .unwrap().clone();
                        return Some(self.build_taint_flow(
                            &taint_info,
                            src_var,
                            &self.extract_sink_name(&assign.source_expr),
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
            // 回退到基于 node defs/uses 的分析
            let has_tainted_use = node.uses.iter().any(|u| {
                let info = state.get(u.as_str());
                info.is_some() && !info.unwrap().sanitized
            });

            if has_tainted_use && !node.defs.is_empty() {
                let tainted_var = node.uses.iter().find(|u| {
                    let info = state.get(u.as_str());
                    info.is_some() && !info.unwrap().sanitized
                }).unwrap();

                let src_info = state.get(tainted_var.as_str()).unwrap().clone();
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
    ) -> Option<TaintFlow> {
        let call = call_by_line.get(&node.start_line)?;

        // 1. 检查是否匹配 sink
        if let Some(sink) = self.find_matching_sink(&call.callee) {
            // 检查参数是否包含污点变量
            let tainted_arg = call.arguments.iter().find(|arg| {
                arg.referenced_vars.iter().any(|v| {
                    state.contains_key(v.as_str()) && !state.get(v.as_str()).unwrap().sanitized
                })
            });

            if let Some(arg) = tainted_arg {
                let tainted_var = arg.referenced_vars.iter().find(|v| {
                    state.contains_key(v.as_str()) && !state.get(v.as_str()).unwrap().sanitized
                }).unwrap();

                let taint_info = state.get(tainted_var.as_str()).unwrap();

                // 构建污点流
                return Some(self.build_taint_flow(
                    taint_info,
                    tainted_var,
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

        // 3. 如果调用有返回值被赋值（x = func(tainted)），传播污点
        // 这在 assignment 节点中处理

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

    fn find_matching_sink(&self, callee: &str) -> Option<&TaintSink> {
        self.sinks.iter().find(|sink| sink.matches(callee, ""))
    }

    /// 在表达式中查找是否有 sink 函数调用
    fn find_matching_sink_in_expr(&self, expr: &str) -> Option<TaintSink> {
        for sink in &self.sinks {
            for pattern in &sink.patterns {
                if expr.contains(pattern) {
                    return Some(sink.clone());
                }
            }
        }
        None
    }

    /// 从表达式中提取 sink 函数名
    fn extract_sink_name(&self, expr: &str) -> String {
        for sink in &self.sinks {
            for pattern in &sink.patterns {
                if expr.contains(pattern) {
                    return pattern.trim_end_matches('(').to_string();
                }
            }
        }
        expr.to_string()
    }

    fn is_sanitizer(&self, callee: &str) -> bool {
        self.sanitizer_patterns.iter().any(|p| callee.contains(p))
    }

    fn extract_var_from_source(&self, line: &str) -> Option<String> {
        let line = line.trim();

        // 赋值语句: var = ...
        if let Some(eq_pos) = line.find('=') {
            if eq_pos > 0 {
                let left = line[..eq_pos].trim();
                let var_name = left
                    .strip_prefix("let ")
                    .or_else(|| left.strip_prefix("var "))
                    .or_else(|| left.strip_prefix("const "))
                    .or_else(|| left.strip_prefix("auto "))
                    .or_else(|| left.strip_prefix("mut "))
                    .unwrap_or(left);

                let var_name = var_name.split('.').next().unwrap_or(var_name);
                let var_name = var_name.split('[').next().unwrap_or(var_name);
                let var_name = var_name.trim().to_string();

                if !var_name.is_empty()
                    && var_name.chars().next().map(|c| c.is_alphabetic()).unwrap_or(false)
                {
                    return Some(var_name);
                }
            }
        }

        // 函数参数（如 request.GET['id'] 中提取的参数名）
        // 如果没有赋值，返回 None（污点源本身不是变量赋值）
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
            TaintSource::new("http_request", "HTTP Request", vec![
                "request.args", "request.form", "request.GET", "request.POST",
                "req.body", "req.query", "req.params",
                "$_GET", "$_POST", "$_REQUEST",
                "getParameter", "process.argv", "sys.argv", "os.Args", "env::args",
            ]),
            TaintSource::new("file_input", "File Input", vec![
                "readFile", "read()", "readlines", "fs.read", "f.read",
                "File.read", "std::fs::read",
            ]),
            TaintSource::new("env_input", "Environment Variable", vec![
                "process.env", "os.environ", "System.getenv", "std::env::var", "getenv",
            ]),
        ]
    }

    fn default_sinks() -> Vec<TaintSink> {
        vec![
            TaintSink::new("sql_exec", "SQL Execution", vec![
                ".execute(", "execute(", ".query(", "query(",
                "cursor.execute", "db.query",
            ], VulnerabilityType::SqlInjection).with_cwe("CWE-89"),
            TaintSink::new("cmd_exec", "Command Execution", vec![
                "exec(", "system(", "shell_exec", "subprocess",
                "os.system", "Runtime.exec", "Command::new", "child_process",
            ], VulnerabilityType::CommandInjection).with_cwe("CWE-78"),
            TaintSink::new("file_path", "File Path", vec![
                "open(", "fopen", "readFile", "writeFile", "fs.open",
            ], VulnerabilityType::PathTraversal).with_cwe("CWE-22"),
            TaintSink::new("html_output", "HTML Output", vec![
                "innerHTML", "document.write", "res.write", "res.send",
            ], VulnerabilityType::CrossSiteScripting).with_cwe("CWE-79"),
            TaintSink::new("http_request", "HTTP Request", vec![
                "fetch(", "axios", "requests.get", "requests.post",
            ], VulnerabilityType::ServerSideRequestForgery).with_cwe("CWE-918"),
            TaintSink::new("eval", "Code Evaluation", vec![
                "eval(", "Function(", "__import__", "compile(",
            ], VulnerabilityType::CodeInjection).with_cwe("CWE-94"),
        ]
    }

    fn default_sanitizers() -> Vec<String> {
        vec![
            "escape".to_string(),
            "sanitize".to_string(),
            "htmlspecialchars".to_string(),
            "parameterized".to_string(),
            "prepare".to_string(),
            "parameterize".to_string(),
            "encode".to_string(),
            "validate".to_string(),
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
        let flows = analyzer.analyze_code(code, &path, "test_func");

        // 应该检测到 SQL 注入
        assert!(!flows.is_empty(), "Should detect SQL injection");
        let flow = &flows[0];
        assert!(matches!(flow.vulnerability_type, VulnerabilityType::SqlInjection));
        assert!(flow.confidence > 0.5, "Confidence should be high: {}", flow.confidence);
    }

    #[test]
    fn test_command_injection_js() {
        let code = r#"userInput = req.query.cmd
result = exec(userInput)"#;
        let mut analyzer = AstTaintAnalyzer::new();
        let path = std::path::PathBuf::from("test.py");  // Use Python syntax for simpler parsing
        let flows = analyzer.analyze_code(code, &path, "handler");

        assert!(!flows.is_empty(), "Should detect command injection: found {} flows", flows.len());
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
        let flows = analyzer.analyze_code(code, &path, "test_func");

        // sanitizer 后的路径应该置信度低
        if !flows.is_empty() {
            let flow = &flows[0];
            assert!(flow.confidence < 0.5, "Sanitized flow should have low confidence: {}", flow.confidence);
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
        let flows = analyzer.analyze_code(code, &path, "safe_func");

        assert!(flows.is_empty(), "Should not report false positive for non-tainted data");
    }
}
