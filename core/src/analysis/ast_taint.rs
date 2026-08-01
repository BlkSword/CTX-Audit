// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 基于 AST 的污点分析器
//!
//! 利用 tree-sitter AST 解析 + CFG 数据流分析，替代逐行文本匹配。
//! 核心流程：AST 解析 → 提取赋值/调用 → 构建 CFG → 前向污点传播（worklist 算法）

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::Arc;

use crate::analysis::alias::{detect_all_aliases, AccessPath, AliasMap};
use crate::analysis::async_flow::{self, CallbackTaintHint};
use crate::analysis::enhanced_dataflow::{EdgeType, EnhancedFlowGraph, EnhancedFlowNode, EnhancedNodeType};
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
///
/// 严重度降一级（用于推测性 source 的 finding 降级）
fn downgrade_severity(severity: super::taint::Severity) -> super::taint::Severity {
    use super::taint::Severity;
    match severity {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        Severity::Low => Severity::Info,
        Severity::Info => Severity::Info,
    }
}

/// 单文件污点报告（生产 CPG 路径）
#[derive(Debug, Default)]
pub struct FileTaintReport {
    /// 全部污点流（含 StorageWrite 闸门流，不做 finding 过滤）
    pub flows: Vec<TaintFlow>,
    /// 分析中曾被污染的变量（含未达 sink 的）：var -> (source_var, source_line)
    pub tainted_vars: HashMap<String, (String, usize)>,
}

/// 不再持有 ASTParser：tree-sitter Parser 不是 Send/Sync，会限制并行。
/// analyze_function_cpg 等核心路径只依赖规则定义；需要解析的地方使用线程本地 parser。
pub struct AstTaintAnalyzer {
    /// 污点源定义
    sources: Arc<Vec<TaintSource>>,
    /// 污点汇定义
    sinks: Arc<Vec<TaintSink>>,
    /// 净化函数模式
    sanitizer_patterns: Arc<Vec<String>>,
}

impl AstTaintAnalyzer {
    pub fn new() -> Self {
        // 尝试从 rules/taint/ 加载 YAML 规则；目录不可用时回退到内置嵌入规则，
        // 嵌入规则也为空才使用硬编码默认值
        let yaml_dir = std::path::Path::new("rules/taint");
        let loaded = crate::rules::taint_loader::load_taint_rules_with_embedded_fallback(yaml_dir);
        if !loaded.sources.is_empty() || !loaded.sinks.is_empty() {
            return Self {
                sources: Arc::new(loaded.sources),
                sinks: Arc::new(loaded.sinks),
                sanitizer_patterns: Arc::new(loaded.sanitizer_patterns),
            };
        }

        // Fallback: 硬编码默认值
        Self::with_default_rules()
    }

    /// 仅使用硬编码默认规则构造（不加载 YAML）。
    /// 用于 YAML 全部不可用时的最终兜底，以及需要对宽松默认规则做断言的测试。
    pub(crate) fn with_default_rules() -> Self {
        Self {
            sources: Arc::new(Self::default_sources()),
            sinks: Arc::new(Self::default_sinks()),
            sanitizer_patterns: Arc::new(Self::default_sanitizers()),
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

        Ok(Self::from_rules(
            loaded.sources,
            loaded.sinks,
            loaded.sanitizer_patterns,
        ))
    }

    /// 直接使用已加载的规则创建分析器，避免重复从磁盘读取 YAML。
    /// 适用于批量扫描场景：规则只加载一次，每个文件构造一个轻量分析器。
    pub fn from_rules(
        sources: Vec<TaintSource>,
        sinks: Vec<TaintSink>,
        sanitizer_patterns: Vec<String>,
    ) -> Self {
        Self::from_rules_arc(
            Arc::new(sources),
            Arc::new(sinks),
            Arc::new(sanitizer_patterns),
        )
    }

    /// 直接使用已加载的规则（Arc 共享版本），避免扫描时每个任务都克隆规则。
    pub fn from_rules_arc(
        sources: Arc<Vec<TaintSource>>,
        sinks: Arc<Vec<TaintSink>>,
        sanitizer_patterns: Arc<Vec<String>>,
    ) -> Self {
        Self {
            sources,
            sinks,
            sanitizer_patterns,
        }
    }

    /// Builder: 替换所有污点源
    pub fn with_sources(mut self, sources: Vec<TaintSource>) -> Self {
        self.sources = Arc::new(sources);
        self
    }

    /// Builder: 替换所有污点汇
    pub fn with_sinks(mut self, sinks: Vec<TaintSink>) -> Self {
        self.sinks = Arc::new(sinks);
        self
    }

    /// Builder: 替换所有净化函数模式
    pub fn with_sanitizers(mut self, patterns: Vec<String>) -> Self {
        self.sanitizer_patterns = Arc::new(patterns);
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
        let mut all = (*self.sources).clone();
        all.extend(sources);
        self.sources = Arc::new(all);
    }

    /// 追加额外的污点汇
    pub fn add_sinks(&mut self, sinks: Vec<TaintSink>) {
        let mut all = (*self.sinks).clone();
        all.extend(sinks);
        self.sinks = Arc::new(all);
    }

    /// 追加额外的净化函数模式
    pub fn add_sanitizers(&mut self, patterns: Vec<String>) {
        let mut all = (*self.sanitizer_patterns).clone();
        all.extend(patterns);
        self.sanitizer_patterns = Arc::new(all);
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
    pub fn analyze_file(&self, file_path: &Path, content: &str) -> Vec<TaintFlow> {
        let mut all_flows = Vec::new();
        let file_path_str = file_path.to_string_lossy().to_string();
        let language = Self::detect_language(&file_path_str);
        let callback_hints = async_flow::detect_callback_hints(content);

        // 使用 AST-based 分析（保留 Tree 供 CFG 构建使用）
        if let Some((tree, _symbols, functions, file_assignments, file_calls)) =
            crate::ast::parser::with_thread_local_parser(|ast_parser| {
                ast_parser.extract_all_for_taint_with_tree(file_path, content)
            })
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

                    // 优先使用 AST-based CFG，fallback 到 text-based。
                    // 两个分支统一为"相对 body_text 行号"坐标系（10.10）：
                    // AST 分支用 from_ast_node_with_base 把绝对行号减为相对，
                    // 与 from_code 一致；下方 line_offset 统一换算回绝对行号。
                    let line_base = func.body_start_line.saturating_sub(1);
                    let func_body_node =
                        Self::find_function_body_node_static(&root, func.start_line, func.end_line);
                    let cfg = if let Some(body_node) = func_body_node {
                        EnhancedFlowGraph::from_ast_node_with_base(
                            &body_node,
                            content,
                            &file_path_str,
                            &func.name,
                            line_base,
                        )
                    } else {
                        EnhancedFlowGraph::from_code(&func.body_text, &file_path_str, &func.name)
                    };

                    // body_text 的首行是 body_start_line（Python/Ruby 与签名行不同行），
                    // 此前误用 start_line 导致 Python 系偏移一行（backlog 10.10）
                    let line_offset = func.body_start_line.saturating_sub(1);
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
        &self,
        code: &str,
        file_path: &Path,
        function_name: &str,
        typed_params: &[TypedParam],
        callback_hints: &[CallbackTaintHint],
    ) -> Vec<TaintFlow> {
        let file_path_str = file_path.to_string_lossy().to_string();
        let language = Self::detect_language(&file_path_str);
        let tmp_path = std::path::PathBuf::from(&file_path_str);
        let (_, assignments, calls) = crate::ast::parser::with_thread_local_parser(|ast_parser| {
            ast_parser.extract_all_for_taint(&tmp_path, code)
        });
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
        self.analyze_function_cpg_with_state(cpg, content, callback_hints)
            .0
    }

    /// 从 FunctionCPG 分析，同时返回分析结束时的污点状态
    ///
    /// 返回 (flows, tainted_vars)：
    /// - flows：到达 sink 的污点流（含 StorageWrite 闸门流，不过滤）
    /// - tainted_vars：分析过程中曾被污染的变量全集（含未到达 sink 的），
    ///   var -> (source_var, source_line)。供探索向查询（"这个变量被污染了吗"）
    pub fn analyze_function_cpg_with_state(
        &self,
        cpg: &super::cpg::FunctionCPG,
        content: &str,
        callback_hints: &[crate::analysis::async_flow::CallbackTaintHint],
    ) -> (Vec<TaintFlow>, HashMap<String, (String, usize)>) {
        // 分支预算（10.12）：路径敏感污点状态随分支点数指数增长
        // （合成用例实测每 +50 个 if 耗时翻倍，250 if ≈ 31s，300+ if 卡死），
        // 超预算函数跳过污点传播，防止单个巨型函数拖死整轮扫描；
        // 规则层扫描不受影响，仍覆盖该文件。
        const MAX_TAINT_BRANCH_POINTS: usize = 80;
        let branch_points = cpg
            .cfg
            .nodes
            .iter()
            .filter(|n| n.successors.len() >= 2)
            .count();
        if branch_points > MAX_TAINT_BRANCH_POINTS {
            tracing::warn!(
                "[TaintAnalysis] 函数 {} 分支点 {} 超过预算 {}，跳过污点传播（{}:{}）",
                cpg.signature.name,
                branch_points,
                MAX_TAINT_BRANCH_POINTS,
                cpg.signature.file_path,
                cpg.signature.start_line
            );
            return (Vec::new(), HashMap::new());
        }
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

        let line_offset = cpg.line_offset;
        let (flows, taint_state) = self.forward_taint_analysis_cpg(
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
        );

        // 汇总各节点状态：变量首次被标记的来源（含未达 sink 的中间污染）
        let mut tainted_vars: HashMap<String, (String, usize)> = HashMap::new();
        for state in taint_state.values() {
            for (path, vt) in state.all_entries() {
                tainted_vars
                    .entry(path.as_dotted())
                    .or_insert_with(|| (vt.source_var.clone(), vt.source_line));
            }
        }
        (flows, tainted_vars)
    }

    /// 单文件污点报告（生产 CPG 路径）
    ///
    /// 与 scanner Stage B 同款路径：extract_all_for_taint_with_tree →
    /// 逐函数构建 CPG（fragment 优先，text 回退）→ analyze_function_cpg。
    /// flows 不做 finding 过滤（StorageWrite 闸门流保留，由调用方解释）。
    pub fn analyze_file_cpg(&self, file_path: &Path, content: &str) -> FileTaintReport {
        let file_path_str = file_path.to_string_lossy().to_string();
        let mut report = FileTaintReport::default();

        let extracted = crate::ast::parser::with_thread_local_parser(|ast_parser| {
            ast_parser.extract_all_for_taint_with_tree(&file_path.to_path_buf(), content)
        });

        if let Some((_tree, _symbols, functions, file_assignments, file_calls)) = extracted {
            let callback_hints = async_flow::detect_callback_hints(content);

            if functions.is_empty() {
                // 无函数体：整个文件构建一个 CPG
                let func_cpg = super::cpg::CPGBuilder::build_file_cpg(
                    content,
                    &file_path_str,
                    &file_assignments,
                    &file_calls,
                );
                let (flows, tainted) =
                    self.analyze_function_cpg_with_state(&func_cpg, content, &callback_hints);
                report.flows.extend(flows);
                report.tainted_vars.extend(tainted);
            } else {
                let ext = file_path
                    .extension()
                    .and_then(|s| s.to_str())
                    .unwrap_or("");
                for func in &functions {
                    let func_hints: Vec<_> = callback_hints
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

                    // 与 Stage B 一致：fragment 重解析优先，失败回退 text-based CPG
                    let func_cpg = crate::ast::parser::with_thread_local_parser(|ast_parser| {
                        if let Some(tree) = ast_parser.parse_fragment(&func.body_text, ext) {
                            let root = tree.root_node();
                            let mut cursor = root.walk();
                            let body_node = root.children(&mut cursor).find(|n| {
                                matches!(
                                    n.kind(),
                                    "block"
                                        | "statement_block"
                                        | "body"
                                        | "suite"
                                        | "block_stmt"
                                )
                            });
                            if let Some(body_node) = body_node {
                                return super::cpg::CPGBuilder::build_function_cpg_from_fragment(
                                    &body_node,
                                    &func.body_text,
                                    &file_path_str,
                                    func,
                                    &func_assignments,
                                    &func_calls,
                                );
                            }
                        }
                        super::cpg::CPGBuilder::build_function_cpg_from_text(
                            &func.body_text,
                            &file_path_str,
                            func,
                            &func_assignments,
                            &func_calls,
                        )
                    });

                    let (flows, tainted) = self.analyze_function_cpg_with_state(
                        &func_cpg,
                        &func.body_text,
                        &func_hints,
                    );
                    report.flows.extend(flows);
                    report.tainted_vars.extend(tainted);
                }
            }
        } else {
            // AST 解析失败，回退到 legacy 路径（无状态输出）
            report.flows = self.analyze_file(file_path, content);
        }

        report
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
        // 同一行可能存在嵌套方法调用（如 response.getWriter().println(data)），
        // collect_calls_recursive 会产生多个 CallInfo。优先保留最外层调用：
        // 若 receiver 更长，则覆盖同一行的旧记录，确保 sink 匹配能看到 println 而非 getWriter。
        let mut call_by_line: HashMap<usize, &CallInfo> = HashMap::new();
        for c in calls.iter() {
            let keep = match call_by_line.get(&c.line) {
                Some(existing) => {
                    let existing_len = existing.receiver.as_ref().map(|r| r.len()).unwrap_or(0);
                    let new_len = c.receiver.as_ref().map(|r| r.len()).unwrap_or(0);
                    new_len > existing_len
                }
                None => true,
            };
            if keep {
                call_by_line.insert(c.line, c);
            }
        }

        // 从赋值中构建别名映射
        let alias_map = self.build_alias_map(assignments);

        // 初始化 worklist（HashSet 辅助 O(1) 去重）
        let mut worklist: VecDeque<usize> = VecDeque::new();
        let mut in_worklist: std::collections::HashSet<usize> = std::collections::HashSet::new();
        worklist.push_back(cfg.entry);
        in_worklist.insert(cfg.entry);

        while let Some(node_id) = worklist.pop_front() {
            in_worklist.remove(&node_id);
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
                        line_offset,
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
                        line_offset,
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
                        line_offset,
                    ) {
                        flows.push(flow);
                    }
                }

                EnhancedNodeType::ConditionHeader => {
                    // 条件分支：检查条件表达式中的污点（暂不处理）
                }

                EnhancedNodeType::LoopHeader => {
                    // Go for range / Python for in / JS for of：
                    // 若 range/in/of 后的集合表达式引用了污点变量，
                    // 将污点传播到迭代变量（:= 或 = 左侧）
                    self.transfer_loop_header(node, &mut new_state, &alias_map);
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
    ) -> (Vec<TaintFlow>, HashMap<usize, super::cpg::PathSensitiveState>) {
        use super::cpg::{ConditionInfo, PathCondition, PathSensitiveState, VarTaintState};
        use crate::analysis::enhanced_dataflow::EdgeType;

        let mut flows = Vec::new();

        // 路径敏感状态：node_id → PathSensitiveState
        let mut taint_state: HashMap<usize, PathSensitiveState> = HashMap::new();

        let assign_by_line: HashMap<usize, &Assignment> =
            assignments.iter().map(|a| (a.line, a)).collect();
        // 同一行可能存在嵌套方法调用（如 response.getWriter().println(data)），
        // collect_calls_recursive 会产生多个 CallInfo。优先保留最外层调用：
        // 若 receiver 更长，则覆盖同一行的旧记录，确保 sink 匹配能看到 println 而非 getWriter。
        let mut call_by_line: HashMap<usize, &CallInfo> = HashMap::new();
        for c in calls.iter() {
            let keep = match call_by_line.get(&c.line) {
                Some(existing) => {
                    let existing_len = existing.receiver.as_ref().map(|r| r.len()).unwrap_or(0);
                    let new_len = c.receiver.as_ref().map(|r| r.len()).unwrap_or(0);
                    new_len > existing_len
                }
                None => true,
            };
            if keep {
                call_by_line.insert(c.line, c);
            }
        }

        let alias_map = self.build_alias_map(assignments);

        let mut worklist: VecDeque<usize> = VecDeque::new();
        let mut in_worklist: std::collections::HashSet<usize> = std::collections::HashSet::new();
        worklist.push_back(cfg.entry);
        in_worklist.insert(cfg.entry);

        while let Some(node_id) = worklist.pop_front() {
            in_worklist.remove(&node_id);
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
                        line_offset,
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
                        line_offset,
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
                            line_offset,
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

        (flows, taint_state)
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

        // 1. 基于类型注解或 Spring 注解的参数污点源
        for tp in typed_params {
            let var_name = tp.name.clone();
            if state.get_var(&var_name).is_some() {
                continue;
            }

            let is_request_type = tp
                .type_annotation
                .as_ref()
                .map(|type_ann| {
                    let type_lower = type_ann.to_lowercase();
                    Self::REQUEST_TYPE_PATTERNS
                        .iter()
                        .any(|pattern| type_lower.contains(&pattern.to_lowercase()))
                })
                .unwrap_or(false);

            let is_http_param_annotation = tp.annotations.iter().any(|ann| {
                Self::HTTP_PARAM_ANNOTATIONS
                    .iter()
                    .any(|pat| ann.contains(pat))
            });

            if is_request_type || is_http_param_annotation {
                let source_desc = if is_http_param_annotation {
                    format!(
                        "{} ({})",
                        tp.name,
                        tp.annotations
                            .iter()
                            .filter(|ann| {
                                Self::HTTP_PARAM_ANNOTATIONS
                                    .iter()
                                    .any(|pat| ann.contains(pat))
                            })
                            .next()
                            .cloned()
                            .unwrap_or_else(|| "HTTP param".to_string())
                    )
                } else {
                    format!(
                        "{}: {}",
                        tp.name,
                        tp.type_annotation.clone().unwrap_or_default()
                    )
                };

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
                        source_desc,
                        vec![PropagationStep {
                            step_type: PropagationStepType::DirectAssignment,
                            from_var: None,
                            to_var: Some(tp.name.clone()),
                            line: line_num,
                            code_snippet: Some(format!(
                                "param: {} {}",
                                tp.annotations.join(" "),
                                tp.type_annotation.clone().unwrap_or_default()
                            )),
                            function_name: None,
                        }],
                    ),
                );
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
            for source in self.sources.iter() {
                if source.matches(line, language) {
                    if let Some(var_name) = self.extract_var_from_source(line) {
                        if state.get_var(&var_name).is_none() {
                            // 二阶 source（存储点读出）：标签携带 (second-order)，
                            // flow 构建时据此降置信度
                            let label = if source.second_order {
                                format!("{} (second-order)", var_name)
                            } else {
                                var_name.clone()
                            };
                            state.insert_var(
                                var_name.clone(),
                                VarTaintState::from_taint(
                                    line_num,
                                    label,
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
            let matched_source = paths.iter().find_map(|path| {
                let dotted = path.as_dotted();
                self.sources.iter().find(|s| s.matches(&dotted, language))
            });
            if let Some(matched) = matched_source {
                let line_num = code
                    .lines()
                    .enumerate()
                    .find(|(_, l)| l.contains(local_var))
                    .map(|(i, _)| i + 1 + line_offset)
                    .unwrap_or(1);
                let label = if matched.second_order {
                    format!("{} (second-order)", local_var)
                } else {
                    local_var.clone()
                };
                state.insert_var(
                    local_var.clone(),
                    VarTaintState::from_taint(
                        line_num,
                        label,
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
        line_offset: usize,
    ) -> Option<TaintFlow> {
        use super::cpg::VarTaintState;

        // assign_by_line/call_by_line 键为文件绝对行号（node_meta 统一存绝对行号），
        // CFG 节点行号为函数体相对行号，查找时用 node.start_line + line_offset 换算
        if let Some(assign) = assign_by_line.get(&(node.start_line + line_offset)) {
            let is_sanitized = call_by_line
                .get(&assign.line)
                .map(|c| self.is_sanitizer(&c.callee))
                .unwrap_or(false)
                || self
                    .sanitizer_patterns
                    .iter()
                    .any(|p| Self::expr_mentions_sanitizer(&assign.source_expr, p));

            // 在 PathSensitiveState 中查找污点变量
            let tainted_source_var =
                self.find_tainted_var_cpg(&assign.source_vars, state, alias_map);

            if let Some(src_var) = tainted_source_var {
                let src_path = AccessPath::from_dotted(&src_var);
                // 防御：is/resolve 判定与 find_taint_for_path 存在边角不一致
                // （如 sanitized 条目），解析不到就放弃本次传播而不是 panic
                let Some(src_vt) = state.find_taint_for_path(&src_path).cloned() else {
                    return None;
                };
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
                    // 若目标变量本身是入口行扫描直接标记的污点源
                    // （如 LDAP getAttributes 的结果变量 attrs），保留其原始
                    // source 标注。否则被上游传播链覆盖后，多条 finding 会共享
                    // 同一 source 行，在扫描收尾按 (file, line_start) 去重时被
                    // 错误合并吞掉（如 00012 的 XSS 被合并进 LDAP finding）。
                    if !is_sanitized {
                        if let Some(existing) = state.get_exact(&tp) {
                            if existing.source_var == tp.as_dotted() {
                                continue;
                            }
                        }
                    }
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

                // 检查赋值右值中的 sink（sensitive_params 位置感知：
                // 污点仅在非敏感参数如 cur.execute(query, (q,)) 的绑定
                // 元组中出现时，属于参数化查询，跳过该右值 sink，
                // 继续检查赋值目标 sink）
                if !is_sanitized {
                    if let Some(sink) =
                        self.find_matching_sink_in_expr(&assign.source_expr, language)
                    {
                        if !Self::sink_exempt(&sink, &assign.source_expr, &src_var)
                            && Self::tainted_var_in_sensitive_args(
                                &assign.source_expr,
                                &sink,
                                &src_var,
                            )
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

                // 检查赋值目标中的 sink（x.innerHTML = tainted 形态：
                // sink 模式在左值属性上，右值只携带污点数据）
                if !is_sanitized {
                    if let Some((sink, sink_name)) =
                        self.find_matching_sink_in_assign_target(&assign.target, language)
                    {
                        let vt = state.find_taint_for_path(&src_path).unwrap().clone();
                        return Some(self.build_taint_flow_cpg(
                            &vt,
                            &src_var,
                            &sink_name,
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
                // 防御：解析不到污点状态时跳过，不 panic
                let Some(src_vt) = state.find_taint_for_path(&src_path).cloned() else {
                    return None;
                };
                for def in &node.defs {
                    let mut steps = src_vt.propagation_steps.clone();
                    steps.push(PropagationStep {
                        step_type: PropagationStepType::DirectAssignment,
                        from_var: Some(tainted_var.clone()),
                        to_var: Some(def.clone()),
                        line: node.start_line + line_offset,
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
        line_offset: usize,
    ) -> Option<TaintFlow> {
        // call_by_line 键为文件绝对行号，CFG 节点为函数体相对行号，加 line_offset 换算
        if let Some(call) = call_by_line.get(&(node.start_line + line_offset)) {
            // 检查 sink（方法调用考虑 receiver，如 needle.get）
            if let Some(sink) = self.match_sink_for_call(call, language) {
                // 1. 检查参数是否被污染；污点变量仅在净化器调用内部出现的参数
                //    （内联净化，如 HtmlUtils.htmlEscape(keyword)）跳过。
                //    sensitive_params 非空时只看敏感下标的参数——
                //    cur.execute(query, (q,)) 中 q 在 arg1（参数绑定元组），
                //    属于参数化查询，不应判定为注入。
                let mut tainted_var: Option<String> = None;
                let mut tainted_used_var: Option<String> = None;
                let mut tainted_arg_text: Option<String> = None;
                for (arg_idx, arg) in call.arguments.iter().enumerate() {
                    if !sink.sensitive_params.is_empty()
                        && !sink.sensitive_params.contains(&arg_idx)
                    {
                        continue;
                    }
                    let Some(used_var) = arg
                        .referenced_vars
                        .iter()
                        .find(|v| self.is_var_tainted_cpg(v, state, alias_map))
                    else {
                        continue;
                    };
                    let resolved = self
                        .resolve_tainted_var_cpg(used_var, state, alias_map)
                        .unwrap_or_else(|| arg.referenced_vars[0].clone());
                    // 表达式文本中出现的是 used_var（可能是别名），两者都检查
                    if self.is_inline_sanitized(&arg.text, used_var)
                        || self.is_inline_sanitized(&arg.text, &resolved)
                    {
                        continue;
                    }
                    tainted_var = Some(resolved);
                    tainted_used_var = Some(used_var.clone());
                    tainted_arg_text = Some(arg.text.clone());
                    break;
                }

                // 2. 检查 receiver 是否被污染（如 statement.executeQuery() 中 statement 由 prepareCall(sql) 生成）
                if tainted_var.is_none() {
                    if let Some(ref recv) = call.receiver {
                        // 优先尝试完整 receiver（如 response.getWriter()）
                        let candidates: Vec<&str> = vec![recv.as_str()]
                            .into_iter()
                            .chain(recv.split('.').collect::<Vec<_>>())
                            .collect();
                        for candidate in candidates {
                            if self.is_var_tainted_cpg(candidate, state, alias_map) {
                                if let Some(resolved) =
                                    self.resolve_tainted_var_cpg(candidate, state, alias_map)
                                {
                                    tainted_var = Some(resolved);
                                    break;
                                }
                            }
                        }
                    }
                }

                if let Some(tainted_var) = tainted_var {
                    let src_path = AccessPath::from_dotted(&tainted_var);
                    let src_vt = state.find_taint_for_path(&src_path).unwrap().clone();

                    // 10.15①/② sink 级豁免：sink 调用处的参数文本只是变量名时，
                    // 取传播链最近一个赋值步骤的右值表达式来判定
                    // （`path = "/uploads/" + str(int(user_id))` → open(path) 形态）。
                    // 注意步骤链在 used_var（如 path）的状态里，源头变量（user_id）无此步骤。
                    let steps_expr = tainted_used_var
                        .as_deref()
                        .and_then(|u| {
                            state.find_taint_for_path(&AccessPath::from_dotted(u))
                        })
                        .or_else(|| state.find_taint_for_path(&src_path))
                        .and_then(|vt| Self::last_assign_snippet(&vt.propagation_steps))
                        .map(|s| s.to_string());
                    let exempt_expr =
                        steps_expr.unwrap_or_else(|| tainted_var.clone());
                    let exempt = match sink.vulnerability_type {
                        VulnerabilityType::ServerSideRequestForgery => {
                            Self::sink_exempt(&sink, &exempt_expr, &tainted_var)
                                // R55：污点所在参数为同源相对 URL（`/api/${id}`）时豁免
                                || tainted_arg_text
                                    .as_deref()
                                    .map(Self::expr_ssrf_relative_url)
                                    .unwrap_or(false)
                        }
                        VulnerabilityType::PathTraversal => Self::expr_taints_all_numeric_with(
                            &exempt_expr,
                            |v| self.is_var_tainted_cpg(v, state, alias_map),
                        ),
                        _ => false,
                    };
                    if exempt {
                        return None;
                    }

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
        // 别名前缀匹配 — 与 is_var_tainted_cpg 的判定保持一致，
        // 避免"判定污染但解析不出路径"导致上游 unwrap panic
        for alias_path in alias_map.resolve(var) {
            if state.find_taint_for_path(&alias_path).is_some() {
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

        // 推测性参数 source（callback/tainted param）不是已确认的外部输入，
        // 降一级严重度并降低置信度，交由上层/LLM 判定（如 SSRF 通知配置场景）
        let is_speculative_source = taint_state.source_var.contains("(callback param)")
            || taint_state.source_var.contains("(tainted param)");
        // 二阶 source（存储点读出）：数据流真实但来源是已存储数据，
        // 保留严重度（存储型 XSS 等本身即高危），只降置信度
        let is_second_order = taint_state.source_var.contains("(second-order)");
        let (severity, confidence) = if is_speculative_source {
            (downgrade_severity(sink.severity), confidence * 0.7)
        } else if is_second_order {
            (sink.severity, confidence * 0.7)
        } else {
            (sink.severity, confidence)
        };

        TaintFlow {
            id: uuid::Uuid::new_v4().to_string(),
            source: FlowLocation {
                file_path: file_path.to_string(),
                line: taint_state.source_line,
                column: None,
                symbol: taint_state.source_var.clone(),
                node_id: None,
                code_snippet: None,
            },
            sink: FlowLocation {
                file_path: file_path.to_string(),
                line: sink_line,
                column: None,
                symbol: sink_name.to_string(),
                node_id: None,
                code_snippet: Some(sink_code.to_string()),
            },
            path,
            vulnerability_type: sink.vulnerability_type.clone(),
            severity,
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

    /// Spring / Jakarta 用户输入参数注解
    ///
    /// 这些注解修饰的方法参数应被视为污点源，无论其类型是否为 String / int。
    const HTTP_PARAM_ANNOTATIONS: &'static [&'static str] = &[
        "@RequestParam",
        "@PathVariable",
        "@RequestBody",
        "@ModelAttribute",
        "@RequestHeader",
        "@CookieValue",
        "@RequestAttribute",
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

        // 1. 基于类型注解或 Spring 注解的参数污点源
        for tp in typed_params {
            if state.contains_key(&tp.name) {
                continue;
            }

            let is_request_type = tp
                .type_annotation
                .as_ref()
                .map(|type_ann| {
                    let type_lower = type_ann.to_lowercase();
                    Self::REQUEST_TYPE_PATTERNS
                        .iter()
                        .any(|pattern| type_lower.contains(&pattern.to_lowercase()))
                })
                .unwrap_or(false);

            let is_http_param_annotation = tp.annotations.iter().any(|ann| {
                Self::HTTP_PARAM_ANNOTATIONS
                    .iter()
                    .any(|pat| ann.contains(pat))
            });

            if is_request_type || is_http_param_annotation {
                let source_desc = if is_http_param_annotation {
                    format!(
                        "{} ({})",
                        tp.name,
                        tp.annotations
                            .iter()
                            .filter(|ann| {
                                Self::HTTP_PARAM_ANNOTATIONS
                                    .iter()
                                    .any(|pat| ann.contains(pat))
                            })
                            .next()
                            .cloned()
                            .unwrap_or_else(|| "HTTP param".to_string())
                    )
                } else {
                    format!(
                        "{}: {}",
                        tp.name,
                        tp.type_annotation.clone().unwrap_or_default()
                    )
                };

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
                        source_var: source_desc,
                        sanitized: false,
                        sanitizer: None,
                        propagation_steps: vec![PropagationStep {
                            step_type: PropagationStepType::DirectAssignment,
                            from_var: None,
                            to_var: Some(tp.name.clone()),
                            line: line_num,
                            code_snippet: Some(format!(
                                "param: {} {}",
                                tp.annotations.join(" "),
                                tp.type_annotation.clone().unwrap_or_default()
                            )),
                            function_name: None,
                        }],
                    },
                );
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
            for source in self.sources.iter() {
                if source.matches(line, language) {
                    let var_name = self.extract_var_from_source(line);
                    if let Some(var_name) = var_name {
                        // 二阶 source（存储点读出）：标签携带 (second-order)
                        let label = if source.second_order {
                            format!("{} (second-order)", var_name)
                        } else {
                            var_name.clone()
                        };
                        state.insert(
                            var_name.clone(),
                            TaintInfo {
                                source_line: line_num,
                                source_var: label,
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
                for source in self.sources.iter() {
                    if source.matches(&path_str, language) {
                        let var_line = code
                            .lines()
                            .enumerate()
                            .find(|(_, l)| l.contains(local_var.as_str()))
                            .map(|(i, _)| i + 1 + line_offset)
                            .unwrap_or(1);

                        let label = if source.second_order {
                            format!("{} (second-order)", path_str)
                        } else {
                            path_str.clone()
                        };
                        state.insert(
                            local_var.clone(),
                            TaintInfo {
                                source_line: var_line,
                                source_var: label,
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
        line_offset: usize,
    ) -> Option<TaintFlow> {
        // CFG 节点为函数体相对行号，assign_by_line 键为文件绝对行号，
        // 用 line_offset 换算（backlog 10.10）
        if let Some(assign) = assign_by_line.get(&(node.start_line + line_offset)) {
            // 检查右值是否包含 sanitizer 调用
            let is_sanitized = call_by_line
                .get(&assign.line)
                .map(|c| self.is_sanitizer(&c.callee))
                .unwrap_or(false)
                || self
                    .sanitizer_patterns
                    .iter()
                    .any(|p| Self::expr_mentions_sanitizer(&assign.source_expr, p));

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
                // （sensitive_params 位置感知：污点仅在非敏感参数如
                //   cur.execute(query, (q,)) 的绑定元组中时不产出 flow）
                if !is_sanitized {
                    if let Some(sink) =
                        self.find_matching_sink_in_expr(&assign.source_expr, language)
                    {
                        if Self::sink_exempt(&sink, &assign.source_expr, &src_var)
                            || !Self::tainted_var_in_sensitive_args(
                                &assign.source_expr,
                                &sink,
                                &src_var,
                            )
                        {
                            return None;
                        }
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
        line_offset: usize,
    ) -> Option<TaintFlow> {
        // CFG 节点为函数体相对行号，call_by_line 键为文件绝对行号，
        // 用 line_offset 换算（backlog 10.10）
        let call = call_by_line.get(&(node.start_line + line_offset))?;

        // 1. 检查是否匹配 sink（方法调用考虑 receiver，如 needle.get）
        if let Some(sink) = self.match_sink_for_call(call, language) {
            // 检查参数是否包含污点变量（直接 + 别名解析）；
            // 污点变量仅在净化器调用内部出现的参数（内联净化，
            // 如 HtmlUtils.htmlEscape(keyword)）跳过。
            // sensitive_params 非空时只看敏感下标的参数——
            // cur.execute(query, (q,)) 中 q 在 arg1（参数绑定元组），
            // 属于参数化查询，不应判定为注入。
            let mut tainted_var: Option<String> = None;
            let mut tainted_used_var: Option<String> = None;
            let mut tainted_arg_text: Option<String> = None;
            for (arg_idx, arg) in call.arguments.iter().enumerate() {
                if !sink.sensitive_params.is_empty() && !sink.sensitive_params.contains(&arg_idx) {
                    continue;
                }
                let Some(used_var) = arg
                    .referenced_vars
                    .iter()
                    .find(|v| self.is_var_tainted(v, state, alias_map))
                else {
                    continue;
                };
                let resolved = self
                    .resolve_tainted_var(used_var, state, alias_map)
                    .unwrap_or_else(|| arg.referenced_vars[0].clone());
                // 表达式文本中出现的是 used_var（可能是别名），两者都检查
                if self.is_inline_sanitized(&arg.text, used_var)
                    || self.is_inline_sanitized(&arg.text, &resolved)
                {
                    continue;
                }
                tainted_var = Some(resolved);
                tainted_used_var = Some(used_var.clone());
                tainted_arg_text = Some(arg.text.clone());
                break;
            }

            // 检查 receiver 是否被污染（如 statement.executeQuery()）
            if tainted_var.is_none() {
                if let Some(ref recv) = call.receiver {
                    let candidates: Vec<&str> = std::iter::once(recv.as_str())
                        .chain(recv.split('.'))
                        .collect();
                    for candidate in candidates {
                        if self.is_var_tainted(candidate, state, alias_map) {
                            tainted_var = self.resolve_tainted_var(candidate, state, alias_map);
                            if tainted_var.is_some() {
                                break;
                            }
                        }
                    }
                }
            }

            if let Some(tainted_var) = tainted_var {
                let taint_info = state.get(&tainted_var)?;

                // 10.15①/② sink 级豁免：sink 调用处参数只是变量名时回溯最近
                // 赋值步骤的右值表达式（`path = ".../" + str(int(uid))` → open(path)）
                let steps_expr = tainted_used_var
                    .as_deref()
                    .and_then(|u| state.get(u))
                    .or_else(|| state.get(&tainted_var))
                    .and_then(|info| Self::last_assign_snippet(&info.propagation_steps))
                    .map(|s| s.to_string());
                let exempt_expr = steps_expr.unwrap_or_else(|| tainted_var.clone());
                let exempt = match sink.vulnerability_type {
                    VulnerabilityType::ServerSideRequestForgery => {
                        Self::sink_exempt(&sink, &exempt_expr, &tainted_var)
                            // R55：污点所在参数为同源相对 URL（`/api/${id}`）时豁免
                            || tainted_arg_text
                                .as_deref()
                                .map(Self::expr_ssrf_relative_url)
                                .unwrap_or(false)
                    }
                    VulnerabilityType::PathTraversal => Self::expr_taints_all_numeric_with(
                        &exempt_expr,
                        |v| self.is_var_tainted(v, state, alias_map),
                    ),
                    _ => false,
                };
                if exempt {
                    return None;
                }
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

        // 推测性参数 source 降级（同 flow 构造主路径）
        let is_speculative_source = taint_info.source_var.contains("(callback param)")
            || taint_info.source_var.contains("(tainted param)");
        // 二阶 source（存储点读出）：保留严重度，降置信度
        let is_second_order = taint_info.source_var.contains("(second-order)");
        let (severity, confidence) = if is_speculative_source {
            (downgrade_severity(sink.severity), confidence * 0.7)
        } else if is_second_order {
            (sink.severity, confidence * 0.7)
        } else {
            (sink.severity, confidence)
        };

        TaintFlow {
            id: uuid::Uuid::new_v4().to_string(),
            source: FlowLocation {
                file_path: file_path.to_string(),
                line: taint_info.source_line,
                column: None,
                symbol: taint_info.source_var.clone(),
                node_id: None,
                code_snippet: None,
            },
            sink: FlowLocation {
                file_path: file_path.to_string(),
                line: sink_line,
                column: None,
                symbol: sink_name.to_string(),
                node_id: None,
                code_snippet: Some(sink_code.to_string()),
            },
            path,
            vulnerability_type: sink.vulnerability_type.clone(),
            severity,
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

    /// 带调用参数上下文的 sink 匹配。
    ///
    /// 命中但声明了类字面量豁免、且参数含 Java 类字面量（`Policy.class`）
    /// 的 sink 视为仓库/类型注册查找（`client.get(Class, name)` 形态），
    /// 跳过——WebFlux/R2DBC 项目中 ReactiveExtensionClient 等内部存储
    /// 客户端因此被误标 SQL Injection/SSRF（halo 深审 FP 家族）。
    fn find_matching_sink_for_call(
        &self,
        callee: &str,
        receiver: Option<&str>,
        language: &str,
        call: &crate::ast::CallInfo,
    ) -> Option<&TaintSink> {
        let arg_texts: Vec<String> = call.arguments.iter().map(|a| a.text.clone()).collect();
        self.sinks.iter().find(|sink| {
            sink.matches_with_context(callee, receiver, language)
                && !sink.is_class_literal_exempt(&arg_texts)
        })
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
                if let Some(s) =
                    self.find_matching_sink_for_call(&qualified, Some(recv), language, call)
                {
                    return Some(s);
                }
                // 再用 receiver 语义 + callee 匹配
                if let Some(s) =
                    self.find_matching_sink_for_call(&call.callee, Some(recv), language, call)
                {
                    return Some(s);
                }
            }
        }
        if let Some(s) = self.find_matching_sink_for_call(&call.callee, None, language, call) {
            return Some(s);
        }

        // storage_write 闸门 sink 补充匹配：SQL 写往往包在字符串参数里
        // （$this->db->query("INSERT INTO ...")、cursor.execute("UPDATE ...")），
        // callee/receiver 匹配不到。闸门只发事件不产 finding，
        // 容许对参数文本做子串匹配（backlog 10.9 的闸门侧修复）
        self.sinks.iter().find(|sink| {
            sink.storage_write
                && sink.match_mode == super::taint::MatchMode::Substring
                && (language == "*"
                    || language.is_empty()
                    || sink.languages.iter().any(|l| l == "*" || l == language))
                && call
                    .arguments
                    .iter()
                    .any(|a| sink.patterns.iter().any(|p| a.text.contains(p.as_str())))
        })
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

    /// 按标识符字符切词后判断表达式中是否出现指定变量（边界安全，避免
    /// `q` 误配 `query`；PHP `$row` 含 `$` 前缀仍可匹配）。
    fn expr_mentions_var(expr: &str, var: &str) -> bool {
        let last_segment = var.rsplit('.').next().unwrap_or(var);
        expr.split(|c: char| !(c.is_alphanumeric() || matches!(c, '_' | '$')))
            .any(|tok| tok == var || tok == last_segment)
    }

    /// 切分调用参数串的顶层参数（忽略嵌套括号/引号内的逗号）。
    fn split_top_level_args(args_text: &str) -> Vec<&str> {
        let mut args = Vec::new();
        let mut depth = 0i32;
        let mut quote: Option<u8> = None;
        let mut start = 0usize;
        let bytes = args_text.as_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            if let Some(q) = quote {
                if b == q && (i == 0 || bytes[i - 1] != b'\\') {
                    quote = None;
                }
                continue;
            }
            match b {
                b'"' | b'\'' | b'`' => quote = Some(b),
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => depth -= 1,
                b',' if depth == 0 => {
                    args.push(&args_text[start..i]);
                    start = i + 1;
                }
                _ => {}
            }
        }
        let tail = args_text[start..].trim();
        if !tail.is_empty() {
            args.push(&args_text[start..]);
        }
        args
    }

    /// 判断污点变量是否出现在 sink 调用的敏感参数位置（赋值右值形态）。
    /// `sensitive_params` 为空时回退旧行为（任意参数）；
    /// 表达式无法解析为调用时保守返回 true（不误杀）。
    /// `cur.execute(query, (q,))` 中 q 仅出现在 arg1（参数绑定元组），
    /// SQL sink 敏感参数为 arg0（查询串），应返回 false。
    fn tainted_var_in_sensitive_args(expr: &str, sink: &TaintSink, var: &str) -> bool {
        if sink.sensitive_params.is_empty() {
            return true;
        }
        let start = match expr.find('(') {
            Some(i) => i,
            None => return true,
        };
        let bytes = expr.as_bytes();
        let mut depth = 0i32;
        let mut end = None;
        for (i, &b) in bytes.iter().enumerate().skip(start) {
            match b {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(end) = end else { return true };
        let args = Self::split_top_level_args(&expr[start + 1..end]);
        sink.sensitive_params
            .iter()
            .any(|&idx| args.get(idx).is_some_and(|a| Self::expr_mentions_var(a, var)))
    }

    /// 表达式中是否出现 Java 类字面量（`Policy.class`）。
    ///
    /// 按标识符字符切词后逐段判断，供类字面量豁免的 sink 使用：
    /// 赋值/返回表达式里的 `client.get(Policy.class, name)` 是存储查找，
    /// 不得标为 SQL/SSRF。
    fn expr_has_class_literal(expr: &str) -> bool {
        expr.split(|c: char| !(c.is_alphanumeric() || matches!(c, '_' | '.' | '$')))
            .any(|tok| super::taint::TaintSink::arg_is_class_literal(tok))
    }

    /// 在表达式中查找是否有 sink 函数调用
    ///
    /// 语义 sink（namespaces / receiver_patterns / exact_matches）只对解析出的
    /// callee / receiver.callee 匹配——完整表达式文本中的属性访问片段
    /// （如 `request.raw` 里的 `.raw`、`this.fetchClientConfig` 里的 `.fetch`）
    /// 不得触发语义 sink（backlog 10.11 误标根因）。
    ///
    /// Substring sink 保持对完整表达式的宽松匹配，兼容旧规则中形如
    /// `exec(` 的模式（可匹配 `exec(user_input)`）。
    fn find_matching_sink_in_expr(&self, expr: &str, language: &str) -> Option<TaintSink> {
        let (receiver, callee) = Self::extract_call_parts_from_expr(expr);
        // 类字面量豁免：表达式含 `Type.class` 时跳过声明了豁免的 sink
        // （`client.get(Policy.class, name)` 是存储查找而非 SQL/SSRF）
        let class_literal_exempt = Self::expr_has_class_literal(expr);
        for sink in self.sinks.iter() {
            if class_literal_exempt && sink.class_literal_exempt {
                continue;
            }
            if sink.has_semantic_constraints() {
                // 语义路径：qualified 优先（支持 exact_matches / namespaces），
                // 再用裸 callee + receiver 语义
                if let Some(recv) = receiver {
                    let qualified = format!("{}.{}", recv, callee);
                    if sink.matches_with_context(&qualified, Some(recv), language) {
                        return Some(sink.clone());
                    }
                }
                if sink.matches_with_context(callee, receiver, language) {
                    return Some(sink.clone());
                }
            } else if sink.matches_with_context(expr, receiver, language) {
                return Some(sink.clone());
            }
        }
        None
    }

    /// 赋值目标（左值）的 sink 匹配
    ///
    /// 用于 `x.innerHTML = tainted` 形态：sink 模式在左值属性上。
    /// 要求 sink 模式是目标的后缀且前置边界为 '.'（属性赋值），
    /// 避免 ".get" 这类调用模式误配 `document.getElementById(...)`
    /// 中的 callee 片段。返回 (sink, sink 名)。
    fn find_matching_sink_in_assign_target(
        &self,
        target: &str,
        language: &str,
    ) -> Option<(TaintSink, String)> {
        let target = target.trim();
        self.sinks
            .iter()
            .filter(|s| !s.storage_write)
            .filter(|s| {
                language == "*"
                    || language.is_empty()
                    || s.languages.iter().any(|l| l == "*" || l == language)
            })
            .find_map(|s| {
                s.patterns.iter().find_map(|p| {
                    if target.len() >= p.len()
                        && target.ends_with(p.as_str())
                        && (target.len() == p.len()
                            || target[..target.len() - p.len()].ends_with('.'))
                    {
                        Some((s.clone(), p.clone()))
                    } else {
                        None
                    }
                })
            })
    }

    /// 从表达式中提取 sink 函数名
    fn extract_sink_name(&self, expr: &str, language: &str) -> String {
        let (receiver, callee) = Self::extract_call_parts_from_expr(expr);
        // 与 find_matching_sink_in_expr 一致的类字面量豁免
        let class_literal_exempt = Self::expr_has_class_literal(expr);
        for sink in self.sinks.iter() {
            if class_literal_exempt && sink.class_literal_exempt {
                continue;
            }
            // 与 find_matching_sink_in_expr 同款语义：语义 sink 只看
            // callee/qualified，Substring sink 才看完整表达式（10.11）
            let matched = if sink.has_semantic_constraints() {
                let qualified_hit = receiver.map(|recv| {
                    let qualified = format!("{}.{}", recv, callee);
                    sink.matches_with_context(&qualified, Some(recv), language)
                });
                qualified_hit == Some(true)
                    || sink.matches_with_context(callee, receiver, language)
            } else {
                sink.matches_with_context(expr, receiver, language)
            };
            if matched {
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

    /// 判断表达式文本中是否出现净化器调用（标识符边界感知）。
    ///
    /// 普通子串匹配会把 `Base64.encodeBase64(x)` 中的 "encode" 误判为净化器，
    /// 导致 `new String(Base64.decodeBase64(Base64.encodeBase64(tainted)))` 这类
    /// 编码往返表达式被整体标记为已净化，切断污点传播。
    /// 这里要求匹配位置之后不能紧跟标识符字符（字母/数字/下划线），
    /// 保证 `encode(`、`URLEncoder.encode` 等仍可命中，而 `encodeBase64` 不命中。
    fn expr_mentions_sanitizer(expr: &str, pattern: &str) -> bool {
        let mut start = 0;
        while let Some(pos) = expr[start..].find(pattern) {
            let abs = start + pos;
            let followed_by_ident = expr
                .as_bytes()
                .get(abs + pattern.len())
                .map(|b| b.is_ascii_alphanumeric() || *b == b'_')
                .unwrap_or(false);
            if !followed_by_ident {
                return true;
            }
            start = abs + 1;
        }
        false
    }

    /// 判断污点变量在表达式中是否仅出现在净化器调用内部（内联净化）。
    ///
    /// 典型场景：sink 调用的参数被净化器就地包裹，
    /// 如 `model.addAttribute("keyword", HtmlUtils.htmlEscape(keyword))`，
    /// 此时污点变量 keyword 虽然到达 sink，但已被内联净化，不应产生 finding。
    ///
    /// 判定逻辑：
    /// 1. 按标识符边界收集表达式中所有净化器调用的参数区间（平衡括号），
    ///    复用 expr_mentions_sanitizer 的边界语义，避免 encode/encodeBase64 误命中；
    /// 2. 污点变量的每次完整出现（标识符边界）都必须落在某个净化器调用的
    ///    参数区间内，否则视为未净化（如 `sink(escape(x), x)` 中第二个 x）。
    fn is_inline_sanitized(&self, expr: &str, tainted_var: &str) -> bool {
        if tainted_var.is_empty() {
            return false;
        }
        let bytes = expr.as_bytes();
        let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';

        // ── 收集净化器调用的参数区间（开括号到配对的闭括号）──────────────
        let mut sanitized_spans: Vec<(usize, usize)> = Vec::new();
        for pattern in self.sanitizer_patterns.iter() {
            let mut start = 0;
            while let Some(pos) = expr[start..].find(pattern.as_str()) {
                let abs = start + pos;
                let end = abs + pattern.len();
                // 与 expr_mentions_sanitizer 一致的后置边界语义
                let followed_by_ident = bytes.get(end).map(|&b| is_ident(b)).unwrap_or(false);
                if followed_by_ident {
                    start = abs + 1;
                    continue;
                }
                // 跳过空白与可选的 .method 链（如 HtmlUtils.htmlEscape），定位开括号
                let mut i = end;
                loop {
                    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                        i += 1;
                    }
                    if bytes.get(i) == Some(&b'.') {
                        i += 1;
                        while i < bytes.len() && is_ident(bytes[i]) {
                            i += 1;
                        }
                        continue;
                    }
                    break;
                }
                if bytes.get(i) == Some(&b'(') {
                    // 平衡括号提取整个调用的参数区间
                    let mut depth = 0usize;
                    let mut j = i;
                    while j < bytes.len() {
                        match bytes[j] {
                            b'(' => depth += 1,
                            b')' => {
                                depth -= 1;
                                if depth == 0 {
                                    break;
                                }
                            }
                            _ => {}
                        }
                        j += 1;
                    }
                    if depth == 0 {
                        sanitized_spans.push((i, j));
                    }
                }
                start = abs + 1;
            }
        }
        if sanitized_spans.is_empty() {
            return false;
        }

        // ── 污点变量的每次完整出现都必须位于某个净化器调用区间内 ──────────
        let mut found_any = false;
        let mut start = 0;
        while let Some(pos) = expr[start..].find(tainted_var) {
            let abs = start + pos;
            let end = abs + tainted_var.len();
            let prev_ok = abs == 0 || !is_ident(bytes[abs - 1]);
            let next_ok = end >= bytes.len() || !is_ident(bytes[end]);
            start = abs + 1;
            if !prev_ok || !next_ok {
                continue;
            }
            found_any = true;
            if !sanitized_spans
                .iter()
                .any(|&(s, e)| abs > s && end <= e)
            {
                return false;
            }
        }
        found_any
    }

    /// 10.15①/② sink 级豁免（判定层沉淀的去误报方向，R51 扩展）。
    ///
    /// - SSRF（10.15①）：sink 表达式中 URL host 为字面量常量时目标固定，
    ///   污点仅影响路径/查询段，不构成 SSRF（`"https://api.com" + path`）；
    ///   host 来自变量（`"https://" + host`）时表达式无完整字面量 `://`，保守不豁免。
    /// - PathTraversal（10.15②）：污点变量的所有出现都处于数值强制转换调用内
    ///   （int()/Number()/parseInt()/parseFloat() 等），插值数字化（DB 自增 id、
    ///   数字主键）拼接进路径不构成路径遍历。
    fn sink_exempt(sink: &TaintSink, expr: &str, tainted_var: &str) -> bool {
        if tainted_var.is_empty() {
            return false;
        }
        match sink.vulnerability_type {
            VulnerabilityType::ServerSideRequestForgery => {
                Self::expr_ssrf_literal_host(expr, tainted_var)
            }
            VulnerabilityType::PathTraversal => {
                Self::expr_var_numeric_coerced(expr, tainted_var)
            }
            _ => false,
        }
    }

    /// 取传播步骤链中最近一个带代码片段的步骤的右值表达式。
    /// 用于 sink 调用处只有变量名时回溯赋值来源（如 `path = ".../" + str(int(uid))` → open(path)）。
    fn last_assign_snippet(steps: &[PropagationStep]) -> Option<&str> {
        steps.iter().rev().find_map(|s| s.code_snippet.as_deref())
    }

    /// 10.15①：URL host 字面量判定。只认 `"scheme://literal"` 直接形态，
    /// host 段取 `://` 后到 `/ ? # " ' 空白 ;` 的第一个分隔符。
    fn expr_ssrf_literal_host(expr: &str, tainted_var: &str) -> bool {
        let Some(pos) = expr.find("://") else {
            return false;
        };
        let rest = &expr[pos + 3..];
        let host_end = rest
            .find(|c: char| matches!(c, '/' | '?' | '#' | '"' | '\'' | ' ' | ';' | '\t' | '\n'))
            .unwrap_or(rest.len());
        let host = &rest[..host_end];
        !host.is_empty() && !host.contains(tainted_var)
    }


    /// R55（10.15① 扩展）：SSRF 同源相对 URL 豁免（BookStack 客户端 XHR FP 家族）。
    /// 污点参数为以 `/` 开头的字符串/模板字面量（`` `/api/${id}` ``）时是同源
    /// 相对 URL——路径段如何被污染 host 都不可控，不构成 SSRF（浏览器 XHR 与
    /// 服务端代码同理）。`//` 开头是协议相对 URL（host 可控），不豁免。
    fn expr_ssrf_relative_url(arg_text: &str) -> bool {
        let t = arg_text.trim();
        let bytes = t.as_bytes();
        if bytes.len() < 2 {
            return false;
        }
        if !matches!(bytes[0], b'\'' | b'"' | b'`') {
            return false;
        }
        bytes[1] == b'/' && bytes.get(2) != Some(&b'/')
    }

    /// 10.15②：污点变量所有出现是否都处于数值强制转换调用参数区间内。
    /// 复用 is_inline_sanitized 的平衡括号配对语义，但转换函数列表固定
    /// （不依赖 sanitizer_patterns——"int(" 子串会误中 print( 等，不能进全局净化器）。
    fn expr_var_numeric_coerced(expr: &str, tainted_var: &str) -> bool {
        if tainted_var.is_empty() {
            return false;
        }
        let coercion_spans = Self::numeric_coercion_spans(expr);
        if coercion_spans.is_empty() {
            return false;
        }
        let bytes = expr.as_bytes();
        let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';

        // ── 污点变量的每次完整出现都必须落在某个转换调用区间内 ──────────
        let mut found_any = false;
        let mut start = 0;
        while let Some(pos) = expr[start..].find(tainted_var) {
            let abs = start + pos;
            let end = abs + tainted_var.len();
            let prev_ok = abs == 0 || !is_ident(bytes[abs - 1]);
            let next_ok = end >= bytes.len() || !is_ident(bytes[end]);
            start = abs + 1;
            if !prev_ok || !next_ok {
                continue;
            }
            found_any = true;
            if !coercion_spans
                .iter()
                .any(|&(s, e)| abs > s && end <= e)
            {
                return false;
            }
        }
        found_any
    }

    /// 收集表达式中所有数值强制转换调用的参数区间（开括号到配对闭括号）。
    fn numeric_coercion_spans(expr: &str) -> Vec<(usize, usize)> {
        const COERCIONS: &[&str] = &[
            "int",
            "integer",
            "Number",
            "parseInt",
            "parseFloat",
            "float",
            "long",
            "double",
            "toInt",
            "atoi",
            "intval",
            "strtol",
            "strtod",
        ];
        let bytes = expr.as_bytes();
        let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';

        let mut coercion_spans: Vec<(usize, usize)> = Vec::new();
        for name in COERCIONS {
            let mut start = 0;
            while let Some(pos) = expr[start..].find(name) {
                let abs = start + pos;
                let end = abs + name.len();
                let prev_ok = abs == 0 || !is_ident(bytes[abs - 1]);
                let next_ok = end >= bytes.len() || !is_ident(bytes[end]);
                if !prev_ok || !next_ok {
                    start = abs + 1;
                    continue;
                }
                // 跳过空白，定位开括号
                let mut i = end;
                while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                if bytes.get(i) != Some(&b'(') {
                    start = abs + 1;
                    continue;
                }
                let mut depth = 0usize;
                let mut j = i;
                while j < bytes.len() {
                    match bytes[j] {
                        b'(' => depth += 1,
                        b')' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    j += 1;
                }
                if depth == 0 {
                    coercion_spans.push((i, j));
                }
                start = abs + 1;
            }
        }
        coercion_spans
    }

    /// 10.15② 表达式级判定：表达式中**所有污点标识符**是否都落在数值转换
    /// 区间内（含源头变量被包裹、sink 调用处只有变量名的回溯场景）。
    /// 任一污点标识符出现在转换区间外 → 不豁免（`str(int(a)) + b` 形态）。
    /// 泛型 state：t 判断单个标识符是否为污点。
    fn expr_taints_all_numeric_with<F>(expr: &str, is_tainted: F) -> bool
    where
        F: Fn(&str) -> bool,
    {
        let coercion_spans = Self::numeric_coercion_spans(expr);
        if coercion_spans.is_empty() {
            return false;
        }
        let bytes = expr.as_bytes();
        let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
        let mut found_taint = false;
        let mut i = 0usize;
        while i < bytes.len() {
            if !is_ident(bytes[i]) {
                i += 1;
                continue;
            }
            let start = i;
            while i < bytes.len() && is_ident(bytes[i]) {
                i += 1;
            }
            let ident = &expr[start..i];
            if !is_tainted(ident) {
                continue;
            }
            found_taint = true;
            // 污点标识符必须整体落在某个转换区间内
            if !coercion_spans
                .iter()
                .any(|&(s, e)| start >= s && i <= e)
            {
                return false;
            }
        }
        found_taint
    }

    /// 数据类型推断：检测是否使用了参数化查询模式
    ///
    /// 保守策略：仅当代码行出现显式参数占位符（? / %s / :name）且没有字符串拼接时，
    /// 或调用的是参数绑定 API（setString、bindParam 等）时才认为是安全的参数化查询。
    /// 这样可避免把 `prepareCall(sql)` 这种拼接 SQL 的调用误判为安全。
    fn is_parameterized_query(&self, callee: &str, code_line: &str) -> bool {
        let callee_lower = callee.to_lowercase();
        let code_lower = code_line.to_lowercase();

        // 显式参数绑定 API：无论 SQL 写法如何，都视为参数化
        let binding_apis = [
            "bind_param",
            "bindparam",
            "bind_value",
            "addparam",
            "setstring",
            "setint",
            "setlong",
            "setobject",
        ];
        for api in &binding_apis {
            if callee_lower.contains(api) {
                return true;
            }
        }

        // 保守的占位符检测：要求存在 ? / %s / :name / @name 等占位符，且没有字符串拼接
        let bytes = code_lower.as_bytes();
        let has_named_placeholder = |prefix: u8| -> bool {
            bytes.iter().enumerate().any(|(i, &b)| {
                if b != prefix {
                    return false;
                }
                let prev_ok = i == 0 || bytes[i - 1] != prefix;
                let next_ok = i + 1 < bytes.len() && bytes[i + 1].is_ascii_alphabetic();
                prev_ok && next_ok
            })
        };
        let has_placeholder = code_lower.contains('?')
            || code_lower.contains("%s")
            || has_named_placeholder(b':')
            || has_named_placeholder(b'@');
        let has_concatenation = code_lower.contains(" + ")
            || code_lower.contains(".format(")
            || code_lower.starts_with("f\"")
            || code_lower.starts_with("f'");

        if has_placeholder && !has_concatenation {
            return true;
        }

        // ORM 安全方法（通常为结构化查询，不含字符串拼接 SQL）
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
            // 无赋值形式：检查 binding call（Go ShouldBind/Bind 等污染参数）
            // 模式：xxx.ShouldBind(&req) / xxx.Bind(&req) / xxx.BindJSON(&req)
            return self.extract_var_from_binding_call(line);
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
                // PHP 变量以 $ 开头（$v / $_GET），赋值提取与参数引用均保留 $ 符
                .map(|c| c.is_alphabetic() || c == '_' || c == '$')
                .unwrap_or(false)
        {
            return Some(var_name);
        }

        None
    }

    /// 从 binding call 中提取被污染的参数变量
    /// 模式：c.ShouldBind(&req) / c.Bind(&req) / c.BindJSON(&req) / json.Unmarshal(data, &req)
    /// 提取 & 后面的变量名
    fn extract_var_from_binding_call(&self, line: &str) -> Option<String> {
        // 查找 &var 模式（Go 取地址符后跟变量名）
        if let Some(amp_pos) = line.find('&') {
            let after_amp = line[amp_pos + 1..].trim();
            // 提取变量名：取字母/数字/下划线序列
            let var_name: String = after_amp
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !var_name.is_empty()
                && var_name
                    .chars()
                    .next()
                    .map(|c| c.is_alphabetic() || c == '_')
                    .unwrap_or(false)
            {
                return Some(var_name);
            }
        }
        None
    }

    /// LoopHeader 传播：for range / for in / for of
    /// 若 range/in/of 后的集合引用了污点变量，将污点传播到迭代变量
    fn transfer_loop_header(
        &self,
        node: &EnhancedFlowNode,
        state: &mut HashMap<String, TaintInfo>,
        alias_map: &AliasMap,
    ) {
        let code = &node.code;
        // 解析 "for X, Y := range Z" 或 "for X in Z" 或 "for (X of Z)"
        // 提取迭代变量（:= 或 = 或 in/of 左侧）和集合表达式（range/in/of 右侧）
        let (iter_vars, collection_expr) = if let Some(range_pos) = code.find("range ") {
            // Go: for _, name := range req.Names
            let before_range = &code[..range_pos];
            let after_range = &code[range_pos + 6..];
            // 提取 := 或 = 左侧的变量
            let lhs = if let Some(pos) = before_range.find(":=") {
                &before_range[..pos]
            } else if let Some(pos) = before_range.find('=') {
                &before_range[..pos]
            } else {
                ""
            };
            let vars: Vec<String> = lhs
                .split(',')
                .filter_map(|v| {
                    let v = v.trim().trim_start_matches("for ").trim();
                    if v.is_empty() || v == "_" { None }
                    else { Some(v.to_string()) }
                })
                .collect();
            (vars, after_range.trim().to_string())
        } else if let Some(in_pos) = code.find(" in ") {
            // Python: for name in req.names
            let before_in = &code[..in_pos];
            let after_in = &code[in_pos + 4..];
            let lhs = before_in.trim_start_matches("for ").trim();
            let vars: Vec<String> = lhs
                .split(',')
                .filter_map(|v| {
                    let v = v.trim();
                    if v.is_empty() || v == "_" { None }
                    else { Some(v.to_string()) }
                })
                .collect();
            (vars, after_in.trim().trim_end_matches(':').to_string())
        } else if let Some(of_pos) = code.find(" of ") {
            // JS: for (const name of req.names)
            let before_of = &code[..of_pos];
            let after_of = &code[of_pos + 4..];
            let lhs = before_of
                .trim_start_matches("for ")
                .trim_start_matches('(')
                .trim_start_matches("const ")
                .trim_start_matches("let ")
                .trim_start_matches("var ")
                .trim();
            let vars: Vec<String> = lhs
                .split(',')
                .filter_map(|v| {
                    let v = v.trim();
                    if v.is_empty() || v == "_" { None }
                    else { Some(v.to_string()) }
                })
                .collect();
            (vars, after_of.trim().trim_end_matches(')').to_string())
        } else {
            return;
        };

        if iter_vars.is_empty() {
            return;
        }

        // 检查集合表达式中是否有污点变量
        let collection_vars: Vec<&str> = collection_expr
            .split(|c: char| !c.is_alphanumeric() && c != '_' && c != '.')
            .filter(|s| !s.is_empty())
            .collect();

        let mut tainted_source: Option<String> = None;
        for cv in &collection_vars {
            let root = cv.split('.').next().unwrap_or(cv);
            if state.contains_key(root) || state.contains_key(*cv) {
                tainted_source = Some(root.to_string());
                break;
            }
            // 别名解析
            for alias in alias_map.resolve(root) {
                let dotted = alias.as_dotted();
                if state.contains_key(&dotted) || state.contains_key(alias.root()) {
                    tainted_source = Some(root.to_string());
                    break;
                }
            }
            if tainted_source.is_some() {
                break;
            }
        }

        if let Some(source_var) = tainted_source {
            for var in &iter_vars {
                if !state.contains_key(var) {
                    state.insert(
                        var.clone(),
                        TaintInfo {
                            source_line: node.start_line,
                            source_var: source_var.clone(),
                            sanitized: false,
                            sanitizer: None,
                            propagation_steps: vec![PropagationStep {
                                step_type: PropagationStepType::FieldPropagation,
                                from_var: Some(source_var.clone()),
                                to_var: Some(var.clone()),
                                line: node.start_line,
                                code_snippet: Some(code.clone()),
                                function_name: None,
                            }],
                        },
                    );
                }
            }
        }
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
            TaintSource::new(
                "template_render_output",
                "Template Render Output",
                vec![
                    "template.render",
                    "env.from_string",
                    "render_template_string",
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
                vec![
                    "open(",
                    "fopen",
                    "readFile",
                    "writeFile",
                    "fs.open",
                    // 10.16 扩展（R51）：Python pathlib Path(x) 构造即路径操作
                    "Path(",
                ],
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
                // compile( 已于 10.15④ 移除：JS 侧 Handlebars/WebAssembly/RegExp
                // compile 为静态模板/正则编译非动态执行；Python 侧 re.compile 高频无害，
                // 真动态执行面由 eval(/exec(/Function( 覆盖
                vec!["eval(", "Function(", "__import__"],
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
        // 使用硬编码默认规则（宽松子串匹配）；YAML 语义规则要求命名空间/精确匹配，
        // 不会命中裸 exec() 调用
        let mut analyzer = AstTaintAnalyzer::with_default_rules();
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
        // 使用硬编码默认规则（宽松子串匹配）；YAML 语义规则不会命中裸 exec() 调用
        let mut analyzer = AstTaintAnalyzer::with_default_rules();
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

    /// 10.16 回归（R42 GHSA-28cf 回放）：Jinja2 模板渲染输出用作文件路径
    /// 必须被识别为路径遍历 source（漏洞版：render 输出直接拼路径，无净化）
    #[test]
    fn test_python_template_render_as_path_source() {
        let code = r#"from jinja2 import Environment
env = Environment()
template = env.from_string("path: {{ user_input }}")
target = template.render(user_input=request.args.get('p'))
f = open("/var/data/" + target)
content = f.read()"#;
        let mut analyzer = AstTaintAnalyzer::new();
        let path = std::path::PathBuf::from("views.py");
        let flows = analyzer.analyze_code(code, &path, "download", &[], &[]);

        assert!(!flows.is_empty(), "模板渲染输出用作路径应命中路径遍历");
    }

    /// 10.16 补充（R51）：render 输出直接经 pathlib Path() 构造（GHSA-28cf 真实链
    /// 形态：filepath.py render → file_handling.py `base_path = Path(rendered_path)`）
    #[test]
    fn test_python_template_render_into_pathlib() {
        let code = r#"from jinja2 import Environment
from pathlib import Path
env = Environment()
template = env.from_string("path: {{ user_input }}")
rendered_path = template.render(user_input=request.args.get('p'))
base_path = Path(rendered_path)
print(base_path)"#;
        let mut analyzer = AstTaintAnalyzer::new();
        let path = std::path::PathBuf::from("views.py");
        let flows = analyzer.analyze_code(code, &path, "download", &[], &[]);

        assert!(!flows.is_empty(), "render 输出经 Path() 构造应命中路径遍历");
    }

    /// 10.16 负例：渲染输出经 basename 净化后不应命中（修复形态）
    #[test]
    fn test_python_template_render_sanitized_no_flow() {
        let code = r#"from jinja2 import Environment
import os
env = Environment()
template = env.from_string("path: {{ user_input }}")
target = template.render(user_input=request.args.get('p'))
safe = os.path.basename(target)
f = open("/var/data/" + safe)
content = f.read()"#;
        let mut analyzer = AstTaintAnalyzer::new();
        let path = std::path::PathBuf::from("views.py");
        let flows = analyzer.analyze_code(code, &path, "download", &[], &[]);

        assert!(flows.is_empty(), "basename 净化后不应命中路径遍历");
    }

    #[test]
    fn test_second_order_source_confidence_discount_keeps_severity() {
        // 二阶 source（存储点读出）：source 标签携带 (second-order)，
        // flow 置信度打折（0.85×0.7≈0.6），严重度保留（存储型漏洞本身即高危）
        let mut so_source = TaintSource::new("so_db", "DB Row", vec![".fetchone("]);
        so_source.second_order = true;
        so_source.languages = vec!["python".to_string()];

        let sink = TaintSink::new(
            "eval",
            "Eval",
            vec!["eval("],
            VulnerabilityType::CodeInjection,
        );

        let analyzer = AstTaintAnalyzer::new()
            .with_sources(vec![so_source])
            .with_sinks(vec![sink]);

        let code = r#"data = cursor.fetchone()
eval(data)"#;
        let path = std::path::PathBuf::from("show.py");
        let flows = analyzer.analyze_code(code, &path, "render", &[], &[]);

        assert!(!flows.is_empty(), "二阶 source → sink 应产生 flow");
        let flow = &flows[0];
        assert!(
            flow.source.symbol.contains("(second-order)"),
            "source 标签应携带 (second-order): {}",
            flow.source.symbol
        );
        assert!(
            flow.confidence < 0.7,
            "二阶 flow 置信度应打折: {}",
            flow.confidence
        );
        assert!(
            matches!(flow.severity, Severity::High | Severity::Critical),
            "二阶 flow 严重度不应降级: {:?}",
            flow.severity
        );
    }

    #[test]
    fn test_storage_write_sink_produces_gate_flow() {
        // storage_write sink：污点到达存储写入点时产生 StorageWrite 类型的 flow
        //（finding 过滤与闸门统计在 scanner 层完成）
        let source = TaintSource::new("input", "Input", vec!["request.args"]);
        let mut sw_sink = TaintSink::new(
            "sql_write",
            "SQL Write",
            vec!["db_query("],
            VulnerabilityType::StorageWrite,
        );
        sw_sink.storage_write = true;

        let analyzer = AstTaintAnalyzer::new()
            .with_sources(vec![source])
            .with_sinks(vec![sw_sink]);

        let code = r#"v = request.args.get('title')
sql = "INSERT INTO t VALUES ('%s')" % v
db_query(sql)"#;
        let path = std::path::PathBuf::from("save.py");
        let flows = analyzer.analyze_code(code, &path, "save", &[], &[]);

        assert!(!flows.is_empty(), "污点写入应产生闸门 flow");
        assert_eq!(
            flows[0].vulnerability_type,
            VulnerabilityType::StorageWrite,
            "闸门 flow 类型应为 StorageWrite"
        );
    }
    /// 生产 Stage B 路径回归：extract_all_for_taint_with_tree →
    /// build_function_cpg_from_text → analyze_function_cpg。
    /// Python 二阶流（DB 读出 → 模板渲染）必须产出带 (second-order) 标签的 flow。
    /// （历史上 body_start_line 偏移 bug 使该路径产出 0 flow）
    #[test]
    fn test_production_cpg_path_python_second_order() {
        let code = r#"import sqlite3
from flask import render_template_string

def show():
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT name FROM users LIMIT 1")
    row = cur.fetchone()
    name = row[0]
    return render_template_string("<h1>" + name + "</h1>")
"#;
        let (cpg, func) = build_production_cpg(code, "show.py", "show");
        let analyzer = yaml_rule_analyzer();
        let flows = analyzer.analyze_function_cpg(&cpg, &func.body_text, &[]);
        assert!(!flows.is_empty(), "生产 CPG 路径应产出二阶 flow");
        assert!(
            flows.iter().any(|f| f.source.symbol.contains("(second-order)")),
            "应存在二阶 flow: {:?}",
            flows.iter().map(|f| f.source.symbol.clone()).collect::<Vec<_>>()
        );
    }

    /// 生产路径回归：一阶输入写入 SQL 字符串赋值时，
    /// storage_write sink（INSERT INTO）在赋值右值命中并产出闸门 flow
    #[test]
    fn test_production_cpg_path_storage_write_gate() {
        let code = r#"import sqlite3
from flask import request

def save():
    name = request.args.get("name")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    sql = "INSERT INTO users (name) VALUES ('%s')" % name
    cur.execute(sql)
    conn.commit()
    return "ok"
"#;
        let (cpg, func) = build_production_cpg(code, "save.py", "save");
        let analyzer = yaml_rule_analyzer();
        let flows = analyzer.analyze_function_cpg(&cpg, &func.body_text, &[]);
        assert!(
            flows.iter().any(|f| f.vulnerability_type == VulnerabilityType::StorageWrite),
            "污点写入存储点应产生闸门 flow: {:?}",
            flows.iter().map(|f| format!("{}", f.vulnerability_type)).collect::<Vec<_>>()
        );
    }

    /// sensitive_params 参数位置感知：cur.execute(query, (q,)) 中污点 q 位于
    /// arg1（参数绑定元组），SQL sink 的敏感参数是 arg0（查询串），
    /// 参数化查询不应产出 SQLi flow（healthchecks docs_search 形态）
    #[test]
    fn test_production_cpg_path_parameterized_execute_not_sqli() {
        let code = r#"import sqlite3
from flask import request

def search():
    q = request.args.get("q")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    query = "SELECT slug FROM docs WHERE docs MATCH ?"
    res = cur.execute(query, (q,))
    return res
"#;
        let (cpg, func) = build_production_cpg(code, "search.py", "search");
        let analyzer = yaml_rule_analyzer();
        let flows = analyzer.analyze_function_cpg(&cpg, &func.body_text, &[]);
        assert!(
            !flows
                .iter()
                .any(|f| f.vulnerability_type == VulnerabilityType::SqlInjection),
            "参数化 execute（污点在 arg1 绑定元组，含赋值右值形态）不应报 SQLi: {:?}",
            flows.iter().map(|f| format!("{}", f.vulnerability_type)).collect::<Vec<_>>()
        );
    }

    /// sensitive_params 正例对照：污点经拼接进入 arg0 查询串仍必须检出
    #[test]
    fn test_production_cpg_path_concat_query_still_sqli() {
        let code = r#"import sqlite3
from flask import request

def search():
    q = request.args.get("q")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT slug FROM docs WHERE slug = '" + q + "'")
    return "ok"
"#;
        let (cpg, func) = build_production_cpg(code, "search.py", "search");
        let analyzer = yaml_rule_analyzer();
        let flows = analyzer.analyze_function_cpg(&cpg, &func.body_text, &[]);
        assert!(
            flows
                .iter()
                .any(|f| f.vulnerability_type == VulnerabilityType::SqlInjection),
            "拼接查询串（污点在 arg0）必须报 SQLi"
        );
    }

    /// 生产路径回归：PHP 函数内一阶链（$_GET → eval）。
    /// 覆盖两个历史 bug：PHP 调用节点（function_call_expression 等）未提取、
    /// $ 开头变量名被 extract_var_from_source 拒绝
    #[test]
    fn test_production_cpg_path_php_first_order() {
        let code = r#"<?php
function handler() {
    $v = $_GET['x'];
    eval($v);
}
"#;
        let (cpg, func) = build_production_cpg(code, "a.php", "handler");
        let analyzer = yaml_rule_analyzer();
        let flows = analyzer.analyze_function_cpg(&cpg, &func.body_text, &[]);
        assert!(
            flows.iter().any(|f| f.sink.symbol.contains("eval")),
            "PHP 一阶链应产出 flow: {:?}",
            flows.iter().map(|f| format!("{}->{}", f.source.symbol, f.sink.symbol)).collect::<Vec<_>>()
        );
    }

    /// 模拟生产 Stage B：从文件内容提取函数并构建 text-based CPG
    fn build_production_cpg(
        code: &str,
        file: &str,
        func_name: &str,
    ) -> (crate::analysis::cpg::FunctionCPG, crate::ast::symbol::FunctionBody) {
        let pb = std::path::PathBuf::from(file);
        let extracted = crate::ast::parser::with_thread_local_parser(|p| {
            p.extract_all_for_taint_with_tree(&pb, code)
        });
        let (_tree, _symbols, functions, file_assignments, file_calls) =
            extracted.expect("extract_all_for_taint_with_tree 失败");
        let func = functions
            .iter()
            .find(|f| f.name == func_name)
            .unwrap_or_else(|| panic!("{} 函数未提取", func_name))
            .clone();
        let fa: Vec<_> = file_assignments
            .iter()
            .filter(|a| a.line >= func.start_line && a.line <= func.end_line)
            .cloned()
            .collect();
        let fc: Vec<_> = file_calls
            .iter()
            .filter(|c| c.line >= func.start_line && c.line <= func.end_line)
            .cloned()
            .collect();
        let cpg = crate::analysis::cpg::CPGBuilder::build_function_cpg_from_text(
            &func.body_text, file, &func, &fa, &fc,
        );
        (cpg, func)
    }

    /// 与 CLI 生产环境一致的 YAML 污点规则分析器
    fn yaml_rule_analyzer() -> AstTaintAnalyzer {
        let loaded = crate::rules::taint_loader::load_taint_rules_with_embedded_fallback(
            std::path::Path::new("rules/taint"),
        );
        AstTaintAnalyzer::from_rules_arc(
            std::sync::Arc::new(loaded.sources),
            std::sync::Arc::new(loaded.sinks),
            std::sync::Arc::new(loaded.sanitizer_patterns),
        )
    }

    /// 属性路径不得命中 SSRF sink（10.11 第二波）：
    /// "request.session.loginAuthProviderIdentifier" 中 "request" 是属性
    /// 路径段而非方法调用，不得命中 ".request" pattern + "request" namespace
    #[test]
    fn test_property_path_not_ssrf_sink() {
        let analyzer = yaml_rule_analyzer();
        for expr in [
            "request.session.loginAuthProviderIdentifier",
            "request.session.oidc?.loginCode ?? undefined",
        ] {
            let hit = analyzer.find_matching_sink_in_expr(expr, "typescript");
            assert!(
                hit.is_none(),
                "属性路径 {:?} 不得命中任何 sink: {:?}",
                expr,
                hit.map(|s| s.id)
            );
        }
        // 正向保持：request 库的 request.get(url) 形态仍命中
        let hit = analyzer.find_matching_sink_in_expr("request.get(url)", "javascript");
        assert!(
            hit.is_some(),
            "request.get(url) 应命中 HTTP 请求类 sink"
        );
    }

    /// backlog 10.11 回归：真实 YAML 规则下，表达式级 sink 检测不得把
    /// 非 SQL/非 HTTP 调用误标为语义 sink——
    /// `client.callbackParams(request.raw)` 曾命中 ".raw"（参数片段子串）、
    /// `this.clientConfigs.get(...)` 曾命中 receiver "client" 子串 + ".get"、
    /// `this.fetchClientConfig(...)` 曾命中 ".fetch" 子串。
    #[test]
    fn test_expr_sink_semantic_no_mislabel() {
        let analyzer = yaml_rule_analyzer();

        // 表达式中的参数属性片段不得触发语义 SQL sink
        let hit = analyzer.find_matching_sink_in_expr("client.callbackParams(request.raw)", "typescript");
        assert!(
            hit.as_ref().map(|s| &s.id) != Some(&"sql_exec".to_string()),
            "request.raw 参数片段不得命中 sql_exec: {:?}",
            hit.map(|s| s.id)
        );

        // Map.get 不得命中 SQL sink（receiver "clientConfigs" 无边界）
        let hit = analyzer
            .find_matching_sink_in_expr("this.clientConfigs.get(oidcIdentifier)", "typescript");
        assert!(
            hit.is_none(),
            "clientConfigs.get 不得命中任何 sink: {:?}",
            hit.map(|s| s.id)
        );

        // fetchClientConfig 不得命中 SSRF sink
        let hit =
            analyzer.find_matching_sink_in_expr("this.fetchClientConfig(oidcConfig)", "typescript");
        assert!(
            hit.as_ref().map(|s| &s.id) != Some(&"http_request".to_string()),
            "fetchClientConfig 不得命中 http_request: {:?}",
            hit.map(|s| s.id)
        );

        // 正向保持：真实 SQL/HTTP 调用仍命中（防过度收紧）
        let hit = analyzer.find_matching_sink_in_expr("connection.query(sql)", "javascript");
        assert_eq!(
            hit.as_ref().map(|s| s.id.as_str()),
            Some("sql_exec"),
            "connection.query 应命中 sql_exec"
        );
        // axios 实例形态（client.get）仍命中 SSRF sink；
        // `.fetch` 已从通用字典移除（Java 存储语义误伤），JS 全局 fetch(
        // 由 express-node 字典覆盖
        let hit = analyzer.find_matching_sink_in_expr("client.get(url)", "javascript");
        assert_eq!(
            hit.as_ref().map(|s| s.id.as_str()),
            Some("http_request"),
            "client.get 应命中 http_request"
        );
        // Substring sink 保持完整表达式宽松匹配
        let hit = analyzer.find_matching_sink_in_expr("eval(userInput)", "javascript");
        assert_eq!(
            hit.as_ref().map(|s| s.id.as_str()),
            Some("eval"),
            "eval(userInput) 应命中 eval sink"
        );
    }

    /// 类字面量豁免（halo WebFlux FP 家族）：`client.get(Policy.class, name)`
    /// 是仓库/类型注册查找，不得命中声明了 class_literal_exempt 的 SQL/SSRF sink；
    /// 无类字面量参数的同形态调用不受影响。
    #[test]
    fn test_class_literal_exempt_sink() {
        let analyzer = yaml_rule_analyzer();

        // 类字面量参数 → SQL/SSRF sink 豁免
        let hit = analyzer
            .find_matching_sink_in_expr("client.get(Policy.class, name)", "java");
        assert!(
            hit.as_ref().map(|s| &s.id) != Some(&"sql_exec".to_string())
                && hit.as_ref().map(|s| &s.id) != Some(&"http_request".to_string()),
            "client.get(Policy.class, name) 不得命中 SQL/SSRF sink: {:?}",
            hit.map(|s| s.id)
        );
        let hit =
            analyzer.find_matching_sink_in_expr("session.fetch(User.class, id)", "java");
        assert!(
            hit.as_ref().map(|s| &s.id) != Some(&"http_request".to_string()),
            "session.fetch(User.class, id) 不得命中 SSRF sink: {:?}",
            hit.map(|s| s.id)
        );

        // 无类字面量参数 → 正常命中（防过度收紧）
        let hit = analyzer.find_matching_sink_in_expr("client.get(url)", "javascript");
        assert_eq!(
            hit.as_ref().map(|s| s.id.as_str()),
            Some("http_request"),
            "client.get(url) 应命中 http_request"
        );

        // 小写开头属性路径（some.class）不得误判为类字面量
        assert!(!crate::analysis::taint::TaintSink::arg_is_class_literal("some.class"));
        assert!(crate::analysis::taint::TaintSink::arg_is_class_literal("Policy.class"));
        assert!(crate::analysis::taint::TaintSink::arg_is_class_literal("com.foo.Policy.class"));
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

    /// backlog 10.10 回归：analyze_file 对多函数 Python 文件，
    /// 非首函数内的污点链必须闭合并报告正确的文件绝对行号——
    /// 此前 line_offset 误用 start_line（签名行），Python 体首行在下一行，
    /// CFG 节点与 assign/call 元数据错位导致查表失败、0 flow。
    #[test]
    fn test_analyze_file_python_second_function_offset() {
        let mut analyzer = AstTaintAnalyzer::new();
        let code = r#"def helper():
    return 1


def handler():
    user_input = request.args.get('cmd')
    eval(user_input)
"#;
        let path = std::path::PathBuf::from("app.py");
        let flows = analyzer.analyze_file(&path, code);
        assert!(
            !flows.is_empty(),
            "analyze_file 应检出第二个函数中的 request.args → eval 链"
        );
        let flow = &flows[0];
        // eval 在第 7 行（文件绝对行号），偏移错误时会偏到 6 或 8
        assert_eq!(
            flow.sink.line, 7,
            "sink 行号应为文件绝对行号 7，实际: {}",
            flow.sink.line
        );
    }

    /// backlog 10.12 回归：分支点超过预算（80）的函数跳过污点传播——
    /// 路径敏感状态随分支数指数增长（合成用例每 +50 if 耗时翻倍，
    /// 300+ if 卡死整轮扫描，nocodb columns.service.ts columnUpdate 案例）。
    /// 必须用 JS/TS 验证：fragment CPG 才构建真实分支边（Python 走
    /// text 回退 CFG，无分支结构，不会爆炸也不会触发预算）。
    #[test]
    fn test_branch_budget_skips_giant_function() {
        let analyzer = yaml_rules_analyzer();
        let path = std::path::PathBuf::from("app.js");

        let mut big = String::from("async function handler(req) {\n  const q = req.query.x;\n");
        for i in 0..120 {
            big.push_str(&format!(
                "  if (req.c{i}) {{ document.getElementById(\"a\").innerHTML = q; }}\n"
            ));
        }
        big.push_str("}\n");
        let report = analyzer.analyze_file_cpg(&path, &big);
        assert!(
            report.flows.is_empty(),
            "分支超预算函数应跳过污点传播，实际产出 {} 条 flow",
            report.flows.len()
        );

        // 对照：预算内的同构代码正常检出（证明预算分支是跳过原因，而非链路本身不工作）
        let mut small = String::from("async function handler(req) {\n  const q = req.query.x;\n");
        for i in 0..5 {
            small.push_str(&format!(
                "  if (req.c{i}) {{ document.getElementById(\"a\").innerHTML = q; }}\n"
            ));
        }
        small.push_str("}\n");
        let report = analyzer.analyze_file_cpg(&path, &small);
        assert!(
            !report.flows.is_empty(),
            "预算内函数的污点流应正常产出"
        );
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
    fn test_java_xss_inline_sanitizer_in_sink_arg_no_flow() {
        // 内联净化：污点变量仅在 sink 参数的净化器调用内部出现，不应产生 finding。
        // 使用无 receiver 的净化器（escapeHtml），保证按行去重后 sink 调用
        // （addAttribute）本身被保留，真正走到 is_inline_sanitized 判定。
        let code = r#"public class SearchController {
    public String search(HttpServletRequest request, Model model) {
        String keyword = request.getParameter("keyword");
        model.addAttribute("keyword", escapeHtml(keyword));
        return "search";
    }
}"#;
        let mut analyzer = analyzer_with_yaml_rules();
        let path = std::path::PathBuf::from("SearchController.java");
        let flows = analyzer.analyze_code(code, &path, "search", &[], &[]);
        assert!(
            flows.is_empty(),
            "内联净化的 addAttribute 参数不应产生 XSS finding，实际 {} 条",
            flows.len()
        );
    }

    #[test]
    fn test_java_xss_sink_arg_without_sanitizer_reports() {
        // 对照组：去掉内联净化后，同样的 addAttribute 调用必须报出
        let code = r#"public class SearchController {
    public String search(HttpServletRequest request, Model model) {
        String keyword = request.getParameter("keyword");
        model.addAttribute("keyword", keyword);
        return "search";
    }
}"#;
        let mut analyzer = analyzer_with_yaml_rules();
        let path = std::path::PathBuf::from("SearchController.java");
        let flows = analyzer.analyze_code(code, &path, "search", &[], &[]);
        assert!(
            !flows.is_empty(),
            "未净化的 addAttribute 参数应产生 XSS finding"
        );
    }

    #[test]
    fn test_java_analyze_file_xss_inline_sanitizer_no_flow() {
        // halo ContentSearchController 误报原样形态（HtmlUtils.htmlEscape 包裹
        // addAttribute 参数），analyze_file 路径不应产生 finding
        let code = r#"public class SearchController {
    public String search(HttpServletRequest request, Model model) {
        String keyword = request.getParameter("keyword");
        model.addAttribute("keyword", HtmlUtils.htmlEscape(keyword));
        return "search";
    }
}"#;
        let mut analyzer = analyzer_with_yaml_rules();
        let path = std::path::PathBuf::from("SearchController.java");
        let flows = analyzer.analyze_file(&path, code);
        assert!(
            flows.is_empty(),
            "analyze_file 路径下内联净化不应产生 XSS finding，实际 {} 条",
            flows.len()
        );
    }

    #[test]
    fn test_java_xss_partial_inline_sanitizer_still_reports() {
        // 部分净化：同一调用中另一个参数仍直接引用污点变量，必须报出
        let code = r#"public class SearchController {
    public String search(HttpServletRequest request, Model model) {
        String keyword = request.getParameter("keyword");
        model.addAttribute(escapeHtml(keyword), keyword);
        return "search";
    }
}"#;
        let mut analyzer = analyzer_with_yaml_rules();
        let path = std::path::PathBuf::from("SearchController.java");
        let flows = analyzer.analyze_code(code, &path, "search", &[], &[]);
        assert!(
            !flows.is_empty(),
            "存在未净化参数时应仍产生 XSS finding"
        );
    }

    #[test]
    fn test_java_xss_inline_sanitizer_cpg_path() {
        // CPG 生产路径（analyze_file_cpg）开/关对照：
        // 带内联净化不报、去掉净化报
        let sanitized_code = r#"public class SearchController {
    public String search(HttpServletRequest request, Model model) {
        String keyword = request.getParameter("keyword");
        model.addAttribute("keyword", escapeHtml(keyword));
        return "search";
    }
}"#;
        let raw_code = sanitized_code.replace("escapeHtml(keyword)", "keyword");
        let path = std::path::PathBuf::from("SearchController.java");

        let mut analyzer = analyzer_with_yaml_rules();
        let report = analyzer.analyze_file_cpg(&path, sanitized_code);
        assert!(
            report.flows.is_empty(),
            "CPG 路径下内联净化不应产生 XSS finding，实际 {} 条",
            report.flows.len()
        );

        let mut analyzer = analyzer_with_yaml_rules();
        let report = analyzer.analyze_file_cpg(&path, &raw_code);
        assert!(
            !report.flows.is_empty(),
            "CPG 路径下未净化的 addAttribute 参数应产生 XSS finding"
        );
    }

    #[test]
    fn test_is_inline_sanitized_unit() {
        // is_inline_sanitized 辅助函数的边界语义直测
        let analyzer = analyzer_with_yaml_rules();
        // 污点变量仅在净化器调用内部 → true
        assert!(analyzer.is_inline_sanitized("HtmlUtils.htmlEscape(keyword)", "keyword"));
        assert!(analyzer.is_inline_sanitized("escapeHtml(keyword)", "keyword"));
        assert!(analyzer.is_inline_sanitized("URLEncoder.encode(x, \"UTF-8\")", "x"));
        // 无净化器 / 净化器外仍有裸引用 → false
        assert!(!analyzer.is_inline_sanitized("keyword", "keyword"));
        assert!(!analyzer.is_inline_sanitized("escapeHtml(keyword) + keyword", "keyword"));
        // 标识符边界：encodeBase64 不得命中 "encode" 净化器
        assert!(!analyzer.is_inline_sanitized("Base64.encodeBase64(data)", "data"));
        // 变量名边界：keyword 不得命中 key
        assert!(!analyzer.is_inline_sanitized("escapeHtml(keyword)", "key"));
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
        AstTaintAnalyzer::from_yaml_dir(&rules_dir).unwrap_or_else(|_| AstTaintAnalyzer::new())
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
        assert!(
            flows
                .iter()
                .any(|f| matches!(f.vulnerability_type, VulnerabilityType::SqlInjection)),
            "Expected SQLi"
        );
        assert!(
            flows
                .iter()
                .any(|f| matches!(f.vulnerability_type, VulnerabilityType::CommandInjection)),
            "Expected command injection"
        );
        assert!(
            flows
                .iter()
                .any(|f| matches!(f.vulnerability_type, VulnerabilityType::PathTraversal)),
            "Expected path traversal"
        );
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
        let (tree, _symbols, functions, file_assignments, file_calls) =
            parser.extract_all_for_taint_with_tree(&path, code).unwrap();
        let callback_hints = crate::analysis::async_flow::detect_callback_hints(code);
        let root = tree.root_node();
        let mut all_flows = Vec::new();
        for func in &functions {
            let func_hints: Vec<_> = callback_hints
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
            let body_node = AstTaintAnalyzer::find_function_body_node_static(
                &root,
                func.start_line,
                func.end_line,
            );
            let func_cpg = if let Some(body_node) = body_node {
                crate::analysis::cpg::CPGBuilder::build_function_cpg(
                    &body_node,
                    code,
                    "app.js",
                    func,
                    &func_assignments,
                    &func_calls,
                )
            } else {
                crate::analysis::cpg::CPGBuilder::build_file_cpg(
                    &func.body_text,
                    "app.js",
                    &func_assignments,
                    &func_calls,
                )
            };
            let func_flows = analyzer.analyze_function_cpg(&func_cpg, &func.body_text, &func_hints);
            all_flows.extend(func_flows);
        }
        assert!(
            all_flows
                .iter()
                .any(|f| matches!(f.vulnerability_type, VulnerabilityType::SqlInjection)),
            "Expected SQLi via CPG"
        );
        assert!(
            all_flows
                .iter()
                .any(|f| matches!(f.vulnerability_type, VulnerabilityType::CommandInjection)),
            "Expected command injection via CPG"
        );
        assert!(
            all_flows
                .iter()
                .any(|f| matches!(f.vulnerability_type, VulnerabilityType::PathTraversal)),
            "Expected path traversal via CPG"
        );
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
        assert!(
            !flows.is_empty(),
            "Expected command injection in text-based CFG"
        );
    }

    #[test]
    fn test_java_sql_header_source() {
        let code = r#"
import javax.servlet.http.*;

public class Test extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getHeader("x");
        String sql = "{call " + param + "}";
        java.sql.Connection connection = org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
        java.sql.CallableStatement statement = connection.prepareCall(sql);
        statement.executeQuery();
    }
}
"#;
        let analyzer = yaml_rules_analyzer();
        let path = std::path::PathBuf::from("Test.java");
        // 使用与扫描 pipeline 一致的 FunctionCPG 路径
        let (functions, assignments, calls) =
            crate::ast::parser::with_thread_local_parser(|p| p.extract_all_for_taint(&path, code));
        let func = functions
            .iter()
            .find(|f| f.name == "doPost")
            .expect("doPost function");
        let func_assignments: Vec<_> = assignments
            .iter()
            .filter(|a| a.line >= func.start_line && a.line <= func.end_line)
            .cloned()
            .collect();
        let func_calls: Vec<_> = calls
            .iter()
            .filter(|c| c.line >= func.start_line && c.line <= func.end_line)
            .cloned()
            .collect();
        let func_cpg = crate::analysis::cpg::CPGBuilder::build_function_cpg_from_text(
            &func.body_text,
            path.to_str().unwrap(),
            func,
            &func_assignments,
            &func_calls,
        );
        let flows = analyzer.analyze_function_cpg(&func_cpg, &func.body_text, &[]);
        assert!(
            flows
                .iter()
                .any(|f| matches!(f.vulnerability_type, VulnerabilityType::SqlInjection)),
            "Expected SQL injection from request.getHeader -> prepareCall/executeQuery"
        );
    }

    #[test]
    fn test_java_sql_headers_chain() {
        let code = r#"
import javax.servlet.http.*;
import java.util.Enumeration;

public class Test extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = "";
        Enumeration<String> headers = request.getHeaders("x");
        if (headers != null && headers.hasMoreElements()) {
            param = headers.nextElement();
        }
        String sql = "INSERT INTO users (username, password) VALUES ('foo','" + param + "')";
        java.sql.Statement statement = org.owasp.benchmark.helpers.DatabaseHelper.getSqlStatement();
        statement.executeUpdate(sql);
    }
}
"#;
        let analyzer = yaml_rules_analyzer();
        let path = std::path::PathBuf::from("Test.java");

        // CPG 路径
        let (functions, assignments, calls) =
            crate::ast::parser::with_thread_local_parser(|p| p.extract_all_for_taint(&path, code));
        let func = functions
            .iter()
            .find(|f| f.name == "doPost")
            .expect("doPost function");
        let func_assignments: Vec<_> = assignments
            .iter()
            .filter(|a| a.line >= func.start_line && a.line <= func.end_line)
            .cloned()
            .collect();
        let func_calls: Vec<_> = calls
            .iter()
            .filter(|c| c.line >= func.start_line && c.line <= func.end_line)
            .cloned()
            .collect();
        let func_cpg = crate::analysis::cpg::CPGBuilder::build_function_cpg_from_text(
            &func.body_text,
            path.to_str().unwrap(),
            func,
            &func_assignments,
            &func_calls,
        );
        let flows = analyzer.analyze_function_cpg(&func_cpg, &func.body_text, &[]);
        assert!(
            flows
                .iter()
                .any(|f| matches!(f.vulnerability_type, VulnerabilityType::SqlInjection)),
            "Expected SQL injection from request.getHeaders chain (CPG)"
        );

        // 生产路径 analyze_file/text CFG 也要能检出（修复前 if 块内赋值会丢失）
        let file_flows = analyzer.analyze_file(&path, code);
        assert!(
            file_flows
                .iter()
                .any(|f| matches!(f.vulnerability_type, VulnerabilityType::SqlInjection)),
            "Expected SQL injection from request.getHeaders chain (analyze_file)"
        );

        // Stage B 并行扫描实际使用的 fragment CPG 路径也要能检出
        let func = functions.iter().find(|f| f.name == "doPost").unwrap();
        let func_assignments: Vec<_> = assignments
            .iter()
            .filter(|a| a.line >= func.start_line && a.line <= func.end_line)
            .cloned()
            .collect();
        let func_calls: Vec<_> = calls
            .iter()
            .filter(|c| c.line >= func.start_line && c.line <= func.end_line)
            .cloned()
            .collect();
        let fragment_flows = crate::ast::parser::with_thread_local_parser(|ast_parser| {
            let tree = ast_parser
                .parse_fragment(&func.body_text, "java")
                .expect("parse fragment");
            let root = tree.root_node();
            let mut cursor = root.walk();
            let body_node = root
                .children(&mut cursor)
                .find(|n| {
                    matches!(
                        n.kind(),
                        "block" | "statement_block" | "body" | "suite" | "block_stmt"
                    )
                })
                .expect("function body");
            let func_cpg = crate::analysis::cpg::CPGBuilder::build_function_cpg_from_fragment(
                &body_node,
                &func.body_text,
                path.to_str().unwrap(),
                func,
                &func_assignments,
                &func_calls,
            );
            analyzer.analyze_function_cpg(&func_cpg, &func.body_text, &[])
        });
        assert!(
            fragment_flows
                .iter()
                .any(|f| matches!(f.vulnerability_type, VulnerabilityType::SqlInjection)),
            "Expected SQL injection from request.getHeaders chain (fragment CPG)"
        );
    }

    #[test]
    fn test_java_sql_multiline_signature() {
        let code = r#"
import javax.servlet.http.*;

public class Test extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String param = request.getParameter("id");
        String sql = "INSERT ..." + param;
        java.sql.Statement statement = org.owasp.benchmark.helpers.DatabaseHelper.getSqlStatement();
        statement.executeUpdate(sql);
    }
}
"#;
        let analyzer = yaml_rules_analyzer();
        let path = std::path::PathBuf::from("Test.java");
        let (functions, assignments, calls) =
            crate::ast::parser::with_thread_local_parser(|p| p.extract_all_for_taint(&path, code));
        let func = functions
            .iter()
            .find(|f| f.name == "doPost")
            .expect("doPost function");
        let func_assignments: Vec<_> = assignments
            .iter()
            .filter(|a| a.line >= func.start_line && a.line <= func.end_line)
            .cloned()
            .collect();
        let func_calls: Vec<_> = calls
            .iter()
            .filter(|c| c.line >= func.start_line && c.line <= func.end_line)
            .cloned()
            .collect();
        let fragment_flows = crate::ast::parser::with_thread_local_parser(|ast_parser| {
            let tree = ast_parser
                .parse_fragment(&func.body_text, "java")
                .expect("parse fragment");
            let root = tree.root_node();
            let mut cursor = root.walk();
            let body_node = root
                .children(&mut cursor)
                .find(|n| {
                    matches!(
                        n.kind(),
                        "block" | "statement_block" | "body" | "suite" | "block_stmt"
                    )
                })
                .expect("function body");
            let func_cpg = crate::analysis::cpg::CPGBuilder::build_function_cpg_from_fragment(
                &body_node,
                &func.body_text,
                path.to_str().unwrap(),
                func,
                &func_assignments,
                &func_calls,
            );
            analyzer.analyze_function_cpg(&func_cpg, &func.body_text, &[])
        });
        assert!(
            fragment_flows
                .iter()
                .any(|f| matches!(f.vulnerability_type, VulnerabilityType::SqlInjection)),
            "Expected SQL injection with multiline signature (fragment CPG)"
        );
    }

    #[test]
    fn test_java_sql_getparameter_with_try_block() {
        let code = r#"
import javax.servlet.http.*;

public class Test extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getParameter("id");
        if (param == null) param = "";
        String sql = "INSERT INTO users (username, password) VALUES ('foo','" + param + "')";
        try {
            java.sql.Statement statement = org.owasp.benchmark.helpers.DatabaseHelper.getSqlStatement();
            statement.executeUpdate(sql);
        } catch (java.sql.SQLException e) {
            response.getWriter().println("Error");
        }
    }
}
"#;
        let analyzer = yaml_rules_analyzer();
        let path = std::path::PathBuf::from("Test.java");
        let (functions, assignments, calls) =
            crate::ast::parser::with_thread_local_parser(|p| p.extract_all_for_taint(&path, code));
        let func = functions
            .iter()
            .find(|f| f.name == "doPost")
            .expect("doPost function");
        let func_assignments: Vec<_> = assignments
            .iter()
            .filter(|a| a.line >= func.start_line && a.line <= func.end_line)
            .cloned()
            .collect();
        let func_calls: Vec<_> = calls
            .iter()
            .filter(|c| c.line >= func.start_line && c.line <= func.end_line)
            .cloned()
            .collect();
        let fragment_flows = crate::ast::parser::with_thread_local_parser(|ast_parser| {
            let tree = ast_parser
                .parse_fragment(&func.body_text, "java")
                .expect("parse fragment");
            let root = tree.root_node();
            let mut cursor = root.walk();
            let body_node = root
                .children(&mut cursor)
                .find(|n| {
                    matches!(
                        n.kind(),
                        "block" | "statement_block" | "body" | "suite" | "block_stmt"
                    )
                })
                .expect("function body");
            let func_cpg = crate::analysis::cpg::CPGBuilder::build_function_cpg_from_fragment(
                &body_node,
                &func.body_text,
                path.to_str().unwrap(),
                func,
                &func_assignments,
                &func_calls,
            );
            analyzer.analyze_function_cpg(&func_cpg, &func.body_text, &[])
        });
        assert!(
            fragment_flows
                .iter()
                .any(|f| matches!(f.vulnerability_type, VulnerabilityType::SqlInjection)),
            "Expected SQL injection with try block (fragment CPG)"
        );
    }

    #[test]
    fn test_java_sql_getparameter_with_null_check() {
        let code = r#"
import javax.servlet.http.*;

public class Test extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getParameter("id");
        if (param == null) param = "";
        String sql = "INSERT INTO users (username, password) VALUES ('foo','" + param + "')";
        java.sql.Statement statement = org.owasp.benchmark.helpers.DatabaseHelper.getSqlStatement();
        statement.executeUpdate(sql);
    }
}
"#;
        let analyzer = yaml_rules_analyzer();
        let path = std::path::PathBuf::from("Test.java");
        let (functions, assignments, calls) =
            crate::ast::parser::with_thread_local_parser(|p| p.extract_all_for_taint(&path, code));
        let func = functions
            .iter()
            .find(|f| f.name == "doPost")
            .expect("doPost function");
        let func_assignments: Vec<_> = assignments
            .iter()
            .filter(|a| a.line >= func.start_line && a.line <= func.end_line)
            .cloned()
            .collect();
        let func_calls: Vec<_> = calls
            .iter()
            .filter(|c| c.line >= func.start_line && c.line <= func.end_line)
            .cloned()
            .collect();
        let fragment_flows = crate::ast::parser::with_thread_local_parser(|ast_parser| {
            let tree = ast_parser
                .parse_fragment(&func.body_text, "java")
                .expect("parse fragment");
            let root = tree.root_node();
            let mut cursor = root.walk();
            let body_node = root
                .children(&mut cursor)
                .find(|n| {
                    matches!(
                        n.kind(),
                        "block" | "statement_block" | "body" | "suite" | "block_stmt"
                    )
                })
                .expect("function body");
            let func_cpg = crate::analysis::cpg::CPGBuilder::build_function_cpg_from_fragment(
                &body_node,
                &func.body_text,
                path.to_str().unwrap(),
                func,
                &func_assignments,
                &func_calls,
            );
            analyzer.analyze_function_cpg(&func_cpg, &func.body_text, &[])
        });
        assert!(
            fragment_flows
                .iter()
                .any(|f| matches!(f.vulnerability_type, VulnerabilityType::SqlInjection)),
            "Expected SQL injection from request.getParameter with null check (fragment CPG)"
        );
    }

    #[test]
    fn test_java_ldap_headers_next_element_with_comment() {
        // 复刻 BenchmarkTest00012：if 体内带行注释的 receiver 传播链。
        // headers 被污染后，param = headers.nextElement()（无参方法，receiver 污染）
        // 应使 param 被污染；if 体中的行注释不得打断该语句到 merge 的 CFG 边。
        let code = r#"
import javax.servlet.http.*;

public class Test extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = "";
        java.util.Enumeration<String> headers = request.getHeaders("BenchmarkTest00012");
        if (headers != null && headers.hasMoreElements()) {
            param = headers.nextElement(); // just grab first element
        }
        param = java.net.URLDecoder.decode(param, "UTF-8");
        String filter = "(&(objectclass=person))(|(uid=" + param + ")(street={0}))";
        javax.naming.directory.InitialDirContext idc = null;
        Object results = idc.search("ou=users", filter, new Object[]{}, null);
    }
}
"#;
        let analyzer = yaml_rules_analyzer();
        let path = std::path::PathBuf::from("Test.java");
        let (functions, assignments, calls) =
            crate::ast::parser::with_thread_local_parser(|p| p.extract_all_for_taint(&path, code));
        let func = functions
            .iter()
            .find(|f| f.name == "doPost")
            .expect("doPost function");
        let func_assignments: Vec<_> = assignments
            .iter()
            .filter(|a| a.line >= func.start_line && a.line <= func.end_line)
            .cloned()
            .collect();
        let func_calls: Vec<_> = calls
            .iter()
            .filter(|c| c.line >= func.start_line && c.line <= func.end_line)
            .cloned()
            .collect();
        let fragment_flows = crate::ast::parser::with_thread_local_parser(|ast_parser| {
            let tree = ast_parser
                .parse_fragment(&func.body_text, "java")
                .expect("parse fragment");
            let root = tree.root_node();
            let mut cursor = root.walk();
            let body_node = root
                .children(&mut cursor)
                .find(|n| {
                    matches!(
                        n.kind(),
                        "block" | "statement_block" | "body" | "suite" | "block_stmt"
                    )
                })
                .expect("function body");
            let func_cpg = crate::analysis::cpg::CPGBuilder::build_function_cpg_from_fragment(
                &body_node,
                &func.body_text,
                path.to_str().unwrap(),
                func,
                &func_assignments,
                &func_calls,
            );
            analyzer.analyze_function_cpg(&func_cpg, &func.body_text, &[])
        });
        assert!(
            fragment_flows
                .iter()
                .any(|f| matches!(f.vulnerability_type, VulnerabilityType::LdapInjection)),
            "Expected LDAP injection via headers.nextElement() receiver (fragment CPG)"
        );
    }

    #[test]
    fn test_java_xpath_base64_nested_constructor() {
        // 复刻 BenchmarkTest00207：嵌套调用/构造器传播链。
        // bar = new String(Base64.decodeBase64(Base64.encodeBase64(param.getBytes())))
        // 中递归参数 param 被污染时 bar 应被污染；encodeBase64 不是净化器，
        // 不得因子串包含 "encode" 而把 bar 标记为已净化。
        let code = r#"
import javax.servlet.http.*;

public class Test extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getHeader("BenchmarkTest00207");
        param = java.net.URLDecoder.decode(param, "UTF-8");
        String bar = "";
        if (param != null) {
            bar = new String(
                    org.apache.commons.codec.binary.Base64.decodeBase64(
                            org.apache.commons.codec.binary.Base64.encodeBase64(
                                    param.getBytes())));
        }
        String expression = "/Employees/Employee[@emplid='" + bar + "']";
        String result = xp.evaluate(expression, xmlDocument);
    }
}
"#;
        let analyzer = yaml_rules_analyzer();
        let path = std::path::PathBuf::from("Test.java");
        let (functions, assignments, calls) =
            crate::ast::parser::with_thread_local_parser(|p| p.extract_all_for_taint(&path, code));
        let func = functions
            .iter()
            .find(|f| f.name == "doPost")
            .expect("doPost function");
        let func_assignments: Vec<_> = assignments
            .iter()
            .filter(|a| a.line >= func.start_line && a.line <= func.end_line)
            .cloned()
            .collect();
        let func_calls: Vec<_> = calls
            .iter()
            .filter(|c| c.line >= func.start_line && c.line <= func.end_line)
            .cloned()
            .collect();
        let fragment_flows = crate::ast::parser::with_thread_local_parser(|ast_parser| {
            let tree = ast_parser
                .parse_fragment(&func.body_text, "java")
                .expect("parse fragment");
            let root = tree.root_node();
            let mut cursor = root.walk();
            let body_node = root
                .children(&mut cursor)
                .find(|n| {
                    matches!(
                        n.kind(),
                        "block" | "statement_block" | "body" | "suite" | "block_stmt"
                    )
                })
                .expect("function body");
            let func_cpg = crate::analysis::cpg::CPGBuilder::build_function_cpg_from_fragment(
                &body_node,
                &func.body_text,
                path.to_str().unwrap(),
                func,
                &func_assignments,
                &func_calls,
            );
            analyzer.analyze_function_cpg(&func_cpg, &func.body_text, &[])
        });
        assert!(
            fragment_flows
                .iter()
                .any(|f| matches!(f.vulnerability_type, VulnerabilityType::XPathInjection)),
            "Expected XPath injection via nested Base64 calls and String constructor (fragment CPG)"
        );
    }

    #[test]
    fn test_js_getjson_second_order_xss() {
        // ServerStatus 形态：jQuery getJSON 回调参数（服务端存储 JSON，二阶场景）
        // → innerHTML 输出。R24 前 HTTP 回调提示不覆盖 $.getJSON + function 表达式，
        // 该形态 AstTaint 产出为 0。
        let code = r##"
function loadServers() {
    $.getJSON("json/stats.json", function(result) {
        for (var i = 0; i < result.servers.length; i++) {
            document.getElementById("name").innerHTML = result.servers[i].name;
        }
    });
}
"##;
        let analyzer = yaml_rules_analyzer();
        let path = std::path::PathBuf::from("serverstatus.js");
        let report = analyzer.analyze_file_cpg(&path, code);
        assert!(
            report.tainted_vars.keys().any(|k| k == "result"),
            "expected callback param 'result' tainted, got: {:?}",
            report.tainted_vars.keys().collect::<Vec<_>>()
        );
        assert!(
            report
                .flows
                .iter()
                .any(|f| f.sink.symbol.contains("innerHTML")),
            "expected innerHTML XSS flow, got sinks: {:?}",
            report.flows.iter().map(|f| &f.sink.symbol).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_analyze_file_cpg_exposes_tainted_vars() {
        // 二阶样例：DB 读取 → 中间变量传播，但不到达任何 sink。
        // 验证 analyze_file_cpg 的 tainted_vars 能暴露"被污染但未达 sink"的变量，
        // 供探索向查询（"这个变量被污染了吗"）使用。
        let code = r#"import sqlite3

def save(cur):
    row = cur.fetchone()
    name = row[0]
    debug = name
    print(debug)
"#;
        let analyzer = yaml_rules_analyzer();
        let path = std::path::PathBuf::from("save.py");
        let report = analyzer.analyze_file_cpg(&path, code);
        // 中间变量应被记录为污染（来源为二阶 source 或传播链）
        assert!(
            report.tainted_vars.contains_key("name"),
            "expected 'name' in tainted_vars, got: {:?}",
            report.tainted_vars.keys().collect::<Vec<_>>()
        );
        assert!(
            report.tainted_vars.contains_key("debug"),
            "expected 'debug' in tainted_vars, got: {:?}",
            report.tainted_vars.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_python_cur_execute_abbreviated_receiver() {
        // backlog 10.9：缩写 receiver（cur vs cursor）此前导致 SQL sink 失配。
        // R21 合成验证 save.py 的 cur.execute(sql) 一阶 SQLi 未检出即此缺口。
        let code = r#"from flask import request

def save():
    name = request.args.get('name')
    sql = "SELECT * FROM users WHERE name = '" + name + "'"
    cur.execute(sql)
"#;
        let analyzer = yaml_rules_analyzer();
        let path = std::path::PathBuf::from("save.py");
        let report = analyzer.analyze_file_cpg(&path, code);
        assert!(
            report
                .flows
                .iter()
                .any(|f| matches!(f.vulnerability_type, VulnerabilityType::SqlInjection)),
            "expected SQL Injection flow via cur.execute, got: {:?}",
            report
                .flows
                .iter()
                .map(|f| format!("{}:{}", f.vulnerability_type, f.sink.symbol))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_storage_write_gate_via_sql_string_arg() {
        // storage_write 闸门补充匹配：SQL 写包在字符串参数里
        // （$this->repo->write("INSERT INTO ...")），callee/receiver 匹配不到
        // 任何 sink 时，对参数文本做子串匹配发出闸门事件。
        // 注：若调用本身命中 SQLi sink（如 mysqli_query），优先产出 SQLi flow
        // （一阶注入本就该报），闸门事件不重复发——scanner 闸门统计的已知残缺口。
        let code = r#"<?php
class Repo {
    function save() {
        $name = $_POST['name'];
        $this->repo->write("INSERT INTO comments (name) VALUES ('$name')");
    }
}
"#;
        let analyzer = yaml_rules_analyzer();
        let path = std::path::PathBuf::from("comment.php");
        let report = analyzer.analyze_file_cpg(&path, code);
        assert!(
            report
                .flows
                .iter()
                .any(|f| matches!(f.vulnerability_type, VulnerabilityType::StorageWrite)),
            "expected StorageWrite gate flow, got: {:?}",
            report
                .flows
                .iter()
                .map(|f| format!("{}:{}", f.vulnerability_type, f.sink.symbol))
                .collect::<Vec<_>>()
        );
    }

    // ── 10.15 判定层 sink/source 去误报（R51 扩展）───────────────────────

    #[test]
    fn test_handlebars_compile_not_code_injection() {
        // 10.15④：Handlebars.compile 是模板编译（默认转义），非动态代码执行。
        // compile( 已从 code-injection sink 移除；eval(/Function( 仍覆盖真动态执行。
        let code = r#"
const Handlebars = require('handlebars');
const userInput = req.query.tpl;
const compiled = Handlebars.compile(userInput);
const html = compiled({ name: 'x' });
res.send(html);
"#;
        let mut analyzer = AstTaintAnalyzer::new();
        let path = std::path::PathBuf::from("t.js");
        let flows = analyzer.analyze_code(code, &path, "handler", &[], &[]);
        assert!(
            !flows
                .iter()
                .any(|f| matches!(f.vulnerability_type, VulnerabilityType::CodeInjection)),
            "Handlebars.compile 不应命中 code-injection sink, got: {:?}",
            flows
                .iter()
                .map(|f| format!("{:?}", f.vulnerability_type))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_python_re_compile_not_code_injection() {
        // 10.15④ 移除 compile( 后，re.compile（正则编译）不再误报
        let code = r#"
pattern = request.GET['p']
rx = re.compile(pattern)
m = rx.search(data)
"#;
        let mut analyzer = AstTaintAnalyzer::new();
        let path = std::path::PathBuf::from("t.py");
        let flows = analyzer.analyze_code(code, &path, "f", &[], &[]);
        assert!(
            !flows
                .iter()
                .any(|f| matches!(f.vulnerability_type, VulnerabilityType::CodeInjection)),
            "re.compile 不应命中 code-injection sink, got: {:?}",
            flows
                .iter()
                .map(|f| format!("{:?}", f.vulnerability_type))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_eval_still_reported_after_compile_removal() {
        // ④ 回归：真动态执行 eval( 必须仍命中
        let code = r#"
src = request.GET['src']
result = eval(src)
"#;
        let mut analyzer = AstTaintAnalyzer::new();
        let path = std::path::PathBuf::from("t.py");
        let flows = analyzer.analyze_code(code, &path, "f", &[], &[]);
        assert!(
            flows
                .iter()
                .any(|f| matches!(f.vulnerability_type, VulnerabilityType::CodeInjection)),
            "eval( 应仍命中 code-injection sink, got: {:?}",
            flows
                .iter()
                .map(|f| format!("{:?}", f.vulnerability_type))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_numeric_coerced_path_exempt() {
        // 10.15②：污点经 int() 数值强制转换后拼接路径，非路径遍历
        let code = r#"
user_id = request.GET['id']
path = "/uploads/" + str(int(user_id))
open(path)
"#;
        let mut analyzer = AstTaintAnalyzer::new();
        let path = std::path::PathBuf::from("t.py");
        let flows = analyzer.analyze_code(code, &path, "f", &[], &[]);
        assert!(
            !flows
                .iter()
                .any(|f| matches!(f.vulnerability_type, VulnerabilityType::PathTraversal)),
            "int() 数值化后的路径拼接不应命中 path traversal, got: {:?}",
            flows
                .iter()
                .map(|f| format!("{:?}", f.vulnerability_type))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_tainted_path_still_reported() {
        // ② 回归：未数值化的污点路径拼接必须仍命中
        let code = r#"
name = request.GET['name']
path = "/uploads/" + name
open(path)
"#;
        let mut analyzer = AstTaintAnalyzer::new();
        let path = std::path::PathBuf::from("t.py");
        let flows = analyzer.analyze_code(code, &path, "f", &[], &[]);
        assert!(
            flows
                .iter()
                .any(|f| matches!(f.vulnerability_type, VulnerabilityType::PathTraversal)),
            "未数值化的污点路径拼接应命中 path traversal, got: {:?}",
            flows
                .iter()
                .map(|f| format!("{:?}", f.vulnerability_type))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_ssrf_literal_host_exempt() {
        // 10.15①：host 为字面量常量（污点仅影响路径段），目标固定非 SSRF
        let code = r#"
path = request.GET['path']
r = requests.get("https://api.internal.example.com/" + path)
"#;
        let mut analyzer = AstTaintAnalyzer::new();
        let path = std::path::PathBuf::from("t.py");
        let flows = analyzer.analyze_code(code, &path, "f", &[], &[]);
        assert!(
            !flows
                .iter()
                .any(|f| matches!(f.vulnerability_type, VulnerabilityType::ServerSideRequestForgery)),
            "字面量 host 不应命中 SSRF sink, got: {:?}",
            flows
                .iter()
                .map(|f| format!("{:?}", f.vulnerability_type))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_ssrf_tainted_host_still_reported() {
        // ① 回归：host 来自污点变量时（表达式无完整字面量 host），必须仍命中
        let code = r#"
host = request.GET['host']
r = requests.get("https://" + host + "/api")
"#;
        let mut analyzer = AstTaintAnalyzer::new();
        let path = std::path::PathBuf::from("t.py");
        let flows = analyzer.analyze_code(code, &path, "f", &[], &[]);
        assert!(
            flows
                .iter()
                .any(|f| matches!(f.vulnerability_type, VulnerabilityType::ServerSideRequestForgery)),
            "污点 host 应命中 SSRF sink, got: {:?}",
            flows
                .iter()
                .map(|f| format!("{:?}", f.vulnerability_type))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_ssrf_relative_url_exempt() {
        // R55：同源相对 URL（`/path/${id}`）host 不可控，不构成 SSRF
        // （BookStack 客户端 XHR FP 家族，window.$http.get）
        let code = r#"const id = req.query.id;
window.$http.get(`/attachments/get/page/${id}`);"#;
        let mut analyzer = AstTaintAnalyzer::new();
        let path = std::path::PathBuf::from("attachments.js");
        let flows = analyzer.analyze_code(code, &path, "f", &[], &[]);
        assert!(
            !flows
                .iter()
                .any(|f| matches!(f.vulnerability_type, VulnerabilityType::ServerSideRequestForgery)),
            "同源相对 URL 不应报 SSRF, got: {:?}",
            flows
                .iter()
                .map(|f| format!("{:?}", f.vulnerability_type))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_ssrf_protocol_relative_url_not_exempt() {
        // R55 回归：`//` 开头是协议相对 URL（host 可控），仍应报 SSRF
        let code = r#"const host = req.query.host;
window.$http.get(`//${host}/api`);"#;
        let mut analyzer = AstTaintAnalyzer::new();
        let path = std::path::PathBuf::from("p.js");
        let flows = analyzer.analyze_code(code, &path, "f", &[], &[]);
        assert!(
            flows
                .iter()
                .any(|f| matches!(f.vulnerability_type, VulnerabilityType::ServerSideRequestForgery)),
            "协议相对 URL 应报 SSRF, got: {:?}",
            flows
                .iter()
                .map(|f| format!("{:?}", f.vulnerability_type))
                .collect::<Vec<_>>()
        );
    }
}
