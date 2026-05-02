// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 跨文件分析模块
//!
//! 提供函数调用图构建、跨文件污点传播和模块依赖分析

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

use super::imports::ImportResolver;
use super::taint::{TaintSource, TaintSink, FlowLocation, Severity, VulnerabilityType};

/// 函数调用图节点
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraphNode {
    /// 节点 ID
    pub id: String,
    /// 函数名
    pub name: String,
    /// 文件路径
    pub file_path: String,
    /// 起始行
    pub start_line: usize,
    /// 结束行
    pub end_line: usize,
    /// 参数列表
    pub parameters: Vec<FunctionParameter>,
    /// 返回类型
    pub return_type: Option<String>,
    /// 调用的函数
    pub calls: Vec<String>,
    /// 被调用的位置
    pub called_by: Vec<String>,
    /// 是否是外部函数（库函数）
    pub is_external: bool,
    /// 是否是污点源
    pub is_taint_source: bool,
    /// 是否是污点汇
    pub is_taint_sink: bool,
}

/// 函数参数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionParameter {
    /// 参数名
    pub name: String,
    /// 参数类型
    pub param_type: Option<String>,
    /// 是否可能是污点
    pub may_be_tainted: bool,
}

/// 调用图
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraph {
    /// 节点映射 (id -> node)
    pub nodes: HashMap<String, CallGraphNode>,
    /// 文件到函数的映射
    pub file_functions: HashMap<String, Vec<String>>,
    /// 入口函数
    pub entry_points: Vec<String>,
    /// 污点源函数
    pub taint_sources: Vec<String>,
    /// 污点汇函数
    pub taint_sinks: Vec<String>,
}

impl CallGraph {
    /// 创建新的调用图
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            file_functions: HashMap::new(),
            entry_points: Vec::new(),
            taint_sources: Vec::new(),
            taint_sinks: Vec::new(),
        }
    }

    /// 添加节点
    pub fn add_node(&mut self, node: CallGraphNode) {
        let id = node.id.clone();
        let file_path = node.file_path.clone();

        if node.is_taint_source {
            self.taint_sources.push(id.clone());
        }
        if node.is_taint_sink {
            self.taint_sinks.push(id.clone());
        }

        self.file_functions
            .entry(file_path)
            .or_insert_with(Vec::new)
            .push(id.clone());

        self.nodes.insert(id, node);
    }

    /// 添加调用关系
    pub fn add_call(&mut self, caller_id: &str, callee_id: &str) {
        if let Some(caller) = self.nodes.get_mut(caller_id) {
            if !caller.calls.contains(&callee_id.to_string()) {
                caller.calls.push(callee_id.to_string());
            }
        }
        if let Some(callee) = self.nodes.get_mut(callee_id) {
            if !callee.called_by.contains(&caller_id.to_string()) {
                callee.called_by.push(caller_id.to_string());
            }
        }
    }

    /// 获取所有调用者（递归）
    pub fn get_all_callers(&self, func_id: &str) -> HashSet<String> {
        let mut callers = HashSet::new();
        self.collect_callers_recursive(func_id, &mut callers);
        callers
    }

    fn collect_callers_recursive(&self, func_id: &str, callers: &mut HashSet<String>) {
        if let Some(node) = self.nodes.get(func_id) {
            for caller_id in &node.called_by {
                if callers.insert(caller_id.clone()) {
                    self.collect_callers_recursive(caller_id, callers);
                }
            }
        }
    }

    /// 获取所有被调用的函数（递归）
    pub fn get_all_callees(&self, func_id: &str) -> HashSet<String> {
        let mut callees = HashSet::new();
        self.collect_callees_recursive(func_id, &mut callees);
        callees
    }

    fn collect_callees_recursive(&self, func_id: &str, callees: &mut HashSet<String>) {
        if let Some(node) = self.nodes.get(func_id) {
            for callee_id in &node.calls {
                if callees.insert(callee_id.clone()) {
                    self.collect_callees_recursive(callee_id, callees);
                }
            }
        }
    }

    /// 查找从污点源到污点汇的路径
    pub fn find_taint_paths(&self) -> Vec<InterproceduralTaintPath> {
        let mut paths = Vec::new();

        for source_id in &self.taint_sources {
            for sink_id in &self.taint_sinks {
                if let Some(call_path) = self.find_call_path(source_id, sink_id) {
                    paths.push(InterproceduralTaintPath {
                        source_id: source_id.clone(),
                        sink_id: sink_id.clone(),
                        call_path,
                        confidence: 0.8,
                    });
                }
            }
        }

        paths
    }

    /// 查找两个函数之间的调用路径
    pub fn find_call_path(&self, from_id: &str, to_id: &str) -> Option<Vec<String>> {
        let mut visited = HashSet::new();
        let mut path = Vec::new();
        self.dfs_call_path(from_id, to_id, &mut visited, &mut path)
    }

    fn dfs_call_path(
        &self,
        current: &str,
        target: &str,
        visited: &mut HashSet<String>,
        path: &mut Vec<String>,
    ) -> Option<Vec<String>> {
        if current == target {
            path.push(current.to_string());
            return Some(path.clone());
        }

        if visited.contains(current) {
            return None;
        }

        visited.insert(current.to_string());
        path.push(current.to_string());

        if let Some(node) = self.nodes.get(current) {
            for callee_id in &node.calls {
                if let Some(result) = self.dfs_call_path(callee_id, target, visited, path) {
                    return Some(result);
                }
            }
        }

        path.pop();
        None
    }
}

impl Default for CallGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// 过程间污点路径
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterproceduralTaintPath {
    /// 污点源函数 ID
    pub source_id: String,
    /// 污点汇函数 ID
    pub sink_id: String,
    /// 调用路径
    pub call_path: Vec<String>,
    /// 置信度
    pub confidence: f32,
}

/// 跨文件污点分析结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossFileTaintResult {
    /// 项目路径
    pub project_path: String,
    /// 调用图
    pub call_graph: CallGraph,
    /// 污点流
    pub taint_flows: Vec<InterproceduralTaintFlow>,
    /// 分析统计
    pub stats: CrossFileAnalysisStats,
}

/// 过程间污点流
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterproceduralTaintFlow {
    /// 流 ID
    pub id: String,
    /// 源位置
    pub source: FlowLocation,
    /// 汇位置
    pub sink: FlowLocation,
    /// 跨文件的传播路径
    pub interprocedural_path: Vec<InterproceduralStep>,
    /// 漏洞类型
    pub vulnerability_type: VulnerabilityType,
    /// 严重程度
    pub severity: Severity,
    /// 置信度
    pub confidence: f32,
}

/// 过程间传播步骤
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterproceduralStep {
    /// 步骤类型
    pub step_type: InterproceduralStepType,
    /// 文件路径
    pub file_path: String,
    /// 函数名
    pub function_name: String,
    /// 行号
    pub line: usize,
    /// 变量名
    pub variable: String,
    /// 代码片段
    pub code: Option<String>,
}

/// 过程间步骤类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InterproceduralStepType {
    /// 污点源
    Source,
    /// 函数参数传入
    ParameterIn,
    /// 函数参数返回
    ParameterOut,
    /// 函数返回值
    ReturnValue,
    /// 赋值传播
    Assignment,
    /// 污点汇
    Sink,
}

/// 函数摘要 — 一个函数对污点传播的"签名"
///
/// 描述函数如何将参数的污点传播到返回值或内部 sink，
/// 使得调用者不需要重新分析函数体。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSummary {
    /// 函数唯一标识 (file_path:func_name:start_line)
    pub func_id: String,

    /// 函数名
    pub func_name: String,

    /// 文件路径
    pub file_path: String,

    /// 参数索引到是否影响返回值的映射
    /// (param_index, affects_return)
    pub taint_propagation: Vec<(usize, bool)>,

    /// 从参数直接到达的 sink
    pub direct_sinks: Vec<SinkReachability>,

    /// 函数体摘要哈希（用于缓存失效）
    pub body_hash: Option<String>,
}

/// Sink 可达性：描述某个参数可以到达哪个 sink
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SinkReachability {
    /// Sink 名称（如 "eval", "execute"）
    pub sink_name: String,

    /// 从哪个参数传播而来
    pub from_param: usize,

    /// 是否经过净化
    pub sanitized: bool,

    /// 净化函数名
    pub sanitizer: Option<String>,

    /// 到达 sink 的行号
    pub sink_line: usize,

    /// 漏洞类型
    pub vuln_type: VulnerabilityType,
}

/// 跨文件分析统计
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CrossFileAnalysisStats {
    /// 分析的文件数
    pub files_analyzed: usize,
    /// 函数总数
    pub total_functions: usize,
    /// 污点源数量
    pub taint_sources: usize,
    /// 污点汇数量
    pub taint_sinks: usize,
    /// 污点流数量
    pub taint_flows: usize,
    /// 跨文件污点流数量
    pub cross_file_flows: usize,
}

/// 跨文件污点分析器
pub struct CrossFileTaintAnalyzer {
    /// 调用图
    call_graph: CallGraph,
    /// 导入解析器
    import_resolver: ImportResolver,
    /// 污点源模式
    source_patterns: Vec<TaintSource>,
    /// 污点汇模式
    sink_patterns: Vec<TaintSink>,
}

impl CrossFileTaintAnalyzer {
    /// 创建新的跨文件污点分析器
    pub fn new() -> Self {
        Self {
            call_graph: CallGraph::new(),
            import_resolver: ImportResolver::new(),
            source_patterns: Self::default_source_patterns(),
            sink_patterns: Self::default_sink_patterns(),
        }
    }

    /// 分析项目
    pub fn analyze_project(&mut self, project_path: &Path) -> CrossFileTaintResult {
        let mut stats = CrossFileAnalysisStats::default();

        // 1. 收集所有源文件
        let source_files = self.collect_source_files(project_path);
        stats.files_analyzed = source_files.len();

        // 2. 构建调用图（逐文件提取函数节点和内部调用）
        for file_path in &source_files {
            self.build_call_graph_for_file(file_path);
        }

        // 3. 跨文件调用解析：将裸函数名匹配到已知函数节点
        self.resolve_cross_file_calls();

        stats.total_functions = self.call_graph.nodes.len();
        stats.taint_sources = self.call_graph.taint_sources.len();
        stats.taint_sinks = self.call_graph.taint_sinks.len();

        // 4. 查找跨文件污点流
        let taint_flows = self.find_interprocedural_taint_flows();
        stats.taint_flows = taint_flows.len();
        stats.cross_file_flows = taint_flows.iter()
            .filter(|f| {
                // 跨文件 = source 和 sink 在不同文件，或路径跨多个文件
                f.source.file_path != f.sink.file_path
                    || f.interprocedural_path.len() > 1
            })
            .count();

        CrossFileTaintResult {
            project_path: project_path.to_string_lossy().to_string(),
            call_graph: self.call_graph.clone(),
            taint_flows,
            stats,
        }
    }

    /// 跨文件调用解析
    ///
    /// extract_function_calls 返回裸函数名（如 "execute"），
    /// 而 add_call 需要完整 ID（如 "src/db.py:execute"）。
    /// 此方法做第二轮匹配，将每个节点的裸函数名与所有已知节点名字匹配。
    fn resolve_cross_file_calls(&mut self) {
        // 构建 name → Vec<func_id> 索引
        let mut name_to_ids: HashMap<String, Vec<String>> = HashMap::new();
        for (id, node) in &self.call_graph.nodes {
            name_to_ids
                .entry(node.name.clone())
                .or_default()
                .push(id.clone());
        }

        // 收集需要添加的跨文件调用关系
        let mut cross_calls: Vec<(String, String)> = Vec::new();

        for (caller_id, node) in &self.call_graph.nodes {
            for bare_name in &node.calls {
                // 如果裸名不包含 ':' 说明未被解析为完整 ID
                if bare_name.contains(':') {
                    continue;
                }
                if let Some(callee_ids) = name_to_ids.get(bare_name) {
                    for callee_id in callee_ids {
                        // 只添加跨文件调用（同文件的已在 build_call_graph_for_file 中处理）
                        let callee_file = self.call_graph.nodes.get(callee_id)
                            .map(|n| n.file_path.as_str())
                            .unwrap_or("");
                        if callee_file != node.file_path {
                            cross_calls.push((caller_id.clone(), callee_id.clone()));
                        }
                    }
                }
            }
        }

        for (caller_id, callee_id) in cross_calls {
            self.call_graph.add_call(&caller_id, &callee_id);
        }
    }

    /// 收集源文件
    fn collect_source_files(&self, project_path: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        self.collect_files_recursive(project_path, &mut files);
        files
    }

    fn collect_files_recursive(&self, dir: &Path, files: &mut Vec<PathBuf>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if !name.starts_with('.')
                            && !matches!(name, "node_modules" | "target" | "vendor" | "__pycache__" | "dist" | "build" | ".git")
                        {
                            self.collect_files_recursive(&path, files);
                        }
                    }
                } else if path.is_file() && self.is_source_file(&path) {
                    files.push(path);
                }
            }
        }
    }

    fn is_source_file(&self, path: &Path) -> bool {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        matches!(
            ext.to_lowercase().as_str(),
            "py" | "js" | "jsx" | "ts" | "tsx" | "java" | "rs" | "go" | "c" | "cpp" | "php" | "rb"
        )
    }

    /// 为单个文件构建调用图
    fn build_call_graph_for_file(&mut self, file_path: &Path) {
        if let Ok(content) = std::fs::read_to_string(file_path) {
            let file_path_str = file_path.to_string_lossy().to_string();
            let language = self.infer_language(file_path);
            let functions = self.extract_functions(&content, &file_path_str, language);

            for func in functions {
                self.call_graph.add_node(func);
            }
        }
    }

    /// 从代码中提取函数
    fn extract_functions(&self, code: &str, file_path: &str, language: &str) -> Vec<CallGraphNode> {
        let mut functions = Vec::new();
        let lines: Vec<&str> = code.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            let line = line.trim();

            // 检测函数定义
            if let Some(func_name) = self.extract_function_name(line, language) {
                let func_id = format!("{}:{}", file_path, func_name);

                // 检查是否是污点源或汇
                let is_source = self.is_taint_source(&func_name);
                let is_sink = self.is_taint_sink(&func_name);

                // 提取参数
                let parameters = self.extract_parameters(line, language);

                // 查找函数调用的其他函数
                let calls = self.extract_function_calls(&lines[i..], language);

                let node = CallGraphNode {
                    id: func_id.clone(),
                    name: func_name,
                    file_path: file_path.to_string(),
                    start_line: i + 1,
                    end_line: self.find_function_end(&lines, i, language),
                    parameters,
                    return_type: None,
                    calls,
                    called_by: Vec::new(),
                    is_external: false,
                    is_taint_source: is_source,
                    is_taint_sink: is_sink,
                };

                functions.push(node);
            }
        }

        functions
    }

    /// 提取函数名
    fn extract_function_name(&self, line: &str, language: &str) -> Option<String> {
        match language {
            "python" => {
                if line.starts_with("def ") {
                    let rest = &line[4..];
                    if let Some(paren_pos) = rest.find('(') {
                        return Some(rest[..paren_pos].trim().to_string());
                    }
                }
            }
            "javascript" | "typescript" => {
                // function name() 或 const name = () => 或 export function name()
                if line.contains("function ") {
                    if let Some(start) = line.find("function ") {
                        let rest = &line[start + 9..];
                        if let Some(paren_pos) = rest.find('(') {
                            return Some(rest[..paren_pos].trim().to_string());
                        }
                    }
                }
                // arrow functions: const name = ()
                if line.contains("=>") && line.contains("=") {
                    if let Some(eq_pos) = line.find('=') {
                        let before_eq = &line[..eq_pos];
                        let words: Vec<&str> = before_eq.split_whitespace().collect();
                        if let Some(last) = words.last() {
                            return Some(last.to_string());
                        }
                    }
                }
            }
            "java" => {
                // public void name() 或 private String name()
                if line.contains("(") && (line.contains("public") || line.contains("private") || line.contains("protected")) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    for part in parts {
                        if part.contains('(') {
                            if let Some(paren_pos) = part.find('(') {
                                return Some(part[..paren_pos].to_string());
                            }
                        }
                    }
                }
            }
            "rust" => {
                // fn name() 或 pub fn name()
                if line.contains("fn ") {
                    if let Some(start) = line.find("fn ") {
                        let rest = &line[start + 3..];
                        if let Some(paren_pos) = rest.find('(') {
                            return Some(rest[..paren_pos].trim().to_string());
                        }
                    }
                }
            }
            "go" => {
                // func name() 或 func (r *Receiver) name()
                if line.starts_with("func ") {
                    let rest = &line[5..];
                    // 跳过接收器
                    let name_start = if rest.starts_with('(') {
                        if let Some(close_paren) = rest.find(')') {
                            close_paren + 1
                        } else {
                            0
                        }
                    } else {
                        0
                    };
                    let name_part = rest[name_start..].trim();
                    if let Some(paren_pos) = name_part.find('(') {
                        return Some(name_part[..paren_pos].trim().to_string());
                    }
                }
            }
            _ => {}
        }
        None
    }

    /// 提取函数参数
    fn extract_parameters(&self, line: &str, language: &str) -> Vec<FunctionParameter> {
        let mut params = Vec::new();

        if let Some(start) = line.find('(') {
            if let Some(end) = line.rfind(')') {
                if end > start {
                    let param_str = &line[start + 1..end];
                    for param in param_str.split(',') {
                        let param = param.trim();
                        if param.is_empty() {
                            continue;
                        }

                        let (name, param_type) = match language {
                            "python" => {
                                // name: type 或 name=default
                                let parts: Vec<&str> = param.split(':').collect();
                                let name = parts[0].split('=').next().unwrap_or("").trim();
                                let t = parts.get(1).map(|s| s.split('=').next().unwrap_or("").trim().to_string());
                                (name.to_string(), t)
                            }
                            "javascript" | "typescript" => {
                                // name: type 或 name
                                let parts: Vec<&str> = param.split(':').collect();
                                let name = parts[0].trim().to_string();
                                let t = parts.get(1).map(|s| s.trim().to_string());
                                (name, t)
                            }
                            "java" => {
                                // Type name
                                let parts: Vec<&str> = param.split_whitespace().collect();
                                if parts.len() >= 2 {
                                    (parts[parts.len() - 1].to_string(), Some(parts[0].to_string()))
                                } else {
                                    (param.to_string(), None)
                                }
                            }
                            "rust" => {
                                // name: Type
                                let parts: Vec<&str> = param.split(':').collect();
                                (parts[0].trim().to_string(), parts.get(1).map(|s| s.trim().to_string()))
                            }
                            "go" => {
                                // name Type 或 Type
                                let parts: Vec<&str> = param.split_whitespace().collect();
                                if parts.len() >= 2 {
                                    (parts[0].to_string(), Some(parts[1].to_string()))
                                } else if parts.len() == 1 {
                                    (parts[0].to_string(), None)
                                } else {
                                    (String::new(), None)
                                }
                            }
                            _ => (param.to_string(), None),
                        };

                        if !name.is_empty() {
                            let may_be_tainted = Self::param_may_be_tainted(&name);
                            params.push(FunctionParameter {
                                name: name.to_string(),
                                param_type,
                                may_be_tainted,
                            });
                        }
                    }
                }
            }
        }

        params
    }

    /// 提取函数调用
    fn extract_function_calls(&self, lines: &[&str], language: &str) -> Vec<String> {
        let mut calls = Vec::new();
        let mut seen = HashSet::new();

        for line in lines {
            // 简单的正则匹配
            let line = line.trim();
            if line.is_empty() || line.starts_with("//") || line.starts_with("#") {
                continue;
            }

            // 查找 function_name( 模式
            let mut i = 0;
            let chars: Vec<char> = line.chars().collect();
            while i < chars.len() {
                if chars[i].is_alphabetic() || chars[i] == '_' {
                    let start = i;
                    while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                        i += 1;
                    }
                    if i < chars.len() && chars[i] == '(' {
                        let func_name: String = chars[start..i].iter().collect();
                        // 排除关键字
                        if !["if", "for", "while", "switch", "return", "print", "console", "self"].contains(&func_name.as_str()) {
                            if seen.insert(func_name.clone()) {
                                calls.push(func_name);
                            }
                        }
                    }
                }
                i += 1;
            }
        }

        calls
    }

    /// 查找函数结束位置
    fn find_function_end(&self, lines: &[&str], start: usize, language: &str) -> usize {
        let base_indent = lines[start].chars().take_while(|c| c.is_whitespace()).count();
        let mut end = start + 1;

        match language {
            "python" => {
                // Python 使用缩进
                while end < lines.len() {
                    let line = lines[end];
                    if line.trim().is_empty() {
                        end += 1;
                        continue;
                    }
                    let current_indent = line.chars().take_while(|c| c.is_whitespace()).count();
                    if current_indent <= base_indent && !line.trim().starts_with('#') {
                        break;
                    }
                    end += 1;
                }
            }
            _ => {
                // 其他语言使用大括号
                let mut brace_count = 0;
                let mut started = false;

                while end < lines.len() {
                    let line = lines[end];
                    for c in line.chars() {
                        if c == '{' {
                            brace_count += 1;
                            started = true;
                        } else if c == '}' {
                            brace_count -= 1;
                            if started && brace_count == 0 {
                                return end + 1;
                            }
                        }
                    }
                    end += 1;
                }
            }
        }

        end
    }

    /// 推断语言
    fn infer_language(&self, path: &Path) -> &str {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        match ext {
            "py" => "python",
            "js" | "jsx" => "javascript",
            "ts" | "tsx" => "typescript",
            "java" => "java",
            "rs" => "rust",
            "go" => "go",
            "c" | "h" => "c",
            "cpp" | "cc" | "cxx" | "hpp" | "hxx" => "cpp",
            "php" => "php",
            "rb" => "ruby",
            _ => "unknown",
        }
    }

    /// 检查参数名是否可能是污点（基于常见命名模式）
    fn param_may_be_tainted(name: &str) -> bool {
        let lower = name.to_lowercase();
        const TAINT_PARAM_NAMES: &[&str] = &[
            "req", "request", "ctx", "context", "input", "data", "payload",
            "query", "params", "body", "form", "user_input", "user",
            "id", "name", "url", "path", "file", "filename", "command",
            "cmd", "sql", "html", "xml", "json", "token", "key",
            "password", "secret", "msg", "message", "content",
        ];
        TAINT_PARAM_NAMES.iter().any(|p| lower == *p || lower.contains(p))
    }

    /// 检查是否是污点源
    fn is_taint_source(&self, func_name: &str) -> bool {
        let lower = func_name.to_lowercase();
        lower.contains("get")
            || lower.contains("read")
            || lower.contains("input")
            || lower.contains("fetch")
            || lower.contains("receive")
            || lower.contains("request")
            || lower.contains("param")
            || self.source_patterns.iter().any(|s| s.matches(func_name, "*"))
    }

    /// 检查是否是污点汇
    fn is_taint_sink(&self, func_name: &str) -> bool {
        let lower = func_name.to_lowercase();
        lower.contains("execute")
            || lower.contains("exec")
            || lower.contains("query")
            || lower.contains("write")
            || lower.contains("send")
            || lower.contains("eval")
            || lower.contains("system")
            || self.sink_patterns.iter().any(|s| s.matches(func_name, "*"))
    }

    /// 查找过程间污点流
    fn find_interprocedural_taint_flows(&self) -> Vec<InterproceduralTaintFlow> {
        let mut flows = Vec::new();

        // 查找从污点源到污点汇的调用路径
        for source_id in &self.call_graph.taint_sources {
            for sink_id in &self.call_graph.taint_sinks {
                if let Some(call_path) = self.call_graph.find_call_path(source_id, sink_id) {
                    if let (Some(source), Some(sink)) = (
                        self.call_graph.nodes.get(source_id),
                        self.call_graph.nodes.get(sink_id),
                    ) {
                        // 构建过程间路径
                        let mut interprocedural_path = Vec::new();

                        for func_id in &call_path {
                            if let Some(func) = self.call_graph.nodes.get(func_id) {
                                interprocedural_path.push(InterproceduralStep {
                                    step_type: if func_id == source_id {
                                        InterproceduralStepType::Source
                                    } else if func_id == sink_id {
                                        InterproceduralStepType::Sink
                                    } else {
                                        InterproceduralStepType::ReturnValue
                                    },
                                    file_path: func.file_path.clone(),
                                    function_name: func.name.clone(),
                                    line: func.start_line,
                                    variable: String::new(),
                                    code: None,
                                });
                            }
                        }

                        let flow = InterproceduralTaintFlow {
                            id: uuid::Uuid::new_v4().to_string(),
                            source: FlowLocation {
                                file_path: source.file_path.clone(),
                                line: source.start_line,
                                column: None,
                                symbol: source.name.clone(),
                                code_snippet: None,
                            },
                            sink: FlowLocation {
                                file_path: sink.file_path.clone(),
                                line: sink.start_line,
                                column: None,
                                symbol: sink.name.clone(),
                                code_snippet: None,
                            },
                            interprocedural_path,
                            vulnerability_type: VulnerabilityType::Generic,
                            severity: Severity::High,
                            confidence: 0.7,
                        };

                        flows.push(flow);
                    }
                }
            }
        }

        flows
    }

    /// 默认污点源模式
    fn default_source_patterns() -> Vec<TaintSource> {
        vec![
            TaintSource::new("http_request", "HTTP Request", vec!["request", "req", "res"]),
            TaintSource::new("file_input", "File Input", vec!["read", "fread", "load"]),
            TaintSource::new("user_input", "User Input", vec!["input", "scanf", "prompt"]),
        ]
    }

    /// 默认污点汇模式
    fn default_sink_patterns() -> Vec<TaintSink> {
        vec![
            TaintSink::new("sql_exec", "SQL Execute", vec!["execute", "query", "exec"], VulnerabilityType::SqlInjection),
            TaintSink::new("command_exec", "Command Execute", vec!["system", "exec", "popen", "shell"], VulnerabilityType::CommandInjection),
            TaintSink::new("file_write", "File Write", vec!["write", "fwrite", "save"], VulnerabilityType::PathTraversal),
        ]
    }
}

impl Default for CrossFileTaintAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl CrossFileTaintAnalyzer {
    /// 计算项目中所有函数的摘要（自底向上）
    ///
    /// 返回 HashMap: func_id → FunctionSummary
    /// 利用调用图做拓扑排序，先计算叶子函数再计算调用者
    pub fn compute_function_summaries(
        &mut self,
        project_path: &Path,
    ) -> HashMap<String, FunctionSummary> {
        // 1. 构建调用图
        let source_files = self.collect_source_files(project_path);
        for file_path in &source_files {
            self.build_call_graph_for_file(file_path);
        }

        // 2. 拓扑排序（近似：按被调用次数排序）
        let sorted_funcs = self.topological_sort();

        // 3. 逐个计算摘要
        let mut summaries = HashMap::new();
        for func_id in sorted_funcs {
            if let Some(summary) = self.compute_single_summary(&func_id) {
                summaries.insert(func_id, summary);
            }
        }

        summaries
    }

    /// 拓扑排序（简化版：按调用深度排序，叶子函数优先）
    fn topological_sort(&self) -> Vec<String> {
        let mut in_degree: HashMap<&String, usize> = HashMap::new();
        for (id, node) in &self.call_graph.nodes {
            in_degree.insert(id, node.calls.len());
        }

        let mut queue: VecDeque<&String> = in_degree.iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(&id, _)| id)
            .collect();

        let mut result = Vec::new();
        while let Some(func_id) = queue.pop_front() {
            result.push(func_id.clone());
            if let Some(node) = self.call_graph.nodes.get(func_id) {
                for caller in &node.called_by {
                    if let Some(deg) = in_degree.get_mut(caller) {
                        *deg = deg.saturating_sub(1);
                        if *deg == 0 {
                            queue.push_back(caller);
                        }
                    }
                }
            }
        }

        // 加上可能有环的剩余节点
        for id in self.call_graph.nodes.keys() {
            if !result.contains(id) {
                result.push(id.clone());
            }
        }

        result
    }

    /// 计算单个函数的摘要
    fn compute_single_summary(&self, func_id: &str) -> Option<FunctionSummary> {
        let node = self.call_graph.nodes.get(func_id)?;

        let mut taint_propagation = Vec::new();
        let mut direct_sinks = Vec::new();

        // 分析每个参数是否可能到达 sink
        for (param_idx, param) in node.parameters.iter().enumerate() {
            if param.may_be_tainted {
                // 如果参数标记为可能的污点源，记录传播信息
                // 简化实现：假设所有 tainted 参数都可能影响返回值
                taint_propagation.push((param_idx, true));

                // 检查函数体内是否有直接调用 sink
                for call in &node.calls {
                    if self.is_taint_sink(call) {
                        direct_sinks.push(SinkReachability {
                            sink_name: call.clone(),
                            from_param: param_idx,
                            sanitized: false,
                            sanitizer: None,
                            sink_line: 0, // 精确行号需要更深层分析
                            vuln_type: self.infer_vuln_type(call),
                        });
                    }
                }
            }
        }

        // 如果函数是污点源，所有参数都标记为可能传播
        if node.is_taint_source {
            for (idx, _param) in node.parameters.iter().enumerate() {
                if !taint_propagation.iter().any(|(i, _)| *i == idx) {
                    taint_propagation.push((idx, true));
                }
            }
        }

        Some(FunctionSummary {
            func_id: func_id.to_string(),
            func_name: node.name.clone(),
            file_path: node.file_path.clone(),
            taint_propagation,
            direct_sinks,
            body_hash: None,
        })
    }

    /// 从 sink 函数名推断漏洞类型
    fn infer_vuln_type(&self, func_name: &str) -> VulnerabilityType {
        let lower = func_name.to_lowercase();

        if lower.contains("exec") || lower.contains("system") || lower.contains("spawn")
            || lower.contains("runtime") || lower.contains("processbuilder")
            || lower.contains("shell_exec") || lower.contains("passthru")
        {
            return VulnerabilityType::CommandInjection;
        }

        if lower.contains("query") || lower.contains("sql") || lower.contains("cursor")
            || lower.contains("jdbctemplate") || lower.contains("statement")
            || lower.contains("preparedstatement") || lower.contains("database")
        {
            return VulnerabilityType::SqlInjection;
        }

        if lower.contains("eval") || lower.contains("compile") || lower.contains("scriptengine")
            || lower.contains("groovyshell") || lower.contains("__import__")
        {
            return VulnerabilityType::CodeInjection;
        }

        if (lower.contains("open") && !lower.contains("response"))
            || lower.contains("readfile") || lower.contains("writefile")
            || lower.contains("fileinputstream") || lower.contains("fileoutputstream")
        {
            return VulnerabilityType::PathTraversal;
        }

        if lower.contains("fetch") || lower.contains("httpclient") || lower.contains("urlconnection")
            || lower.contains("resttemplate") || lower.contains("webclient")
            || lower.contains("sendrequest")
        {
            return VulnerabilityType::ServerSideRequestForgery;
        }

        if lower.contains("innerhtml") || lower.contains("document.write")
            || lower.contains("getwriter") || lower.contains("dangerouslysetinnerhtml")
        {
            return VulnerabilityType::CrossSiteScripting;
        }

        if lower.contains("deserialize") || lower.contains("readobject")
            || lower.contains("objectinputstream") || lower.contains("readvalue")
            || lower.contains("pickle") || lower.contains("unserialize")
        {
            return VulnerabilityType::InsecureDeserialization;
        }

        if lower.contains("redirect") || lower.contains("sendredirect") {
            return VulnerabilityType::OpenRedirect;
        }

        if lower.contains("ldap") {
            return VulnerabilityType::LdapInjection;
        }

        if lower.contains("request") {
            return VulnerabilityType::ServerSideRequestForgery;
        }

        VulnerabilityType::Generic
    }

    /// 利用已有的函数摘要做跨函数污点传播
    ///
    /// 当分析到调用 `callee(tainted_var)` 时，
    /// 查找 callee 的摘要，判断参数污点是否传播到返回值或内部 sink
    pub fn propagate_with_summary(
        &self,
        summaries: &HashMap<String, FunctionSummary>,
        callee_name: &str,
        arg_tainted: &[bool],
    ) -> SummaryPropagationResult {
        let mut result = SummaryPropagationResult {
            return_tainted: false,
            sinks_reached: Vec::new(),
        };

        // 查找匹配的摘要
        let summary = summaries.values().find(|s| {
            s.func_name == callee_name ||
            s.func_id.contains(callee_name)
        });

        if let Some(summary) = summary {
            for (param_idx, affects_return) in &summary.taint_propagation {
                if *param_idx < arg_tainted.len() && arg_tainted[*param_idx] {
                    if *affects_return {
                        result.return_tainted = true;
                    }
                    // 添加该参数到达的 sink
                    for sink in &summary.direct_sinks {
                        if sink.from_param == *param_idx {
                            result.sinks_reached.push(sink.clone());
                        }
                    }
                }
            }
        }

        result
    }
}

/// 函数摘要传播结果
#[derive(Debug, Clone)]
pub struct SummaryPropagationResult {
    /// 返回值是否被污点影响
    pub return_tainted: bool,
    /// 到达的 sink 列表
    pub sinks_reached: Vec<SinkReachability>,
}

// ── 上下文组装器 ──────────────────────────────────────────

/// 文件上下文信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileContext {
    /// 目标文件路径
    pub file_path: String,
    /// 调用此文件函数的 callers
    pub callers: Vec<CallerInfo>,
    /// 此文件调用的外部函数 callees
    pub callees: Vec<CalleeInfo>,
    /// 信任边界（外部输入点）
    pub trust_boundaries: Vec<TrustBoundaryInfo>,
    /// 上游是否有验证逻辑
    pub upstream_validation: Vec<String>,
}

/// 调用者信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallerInfo {
    pub function_name: String,
    pub file_path: String,
    pub line: usize,
}

/// 被调用者信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalleeInfo {
    pub function_name: String,
    pub file_path: Option<String>,
    pub is_external: bool,
}

/// 信任边界信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustBoundaryInfo {
    pub function_name: String,
    pub line: usize,
    pub input_type: String,
}

/// 上下文组装器 — 为指定文件构建跨文件上下文
pub struct ContextAssembler {
    /// 调用图
    call_graph: CallGraph,
}

impl ContextAssembler {
    /// 从调用图创建
    pub fn new(call_graph: CallGraph) -> Self {
        Self { call_graph }
    }

    /// 从项目路径直接构建
    pub fn from_project(project_path: &Path) -> Self {
        let mut analyzer = CrossFileTaintAnalyzer::new();
        let _ = analyzer.analyze_project(project_path);
        Self {
            call_graph: analyzer.call_graph,
        }
    }

    /// 为指定文件组装上下文
    pub fn assemble_context(&self, file_path: &str) -> FileContext {
        let file_str = file_path.replace('\\', "/");

        // 1. 找到该文件中的所有函数
        let file_funcs = self.call_graph.file_functions
            .get(&file_str)
            .cloned()
            .unwrap_or_default();

        // 2. 收集 callers（谁调用了这个文件的函数）
        let mut callers = Vec::new();
        for func_id in &file_funcs {
            if let Some(node) = self.call_graph.nodes.get(func_id) {
                for caller_id in &node.called_by {
                    if let Some(caller) = self.call_graph.nodes.get(caller_id) {
                        // 排除同文件的调用
                        if caller.file_path != file_str {
                            callers.push(CallerInfo {
                                function_name: caller.name.clone(),
                                file_path: caller.file_path.clone(),
                                line: caller.start_line,
                            });
                        }
                    }
                }
            }
        }

        // 3. 收集 callees（这个文件调用了哪些外部函数）
        let mut callees = Vec::new();
        for func_id in &file_funcs {
            if let Some(node) = self.call_graph.nodes.get(func_id) {
                for callee_id in &node.calls {
                    if let Some(callee) = self.call_graph.nodes.get(callee_id) {
                        callees.push(CalleeInfo {
                            function_name: callee.name.clone(),
                            file_path: if callee.is_external {
                                None
                            } else {
                                Some(callee.file_path.clone())
                            },
                            is_external: callee.is_external,
                        });
                    }
                }
            }
        }

        // 4. 识别信任边界（外部输入点）
        let mut trust_boundaries = Vec::new();
        for func_id in &file_funcs {
            if let Some(node) = self.call_graph.nodes.get(func_id) {
                if node.is_taint_source {
                    trust_boundaries.push(TrustBoundaryInfo {
                        function_name: node.name.clone(),
                        line: node.start_line,
                        input_type: "external_input".to_string(),
                    });
                }
                // 检查参数是否可能是污点
                for param in &node.parameters {
                    if param.may_be_tainted {
                        trust_boundaries.push(TrustBoundaryInfo {
                            function_name: format!("{}({})", node.name, param.name),
                            line: node.start_line,
                            input_type: format!("param:{}", param.name),
                        });
                    }
                }
            }
        }

        // 5. 检测上游验证
        let mut upstream_validation = Vec::new();
        for caller in &callers {
            if let Some(caller_funcs) = self.call_graph.file_functions.get(&caller.file_path) {
                for cfunc_id in caller_funcs {
                    if let Some(cfunc) = self.call_graph.nodes.get(cfunc_id) {
                        // 检查验证相关函数名
                        let name_lower = cfunc.name.to_lowercase();
                        if name_lower.contains("validate")
                            || name_lower.contains("sanitize")
                            || name_lower.contains("check")
                            || name_lower.contains("verify")
                            || name_lower.contains("auth")
                        {
                            upstream_validation.push(format!(
                                "{}:{} ({})",
                                caller.file_path,
                                cfunc.start_line,
                                cfunc.name,
                            ));
                        }
                    }
                }
            }
        }

        FileContext {
            file_path: file_str,
            callers,
            callees,
            trust_boundaries,
            upstream_validation,
        }
    }

    /// 获取调用图引用
    pub fn call_graph(&self) -> &CallGraph {
        &self.call_graph
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_graph_creation() {
        let graph = CallGraph::new();
        assert!(graph.nodes.is_empty());
    }

    #[test]
    fn test_call_graph_add_node() {
        let mut graph = CallGraph::new();
        let node = CallGraphNode {
            id: "test.py:main".to_string(),
            name: "main".to_string(),
            file_path: "test.py".to_string(),
            start_line: 1,
            end_line: 10,
            parameters: vec![],
            return_type: None,
            calls: vec![],
            called_by: vec![],
            is_external: false,
            is_taint_source: false,
            is_taint_sink: false,
        };

        graph.add_node(node);
        assert_eq!(graph.nodes.len(), 1);
    }

    #[test]
    fn test_call_graph_add_call() {
        let mut graph = CallGraph::new();

        let caller = CallGraphNode {
            id: "test.py:main".to_string(),
            name: "main".to_string(),
            file_path: "test.py".to_string(),
            start_line: 1,
            end_line: 10,
            parameters: vec![],
            return_type: None,
            calls: vec![],
            called_by: vec![],
            is_external: false,
            is_taint_source: false,
            is_taint_sink: false,
        };

        let callee = CallGraphNode {
            id: "test.py:helper".to_string(),
            name: "helper".to_string(),
            file_path: "test.py".to_string(),
            start_line: 11,
            end_line: 15,
            parameters: vec![],
            return_type: None,
            calls: vec![],
            called_by: vec![],
            is_external: false,
            is_taint_source: false,
            is_taint_sink: false,
        };

        graph.add_node(caller);
        graph.add_node(callee);
        graph.add_call("test.py:main", "test.py:helper");

        assert!(graph.nodes.get("test.py:main").unwrap().calls.contains(&"test.py:helper".to_string()));
        assert!(graph.nodes.get("test.py:helper").unwrap().called_by.contains(&"test.py:main".to_string()));
    }

    #[test]
    fn test_extract_function_name_python() {
        let analyzer = CrossFileTaintAnalyzer::new();
        assert_eq!(analyzer.extract_function_name("def main():", "python"), Some("main".to_string()));
        assert_eq!(analyzer.extract_function_name("def get_user(id):", "python"), Some("get_user".to_string()));
    }

    #[test]
    fn test_extract_function_name_javascript() {
        let analyzer = CrossFileTaintAnalyzer::new();
        assert_eq!(analyzer.extract_function_name("function main() {", "javascript"), Some("main".to_string()));
        assert_eq!(analyzer.extract_function_name("const helper = () =>", "javascript"), Some("helper".to_string()));
    }

    #[test]
    fn test_is_taint_source() {
        let analyzer = CrossFileTaintAnalyzer::new();
        assert!(analyzer.is_taint_source("getUserInput"));
        assert!(analyzer.is_taint_source("read_file"));
        assert!(!analyzer.is_taint_source("calculate"));
    }

    #[test]
    fn test_is_taint_sink() {
        let analyzer = CrossFileTaintAnalyzer::new();
        assert!(analyzer.is_taint_sink("executeQuery"));
        assert!(analyzer.is_taint_sink("system"));
        assert!(!analyzer.is_taint_sink("format"));
    }

    #[test]
    fn test_param_may_be_tainted() {
        assert!(CrossFileTaintAnalyzer::param_may_be_tainted("req"));
        assert!(CrossFileTaintAnalyzer::param_may_be_tainted("input"));
        assert!(CrossFileTaintAnalyzer::param_may_be_tainted("user_input"));
        assert!(CrossFileTaintAnalyzer::param_may_be_tainted("payload"));
        assert!(!CrossFileTaintAnalyzer::param_may_be_tainted("index"));
        assert!(!CrossFileTaintAnalyzer::param_may_be_tainted("count"));
    }

    #[test]
    fn test_cross_file_taint_flow_detection() {
        // 创建临时项目目录
        let tmp_dir = std::env::temp_dir().join("ctx_audit_cross_file_test");
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();

        // source.py: 获取用户输入的函数 + 跨文件调用 execute_query
        let source_code = r#"
def get_user_input(request):
    user_id = request.args.get('id')
    return user_id

def handle_request(request):
    user_input = get_user_input(request)
    execute_query(user_input)
"#;
        // sink.py: 包含执行数据库查询的函数
        let sink_code = r#"
def execute_query(query):
    cursor.execute(query)
"#;

        std::fs::write(tmp_dir.join("source.py"), source_code).unwrap();
        std::fs::write(tmp_dir.join("sink.py"), sink_code).unwrap();

        let mut analyzer = CrossFileTaintAnalyzer::new();
        let result = analyzer.analyze_project(&tmp_dir);

        // 验证调用图被构建
        assert!(result.stats.files_analyzed >= 2, "Should analyze at least 2 files, got {}", result.stats.files_analyzed);
        assert!(result.stats.total_functions >= 3, "Should find at least 3 functions, got {}", result.stats.total_functions);

        // 验证 taint sources 和 sinks 被识别
        // get_user_input 包含 "get" → is_taint_source
        // execute_query 包含 "execute" → is_taint_sink
        assert!(result.stats.taint_sources > 0, "Should find taint sources, got {}", result.stats.taint_sources);
        assert!(result.stats.taint_sinks > 0, "Should find taint sinks, got {}", result.stats.taint_sinks);

        // 验证跨文件调用关系被解析
        // handle_request (source.py) 调用 execute_query (sink.py) → 应建立跨文件调用边
        let has_cross_file_calls = result.call_graph.nodes.values()
            .any(|n| n.calls.iter().any(|c| {
                if let Some(callee) = result.call_graph.nodes.get(c) {
                    callee.file_path != n.file_path
                } else {
                    false
                }
            }));
        assert!(has_cross_file_calls, "Should resolve cross-file call relationships");

        // 验证检测到 taint 流（source → sink 路径）
        assert!(result.stats.taint_flows > 0, "Should detect taint flows from source to sink, got {}", result.stats.taint_flows);

        // 清理
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_cross_file_same_language_javascript() {
        let tmp_dir = std::env::temp_dir().join("ctx_audit_cross_file_js_test");
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();

        let handler_code = r#"
function handleRequest(req) {
    const userInput = req.query.input;
    return processInput(userInput);
}
"#;
        let processor_code = r#"
function processInput(data) {
    return executeCommand(data);
}

function executeCommand(cmd) {
    exec(cmd);
}
"#;

        std::fs::write(tmp_dir.join("handler.js"), handler_code).unwrap();
        std::fs::write(tmp_dir.join("processor.js"), processor_code).unwrap();

        let mut analyzer = CrossFileTaintAnalyzer::new();
        let result = analyzer.analyze_project(&tmp_dir);

        assert!(result.stats.files_analyzed >= 2);
        assert!(result.stats.taint_sources > 0, "handleRequest should be identified as taint source");
        assert!(result.stats.taint_sinks > 0, "executeCommand should be identified as taint sink");

        // handlerRequest calls processInput (cross-file)
        let has_cross = result.call_graph.nodes.values()
            .any(|n| n.calls.iter().any(|c| {
                result.call_graph.nodes.get(c)
                    .map(|callee| callee.file_path != n.file_path)
                    .unwrap_or(false)
            }));
        assert!(has_cross, "Should resolve cross-file JS call relationships");

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_function_summaries() {
        let tmp_dir = std::env::temp_dir().join("ctx_audit_summary_test");
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();

        let code = r#"
def get_user(request):
    user_id = request.args.get('id')
    return user_id

def query_user(user_id):
    cursor.execute(user_id)
"#;
        std::fs::write(tmp_dir.join("users.py"), code).unwrap();

        let mut analyzer = CrossFileTaintAnalyzer::new();
        let summaries = analyzer.compute_function_summaries(&tmp_dir);

        // get_user 是 taint source，应该有摘要
        assert!(!summaries.is_empty(), "Should compute function summaries");

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
