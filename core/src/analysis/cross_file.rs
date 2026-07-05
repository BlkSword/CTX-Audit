// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 跨文件分析模块
//!
//! 提供函数调用图构建、跨文件污点传播和模块依赖分析

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use super::imports::ImportResolver;
use super::taint::{FlowLocation, Severity, TaintSink, TaintSource, VulnerabilityType};
use crate::ast::{CallInfo, CallbackArg, Symbol};

/// 调用目标 — 方法调用的 receiver 信息
///
/// 替代裸函数名字符串，保留 `obj.method()` 中的 `obj` 信息，
/// 以便跨文件解析时缩小匹配范围。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CallTarget {
    /// 被调用函数/方法名
    pub callee: String,
    /// 方法调用的 receiver（obj.method() → Some("obj")）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver: Option<String>,
    /// 完整调用表达式文本（用于回退匹配）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    /// 调用点行号（1-based），用于在 call_site_args 中定位实参
    #[serde(default, skip_serializing_if = "is_zero")]
    pub line: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

impl CallTarget {
    pub fn new(callee: impl Into<String>) -> Self {
        Self {
            callee: callee.into(),
            receiver: None,
            raw: None,
            line: 0,
        }
    }

    pub fn with_receiver(callee: impl Into<String>, receiver: impl Into<String>) -> Self {
        let callee = callee.into();
        let receiver = receiver.into();
        let raw = Some(format!("{}.{}()", receiver, callee));
        Self {
            callee,
            receiver: Some(receiver),
            raw,
            line: 0,
        }
    }

    pub fn with_line(mut self, line: usize) -> Self {
        self.line = line;
        self
    }
}

impl From<String> for CallTarget {
    fn from(callee: String) -> Self {
        Self::new(callee)
    }
}

impl From<&str> for CallTarget {
    fn from(callee: &str) -> Self {
        Self::new(callee.to_string())
    }
}

impl From<CallInfo> for CallTarget {
    fn from(c: CallInfo) -> Self {
        let base = if c.is_method {
            Self::with_receiver(c.callee, c.receiver.unwrap_or_default())
        } else {
            Self::new(c.callee)
        };
        base.with_line(c.line)
    }
}

/// 判断一个调用目标是否为常见内置/标准库函数，
/// 这类函数在全局名称回退阶段可直接跳过，减少无效匹配。
fn is_builtin_call_target(ct: &CallTarget) -> bool {
    static BUILTINS: OnceLock<HashSet<(&'static str, Option<&'static str>)>> = OnceLock::new();
    let set = BUILTINS.get_or_init(|| {
        let mut s = HashSet::new();
        // console.*
        for name in ["log", "error", "warn", "info", "debug", "trace"] {
            s.insert((name, Some("console")));
        }
        // JSON.*
        s.insert(("parse", Some("JSON")));
        s.insert(("stringify", Some("JSON")));
        // 全局工具函数
        for name in [
            "setTimeout", "setInterval", "clearTimeout", "clearInterval",
            "parseInt", "parseFloat", "isNaN", "isFinite",
        ] {
            s.insert((name, None));
        }
        s
    });

    if set.contains(&(ct.callee.as_str(), ct.receiver.as_deref())) {
        return true;
    }
    // receiver == console / JSON 时，任意方法都视为内置
    if let Some(recv) = ct.receiver.as_deref() {
        if recv == "console" || recv == "JSON" {
            return true;
        }
    }
    false
}

/// 常见通用方法名集合：这类名字在全局名称回退阶段应被跳过，
/// 否则在 Juliet / 大型 monorepo 中会把所有同名函数连成 O(n²) 边。
fn is_common_generic_name(name: &str) -> bool {
    static COMMON: OnceLock<HashSet<&'static str>> = OnceLock::new();
    let set = COMMON.get_or_init(|| {
        [
            // Juliet / 测试框架中重复出现的名字，极易造成 O(n²) 调用边
            "main", "bad", "good", "good1", "good2", "good3", "goodG2B", "goodB2G",
            // 单元测试生命周期方法
            "test", "setup", "teardown",
        ]
        .into_iter()
        .collect()
    });
    set.contains(name)
}

/// 全局名称回退时，单个 callee 允许匹配的最大函数节点数。
/// 超过该阈值说明是高度通用的名字（如 bad/good/main），应跳过。
const GLOBAL_FALLBACK_MAX_MATCHES: usize = 32;

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
    pub calls: Vec<CallTarget>,
    /// 被调用的位置
    pub called_by: Vec<String>,
    /// 是否是外部函数（库函数）
    pub is_external: bool,
    /// 是否是污点源
    pub is_taint_source: bool,
    /// 是否是污点汇
    pub is_taint_sink: bool,
    /// 污点汇对应的漏洞类型（从匹配的 sink pattern 提取）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sink_type: Option<VulnerabilityType>,
    /// 是否为合成回调节点（匿名箭头函数/函数表达式）
    #[serde(default)]
    pub is_callback: bool,
    /// 父调用点的行号（回调注册所在位置）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_call_site: Option<usize>,
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
            if !caller.calls.iter().any(|c| c.callee == callee_id) {
                caller.calls.push(CallTarget::new(callee_id));
            }
        }
        if let Some(callee) = self.nodes.get_mut(callee_id) {
            if !callee.called_by.iter().any(|c| c == caller_id) {
                callee.called_by.push(caller_id.to_string());
            }
        }
    }

    /// 合并另一个调用图（假设节点 ID 跨图不冲突）
    pub fn merge_from(&mut self, other: CallGraph) {
        for (_, node) in other.nodes {
            self.add_node(node);
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
            for target in &node.calls {
                if callees.insert(target.callee.clone()) {
                    self.collect_callees_recursive(&target.callee, callees);
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

    /// 查找两个函数之间的调用路径（BFS，返回最短路径）
    pub fn find_call_path(&self, from_id: &str, to_id: &str) -> Option<Vec<String>> {
        if from_id == to_id {
            return Some(vec![from_id.to_string()]);
        }

        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<(String, Vec<String>)> = VecDeque::new();
        queue.push_back((from_id.to_string(), vec![from_id.to_string()]));
        visited.insert(from_id.to_string());

        while let Some((current_id, path)) = queue.pop_front() {
            if let Some(node) = self.nodes.get(&current_id) {
                for ct in &node.calls {
                    let callee_id = &ct.callee;
                    if !visited.insert(callee_id.clone()) {
                        continue;
                    }
                    let mut new_path = path.clone();
                    new_path.push(callee_id.clone());
                    if callee_id == to_id {
                        return Some(new_path);
                    }
                    queue.push_back((callee_id.clone(), new_path));
                }
            }
        }

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
    /// 调用图（Arc 零拷贝共享）
    pub call_graph: Arc<CallGraph>,
    /// 污点流
    pub taint_flows: Vec<InterproceduralTaintFlow>,
    /// 分析统计
    pub stats: CrossFileAnalysisStats,
    /// 类型层次结构（类/接口继承关系）
    pub type_hierarchy: super::type_hierarchy::TypeHierarchy,
    /// 框架中间件模型
    pub middleware_model: super::middleware::MiddlewareModel,
    /// 文件导入别名映射: normalized_file_path → (local_name → ImportResolution)
    pub file_import_aliases: HashMap<String, HashMap<String, ImportResolution>>,
    /// 局部变量→类型映射: normalized_file_path → (var_name → type_name)
    pub variable_type_map: HashMap<String, HashMap<String, String>>,
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
    /// 置信度衰减因素
    #[serde(default)]
    pub confidence_factors: Vec<String>,
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

    /// 参数通过数据流到达的下游调用参数。
    /// 用于跨文件多跳传播：若参数 p 被污染，则这些 callee 的第 arg_idx 个参数也被污染。
    pub param_to_calls: Vec<ParamToCall>,

    /// 函数体摘要哈希（用于缓存失效）
    pub body_hash: Option<String>,
}

/// 参数到下游调用参数的映射
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamToCall {
    /// 当前函数参数索引
    pub param_idx: usize,
    /// 被调函数名
    pub callee: String,
    /// 实参索引
    pub arg_idx: usize,
    /// 调用点行号
    pub call_line: usize,
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

/// 导入解析结果 — 将调用者文件中的局部名称映射到目标文件和导出名称
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportResolution {
    /// 源模块路径（如 './db', '../utils/helper'）
    pub source_module: String,
    /// 被导入的原始导出名称
    pub original_export_name: String,
    /// 是否为默认导入（无法确定具体导出名称）
    pub is_default: bool,
}

/// 跨文件污点分析器
pub struct CrossFileTaintAnalyzer {
    /// 调用图
    call_graph: CallGraph,
    /// 导入解析器
    import_resolver: ImportResolver,
    /// 污点源模式
    source_patterns: Arc<Vec<TaintSource>>,
    /// 污点汇模式
    sink_patterns: Arc<Vec<TaintSink>>,
    /// CPG 缓存（从 scan pipeline Stage B 传入）
    cpg_cache: HashMap<String, super::cpg::FunctionCPG>,
    /// CPG taint flow 缓存
    cpg_taint_flows: HashMap<String, Vec<super::taint::TaintFlow>>,
    /// Stage B 已解析 AST 产物缓存：file_path -> (symbols, calls)
    /// 供 Stage C 调用图构建直接复用，避免对同一文件二次 parse。
    parsed_ast_cache: HashMap<String, (Vec<Symbol>, Vec<CallInfo>)>,
    /// 文件导入别名映射: file_path -> (local_name -> ImportResolution)
    file_import_aliases: HashMap<String, HashMap<String, ImportResolution>>,
    /// 局部变量→类型映射: file_path -> (var_name -> type_name)
    /// 追踪 const x = new Type(...) 中的 x→Type 关系，
    /// 用于 receiver 感知的跨文件调用解析（取代全局名称回退）
    variable_type_map: HashMap<String, HashMap<String, String>>,
    /// 类型层次结构（类/接口继承关系）
    type_hierarchy: super::type_hierarchy::TypeHierarchy,
    /// 框架中间件模型（Express app.use, Django MIDDLEWARE）
    middleware_model: super::middleware::MiddlewareModel,
    /// 调用点参数缓存：key = "caller_func_id:call_line"，value = 该调用的参数列表
    /// 用于跨文件摘要传播时判断 caller 的污点变量是否传入 callee 的敏感参数
    call_site_args: HashMap<String, Vec<crate::ast::ArgInfo>>,
    /// 模块路径解析缓存：(source_module, importing_file) -> 解析出的文件路径
    /// 避免 resolve_cross_file_calls / inject_middleware_edges 中重复 IO/路径归一化
    module_resolution_cache: std::sync::Mutex<HashMap<(String, String), Option<String>>>,
    /// 文件原始内容缓存（用于避免传播阶段反复读盘）
    file_content_cache: HashMap<String, String>,
    /// 文件按行切分后的缓存（与 file_content_cache 配套，避免重复 split）
    file_lines_cache: HashMap<String, Vec<String>>,
}

impl CrossFileTaintAnalyzer {
    /// 创建新的跨文件污点分析器
    pub fn new() -> Self {
        Self {
            call_graph: CallGraph::new(),
            import_resolver: ImportResolver::new(),
            source_patterns: Arc::new(Self::default_source_patterns()),
            sink_patterns: Arc::new(Self::default_sink_patterns()),
            cpg_cache: HashMap::new(),
            cpg_taint_flows: HashMap::new(),
            parsed_ast_cache: HashMap::new(),
            file_import_aliases: HashMap::new(),
            variable_type_map: HashMap::new(),
            type_hierarchy: super::type_hierarchy::TypeHierarchy::new(),
            middleware_model: super::middleware::MiddlewareModel::new(),
            call_site_args: HashMap::new(),
            module_resolution_cache: std::sync::Mutex::new(HashMap::new()),
            file_content_cache: HashMap::new(),
            file_lines_cache: HashMap::new(),
        }
    }

    /// 使用外部加载的 YAML 污点规则创建分析器
    ///
    /// 让跨文件分析复用 Stage B 的 taint 规则（如 rules/taint/frameworks/*.yaml），
    /// 而不是只依赖默认硬编码规则。
    pub fn with_rules(
        sources: Vec<super::taint::TaintSource>,
        sinks: Vec<super::taint::TaintSink>,
    ) -> Self {
        let mut analyzer = Self::new();
        analyzer.source_patterns = Arc::new(sources);
        analyzer.sink_patterns = Arc::new(sinks);
        analyzer
    }

    /// 注入 CPG 缓存（从 scan pipeline Stage B 传入）
    pub fn set_cpg_cache(
        &mut self,
        cpg_cache: HashMap<String, super::cpg::FunctionCPG>,
        taint_flows: HashMap<String, Vec<super::taint::TaintFlow>>,
    ) {
        self.cpg_cache = cpg_cache;
        self.cpg_taint_flows = taint_flows;
    }

    /// 注入 Stage B 已解析的 AST 产物
    pub fn set_parsed_ast_cache(
        &mut self,
        cache: HashMap<String, (Vec<Symbol>, Vec<CallInfo>)>,
    ) {
        self.parsed_ast_cache = cache;
    }

    /// 合并另一个分析器的文件级结果（用于并行 Stage C 结果归并）
    pub fn merge_from(&mut self, mut other: CrossFileTaintAnalyzer) {
        self.call_graph.merge_from(other.call_graph);
        self.import_resolver.merge_from(other.import_resolver);
        self.file_import_aliases.extend(other.file_import_aliases);
        self.variable_type_map.extend(other.variable_type_map);
        self.type_hierarchy.merge_from(other.type_hierarchy);
        self.middleware_model.merge_from(other.middleware_model);
        self.call_site_args.extend(other.call_site_args);
        // cpg_cache / cpg_taint_flows / parsed_ast_cache 由主分析器持有，不覆盖
        self.cpg_cache.extend(other.cpg_cache);
        self.cpg_taint_flows.extend(other.cpg_taint_flows);
        self.parsed_ast_cache.extend(other.parsed_ast_cache);
    }

    /// 分析项目
    pub fn analyze_project(&mut self, project_path: &Path) -> CrossFileTaintResult {
        let mut stats = CrossFileAnalysisStats::default();

        // 1. 收集所有源文件
        let source_files = self.collect_source_files(project_path);
        stats.files_analyzed = source_files.len();

        // 1.5 预加载文件内容，避免后续反复读盘
        self.preload_file_contents(&source_files);

        // 2. 构建调用图（逐文件提取函数节点和内部调用）
        for file_path in &source_files {
            self.build_call_graph_for_file(file_path);
        }

        // 3. 跨文件调用解析：将裸函数名匹配到已知函数节点
        self.filter_constructor_fps();
        self.resolve_cross_file_calls();
        self.inject_middleware_edges();

        stats.total_functions = self.call_graph.nodes.len();
        stats.taint_sources = self.call_graph.taint_sources.len();
        stats.taint_sinks = self.call_graph.taint_sinks.len();

        // 4. 查找跨文件污点流
        let taint_flows = self.find_interprocedural_taint_flows();
        stats.taint_flows = taint_flows.len();
        stats.cross_file_flows = taint_flows
            .iter()
            .filter(|f| {
                // 跨文件 = source 和 sink 在不同文件，或路径跨多个文件
                f.source.file_path != f.sink.file_path || f.interprocedural_path.len() > 1
            })
            .count();

        CrossFileTaintResult {
            project_path: project_path.to_string_lossy().to_string(),
            call_graph: Arc::new(std::mem::take(&mut self.call_graph)),
            taint_flows,
            stats,
            type_hierarchy: std::mem::take(&mut self.type_hierarchy),
            middleware_model: std::mem::take(&mut self.middleware_model),
            file_import_aliases: std::mem::take(&mut self.file_import_aliases),
            variable_type_map: std::mem::take(&mut self.variable_type_map),
        }
    }

    /// 分析指定文件子集（用于深度扫描，避免全项目遍历）
    pub fn analyze_files(
        &mut self,
        project_path: &Path,
        files: &[PathBuf],
    ) -> CrossFileTaintResult {
        let mut stats = CrossFileAnalysisStats::default();

        // 只处理传入的文件列表
        stats.files_analyzed = files.len();

        self.preload_file_contents(files);

        for file_path in files {
            self.build_call_graph_for_file(file_path);
        }

        self.filter_constructor_fps();
        self.resolve_cross_file_calls();
        self.inject_middleware_edges();

        stats.total_functions = self.call_graph.nodes.len();
        stats.taint_sources = self.call_graph.taint_sources.len();
        stats.taint_sinks = self.call_graph.taint_sinks.len();

        let taint_flows = self.find_interprocedural_taint_flows();
        stats.taint_flows = taint_flows.len();
        stats.cross_file_flows = taint_flows
            .iter()
            .filter(|f| f.source.file_path != f.sink.file_path || f.interprocedural_path.len() > 1)
            .count();

        CrossFileTaintResult {
            project_path: project_path.to_string_lossy().to_string(),
            call_graph: Arc::new(std::mem::take(&mut self.call_graph)),
            taint_flows,
            stats,
            type_hierarchy: std::mem::take(&mut self.type_hierarchy),
            middleware_model: std::mem::take(&mut self.middleware_model),
            file_import_aliases: std::mem::take(&mut self.file_import_aliases),
            variable_type_map: std::mem::take(&mut self.variable_type_map),
        }
    }

    /// 分析指定文件子集，复用已有的文件内容缓存（避免重复 I/O）
    pub fn analyze_files_with_content(
        &mut self,
        project_path: &Path,
        files: &[PathBuf],
        content_cache: &HashMap<String, String>,
    ) -> CrossFileTaintResult {
        let mut stats = CrossFileAnalysisStats::default();
        stats.files_analyzed = files.len();

        // 复用外部传入的内容缓存，并预加载其余文件
        for file_path in files {
            let file_str = file_path.to_string_lossy().to_string();
            if let Some(content) = content_cache.get(&file_str) {
                self.file_content_cache
                    .insert(file_str.clone(), content.clone());
                self.file_lines_cache
                    .insert(file_str, content.lines().map(|s| s.to_string()).collect());
            }
        }
        self.preload_file_contents(files);

        // 并行构建每个文件的调用图子图，再归并到主分析器
        let partials: Vec<CrossFileTaintAnalyzer> = files
            .par_iter()
            .filter_map(|file_path| {
                let file_str = file_path.to_string_lossy().to_string();
                let content = self.file_content_cache.get(&file_str).cloned()?;
                if !self.is_ast_supported(file_path) {
                    return None;
                }
                let mut local = Self::new();
                local.source_patterns = self.source_patterns.clone();
                local.sink_patterns = self.sink_patterns.clone();
                // 只传递当前文件的 Stage B AST 产物，避免克隆整个缓存
                if let Some((symbols, calls)) = self.parsed_ast_cache.get(&file_str) {
                    let mut subset = HashMap::new();
                    subset.insert(file_str.clone(), (symbols.clone(), calls.clone()));
                    local.set_parsed_ast_cache(subset);
                }
                // 只传递当前文件相关的 Stage B CPG 缓存，用于填充函数参数信息
                let local_cpg_cache: HashMap<String, super::cpg::FunctionCPG> = self
                    .cpg_cache
                    .iter()
                    .filter(|(k, _)| k.starts_with(file_str.as_str()))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                local.set_cpg_cache(local_cpg_cache, HashMap::new());
                local.build_call_graph_for_file_with_content(file_path, &content);
                Some(local)
            })
            .collect();

        for mut partial in partials {
            self.merge_from(partial);
        }

        self.filter_constructor_fps();
        self.resolve_cross_file_calls();
        self.inject_middleware_edges();

        stats.total_functions = self.call_graph.nodes.len();
        stats.taint_sources = self.call_graph.taint_sources.len();
        stats.taint_sinks = self.call_graph.taint_sinks.len();

        let taint_flows = self.find_interprocedural_taint_flows();
        stats.taint_flows = taint_flows.len();
        stats.cross_file_flows = taint_flows
            .iter()
            .filter(|f| f.source.file_path != f.sink.file_path || f.interprocedural_path.len() > 1)
            .count();

        CrossFileTaintResult {
            project_path: project_path.to_string_lossy().to_string(),
            call_graph: Arc::new(std::mem::take(&mut self.call_graph)),
            taint_flows,
            stats,
            type_hierarchy: std::mem::take(&mut self.type_hierarchy),
            middleware_model: std::mem::take(&mut self.middleware_model),
            file_import_aliases: std::mem::take(&mut self.file_import_aliases),
            variable_type_map: std::mem::take(&mut self.variable_type_map),
        }
    }

    /// 用已有内容构建调用图（跳过磁盘 I/O）
    fn build_call_graph_for_file_with_content(&mut self, file_path: &Path, content: &str) {
        let file_path_str = file_path.to_string_lossy().to_string();

        // 解析文件导入（用于后续跨文件调用精确匹配）
        self.parse_file_imports(&file_path_str, content);
        self.parse_variable_types(&file_path_str, content);
        // 扫描框架中间件和路由注册
        super::middleware::scan_middleware(file_path, content, &mut self.middleware_model);

        if self.is_ast_supported(file_path) {
            // 优先复用 Stage B 已解析的 AST 产物
            let (symbols, calls) = if let Some((cached_symbols, cached_calls)) =
                self.parsed_ast_cache.get(&file_path_str)
            {
                (cached_symbols.clone(), cached_calls.clone())
            } else {
                crate::ast::parser::with_thread_local_parser(|parser| {
                    let (symbols_result, calls) = parser.parse_and_extract_calls(file_path, content);
                    match symbols_result {
                        Ok(symbols) => (symbols, calls),
                        Err(_) => (Vec::new(), calls),
                    }
                })
            };

            if symbols.is_empty() {
                let language = self.infer_language(file_path);
                let functions = self.extract_functions(&content, &file_path_str, language);
                for func in functions {
                    self.call_graph.add_node(func);
                }
                return;
            }

            for symbol in &symbols {
                if !matches!(
                    symbol.kind,
                    crate::ast::SymbolKind::Function | crate::ast::SymbolKind::Method
                ) {
                    continue;
                }

                let func_name = symbol.name.clone();
                let func_id = format!("{}:{}", file_path_str, func_name);
                let func_name_clone = func_name.clone();

                let calls_in_range: Vec<&CallInfo> = calls
                    .iter()
                    .filter(|c| {
                        c.line >= symbol.start_line as usize && c.line <= symbol.end_line as usize
                    })
                    .collect();

                let calls_in_func: Vec<CallTarget> = calls_in_range
                    .iter()
                    .map(|c| CallTarget::from((*c).clone()))
                    .collect();

                let body_text = Self::extract_body(
                    content,
                    symbol.start_line as usize,
                    symbol.end_line as usize,
                );
                let is_source = self.is_taint_source(&func_name, &body_text);

                // 优先按函数体内的具体 sink 调用判断（可处理 response.getWriter().println、
                // stmt.executeBatch 等 Semantic 规则），函数名兜底。
                let (mut is_sink, mut sink_type) = (false, None);
                for call in &calls_in_range {
                    if let Some(vt) = self.is_sink_call(call) {
                        is_sink = true;
                        sink_type = Some(vt);
                        break;
                    }
                }
                if !is_sink {
                    (is_sink, sink_type) = self.is_taint_sink(&func_name, &body_text);
                }

                // 优先复用 Stage B CPG 中的参数信息，使跨文件/跨函数传播能正确映射形参。
                let cpg_key = format!(
                    "{}:{}:{}",
                    file_path_str, func_name, symbol.start_line
                );
                let parameters = self
                    .cpg_cache
                    .get(&cpg_key)
                    .map(|cpg| {
                        cpg.signature
                            .params
                            .iter()
                            .map(|p| FunctionParameter {
                                name: p.name.clone(),
                                param_type: p.type_annotation.clone(),
                                may_be_tainted: false,
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                let node = CallGraphNode {
                    id: func_id.clone(),
                    name: func_name,
                    file_path: file_path_str.clone(),
                    start_line: symbol.start_line as usize,
                    end_line: symbol.end_line as usize,
                    parameters,
                    return_type: None,
                    calls: calls_in_func,
                    called_by: Vec::new(),
                    is_external: false,
                    is_taint_source: is_source,
                    is_taint_sink: is_sink,
                    sink_type,
                    is_callback: false,
                    parent_call_site: None,
                };
                self.call_graph.add_node(node);

                // 注册回调
                let mut cb_idx: usize = 0;
                for call in &calls_in_range {
                    for cb in &call.callback_args {
                        let cb_id = format!(
                            "{}:{}:{}:cb{}",
                            file_path_str, func_name_clone, call.line, cb_idx
                        );
                        let cb_calls = self.extract_calls_from_body(&cb.body_text);
                        let cb_params: Vec<FunctionParameter> = cb
                            .params
                            .iter()
                            .map(|p| FunctionParameter {
                                name: p.clone(),
                                param_type: None,
                                may_be_tainted: false,
                            })
                            .collect();

                        let (cb_is_sink, cb_sink_type) = self.is_taint_sink("", &cb.body_text);
                        let cb_node = CallGraphNode {
                            id: cb_id.clone(),
                            name: format!("<callback@{}>", call.line),
                            file_path: file_path_str.clone(),
                            start_line: cb.start_line,
                            end_line: cb.end_line,
                            parameters: cb_params,
                            return_type: None,
                            calls: cb_calls,
                            called_by: vec![func_id.clone()],
                            is_external: false,
                            is_taint_source: false,
                            is_taint_sink: cb_is_sink,
                            sink_type: cb_sink_type,
                            is_callback: true,
                            parent_call_site: Some(call.line),
                        };

                        self.call_graph.add_node(cb_node);
                        self.call_graph.add_call(&func_id, &cb_id);
                        cb_idx += 1;
                    }
                }
            }

            // 构建类型层次结构
            for symbol in &symbols {
                match symbol.kind {
                    crate::ast::SymbolKind::Class => {
                        self.type_hierarchy.register_type(
                            &symbol.name,
                            super::type_hierarchy::TypeKind::Class,
                            &symbol.parent_classes,
                            &file_path_str,
                            symbol.start_line as usize,
                            symbol.end_line as usize,
                        );
                    }
                    crate::ast::SymbolKind::Interface => {
                        self.type_hierarchy.register_type(
                            &symbol.name,
                            super::type_hierarchy::TypeKind::Interface,
                            &symbol.parent_classes,
                            &file_path_str,
                            symbol.start_line as usize,
                            symbol.end_line as usize,
                        );
                    }
                    crate::ast::SymbolKind::Method => {
                        if let Some(owner) =
                            symbol.metadata.get("ownerClass").and_then(|v| v.as_str())
                        {
                            self.type_hierarchy.register_method(
                                owner,
                                super::type_hierarchy::MethodSignature {
                                    name: symbol.name.clone(),
                                    file_path: file_path_str.clone(),
                                    start_line: symbol.start_line as usize,
                                    is_static: false,
                                },
                            );
                        }
                    }
                    _ => {}
                }
            }
        } else {
            let file_path_str = file_path.to_string_lossy().to_string();
            let language = self.infer_language(file_path);
            let functions = self.extract_functions(content, &file_path_str, language);
            for func in functions {
                self.call_graph.add_node(func);
            }
        }
    }

    /// 解析局部变量→类型映射（const x = new Type(...) / const x = Type(...)）
    ///
    /// 追踪 `userDAO` → `UserDAO` 这样的关系，使 resolve_cross_file_calls 能通过
    /// receiver 变量名反查其类型，进而通过 import 别名定位到正确的目标文件。
    fn parse_variable_types(&mut self, file_path: &str, content: &str) {
        let normalized = normalize_path(file_path);
        let mut var_types: HashMap<String, String> = HashMap::new();

        // 模式: const/let/var varName = new TypeName(...)
        // 也匹配: const/let/var varName = TypeName(...)  (无 new 的构造函数)
        let re =
            regex::Regex::new(r"(?:const|let|var)\s+(\w+)\s*=\s*(?:new\s+)?(\w+)\s*\(").unwrap();

        for cap in re.captures_iter(content) {
            let var_name = cap[1].to_string();
            let type_name = cap[2].to_string();
            // 跳过明显不是类型名的变量（如小写开头的方法调用）
            if type_name
                .chars()
                .next()
                .map(|c| c.is_uppercase())
                .unwrap_or(false)
            {
                var_types.entry(var_name).or_insert(type_name);
            }
        }

        if !var_types.is_empty() {
            self.variable_type_map.insert(normalized, var_types);
        }
    }

    /// 解析文件导入，填充 file_import_aliases
    fn parse_file_imports(&mut self, file_path: &str, content: &str) {
        let module = self
            .import_resolver
            .parse_file(Path::new(file_path), content);
        let mut aliases: HashMap<String, ImportResolution> = HashMap::new();

        for import in &module.imports {
            for symbol in &import.symbols {
                let local_name = symbol
                    .alias
                    .as_ref()
                    .unwrap_or(&symbol.original_name)
                    .clone();
                // 跳过通配符导入 (*)
                if local_name == "*" {
                    continue;
                }
                aliases.insert(
                    local_name,
                    ImportResolution {
                        source_module: import.source.clone(),
                        original_export_name: symbol.original_name.clone(),
                        is_default: symbol.is_default,
                    },
                );
            }
        }

        if !aliases.is_empty() {
            self.file_import_aliases
                .insert(normalize_path(file_path), aliases);
        }
    }

    /// 带缓存的模块路径解析（独立函数，供并行调用图分辨率使用）
    fn resolve_module_to_file_with_cache(
        cache: &std::sync::Mutex<HashMap<(String, String), Option<String>>>,
        source_module: &str,
        importing_file: &str,
    ) -> Option<String> {
        let key = (source_module.to_string(), importing_file.to_string());
        {
            let c = cache.lock().unwrap();
            if let Some(cached) = c.get(&key) {
                return cached.clone();
            }
        }

        let importing_path = Path::new(importing_file);
        let importing_dir = match importing_path.parent() {
            Some(d) => d,
            None => {
                cache.lock().unwrap().insert(key, None);
                return None;
            }
        };

        // 标准化模块路径：去除 ./ 前缀，保留 ../ 前缀（由 Path::join 处理）
        let resolved = if let Some(stripped) = source_module.strip_prefix("./") {
            importing_dir.join(stripped)
        } else {
            importing_dir.join(source_module)
        };

        // 尝试的扩展名列表
        let extensions = [
            "js", "jsx", "ts", "tsx", "py", "rs", "go", "java", "c", "cpp", "php", "rb",
        ];

        let result = if resolved.exists() && resolved.is_file() {
            Some(resolved.to_string_lossy().to_string())
        } else {
            // 2. 尝试添加扩展名
            let mut found = None;
            for ext in &extensions {
                let with_ext = resolved.with_extension(ext);
                if with_ext.exists() {
                    found = Some(with_ext.to_string_lossy().to_string());
                    break;
                }
            }
            if found.is_none() {
                // 3. 尝试 index 文件（JS/TS 生态）
                for ext in &["js", "ts", "jsx", "tsx"] {
                    let index_file = resolved.join(format!("index.{}", ext));
                    if index_file.exists() {
                        found = Some(index_file.to_string_lossy().to_string());
                        break;
                    }
                }
            }
            if found.is_none() {
                // 4. 尝试 __init__.py（Python 包）
                let init_py = resolved.join("__init__.py");
                if init_py.exists() {
                    found = Some(init_py.to_string_lossy().to_string());
                }
            }
            found
        };

        cache.lock().unwrap().insert(key, result.clone());
        result
    }

    /// 将导入的模块路径解析为实际文件路径
    ///
    /// 支持相对路径（`./foo`, `../bar`），尝试常见扩展名和 index 文件。
    fn resolve_module_to_file(&self, source_module: &str, importing_file: &str) -> Option<String> {
        Self::resolve_module_to_file_with_cache(
            &self.module_resolution_cache,
            source_module,
            importing_file,
        )
    }

    /// 跨文件调用解析
    /// 过滤构造函数误标：外层 Function 包含 Method 节点时，将其从 source/sink 移除
    ///
    /// 背景：`SessionHandler(db)` 等构造函数 body 覆盖整个文件（包含所有 `this.method =`
    /// 定义），函数体文本匹配到 req.body/res.redirect 等 pattern 后会被误标为 source+sink，
    /// 产生大量 FP 跨文件流。实际 source/sink 是内层 Method 节点。
    fn filter_constructor_fps(&mut self) {
        // 收集所有节点按文件分组
        let mut file_nodes: HashMap<String, Vec<(String, usize, usize, bool, bool)>> =
            HashMap::new();
        for (id, node) in &self.call_graph.nodes {
            file_nodes
                .entry(normalize_path(&node.file_path))
                .or_default()
                .push((
                    id.clone(),
                    node.start_line,
                    node.end_line,
                    node.is_taint_source,
                    node.is_taint_sink,
                ));
        }

        let mut demote_sources: HashSet<String> = HashSet::new();
        let mut demote_sinks: HashSet<String> = HashSet::new();

        for (_file, nodes) in &file_nodes {
            for (outer_id, outer_start, outer_end, outer_is_source, outer_is_sink) in nodes {
                if !outer_is_source && !outer_is_sink {
                    continue;
                }
                // 检查是否存在严格嵌套且同样是 source/sink 的内层节点
                let has_inner_source_or_sink = nodes.iter().any(
                    |(inner_id, inner_start, inner_end, inner_is_source, inner_is_sink)| {
                        inner_id != outer_id
                            && *inner_start > *outer_start
                            && *inner_end < *outer_end
                            && (*inner_is_source || *inner_is_sink)
                    },
                );
                if has_inner_source_or_sink {
                    if *outer_is_source {
                        demote_sources.insert(outer_id.clone());
                    }
                    if *outer_is_sink {
                        demote_sinks.insert(outer_id.clone());
                    }
                }
            }
        }

        // 应用降级
        for id in &demote_sources {
            if let Some(node) = self.call_graph.nodes.get_mut(id) {
                node.is_taint_source = false;
            }
        }
        for id in &demote_sinks {
            if let Some(node) = self.call_graph.nodes.get_mut(id) {
                node.is_taint_sink = false;
                node.sink_type = None;
            }
        }
        self.call_graph
            .taint_sources
            .retain(|id| !demote_sources.contains(id));
        self.call_graph
            .taint_sinks
            .retain(|id| !demote_sinks.contains(id));

        let total = demote_sources.len() + demote_sinks.len();
        if total > 0 {
            tracing::info!(
                "[CrossFileTaint] 过滤构造函数误标: {} source + {} sink 降级",
                demote_sources.len(),
                demote_sinks.len()
            );
        }
    }

    ///
    /// 两阶段匹配：
    /// 1. **Import alias 精确匹配**：利用 import 语句将局部名称解析为
    ///    (目标文件, 原始导出名)，精确匹配跨文件调用。
    /// 2. **全局名称回退**：对无法通过 import 解析的裸名称，
    ///    退回到全局名称匹配。
    fn resolve_cross_file_calls(&mut self) {
        // 构建 name → Vec<func_id> 索引
        let mut name_to_ids: HashMap<String, Vec<String>> = HashMap::new();
        // 构建 file -> func_name -> [func_id] 二级索引（用于 import 精确匹配）
        let mut file_name_to_ids: HashMap<String, HashMap<String, Vec<String>>> = HashMap::new();

        for (id, node) in &self.call_graph.nodes {
            name_to_ids
                .entry(node.name.clone())
                .or_default()
                .push(id.clone());
            file_name_to_ids
                .entry(normalize_path(&node.file_path))
                .or_default()
                .entry(node.name.clone())
                .or_default()
                .push(id.clone());
        }

        // 只读引用，供并行闭包捕获
        let all_nodes = &self.call_graph.nodes;
        let file_import_aliases = &self.file_import_aliases;
        let variable_type_map = &self.variable_type_map;
        let type_hierarchy = &self.type_hierarchy;
        let module_resolution_cache = &self.module_resolution_cache;
        let name_to_ids_ref = &name_to_ids;
        let file_name_to_ids_ref = &file_name_to_ids;

        // 并行处理每个 caller，收集跨文件调用边
        let node_vec: Vec<(String, CallGraphNode)> = all_nodes
            .iter()
            .map(|(id, node)| (id.clone(), node.clone()))
            .collect();

        let cross_call_batches: Vec<Vec<(String, String)>> = node_vec
            .into_par_iter()
            .map(|(caller_id, node)| {
                let caller_file_normalized = normalize_path(&node.file_path);
                let import_aliases = file_import_aliases.get(&caller_file_normalized);
                let mut local_edges = Vec::new();

                for ct in &node.calls {
                    if ct.callee.contains(':') {
                        continue;
                    }

                    let mut resolved = false;

                    // ── Phase 1: Import alias 精确匹配 ──
                    if let Some(aliases) = import_aliases {
                        if let Some(resolution) = aliases.get(&ct.callee) {
                            if let Some(target_file) = Self::resolve_module_to_file_with_cache(
                                module_resolution_cache,
                                &resolution.source_module,
                                &node.file_path,
                            ) {
                                let target_normalized = normalize_path(&target_file);
                                if let Some(file_funcs) = file_name_to_ids_ref.get(&target_normalized) {
                                    let lookup_name = if resolution.is_default {
                                        &ct.callee
                                    } else {
                                        &resolution.original_export_name
                                    };

                                    if let Some(callee_ids) = file_funcs.get(lookup_name) {
                                        for callee_id in callee_ids {
                                            if callee_id != &caller_id {
                                                local_edges.push((caller_id.clone(), callee_id.clone()));
                                                resolved = true;
                                            }
                                        }
                                    }

                                    if !resolved && resolution.is_default {
                                        for (_, callee_ids) in file_funcs {
                                            for callee_id in callee_ids {
                                                if callee_id != &caller_id {
                                                    local_edges.push((caller_id.clone(), callee_id.clone()));
                                                    resolved = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // ── Phase 2: receiver 感知解析 ──
                    if !resolved {
                        let receiver_target_file: Option<String> =
                            ct.receiver.as_ref().and_then(|recv| {
                                if let Some(target) = import_aliases
                                    .and_then(|aliases| aliases.get(recv))
                                    .and_then(|res| {
                                        Self::resolve_module_to_file_with_cache(
                                            module_resolution_cache,
                                            &res.source_module,
                                            &node.file_path,
                                        )
                                    })
                                {
                                    return Some(target);
                                }
                                let var_types = variable_type_map.get(&caller_file_normalized)?;
                                let type_name = var_types.get(recv)?;
                                let aliases = import_aliases?;
                                let resolution = aliases.get(type_name)?;
                                Self::resolve_module_to_file_with_cache(
                                    module_resolution_cache,
                                    &resolution.source_module,
                                    &node.file_path,
                                )
                            });

                        if let Some(callee_ids) = name_to_ids_ref.get(&ct.callee) {
                            // 防止通用名（如 Juliet 的 bad/good/main）产生 O(n²) 调用边
                            if callee_ids.len() > GLOBAL_FALLBACK_MAX_MATCHES
                                || is_common_generic_name(&ct.callee)
                            {
                                continue;
                            }
                            for callee_id in callee_ids {
                                if callee_id == &caller_id {
                                    continue;
                                }
                                let callee_file = all_nodes
                                    .get(callee_id)
                                    .map(|n| normalize_path(&n.file_path))
                                    .unwrap_or_default();
                                if callee_file == caller_file_normalized {
                                    // 同文件内调用：直接建立边（caller/callee 已在同一文件）
                                    local_edges.push((caller_id.clone(), callee_id.clone()));
                                    resolved = true;
                                    continue;
                                }
                                if let Some(ref target_file) = receiver_target_file {
                                    let target_normalized = normalize_path(target_file);
                                    if callee_file == target_normalized {
                                        local_edges.push((caller_id.clone(), callee_id.clone()));
                                        resolved = true;
                                    }
                                } else {
                                    if is_builtin_call_target(ct) {
                                        continue;
                                    }
                                    local_edges.push((caller_id.clone(), callee_id.clone()));
                                }
                            }
                        }
                    }

                    // ── Phase 3: 类型层次虚方法分发 ──
                    if !resolved && ct.receiver.is_some() && !type_hierarchy.is_empty() {
                        let recv_name = ct.receiver.as_deref().unwrap_or("");
                        let resolved_methods =
                            type_hierarchy.resolve_virtual_method(recv_name, &ct.callee);

                        for rm in &resolved_methods {
                            if let Some(file_funcs) =
                                file_name_to_ids_ref.get(&normalize_path(&rm.file_path))
                            {
                                if let Some(callee_ids) = file_funcs.get(&ct.callee) {
                                    for callee_id in callee_ids {
                                        if callee_id != &caller_id {
                                            local_edges.push((caller_id.clone(), callee_id.clone()));
                                            resolved = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                local_edges
            })
            .collect();

        for batch in cross_call_batches {
            for (caller_id, callee_id) in batch {
                self.call_graph.add_call(&caller_id, &callee_id);
            }
        }
    }

    /// 收集源文件
    fn collect_source_files(&self, project_path: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        self.collect_files_recursive(project_path, &mut files);
        files
    }

    /// 预加载所有待分析文件的内容到内存，避免后续阶段反复读盘
    fn preload_file_contents(&mut self, file_paths: &[PathBuf]) {
        for path in file_paths {
            let path_str = path.to_string_lossy().to_string();
            if self.file_content_cache.contains_key(&path_str) {
                continue;
            }
            if let Ok(content) = std::fs::read_to_string(path) {
                let lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
                self.file_content_cache.insert(path_str.clone(), content);
                self.file_lines_cache.insert(path_str, lines);
            }
        }
    }

    fn get_file_content(&self, file_path: &str) -> Option<&str> {
        self.file_content_cache.get(file_path).map(|s| s.as_str())
    }

    fn get_file_lines(&self, file_path: &str) -> Option<&[String]> {
        self.file_lines_cache.get(file_path).map(|v| v.as_slice())
    }

    fn collect_files_recursive(&self, dir: &Path, files: &mut Vec<PathBuf>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if !name.starts_with('.')
                            && !matches!(
                                name,
                                "node_modules"
                                    | "target"
                                    | "vendor"
                                    | "__pycache__"
                                    | "dist"
                                    | "build"
                                    | ".git"
                            )
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
        if self.is_ast_supported(file_path) {
            self.build_call_graph_for_file_ast(file_path);
        } else {
            let file_path_str = file_path.to_string_lossy().to_string();
            let content = match self.file_content_cache.get(&file_path_str).cloned() {
                Some(c) => c,
                None => return,
            };
            let language = self.infer_language(file_path);
            let functions = self.extract_functions(&content, &file_path_str, language);
            for func in functions {
                self.call_graph.add_node(func);
            }
        }
    }

    /// 判断文件是否支持 AST 解析
    fn is_ast_supported(&self, path: &Path) -> bool {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        matches!(
            ext,
            "js" | "jsx"
                | "ts"
                | "tsx"
                | "py"
                | "java"
                | "rs"
                | "go"
                | "c"
                | "h"
                | "cpp"
                | "hpp"
                | "cc"
        )
    }

    /// 使用 AST 解析构建调用图（更精确的函数提取和调用关系）
    fn build_call_graph_for_file_ast(&mut self, file_path: &Path) {
        let file_path_str = file_path.to_string_lossy().to_string();
        let content = match self.file_content_cache.get(&file_path_str).cloned() {
            Some(c) => c,
            None => return,
        };

        // 解析文件导入（用于后续跨文件调用精确匹配）
        self.parse_file_imports(&file_path_str, &content);
        // 扫描框架中间件和路由注册
        super::middleware::scan_middleware(file_path, &content, &mut self.middleware_model);

        // 优先复用 Stage B 已解析的 AST 产物，避免二次 parse
        let (symbols, calls) = if let Some((cached_symbols, cached_calls)) =
            self.parsed_ast_cache.get(&file_path_str)
        {
            (cached_symbols.clone(), cached_calls.clone())
        } else {
            crate::ast::parser::with_thread_local_parser(|parser| {
                let (symbols_result, calls) = parser.parse_and_extract_calls(file_path, &content);
                match symbols_result {
                    Ok(symbols) => (symbols, calls),
                    Err(_) => (Vec::new(), calls),
                }
            })
        };

        if symbols.is_empty() {
            let language = self.infer_language(file_path);
            let functions = self.extract_functions(&content, &file_path_str, language);
            for func in functions {
                self.call_graph.add_node(func);
            }
            return;
        }

        // 从 symbols 中提取函数/方法定义
        for symbol in &symbols {
            if !matches!(
                symbol.kind,
                crate::ast::SymbolKind::Function | crate::ast::SymbolKind::Method
            ) {
                continue;
            }

            let func_name = symbol.name.clone();
            let func_id = format!("{}:{}", file_path_str, func_name);
            // 保存副本供回调注册使用（func_name 会被移动到 node 中）
            let func_name_clone = func_name.clone();

            // 收集该函数范围内的调用（保留 CallInfo 用于回调检测）
            let calls_in_range: Vec<&CallInfo> = calls
                .iter()
                .filter(|c| {
                    c.line >= symbol.start_line as usize && c.line <= symbol.end_line as usize
                })
                .collect();

            let calls_in_func: Vec<CallTarget> = calls_in_range
                .iter()
                .map(|c| CallTarget::from((*c).clone()))
                .collect();

            // 缓存每个调用点的参数，供摘要传播使用
            for c in &calls_in_range {
                let site_key = format!("{}:{}", func_id, c.line);
                self.call_site_args.insert(site_key, c.arguments.clone());
            }

            // 检测函数参数中哪些可能是污点
            let parameters: Vec<FunctionParameter> = self.extract_ast_parameters(symbol, &content);

            let body_text = Self::extract_body(
                &content,
                symbol.start_line as usize,
                symbol.end_line as usize,
            );
            let is_source = self.is_taint_source(&func_name, &body_text);

            // 优先按函数体内的具体调用判断 sink（能处理 Semantic 规则如 stmt.executeQuery）
            let (mut is_sink, mut sink_type) = (false, None);
            for call in &calls_in_range {
                if let Some(vt) = self.is_sink_call(call) {
                    is_sink = true;
                    sink_type = Some(vt);
                    break;
                }
            }
            if !is_sink {
                (is_sink, sink_type) = self.is_taint_sink(&func_name, &body_text);
            }

            let node = CallGraphNode {
                id: func_id.clone(),
                name: func_name,
                file_path: file_path_str.clone(),
                start_line: symbol.start_line as usize,
                end_line: symbol.end_line as usize,
                parameters,
                return_type: None,
                calls: calls_in_func,
                called_by: Vec::new(),
                is_external: false,
                is_taint_source: is_source,
                is_taint_sink: is_sink,
                sink_type,
                is_callback: false,
                parent_call_site: None,
            };

            self.call_graph.add_node(node);

            // 注册回调：对范围内的每个调用，检测内联回调函数并注册为合成节点
            let mut cb_idx: usize = 0;
            for call in &calls_in_range {
                for cb in &call.callback_args {
                    let cb_id = format!(
                        "{}:{}:{}:cb{}",
                        file_path_str, func_name_clone, call.line, cb_idx
                    );
                    let cb_calls = self.extract_calls_from_body(&cb.body_text);
                    let cb_params: Vec<FunctionParameter> = cb
                        .params
                        .iter()
                        .map(|p| FunctionParameter {
                            name: p.clone(),
                            param_type: None,
                            may_be_tainted: is_source,
                        })
                        .collect();

                    let (cb_is_sink, cb_sink_type) = self.is_taint_sink("", &cb.body_text);
                    let cb_node = CallGraphNode {
                        id: cb_id.clone(),
                        name: format!("<callback@{}>", call.line),
                        file_path: file_path_str.clone(),
                        start_line: cb.start_line,
                        end_line: cb.end_line,
                        parameters: cb_params,
                        return_type: None,
                        calls: cb_calls,
                        called_by: vec![func_id.clone()],
                        is_external: false,
                        is_taint_source: false,
                        is_taint_sink: cb_is_sink,
                        sink_type: cb_sink_type,
                        is_callback: true,
                        parent_call_site: Some(call.line),
                    };

                    self.call_graph.add_node(cb_node);
                    self.call_graph.add_call(&func_id, &cb_id);
                    cb_idx += 1;
                }
            }
        }

        // 构建类型层次结构：提取 Class/Interface/Struct 符号
        for symbol in &symbols {
            match symbol.kind {
                crate::ast::SymbolKind::Class => {
                    self.type_hierarchy.register_type(
                        &symbol.name,
                        super::type_hierarchy::TypeKind::Class,
                        &symbol.parent_classes,
                        &file_path_str,
                        symbol.start_line as usize,
                        symbol.end_line as usize,
                    );
                }
                crate::ast::SymbolKind::Interface => {
                    self.type_hierarchy.register_type(
                        &symbol.name,
                        super::type_hierarchy::TypeKind::Interface,
                        &symbol.parent_classes,
                        &file_path_str,
                        symbol.start_line as usize,
                        symbol.end_line as usize,
                    );
                }
                crate::ast::SymbolKind::Struct => {
                    self.type_hierarchy.register_type(
                        &symbol.name,
                        super::type_hierarchy::TypeKind::Struct,
                        &symbol.parent_classes,
                        &file_path_str,
                        symbol.start_line as usize,
                        symbol.end_line as usize,
                    );
                }
                crate::ast::SymbolKind::Method => {
                    if let Some(owner) = symbol.metadata.get("ownerClass").and_then(|v| v.as_str())
                    {
                        self.type_hierarchy.register_method(
                            owner,
                            super::type_hierarchy::MethodSignature {
                                name: symbol.name.clone(),
                                file_path: file_path_str.clone(),
                                start_line: symbol.start_line as usize,
                                is_static: false,
                            },
                        );
                    }
                }
                _ => {}
            }
        }

        // 检测动态 import/require
        self.detect_dynamic_imports(&content, &file_path_str);
    }

    /// 从 AST Symbol 中提取参数信息
    fn extract_ast_parameters(
        &self,
        symbol: &crate::ast::Symbol,
        content: &str,
    ) -> Vec<FunctionParameter> {
        let mut params = Vec::new();
        let func_name = &symbol.name;
        let body_text = Self::extract_body(
            content,
            symbol.start_line as usize,
            symbol.end_line as usize,
        );
        let is_source = self.is_taint_source(func_name, &body_text);

        // 尝试从 symbol 的 metadata 中提取参数
        if let Some(params_val) = symbol.metadata.get("params") {
            if let Some(arr) = params_val.as_array() {
                for p in arr {
                    let name = p.as_str().unwrap_or("").to_string();
                    if !name.is_empty() {
                        params.push(FunctionParameter {
                            name,
                            param_type: None,
                            may_be_tainted: is_source,
                        });
                    }
                }
            }
        }

        // fallback：使用通用参数名模式
        if params.is_empty() && is_source {
            params.push(FunctionParameter {
                name: "input".to_string(),
                param_type: None,
                may_be_tainted: true,
            });
        }

        params
    }

    /// 检测动态 import/require 模式，在调用图中标记不可解析的调用
    fn detect_dynamic_imports(&mut self, content: &str, file_path: &str) {
        let mut dynamic_imports = Vec::new();

        for (i, line) in content.lines().enumerate() {
            let trimmed = line.trim();

            // import(expr) — ES dynamic import
            if trimmed.contains("import(") {
                let inner = self.extract_balanced_parens(trimmed, "import(");
                if !inner.starts_with('"') && !inner.starts_with('\'') && !inner.starts_with('`') {
                    dynamic_imports.push((format!("dynamic_import_{}", i), i + 1));
                }
            }

            // require(var) / require(`template${}`) / require(a + b) — dynamic CommonJS
            if let Some(idx) = trimmed.find("require(") {
                let inner = self.extract_balanced_parens(&trimmed[idx..], "require(");
                if !inner.starts_with('"') && !inner.starts_with('\'') {
                    dynamic_imports.push((format!("dynamic_require_{}", i), i + 1));
                }
            }
        }

        // 为每个动态 import 创建特殊节点
        for (name, line) in dynamic_imports {
            let func_id = format!("{}:{}", file_path, name);
            self.call_graph.add_node(CallGraphNode {
                id: func_id.clone(),
                name,
                file_path: file_path.to_string(),
                start_line: line,
                end_line: line,
                parameters: Vec::new(),
                return_type: None,
                calls: vec![CallTarget::new("<dynamic>")],
                called_by: Vec::new(),
                is_external: false,
                is_taint_source: true,
                is_taint_sink: false,
                sink_type: None,
                is_callback: false,
                parent_call_site: None,
            });
        }
    }

    /// 从 "prefix(" 后提取括号内内容（不嵌套）
    fn extract_balanced_parens<'a>(&self, s: &'a str, prefix: &str) -> &'a str {
        if let Some(start) = s.find(prefix) {
            let after = &s[start + prefix.len()..];
            if let Some(end) = after.find(')') {
                return &after[..end].trim();
            }
        }
        ""
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

                // 检查是否是污点源或汇（fallback 路径：仅函数名兜底，函数体提取成本高且此路径少走）
                let is_source = self.is_taint_source(&func_name, "");
                let (is_sink, sink_type) = self.is_taint_sink(&func_name, "");

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
                    sink_type,
                    is_callback: false,
                    parent_call_site: None,
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
                if line.contains("(")
                    && (line.contains("public")
                        || line.contains("private")
                        || line.contains("protected"))
                {
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
                                let t = parts
                                    .get(1)
                                    .map(|s| s.split('=').next().unwrap_or("").trim().to_string());
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
                                    (
                                        parts[parts.len() - 1].to_string(),
                                        Some(parts[0].to_string()),
                                    )
                                } else {
                                    (param.to_string(), None)
                                }
                            }
                            "rust" => {
                                // name: Type
                                let parts: Vec<&str> = param.split(':').collect();
                                (
                                    parts[0].trim().to_string(),
                                    parts.get(1).map(|s| s.trim().to_string()),
                                )
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
    fn extract_function_calls(&self, lines: &[&str], _language: &str) -> Vec<CallTarget> {
        let mut calls = Vec::new();
        let mut seen = HashSet::new();

        const KEYWORDS: &[&str] = &[
            "if",
            "for",
            "while",
            "switch",
            "return",
            "print",
            "console",
            "self",
            "new",
            "typeof",
            "instanceof",
            "throw",
            "delete",
            "class",
            "import",
            "export",
            "from",
            "async",
            "await",
        ];

        for line in lines {
            let line = line.trim();
            if line.is_empty() || line.starts_with("//") || line.starts_with("#") {
                continue;
            }

            let chars: Vec<char> = line.chars().collect();
            let mut i = 0;

            while i < chars.len() {
                if chars[i] == '.'
                    && i + 1 < chars.len()
                    && (chars[i + 1].is_alphabetic() || chars[i + 1] == '_')
                {
                    // .method( 模式
                    i += 1;
                    let start = i;
                    while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                        i += 1;
                    }
                    if i < chars.len() && chars[i] == '(' {
                        let method_name: String = chars[start..i].iter().collect();
                        if !KEYWORDS.contains(&method_name.as_str()) {
                            if seen.insert(method_name.clone()) {
                                calls.push(CallTarget::new(method_name));
                            }
                        }
                    }
                } else if chars[i].is_alphabetic() || chars[i] == '_' {
                    // identifier( 模式
                    let start = i;
                    while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                        i += 1;
                    }
                    if i < chars.len() && chars[i] == '(' {
                        let func_name: String = chars[start..i].iter().collect();
                        if !KEYWORDS.contains(&func_name.as_str()) {
                            if seen.insert(func_name.clone()) {
                                calls.push(CallTarget::new(func_name));
                            }
                        }
                    }
                } else {
                    i += 1;
                }
            }
        }

        calls
    }

    /// 从纯文本函数体提取函数调用名（用于回调体分析）
    fn extract_calls_from_body(&self, body_text: &str) -> Vec<CallTarget> {
        let lines: Vec<&str> = body_text.lines().collect();
        self.extract_function_calls(&lines, "javascript")
    }

    /// 查找函数结束位置
    fn find_function_end(&self, lines: &[&str], start: usize, language: &str) -> usize {
        let base_indent = lines[start]
            .chars()
            .take_while(|c| c.is_whitespace())
            .count();
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
            "req",
            "request",
            "ctx",
            "context",
            "input",
            "data",
            "payload",
            "query",
            "params",
            "body",
            "form",
            "user_input",
            "user",
            "id",
            "name",
            "url",
            "path",
            "file",
            "filename",
            "command",
            "cmd",
            "sql",
            "html",
            "xml",
            "json",
            "token",
            "key",
            "password",
            "secret",
            "msg",
            "message",
            "content",
        ];
        TAINT_PARAM_NAMES
            .iter()
            .any(|p| lower == *p || lower.contains(p))
    }

    /// 按函数名判断是否是污点源（兜底：教学/测试代码的语义命名）
    fn is_source_by_name(&self, func_name: &str) -> bool {
        let lower = func_name.to_lowercase();
        let lower = lower.as_str();

        // 精确匹配（全词）
        const EXACT: &[&str] = &[
            "get", "read", "input", "fetch", "receive", "request", "parse", "load", "open", "recv",
            "accept",
        ];
        if EXACT.iter().any(|p| lower == *p) {
            return true;
        }

        // 前缀匹配（兼容 snake_case 和 camelCase）
        const PREFIX: &[&str] = &[
            "get_user",
            "get_input",
            "get_data",
            "get_param",
            "get_query",
            "getuser",
            "getinput",
            "getdata",
            "getparam",
            "getquery",
            "getrequest",
            "getpayload",
            "read_file",
            "read_input",
            "read_data",
            "readfile",
            "readinput",
            "readdata",
            "fetch_data",
            "fetch_url",
            "fetch_api",
            "fetchdata",
            "fetchurl",
            "fetchapi",
            "receive_data",
            "receive_input",
            "receive_message",
            "receivedata",
            "receiveinput",
            "receivemessage",
            "parse_input",
            "parse_data",
            "parse_request",
            "parse_body",
            "parseinput",
            "parsedata",
            "parserequest",
            "parsebody",
            "load_data",
            "load_file",
            "load_input",
            "loaddata",
            "loadfile",
            "loadinput",
            "request_input",
            "request_data",
            "requestinput",
            "requestdata",
        ];
        if PREFIX.iter().any(|p| lower.starts_with(p)) {
            return true;
        }

        // 后缀匹配
        const SUFFIX: &[&str] = &[
            "_input", "_data", "_request", "_payload", "_query", "_params", "_body", "_form",
            "_message", "input", "data", "request", "payload", "query",
        ];
        if SUFFIX
            .iter()
            .any(|p| lower.ends_with(p) && lower.len() > p.len())
        {
            return true;
        }

        self.source_patterns
            .iter()
            .any(|s| s.matches(func_name, "*"))
    }

    /// 检查是否是污点源：函数名兜底 + 函数体内容匹配（核心修复）
    ///
    /// 真实项目用业务命名（handleLoginRequest/displayResearch），函数名不含
    /// get_/input 等关键词，但函数体里会出现 req.body 等真实 source。
    /// 因此对函数体内容做 pattern 匹配，by-name 仅作兜底。
    fn is_taint_source(&self, func_name: &str, body: &str) -> bool {
        if self.is_source_by_name(func_name) {
            return true;
        }
        self.source_patterns.iter().any(|s| s.matches(body, "*"))
    }

    /// 按函数名判断是否是污点汇（兜底）
    fn is_sink_by_name(&self, func_name: &str) -> bool {
        let lower = func_name.to_lowercase();
        let lower = lower.as_str();

        // 精确匹配（全词）
        const EXACT: &[&str] = &[
            "execute", "exec", "query", "write", "send", "eval", "system", "run", "open",
            "redirect",
        ];
        if EXACT.iter().any(|p| lower == *p) {
            return true;
        }

        // 前缀匹配（兼容 snake_case 和 camelCase）
        const PREFIX: &[&str] = &[
            "execute_",
            "exec_",
            "query_",
            "send_",
            "write_",
            "eval_",
            "system_",
            "run_command",
            "run_query",
            "redirect_to",
            "redirect_url",
            "executecommand",
            "runcommand",
            "runquery",
            "redirectto",
            "redirecturl",
        ];
        if PREFIX.iter().any(|p| lower.starts_with(p)) {
            return true;
        }

        // 后缀匹配
        const SUFFIX: &[&str] = &[
            "_execute", "_exec", "_query", "_write", "_send", "_eval", "_system", "_command",
            "_sql", "_shell",
        ];
        if SUFFIX.iter().any(|p| lower.ends_with(p)) {
            return true;
        }

        self.sink_patterns.iter().any(|s| s.matches(func_name, "*"))
    }

    /// 检查是否是污点汇：函数名兜底 + 函数体内容匹配（核心修复）
    /// 返回 (is_sink, matched_vulnerability_type)
    fn is_taint_sink(&self, func_name: &str, body: &str) -> (bool, Option<VulnerabilityType>) {
        // 优先按函数体内容匹配（可确定漏洞类型）
        for s in self.sink_patterns.iter() {
            if s.matches(body, "*") && !Self::is_body_sanitized_for_sink(body, s) {
                return (true, Some(s.vulnerability_type));
            }
        }
        // 按函数名兜底（无法确定具体类型）
        if self.is_sink_by_name(func_name) {
            return (true, None);
        }
        (false, None)
    }

    /// 通用 sink 净化检测：若规则声明了 sanitizers，且函数体中在 sink 出现之前
    /// 存在任一 sanitizer 模式，则判定该 sink 已被净化。
    fn is_body_sanitized_for_sink(body: &str, sink: &TaintSink) -> bool {
        if sink.sanitizers.is_empty() {
            return false;
        }

        let lines: Vec<&str> = body.lines().collect();

        // 收集 sink 模式首次出现的行号
        let mut first_sink_line: Option<usize> = None;
        for (idx, line) in lines.iter().enumerate() {
            let lower = line.to_lowercase();
            for pat in &sink.patterns {
                if lower.contains(&pat.to_lowercase()) {
                    first_sink_line = Some(idx);
                    break;
                }
            }
            if first_sink_line.is_some() {
                break;
            }
        }
        let Some(sink_line) = first_sink_line else {
            return false;
        };

        // 检查是否有 sanitizer 出现在 sink 之前（同一行也视为已净化）
        for (idx, line) in lines.iter().enumerate().take(sink_line + 1) {
            let lower = line.to_lowercase();
            for san in &sink.sanitizers {
                if lower.contains(&san.to_lowercase()) {
                    return true;
                }
            }
        }

        false
    }

    /// 判断单个函数调用是否命中某个 sink 规则（支持 Semantic 规则）
    fn is_sink_call(&self, call: &CallInfo) -> Option<VulnerabilityType> {
        for s in self.sink_patterns.iter() {
            // 先按 callee + receiver 做语义匹配
            if s.matches_with_context(&call.callee, call.receiver.as_deref(), "*") {
                return Some(s.vulnerability_type);
            }
            // 再按完整调用表达式做子串/语义匹配（如 stmt.executeQuery）
            if let Some(receiver) = &call.receiver {
                let qualified = format!("{}.{}", receiver, call.callee);
                if s.matches_with_context(&qualified, Some(receiver), "*") {
                    return Some(s.vulnerability_type);
                }
            }
        }
        None
    }

    /// 计算当前调用图中所有函数的摘要（不复建调用图）
    fn compute_function_summaries_from_current_graph(&self) -> HashMap<String, FunctionSummary> {
        let sorted = self.topological_sort();
        let mut summaries = HashMap::new();
        for func_id in sorted {
            if let Some(summary) = self.compute_single_summary(&func_id) {
                summaries.insert(func_id, summary);
            }
        }
        summaries
    }

    /// 获取函数入口处的初始污点变量集合
    ///
    /// 优先从 CPG taint flows 的 source.symbol 提取；若无 CPG，对 source 函数做简单行扫描兜底。
    fn initial_tainted_variables(&self, func_id: &str) -> HashSet<String> {
        let mut vars = HashSet::new();

        // 1. 优先使用 Stage B 传来的精确污点流
        if let Some(flows) = self.cpg_taint_flows.get(func_id) {
            for flow in flows {
                vars.insert(flow.source.symbol.clone());
            }
        }

        // 2. CPG 缺失时，对 source 函数做简单文本兜底
        if vars.is_empty() {
            if let Some(node) = self.call_graph.nodes.get(func_id) {
                if node.is_taint_source {
                    if let Some(lines) = self.get_file_lines(&node.file_path) {
                        let body = Self::extract_body_from_lines(lines, node.start_line, node.end_line);
                        for line in body.iter() {
                            for source in self.source_patterns.iter() {
                                if source.matches(line, "*") {
                                    if let Some(var) = Self::extract_var_from_source_line(line) {
                                        vars.insert(var);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        vars
    }

    /// 从一行 source 赋值中提取左值变量名
    fn extract_var_from_source_line(line: &str) -> Option<String> {
        let line = line.trim();
        let left = if let Some(pos) = line.find(":=") {
            line[..pos].trim()
        } else if let Some(pos) = line.find('=') {
            line[..pos].trim()
        } else {
            return None;
        };

        let left = left
            .strip_prefix("let ")
            .or_else(|| left.strip_prefix("var "))
            .or_else(|| left.strip_prefix("const "))
            .or_else(|| left.strip_prefix("auto "))
            .or_else(|| left.strip_prefix("mut "))
            .or_else(|| left.strip_prefix("final "))
            .unwrap_or(left);

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
            Some(var_name)
        } else {
            None
        }
    }

    /// 基于函数摘要的参数级跨文件污点传播
    ///
    /// 相比原 find_interprocedural_taint_flows 的纯调用图 BFS，这里会：
    /// - 跟踪每个函数内哪些变量被污染
    /// - 在调用点根据实参→形参映射传播污染
    /// - 仅当 callee 摘要显示污染参数能到达 sink 时才生成 flow
    fn propagate_taint_with_summaries(&self) -> Vec<InterproceduralTaintFlow> {
        let summaries = self.compute_function_summaries_from_current_graph();
        let sink_set: HashSet<&String> = self.call_graph.taint_sinks.iter().collect();
        let sink_reachable = self.compute_sink_reachable_set();
        let mut flows = Vec::new();

        for source_id in &self.call_graph.taint_sources {
            // source 到不了任何 sink，跳过整个 source
            if !sink_reachable.contains(source_id) {
                continue;
            }

            let initial_vars = self.initial_tainted_variables(source_id);
            if initial_vars.is_empty() {
                continue;
            }

            // visited[func_id] = 该函数已出现过的污点变量集合
            let mut visited: HashMap<String, HashSet<String>> = HashMap::new();
            let mut queue: VecDeque<(String, HashSet<String>, Vec<String>)> = VecDeque::new();

            visited
                .entry(source_id.clone())
                .or_default()
                .extend(initial_vars.iter().cloned());
            queue.push_back((
                source_id.clone(),
                initial_vars.clone(),
                vec![source_id.clone()],
            ));

            while let Some((current_id, mut current_tainted, path)) = queue.pop_front() {
                // 当前函数本身是 sink，且内部污点能命中 sink（已有 CPG 单文件结果兜底）
                if sink_set.contains(&current_id) && current_id != *source_id {
                    if let (Some(source_node), Some(sink_node)) = (
                        self.call_graph.nodes.get(source_id),
                        self.call_graph.nodes.get(&current_id),
                    ) {
                        let vuln_type = sink_node.sink_type.unwrap_or(VulnerabilityType::Generic);
                        flows.push(self.build_interprocedural_flow(
                            source_node,
                            sink_node,
                            &path,
                            vuln_type,
                            "summary_direct_sink",
                        ));
                    }
                }

                let Some(node) = self.call_graph.nodes.get(&current_id) else {
                    continue;
                };

                // 预读当前函数源码，用于返回值污点 LHS 提取
                let current_lines: Vec<String> = self
                    .get_file_lines(&node.file_path)
                    .map(|lines| lines.to_vec())
                    .unwrap_or_default();

                for ct in &node.calls {
                    let callee_id = &ct.callee;
                    if callee_id == &current_id {
                        continue;
                    }
                    let Some(callee_node) = self.call_graph.nodes.get(callee_id) else {
                        continue;
                    };

                    // 通过调用点参数映射，判断 caller 的哪些污点变量传入 callee 的哪些形参
                    let site_key = format!("{}:{}", current_id, ct.line);
                    let mut callee_tainted: HashSet<String> = HashSet::new();
                    if let Some(args) = self.call_site_args.get(&site_key) {
                        for (param_idx, arg) in args.iter().enumerate() {
                            if param_idx >= callee_node.parameters.len() {
                                break;
                            }
                            if arg
                                .referenced_vars
                                .iter()
                                .any(|v| current_tainted.contains(v))
                            {
                                callee_tainted
                                    .insert(callee_node.parameters[param_idx].name.clone());
                            }
                        }
                    }

                    // 利用函数摘要的 param_to_calls 补充重命名/字段访问等数据流
                    if let Some(current_summary) = summaries.get(&current_id) {
                        let tainted_param_indices: Vec<(usize, &str)> = node
                            .parameters
                            .iter()
                            .enumerate()
                            .filter(|(_, p)| current_tainted.contains(&p.name))
                            .map(|(i, p)| (i, p.name.as_str()))
                            .collect();
                        for (param_idx, _) in tainted_param_indices {
                            for ptc in current_summary.param_to_calls.iter().filter(|ptc| {
                                ptc.param_idx == param_idx
                                    && ptc.callee == ct.callee
                                    && ptc.call_line == ct.line
                            }) {
                                if ptc.arg_idx < callee_node.parameters.len() {
                                    callee_tainted
                                        .insert(callee_node.parameters[ptc.arg_idx].name.clone());
                                }
                            }
                        }
                    }

                    if callee_tainted.is_empty() {
                        continue;
                    }

                    // 查询 callee 摘要：污染参数是否到达 sink
                    if let Some(summary) = summaries.get(callee_id) {
                        for ds in &summary.direct_sinks {
                            if ds.sanitized {
                                continue;
                            }
                            if ds.from_param < callee_node.parameters.len()
                                && callee_tainted
                                    .contains(&callee_node.parameters[ds.from_param].name)
                            {
                                if let Some(source_node) = self.call_graph.nodes.get(source_id) {
                                    let mut sink_path = path.clone();
                                    sink_path.push(callee_id.clone());
                                    flows.push(self.build_interprocedural_flow(
                                        source_node,
                                        callee_node,
                                        &sink_path,
                                        ds.vuln_type.clone(),
                                        "summary_param_to_sink",
                                    ));
                                }
                            }
                        }

                        // 若污染参数影响返回值，尝试把赋值 LHS 变量也标记为污点
                        for (param_idx, affects_return) in &summary.taint_propagation {
                            if *affects_return
                                && *param_idx < callee_node.parameters.len()
                                && callee_tainted.contains(&callee_node.parameters[*param_idx].name)
                            {
                                if let Some(lhs) = Self::extract_call_assignment_lhs(
                                    &current_lines,
                                    ct.line,
                                    &ct.callee,
                                ) {
                                    current_tainted.insert(lhs);
                                }
                            }
                        }
                    }

                    // 继续进入 callee 内部传播（参数级 forward）
                    // 只扩展能到达 sink 的 callee，避免死路传播
                    if !sink_reachable.contains(callee_id) {
                        continue;
                    }
                    let prev = visited.entry(callee_id.clone()).or_default();
                    let new_vars: HashSet<String> =
                        callee_tainted.difference(prev).cloned().collect();
                    if !new_vars.is_empty() {
                        prev.extend(new_vars.iter().cloned());
                        let mut new_path = path.clone();
                        new_path.push(callee_id.clone());
                        let mut next_tainted = callee_tainted;
                        // 保留在 callee 内可能继续使用的原始污点别名（形参名）
                        next_tainted
                            .retain(|v| callee_node.parameters.iter().any(|p| p.name == *v));
                        if !next_tainted.is_empty() {
                            queue.push_back((callee_id.clone(), next_tainted, new_path));
                        }
                    }
                }
            }
        }

        flows
    }

    /// 构造一个 InterproceduralTaintFlow
    fn build_interprocedural_flow(
        &self,
        source: &CallGraphNode,
        sink: &CallGraphNode,
        path: &[String],
        vuln_type: VulnerabilityType,
        factor: &str,
    ) -> InterproceduralTaintFlow {
        let mut interprocedural_path = Vec::new();
        for func_id in path {
            if let Some(func) = self.call_graph.nodes.get(func_id) {
                interprocedural_path.push(InterproceduralStep {
                    step_type: if func_id == &source.id {
                        InterproceduralStepType::Source
                    } else if func_id == &sink.id {
                        InterproceduralStepType::Sink
                    } else {
                        InterproceduralStepType::ParameterIn
                    },
                    file_path: func.file_path.clone(),
                    function_name: func.name.clone(),
                    line: func.start_line,
                    variable: String::new(),
                    code: None,
                });
            }
        }

        let (confidence, mut confidence_factors) = self.calculate_flow_confidence(path);
        confidence_factors.push(format!("summary:{}", factor));

        InterproceduralTaintFlow {
            id: uuid::Uuid::new_v4().to_string(),
            source: FlowLocation {
                file_path: source.file_path.clone(),
                line: source.start_line,
                column: None,
                symbol: source.name.clone(),
                node_id: Some(source.id.clone()),
                code_snippet: None,
            },
            sink: FlowLocation {
                file_path: sink.file_path.clone(),
                line: sink.start_line,
                column: None,
                symbol: sink.name.clone(),
                node_id: Some(sink.id.clone()),
                code_snippet: None,
            },
            interprocedural_path,
            vulnerability_type: vuln_type,
            severity: Severity::High,
            confidence,
            confidence_factors,
        }
    }

    /// 从文件内容按行范围提取函数体文本
    fn extract_body(content: &str, start_line: usize, end_line: usize) -> String {
        content
            .lines()
            .enumerate()
            .filter(|(i, _)| (*i + 1) >= start_line && (*i + 1) <= end_line)
            .map(|(_, l)| l)
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn extract_body_from_lines(
        lines: &[String],
        start_line: usize,
        end_line: usize,
    ) -> Vec<String> {
        lines
            .iter()
            .enumerate()
            .filter(|(i, _)| (*i + 1) >= start_line && (*i + 1) <= end_line)
            .map(|(_, l)| l.clone())
            .collect()
    }

    /// 从函数调用所在行提取赋值左值变量名。
    /// 用于返回值污点传播：若 `x = callee(...)` 且 callee 的返回值被污染，则 x 也被污染。
    fn extract_call_assignment_lhs(
        lines: &[String],
        call_line: usize,
        callee: &str,
    ) -> Option<String> {
        let idx = call_line.saturating_sub(1);
        let line = lines.get(idx)?;

        // 要求行内包含 callee(
        if !line.contains(&format!("{}(", callee)) {
            return None;
        }

        // 简单赋值：LHS = ...callee(...
        let eq_pos = line.find('=')?;
        let rhs = &line[eq_pos + 1..];
        if !rhs.contains(&format!("{}(", callee)) {
            return None;
        }

        let lhs = line[..eq_pos].trim();
        // 去除类型声明、final、var/let/const 等前缀，取最后一个标识符
        let var_name = lhs
            .split_whitespace()
            .last()
            .unwrap_or(lhs)
            .trim_start_matches('*')
            .trim_start_matches('&')
            .split(':')
            .next()
            .unwrap_or(lhs)
            .split('.')
            .next()
            .unwrap_or(lhs)
            .split('[')
            .next()
            .unwrap_or(lhs)
            .trim()
            .to_string();

        if !var_name.is_empty()
            && var_name
                .chars()
                .next()
                .map(|c| c.is_alphabetic() || c == '_')
                .unwrap_or(false)
        {
            Some(var_name)
        } else {
            None
        }
    }

    /// 查找过程间污点流
    ///
    /// 优先使用基于函数摘要的参数级传播；若摘要传播未产生结果，
    /// 回退到纯调用图 BFS。
    fn find_interprocedural_taint_flows(&self) -> Vec<InterproceduralTaintFlow> {
        let summary_flows = self.propagate_taint_with_summaries();
        if !summary_flows.is_empty() {
            return summary_flows;
        }
        self.find_interprocedural_taint_flows_fallback()
    }

    /// 预计算：从所有 sink 反向 BFS，得到“可能到达 sink”的节点集合。
    fn compute_sink_reachable_set(&self) -> HashSet<String> {
        let mut reachable: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<String> = VecDeque::new();
        for sink_id in &self.call_graph.taint_sinks {
            if reachable.insert(sink_id.clone()) {
                queue.push_back(sink_id.clone());
            }
        }
        while let Some(node_id) = queue.pop_front() {
            if let Some(node) = self.call_graph.nodes.get(&node_id) {
                for caller_id in &node.called_by {
                    if reachable.insert(caller_id.clone()) {
                        queue.push_back(caller_id.clone());
                    }
                }
            }
        }
        reachable
    }

    /// 纯调用图 BFS 兜底：从 source 函数出发，沿调用图找到所有可达 sink 函数
    fn find_interprocedural_taint_flows_fallback(&self) -> Vec<InterproceduralTaintFlow> {
        let sink_set: HashSet<&String> = self.call_graph.taint_sinks.iter().collect();
        let mut flows = Vec::new();

        // 预计算 sink 可达集，正向搜索只扩展这些节点。
        let sink_reachable = self.compute_sink_reachable_set();

        // 对每个 source 做 BFS，一次遍历找到所有可达的 sink
        for source_id in &self.call_graph.taint_sources {
            // source 本身就到不了任何 sink，跳过
            if !sink_reachable.contains(source_id) {
                continue;
            }

            // BFS: source_id → (path_from_source)
            let mut visited: HashSet<&String> = HashSet::new();
            // queue: (current_node, path_from_source)
            let mut queue: VecDeque<(String, Vec<String>)> = VecDeque::new();
            queue.push_back((source_id.clone(), vec![source_id.clone()]));
            visited.insert(source_id);

            while let Some((current_id, path)) = queue.pop_front() {
                // 检查当前节点是否是 sink
                if sink_set.contains(&current_id) && current_id != *source_id {
                    if let (Some(source), Some(sink)) = (
                        self.call_graph.nodes.get(source_id),
                        self.call_graph.nodes.get(&current_id),
                    ) {
                        let mut interprocedural_path = Vec::new();
                        for func_id in &path {
                            if let Some(func) = self.call_graph.nodes.get(func_id) {
                                interprocedural_path.push(InterproceduralStep {
                                    step_type: if func_id == source_id {
                                        InterproceduralStepType::Source
                                    } else if func_id == &current_id {
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

                        let (confidence, confidence_factors) =
                            self.calculate_flow_confidence(&path);

                        // 使用 sink 节点匹配到的漏洞类型（从 taint rule pattern 提取）
                        // 如果 sink 没有匹配到具体类型（name-based fallback），回退为 Generic
                        let vuln_type = sink.sink_type.unwrap_or(VulnerabilityType::Generic);

                        flows.push(InterproceduralTaintFlow {
                            id: uuid::Uuid::new_v4().to_string(),
                            source: FlowLocation {
                                file_path: source.file_path.clone(),
                                line: source.start_line,
                                column: None,
                                symbol: source.name.clone(),
                                node_id: None,
                                code_snippet: None,
                            },
                            sink: FlowLocation {
                                file_path: sink.file_path.clone(),
                                line: sink.start_line,
                                column: None,
                                symbol: sink.name.clone(),
                                node_id: None,
                                code_snippet: None,
                            },
                            interprocedural_path,
                            vulnerability_type: vuln_type,
                            severity: Severity::High,
                            confidence,
                            confidence_factors,
                        });
                    }
                    // 继续探索（sink 可能转发到另一个 sink）
                }

                // 扩展邻居（只扩展可能到达 sink 的节点）
                if let Some(node) = self.call_graph.nodes.get(&current_id) {
                    for ct in &node.calls {
                        if sink_reachable.contains(&ct.callee) && !visited.contains(&ct.callee) {
                            visited.insert(&ct.callee);
                            let mut new_path = path.clone();
                            new_path.push(ct.callee.clone());
                            queue.push_back((ct.callee.clone(), new_path));
                        }
                    }
                }
            }
        }

        flows
    }

    /// 基于传播路径特征计算置信度
    fn calculate_flow_confidence(&self, call_path: &[String]) -> (f32, Vec<String>) {
        let mut confidence: f32 = 0.8;
        let mut factors = Vec::new();

        // 中间节点衰减
        let hops = call_path.len().saturating_sub(2);
        if hops > 0 {
            let decay = 0.85_f32.powi(hops as i32);
            confidence *= decay;
            factors.push(format!("intermediate_hops:{}", hops));
        }

        // 跨文件衰减
        let files: HashSet<&str> = call_path
            .iter()
            .filter_map(|id| id.split(':').next())
            .collect();
        if files.len() > 1 {
            confidence *= 0.9;
            if files.len() > 2 {
                confidence *= 0.95;
            }
            factors.push(format!("cross_file:{}", files.len()));
        }

        // 动态节点衰减
        let has_dynamic = call_path.iter().any(|func_id| {
            self.call_graph
                .nodes
                .get(func_id)
                .map(|n| n.calls.iter().any(|c| c.callee == "<dynamic>"))
                .unwrap_or(false)
        });
        if has_dynamic {
            confidence *= 0.5;
            factors.push("dynamic_import".to_string());
        }

        (confidence.clamp(0.1, 1.0), factors)
    }

    /// 默认污点源模式（按代码内容匹配，用于 is_taint_source 的函数体匹配）
    fn default_source_patterns() -> Vec<TaintSource> {
        vec![
            TaintSource::new(
                "http_request_body",
                "HTTP Request",
                vec![
                    "req.body",
                    "req.query",
                    "req.params",
                    "req.headers",
                    "req.cookies",
                    "request.body",
                    "request.query",
                    "request.params",
                    "req.get(",
                    "req.param(",
                    "req.header(",
                ],
            ),
            TaintSource::new(
                "process_input",
                "Process Input",
                vec![
                    "process.argv",
                    "process.env",
                    "process.stdin",
                    "os.environ",
                    "sys.argv",
                ],
            ),
            TaintSource::new(
                "file_input",
                "File Input",
                vec![
                    "fs.readFile",
                    "readFileSync",
                    "createReadStream",
                    "fread",
                    "fopen",
                ],
            ),
            // 泛化兜底：匹配按安全语义命名的教学/测试代码（仅供 by-name 兜底使用）
            TaintSource::new(
                "user_input_named",
                "User Input (named)",
                vec![
                    "getuserinput",
                    "get_input",
                    "get_user",
                    "read_input",
                    "scanf",
                    "prompt",
                ],
            ),
            // Java / Spring HTTP 输入
            TaintSource::new(
                "java_http_input",
                "Java HTTP Input",
                vec![
                    "@RequestParam",
                    "@PathVariable",
                    "@RequestBody",
                    "@RequestHeader",
                    "@CookieValue",
                    "@ModelAttribute",
                    "HttpServletRequest",
                    "ServletRequest",
                    "getParameter(",
                    "getParameterValues(",
                    "getHeader(",
                    "getHeaders(",
                    "getQueryString(",
                    "getInputStream(",
                    "getReader(",
                    "getCookies(",
                ],
            ),
        ]
    }

    /// 默认污点汇模式（按代码内容匹配）
    fn default_sink_patterns() -> Vec<TaintSink> {
        vec![
            TaintSink::new(
                "code_injection",
                "Code Injection",
                vec!["eval(", "new Function(", "vm.runIn", "vm.Script"],
                VulnerabilityType::CodeInjection,
            ),
            TaintSink::new(
                "command_injection",
                "Command Injection",
                vec![
                    "exec(",
                    "execSync(",
                    "spawn(",
                    "child_process",
                    "system(",
                    "popen(",
                    "Runtime.getRuntime().exec",
                    "Runtime.exec",
                    "ProcessBuilder",
                    "ProcessBuilder.command",
                ],
                VulnerabilityType::CommandInjection,
            ),
            TaintSink::new(
                "sql_injection",
                "SQL Injection",
                vec![
                    ".query(",
                    ".execute(",
                    "executeQuery",
                    "Statement.execute",
                    "PreparedStatement.execute",
                    "jdbcTemplate.query",
                    "jdbcTemplate.execute",
                    "createStatement().execute",
                ],
                VulnerabilityType::SqlInjection,
            ),
            TaintSink::new(
                "nosql_injection",
                "NoSQL Injection",
                vec![
                    ".findOne(",
                    ".find(",
                    "collection.find",
                    "db.collection",
                    "$where",
                ],
                VulnerabilityType::NoSqlInjection,
            ),
            TaintSink::new(
                "ssrf",
                "SSRF",
                vec![
                    "http.request",
                    "https.request",
                    "fetch(",
                    "axios",
                    "needle.get",
                ],
                VulnerabilityType::ServerSideRequestForgery,
            ),
            TaintSink::new(
                "xss",
                "XSS",
                vec!["res.write(", "res.send(", "innerHTML", "response.write("],
                VulnerabilityType::CrossSiteScripting,
            ),
            TaintSink::new(
                "path_traversal",
                "Path Traversal",
                vec!["writeFile", "writeFileSync", "createWriteStream", "fs.open"],
                VulnerabilityType::PathTraversal,
            ),
            TaintSink::new(
                "open_redirect",
                "Open Redirect",
                vec!["redirect(", "res.redirect"],
                VulnerabilityType::OpenRedirect,
            ),
            TaintSink::new(
                "java_deserialization",
                "Java Deserialization",
                vec![
                    "ObjectInputStream",
                    "ObjectInputStream.readObject",
                    "readObject(",
                    "defaultReadObject",
                    "ObjectMapper.readValue",
                    "objectMapper.readValue",
                ],
                VulnerabilityType::InsecureDeserialization,
            ),
        ]
    }

    /// 注入中间件虚拟边：将 Express app.use() 中间件连接到同文件的路由 handler
    fn inject_middleware_edges(&mut self) {
        for mw in &self.middleware_model.express_middleware.clone() {
            let mw_func_id = self
                .call_graph
                .nodes
                .iter()
                .find(|(_, node)| {
                    node.name == mw.handler_name
                        && normalize_path(&node.file_path) == normalize_path(&mw.handler_file)
                })
                .map(|(id, _)| id.clone());

            let mw_id = match mw_func_id {
                Some(id) => id,
                None => {
                    let normalized_file = normalize_path(&mw.handler_file);
                    if let Some(aliases) = self.file_import_aliases.get(&normalized_file) {
                        if let Some(resolution) = aliases.get(&mw.handler_name) {
                            if let Some(target_file) = self
                                .resolve_module_to_file(&resolution.source_module, &mw.handler_file)
                            {
                                let target_norm = normalize_path(&target_file);
                                if let Some(id) = self
                                    .call_graph
                                    .nodes
                                    .iter()
                                    .find(|(_, n)| {
                                        n.name == resolution.original_export_name
                                            && normalize_path(&n.file_path) == target_norm
                                    })
                                    .map(|(id, _)| id.clone())
                                {
                                    id
                                } else {
                                    continue;
                                }
                            } else {
                                continue;
                            }
                        } else {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }
            };

            let route_lines = self
                .middleware_model
                .get_express_route_lines(&mw.handler_file);
            for &line in route_lines {
                for (route_id, route_node) in &self.call_graph.nodes.clone() {
                    if normalize_path(&route_node.file_path) == normalize_path(&mw.handler_file)
                        && !route_node.is_callback
                        && (route_node.start_line <= line && route_node.end_line >= line)
                    {
                        self.call_graph.add_call(&mw_id, route_id);
                    }
                }
            }
        }
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
        // 1. 收集并预加载源文件内容
        let source_files = self.collect_source_files(project_path);
        self.preload_file_contents(&source_files);

        // 2. 构建调用图
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

        let mut queue: VecDeque<&String> = in_degree
            .iter()
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

    /// 计算单个函数的摘要（优先使用 CPG 精确摘要）
    fn compute_single_summary(&self, func_id: &str) -> Option<FunctionSummary> {
        // 优先使用 CPG 摘要
        if let Some(func_cpg) = self.cpg_cache.get(func_id) {
            let taint_flows = self
                .cpg_taint_flows
                .get(func_id)
                .cloned()
                .unwrap_or_default();

            let body_text = if let Some(content) =
                self.get_file_content(&func_cpg.signature.file_path)
            {
                Self::extract_body(
                    content,
                    func_cpg.signature.start_line,
                    func_cpg.signature.end_line,
                )
            } else {
                String::new()
            };

            let summary = super::cpg::compute_summary_from_cpg(
                func_cpg,
                &taint_flows,
                &body_text,
                &self.sink_patterns,
            );
            if !summary.taint_propagation.is_empty() || !summary.direct_sinks.is_empty() {
                return Some(summary);
            }
        }

        // 回退到 heuristic
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
                for ct in &node.calls {
                    if self.is_sink_by_name(&ct.callee) {
                        direct_sinks.push(SinkReachability {
                            sink_name: ct.callee.clone(),
                            from_param: param_idx,
                            sanitized: false,
                            sanitizer: None,
                            sink_line: 0, // 精确行号需要更深层分析
                            vuln_type: self.infer_vuln_type(&ct.callee),
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

        // 对明确标记为 sink 的函数，保守认为每个参数都可能到达其内部 sink 调用。
        // 这是单文件 bad() -> badSink() 模式的关键兜底：badSink 不是污点源，但接受
        // 来自 bad() 的污染参数后将其传入 println/exec 等 sink。
        if node.is_taint_sink {
            for ct in &node.calls {
                if self.is_sink_by_name(&ct.callee) {
                    for (param_idx, _param) in node.parameters.iter().enumerate() {
                        // 避免重复记录同一 param + sink
                        let already = direct_sinks.iter().any(|ds: &SinkReachability| {
                            ds.from_param == param_idx && ds.sink_name == ct.callee
                        });
                        if !already {
                            direct_sinks.push(SinkReachability {
                                sink_name: ct.callee.clone(),
                                from_param: param_idx,
                                sanitized: false,
                                sanitizer: None,
                                sink_line: ct.line,
                                vuln_type: self.infer_vuln_type(&ct.callee),
                            });
                        }
                    }
                }
            }
        }

        // 启发式 param_to_calls：参数名直接出现在调用实参中
        let mut param_to_calls = Vec::new();
        for (param_idx, param) in node.parameters.iter().enumerate() {
            for ct in &node.calls {
                let site_key = format!("{}:{}", func_id, ct.line);
                if let Some(args) = self.call_site_args.get(&site_key) {
                    for (arg_idx, arg) in args.iter().enumerate() {
                        if arg.referenced_vars.iter().any(|v| v == &param.name) {
                            param_to_calls.push(ParamToCall {
                                param_idx,
                                callee: ct.callee.clone(),
                                arg_idx,
                                call_line: ct.line,
                            });
                        }
                    }
                }
            }
        }

        Some(FunctionSummary {
            func_id: func_id.to_string(),
            func_name: node.name.clone(),
            file_path: node.file_path.clone(),
            taint_propagation,
            direct_sinks,
            param_to_calls,
            body_hash: None,
        })
    }

    /// 从 sink 函数名推断漏洞类型
    fn infer_vuln_type(&self, func_name: &str) -> VulnerabilityType {
        let lower = func_name.to_lowercase();

        if lower.contains("exec")
            || lower.contains("system")
            || lower.contains("spawn")
            || lower.contains("runtime")
            || lower.contains("processbuilder")
            || lower.contains("shell_exec")
            || lower.contains("passthru")
        {
            return VulnerabilityType::CommandInjection;
        }

        if lower.contains("query")
            || lower.contains("sql")
            || lower.contains("cursor")
            || lower.contains("jdbctemplate")
            || lower.contains("statement")
            || lower.contains("preparedstatement")
            || lower.contains("database")
        {
            return VulnerabilityType::SqlInjection;
        }

        if lower.contains("eval")
            || lower.contains("compile")
            || lower.contains("scriptengine")
            || lower.contains("groovyshell")
            || lower.contains("__import__")
        {
            return VulnerabilityType::CodeInjection;
        }

        if (lower.contains("open") && !lower.contains("response"))
            || lower.contains("readfile")
            || lower.contains("writefile")
            || lower.contains("fileinputstream")
            || lower.contains("fileoutputstream")
        {
            return VulnerabilityType::PathTraversal;
        }

        if lower.contains("fetch")
            || lower.contains("httpclient")
            || lower.contains("urlconnection")
            || lower.contains("resttemplate")
            || lower.contains("webclient")
            || lower.contains("sendrequest")
        {
            return VulnerabilityType::ServerSideRequestForgery;
        }

        if lower.contains("innerhtml")
            || lower.contains("document.write")
            || lower.contains("getwriter")
            || lower.contains("dangerouslysetinnerhtml")
        {
            return VulnerabilityType::CrossSiteScripting;
        }

        if lower.contains("deserialize")
            || lower.contains("readobject")
            || lower.contains("objectinputstream")
            || lower.contains("readvalue")
            || lower.contains("pickle")
            || lower.contains("unserialize")
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
        let summary = summaries
            .values()
            .find(|s| s.func_name == callee_name || s.func_id.contains(callee_name));

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
    /// 调用图（Arc 共享，零拷贝）
    call_graph: Arc<CallGraph>,
}

impl ContextAssembler {
    /// 从调用图创建
    pub fn new(call_graph: Arc<CallGraph>) -> Self {
        Self { call_graph }
    }

    /// 从项目路径直接构建
    pub fn from_project(project_path: &Path) -> Self {
        let mut analyzer = CrossFileTaintAnalyzer::new();
        let _ = analyzer.analyze_project(project_path);
        Self {
            call_graph: Arc::new(std::mem::take(&mut analyzer.call_graph)),
        }
    }

    /// 为指定文件组装上下文
    pub fn assemble_context(&self, file_path: &str) -> FileContext {
        let file_str = file_path.replace('\\', "/");

        // 1. 找到该文件中的所有函数
        let file_funcs = self
            .call_graph
            .file_functions
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
                for ct in &node.calls {
                    if let Some(callee) = self.call_graph.nodes.get(&ct.callee) {
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
                                caller.file_path, cfunc.start_line, cfunc.name,
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

/// 标准化文件路径（统一使用正斜杠）
pub fn normalize_path(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    // Resolve . and .. path components
    let parts: Vec<&str> = normalized.split('/').collect();
    let mut resolved: Vec<&str> = Vec::new();
    for part in parts {
        if part == "." || part.is_empty() {
            continue;
        }
        if part == ".." {
            resolved.pop();
        } else {
            resolved.push(part);
        }
    }
    resolved.join("/")
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
            sink_type: None,
            is_callback: false,
            parent_call_site: None,
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
            sink_type: None,
            is_callback: false,
            parent_call_site: None,
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
            sink_type: None,
            is_callback: false,
            parent_call_site: None,
        };

        graph.add_node(caller);
        graph.add_node(callee);
        graph.add_call("test.py:main", "test.py:helper");

        assert!(graph
            .nodes
            .get("test.py:main")
            .unwrap()
            .calls
            .iter()
            .any(|c| c.callee == "test.py:helper".to_string()));
        assert!(graph
            .nodes
            .get("test.py:helper")
            .unwrap()
            .called_by
            .contains(&"test.py:main".to_string()));
    }

    #[test]
    fn test_extract_function_name_python() {
        let analyzer = CrossFileTaintAnalyzer::new();
        assert_eq!(
            analyzer.extract_function_name("def main():", "python"),
            Some("main".to_string())
        );
        assert_eq!(
            analyzer.extract_function_name("def get_user(id):", "python"),
            Some("get_user".to_string())
        );
    }

    #[test]
    fn test_extract_function_name_javascript() {
        let analyzer = CrossFileTaintAnalyzer::new();
        assert_eq!(
            analyzer.extract_function_name("function main() {", "javascript"),
            Some("main".to_string())
        );
        assert_eq!(
            analyzer.extract_function_name("const helper = () =>", "javascript"),
            Some("helper".to_string())
        );
    }

    #[test]
    fn test_is_taint_source() {
        let analyzer = CrossFileTaintAnalyzer::new();
        // 函数名兜底（教学/测试命名）
        assert!(analyzer.is_taint_source("getUserInput", ""));
        assert!(analyzer.is_taint_source("read_file", ""));
        assert!(!analyzer.is_taint_source("calculate", ""));
        // 核心修复：函数体内容匹配（真实项目用业务命名，source 在函数体里）
        assert!(analyzer.is_taint_source("handler", "const x = req.body.name;"));
        assert!(analyzer.is_taint_source("callback", "return req.query.url;"));
    }

    #[test]
    fn test_is_taint_sink() {
        let analyzer = CrossFileTaintAnalyzer::new();
        // 函数名兜底（只返回 bool，无具体类型）
        assert!(analyzer.is_taint_sink("executeQuery", "").0);
        assert!(analyzer.is_taint_sink("system", "").0);
        assert!(!analyzer.is_taint_sink("format", "").0);
        // 核心修复：函数体内容匹配（返回具体漏洞类型）
        assert!(analyzer.is_taint_sink("handler", "eval(req.body.x);").0);
        assert_eq!(
            analyzer.is_taint_sink("handler", "eval(req.body.x);").1,
            Some(VulnerabilityType::CodeInjection)
        );
        assert!(analyzer.is_taint_sink("callback", "needle.get(url);").0);
        assert_eq!(
            analyzer.is_taint_sink("callback", "needle.get(url);").1,
            Some(VulnerabilityType::ServerSideRequestForgery)
        );
        assert!(
            analyzer
                .is_taint_sink("callback", "usersCol.findOne({userName});")
                .0
        );
        assert_eq!(
            analyzer
                .is_taint_sink("callback", "usersCol.findOne({userName});")
                .1,
            Some(VulnerabilityType::NoSqlInjection)
        );
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
        assert!(
            result.stats.files_analyzed >= 2,
            "Should analyze at least 2 files, got {}",
            result.stats.files_analyzed
        );
        assert!(
            result.stats.total_functions >= 3,
            "Should find at least 3 functions, got {}",
            result.stats.total_functions
        );

        // 验证 taint sources 和 sinks 被识别
        // get_user_input 包含 "get" → is_taint_source
        // execute_query 包含 "execute" → is_taint_sink
        assert!(
            result.stats.taint_sources > 0,
            "Should find taint sources, got {}",
            result.stats.taint_sources
        );
        assert!(
            result.stats.taint_sinks > 0,
            "Should find taint sinks, got {}",
            result.stats.taint_sinks
        );

        // 验证跨文件调用关系被解析
        // handle_request (source.py) 调用 execute_query (sink.py) → 应建立跨文件调用边
        let has_cross_file_calls = result.call_graph.nodes.values().any(|n| {
            n.calls.iter().any(|c| {
                if let Some(callee) = result.call_graph.nodes.get(&c.callee) {
                    callee.file_path != n.file_path
                } else {
                    false
                }
            })
        });
        assert!(
            has_cross_file_calls,
            "Should resolve cross-file call relationships"
        );

        // 验证检测到 taint 流（source → sink 路径）
        assert!(
            result.stats.taint_flows > 0,
            "Should detect taint flows from source to sink, got {}",
            result.stats.taint_flows
        );

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
        assert!(
            result.stats.taint_sources > 0,
            "handleRequest should be identified as taint source"
        );
        assert!(
            result.stats.taint_sinks > 0,
            "executeCommand should be identified as taint sink"
        );

        // handlerRequest calls processInput (cross-file)
        let has_cross = result.call_graph.nodes.values().any(|n| {
            n.calls.iter().any(|c| {
                result
                    .call_graph
                    .nodes
                    .get(&c.callee)
                    .map(|callee| callee.file_path != n.file_path)
                    .unwrap_or(false)
            })
        });
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

    #[test]
    fn test_import_alias_named_import_js() {
        // import { executeQuery as runQuery } from './db'
        // → 调用 runQuery() 应匹配 db.js 中的 executeQuery
        let tmp_dir = std::env::temp_dir().join("ctx_audit_import_alias_test");
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();

        let handler_code = r#"
import { executeQuery as runQuery } from './db';

function handleRequest(req) {
    const userInput = req.query.input;
    runQuery(userInput);
}
"#;
        let db_code = r#"
function executeQuery(query) {
    db.query(query);
}
"#;

        std::fs::write(tmp_dir.join("handler.js"), handler_code).unwrap();
        std::fs::write(tmp_dir.join("db.js"), db_code).unwrap();

        let mut analyzer = CrossFileTaintAnalyzer::new();
        let result = analyzer.analyze_project(&tmp_dir);

        // 验证 import alias 被正确解析
        let has_import_resolved_call = result.call_graph.nodes.values().any(|n| {
            n.file_path.ends_with("handler.js")
                && n.calls.iter().any(|c| {
                    result
                        .call_graph
                        .nodes
                        .get(&c.callee)
                        .map(|callee| {
                            callee.name == "executeQuery" && callee.file_path.ends_with("db.js")
                        })
                        .unwrap_or(false)
                })
        });
        assert!(has_import_resolved_call,
            "import {{ executeQuery as runQuery }} should resolve runQuery() -> executeQuery in db.js");

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_import_alias_named_no_alias_js() {
        // import { executeQuery } from './db'
        // → 调用 executeQuery() 应匹配 db.js 中的 executeQuery
        let tmp_dir = std::env::temp_dir().join("ctx_audit_import_noalias_test");
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();

        let handler_code = r#"
import { executeQuery } from './db';

function handleRequest(req) {
    executeQuery(req.query.input);
}
"#;
        let db_code = r#"
function executeQuery(query) {
    db.query(query);
}
"#;

        std::fs::write(tmp_dir.join("handler.js"), handler_code).unwrap();
        std::fs::write(tmp_dir.join("db.js"), db_code).unwrap();

        let mut analyzer = CrossFileTaintAnalyzer::new();
        let result = analyzer.analyze_project(&tmp_dir);

        let has_import_resolved_call = result.call_graph.nodes.values().any(|n| {
            n.file_path.ends_with("handler.js")
                && n.calls.iter().any(|c| {
                    result
                        .call_graph
                        .nodes
                        .get(&c.callee)
                        .map(|callee| {
                            callee.name == "executeQuery" && callee.file_path.ends_with("db.js")
                        })
                        .unwrap_or(false)
                })
        });
        assert!(
            has_import_resolved_call,
            "import {{ executeQuery }} should resolve executeQuery() -> executeQuery in db.js"
        );

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_import_alias_python_as() {
        // from db import execute_query as run_query
        // → 调用 run_query() 应匹配 db.py 中的 execute_query
        let tmp_dir = std::env::temp_dir().join("ctx_audit_import_py_alias_test");
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();

        let handler_code = r#"
from db import execute_query as run_query

def handle_request(request):
    user_input = request.args.get('id')
    run_query(user_input)
"#;
        let db_code = r#"
def execute_query(query):
    cursor.execute(query)
"#;

        std::fs::write(tmp_dir.join("handler.py"), handler_code).unwrap();
        std::fs::write(tmp_dir.join("db.py"), db_code).unwrap();

        let mut analyzer = CrossFileTaintAnalyzer::new();
        let result = analyzer.analyze_project(&tmp_dir);

        let has_import_resolved_call = result.call_graph.nodes.values().any(|n| {
            n.file_path.ends_with("handler.py")
                && n.calls.iter().any(|c| {
                    result
                        .call_graph
                        .nodes
                        .get(&c.callee)
                        .map(|callee| {
                            callee.name == "execute_query" && callee.file_path.ends_with("db.py")
                        })
                        .unwrap_or(false)
                })
        });
        assert!(has_import_resolved_call,
            "from db import execute_query as run_query should resolve run_query() → execute_query in db.py");

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_import_alias_commonjs_destructure() {
        // const { exec } = require('./db')
        // → 调用 exec() 应匹配 db.js 中的 exec
        let tmp_dir = std::env::temp_dir().join("ctx_audit_import_cjs_test");
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();

        let handler_code = r#"
const { exec } = require('./db');

function handleRequest(req) {
    exec(req.query.input);
}
"#;
        let db_code = r#"
function exec(cmd) {
    child_process.exec(cmd);
}
"#;

        std::fs::write(tmp_dir.join("handler.js"), handler_code).unwrap();
        std::fs::write(tmp_dir.join("db.js"), db_code).unwrap();

        let mut analyzer = CrossFileTaintAnalyzer::new();
        let result = analyzer.analyze_project(&tmp_dir);

        let has_import_resolved_call = result.call_graph.nodes.values().any(|n| {
            n.file_path.ends_with("handler.js")
                && n.calls.iter().any(|c| {
                    result
                        .call_graph
                        .nodes
                        .get(&c.callee)
                        .map(|callee| callee.name == "exec" && callee.file_path.ends_with("db.js"))
                        .unwrap_or(false)
                })
        });
        assert!(
            has_import_resolved_call,
            "const {{ exec }} = require('./db') should resolve exec() -> exec in db.js"
        );

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_import_alias_fallback_to_global_match() {
        // 当 import 解析失败时，应回退到全局名称匹配
        let tmp_dir = std::env::temp_dir().join("ctx_audit_import_fallback_test");
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();

        let source_code = r#"
def get_user_input(request):
    user_id = request.args.get('id')
    return user_id

def handle_request(request):
    user_input = get_user_input(request)
    execute_query(user_input)
"#;
        let sink_code = r#"
def execute_query(query):
    cursor.execute(query)
"#;

        std::fs::write(tmp_dir.join("source.py"), source_code).unwrap();
        std::fs::write(tmp_dir.join("sink.py"), sink_code).unwrap();

        let mut analyzer = CrossFileTaintAnalyzer::new();
        let result = analyzer.analyze_project(&tmp_dir);

        assert!(
            result.stats.taint_flows > 0,
            "Global name matching fallback should still work: {}",
            result.stats.taint_flows
        );

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_callback_arrow_function_registered() {
        // app.get('/x', (req, res) => { exec(req.body) })
        // → 回调节点应被注册并包含 exec 调用
        let tmp_dir = std::env::temp_dir().join("ctx_audit_cb_arrow_test");
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();

        let code = r#"
const express = require('express');
const app = express();

function setup() {
    app.get('/user', (req, res) => {
        const cmd = req.query.cmd;
        exec(cmd);
    });
}
"#;
        std::fs::write(tmp_dir.join("app.js"), code).unwrap();

        let mut analyzer = CrossFileTaintAnalyzer::new();
        let result = analyzer.analyze_project(&tmp_dir);

        // 验证回调节点存在
        let has_callback = result
            .call_graph
            .nodes
            .values()
            .any(|n| n.is_callback && n.name.starts_with("<callback@"));
        assert!(
            has_callback,
            "Arrow function callback should be registered as synthetic CallGraphNode"
        );

        // 验证回调内的调用被提取（exec）
        let has_exec_in_callback = result
            .call_graph
            .nodes
            .values()
            .filter(|n| n.is_callback)
            .any(|n| n.calls.iter().any(|c| c.callee == "exec"));
        assert!(has_exec_in_callback, "Callback should contain 'exec' call");

        // 验证 setup → callback 的边
        let has_edge = result
            .call_graph
            .nodes
            .values()
            .filter(|n| n.is_callback)
            .any(|cb| cb.called_by.iter().any(|caller| caller.contains("setup")));
        assert!(has_edge, "setup() should have edge to callback node");

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_callback_in_promise_then() {
        // .then(data => { processData(data) })
        // → 回调应被注册为合成节点
        let tmp_dir = std::env::temp_dir().join("ctx_audit_cb_promise_test");
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();

        let code = r#"
function fetchData(url) {
    return fetch(url)
        .then(response => response.json())
        .then(data => {
            processData(data);
        });
}
"#;
        std::fs::write(tmp_dir.join("api.js"), code).unwrap();

        let mut analyzer = CrossFileTaintAnalyzer::new();
        let result = analyzer.analyze_project(&tmp_dir);

        let cb_count = result
            .call_graph
            .nodes
            .values()
            .filter(|n| n.is_callback)
            .count();
        assert!(
            cb_count >= 1,
            "Promise .then() callbacks should be registered, got {} callback(s)",
            cb_count
        );

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_callback_nested_in_function_expression() {
        // app.use((req, res, next) => { ... })
        let tmp_dir = std::env::temp_dir().join("ctx_audit_cb_nested_test");
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();

        let code = r#"
function setupMiddleware(app) {
    app.use(function(req, res, next) {
        req.user = null;
        next();
    });
}
"#;
        std::fs::write(tmp_dir.join("middleware.js"), code).unwrap();

        let mut analyzer = CrossFileTaintAnalyzer::new();
        let result = analyzer.analyze_project(&tmp_dir);

        let has_function_expr_cb = result
            .call_graph
            .nodes
            .values()
            .any(|n| n.is_callback && n.parameters.iter().any(|p| p.name == "req"));
        assert!(
            has_function_expr_cb,
            "function expression callback should be registered with correct params"
        );

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_receiver_based_method_resolution() {
        // const db = require('./db'); db.query(x)
        // → 验证 receiver 信息在 CallTarget 中被保留
        let tmp_dir = std::env::temp_dir().join("ctx_audit_receiver_test");
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();

        let handler_code = r#"
const db = require('./db');

function handleRequest(req) {
    db.query(req.query.id);
}
"#;
        let db_code = r#"
function query(sql) {
    database.execute(sql);
}
"#;

        std::fs::write(tmp_dir.join("handler.js"), handler_code).unwrap();
        std::fs::write(tmp_dir.join("db.js"), db_code).unwrap();

        let mut analyzer = CrossFileTaintAnalyzer::new();
        let result = analyzer.analyze_project(&tmp_dir);

        // 验证 CallTarget 类型（calls 字段现在是 Vec<CallTarget>）
        let handler_node = result
            .call_graph
            .nodes
            .values()
            .find(|n| n.name == "handleRequest");
        assert!(
            handler_node.is_some(),
            "handleRequest should exist in call graph"
        );
        let handler = handler_node.unwrap();
        assert!(!handler.calls.is_empty(), "handleRequest should have calls");

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_java_cross_file_taint_with_yaml_rules() {
        // 验证注入 YAML 规则后，跨文件分析能发现 Java 多文件 source->sink 链路
        let tmp_dir = std::env::temp_dir().join("ctx_audit_java_cross_file_test");
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();

        let controller_code = r#"
import javax.servlet.http.HttpServletRequest;

public class Controller {
    private final UserDao userDao = new UserDao();

    public void doGet(HttpServletRequest request) throws Exception {
        String id = request.getParameter("id");
        userDao.findById(id);
    }
}
"#;
        let dao_code = r#"
import java.sql.Statement;

public class UserDao {
    private Statement stmt;

    public void findById(String userId) throws Exception {
        String sql = "SELECT * FROM users WHERE id = " + userId;
        stmt.executeQuery(sql);
    }
}
"#;

        std::fs::write(tmp_dir.join("Controller.java"), controller_code).unwrap();
        std::fs::write(tmp_dir.join("UserDao.java"), dao_code).unwrap();

        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let rules_dir = std::path::Path::new(&manifest_dir)
            .parent()
            .unwrap()
            .join("rules")
            .join("taint");

        let loaded = crate::rules::taint_loader::load_taint_rules_from_dir(&rules_dir)
            .expect("load taint rules");
        let mut analyzer = CrossFileTaintAnalyzer::with_rules(loaded.sources, loaded.sinks);
        let result = analyzer.analyze_project(&tmp_dir);

        assert!(
            result.stats.taint_flows > 0,
            "跨文件分析应发现 Controller.doGet -> UserDao.findById -> executeQuery 的污点流，实际 {} 条",
            result.stats.taint_flows
        );

        let has_controller_to_dao = result.taint_flows.iter().any(|f| {
            f.source.file_path.ends_with("Controller.java")
                && f.sink.file_path.ends_with("UserDao.java")
        });
        assert!(
            has_controller_to_dao,
            "应存在从 Controller.java 到 UserDao.java 的跨文件污点流"
        );

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_java_cross_file_no_false_positive_on_safe_param() {
        // 污点传入 helper 的非敏感参数，不应生成跨文件 flow
        let tmp_dir = std::env::temp_dir().join("ctx_audit_java_cross_fp_test");
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();

        let controller_code = r#"
import javax.servlet.http.HttpServletRequest;

public class Controller {
    private final Helper helper = new Helper();

    public void doGet(HttpServletRequest request) {
        String id = request.getParameter("id");
        helper.log(id);
    }
}
"#;
        let helper_code = r#"
public class Helper {
    public String log(String msg) {
        return msg.trim();
    }

    public void query(String sql) throws Exception {
        stmt.executeQuery(sql);
    }
}
"#;

        std::fs::write(tmp_dir.join("Controller.java"), controller_code).unwrap();
        std::fs::write(tmp_dir.join("Helper.java"), helper_code).unwrap();

        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let rules_dir = std::path::Path::new(&manifest_dir)
            .parent()
            .unwrap()
            .join("rules")
            .join("taint");

        let loaded = crate::rules::taint_loader::load_taint_rules_from_dir(&rules_dir)
            .expect("load taint rules");
        let mut analyzer = CrossFileTaintAnalyzer::with_rules(loaded.sources, loaded.sinks);
        let result = analyzer.analyze_project(&tmp_dir);

        // Controller -> Helper.log 不是 sink，不应产生 flow
        let has_false_flow = result.taint_flows.iter().any(|f| {
            f.source.file_path.ends_with("Controller.java")
                && f.sink.file_path.ends_with("Helper.java")
        });
        assert!(
            !has_false_flow,
            "污点传入 log() 这种非敏感参数时不应生成跨文件 flow"
        );

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_java_cross_file_multi_hop_with_rename() {
        // source -> helper (rename) -> sink，验证 param_to_calls 能支撑多跳传播
        let tmp_dir = std::env::temp_dir().join("ctx_audit_java_multi_hop_test");
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();

        let a_code = r#"
import javax.servlet.http.HttpServletRequest;

public class Controller {
    private final Helper helper = new Helper();

    public void doGet(HttpServletRequest request) {
        String id = request.getParameter("id");
        helper.process(id);
    }
}
"#;
        let b_code = r#"
public class Helper {
    public void process(String input) {
        String sql = "SELECT * FROM users WHERE id = '" + input + "'";
        Dao dao = new Dao();
        dao.run(sql);
    }
}
"#;
        let c_code = r#"
public class Dao {
    public void run(String query) throws Exception {
        stmt.executeQuery(query);
    }
}
"#;

        std::fs::write(tmp_dir.join("Controller.java"), a_code).unwrap();
        std::fs::write(tmp_dir.join("Helper.java"), b_code).unwrap();
        std::fs::write(tmp_dir.join("Dao.java"), c_code).unwrap();

        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let rules_dir = std::path::Path::new(&manifest_dir)
            .parent()
            .unwrap()
            .join("rules")
            .join("taint");

        let loaded = crate::rules::taint_loader::load_taint_rules_from_dir(&rules_dir)
            .expect("load taint rules");
        let mut analyzer = CrossFileTaintAnalyzer::with_rules(loaded.sources, loaded.sinks);
        let result = analyzer.analyze_project(&tmp_dir);

        let has_flow = result.taint_flows.iter().any(|f| {
            f.source.file_path.ends_with("Controller.java")
                && f.sink.file_path.ends_with("Dao.java")
        });
        assert!(
            has_flow,
            "应发现 Controller -> Helper -> Dao 的多跳跨文件污点流，实际 {} 条",
            result.stats.taint_flows
        );

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_java_intra_file_bad_to_badsink() {
        let tmp_dir = std::env::temp_dir().join("ctx_audit_java_badsink_test");
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();

        let code = r#"
import javax.servlet.http.*;

public class JulietStyle extends HttpServlet {
    public void bad(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String data = request.getParameter("name");
        badSink(data, response);
    }

    public void badSink(String data, HttpServletResponse response) throws Exception {
        response.getWriter().println(data);
    }
}
"#;
        std::fs::write(tmp_dir.join("JulietStyle.java"), code).unwrap();

        let sources = vec![crate::analysis::taint::TaintSource::new(
            "java_http_request",
            "Java HTTP Request",
            vec!["request.getParameter"],
        )];
        let mut sinks = CrossFileTaintAnalyzer::default_sink_patterns();
        sinks.push(crate::analysis::taint::TaintSink::new(
            "xss",
            "XSS",
            vec!["println", "response.getWriter().println"],
            crate::analysis::taint::VulnerabilityType::CrossSiteScripting,
        ));
        let mut analyzer = CrossFileTaintAnalyzer::with_rules(sources, sinks);
        let result = analyzer.analyze_project(&tmp_dir);
        eprintln!("stats: {:?}", result.stats);
        for n in result.call_graph.nodes.values() {
            eprintln!(
                "node: {} params={:?} source={} sink={} calls={:?}",
                n.id, n.parameters, n.is_taint_source, n.is_taint_sink, n.calls
            );
        }
        assert!(
            result.stats.taint_flows > 0,
            "应发现单文件 bad -> badSink 的 XSS 污点流，实际 {} 条",
            result.stats.taint_flows
        );

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
