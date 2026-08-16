// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 调用图查询引擎
//!
//! 为 LLM 工具提供确定性的图查询能力，将 CrossFileTaintAnalyzer 构建的
//! CallGraph、TypeHierarchy、MiddlewareModel 暴露为可查询接口。
//!
//! 每个查询方法返回的是基于 AST 解析的确定性结果，不依赖任何 LLM 推断。

use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use super::cross_file::{
    normalize_path, CallGraph, CallGraphNode, CallTarget, CrossFileTaintResult,
};
use super::middleware::MiddlewareModel;
use super::type_hierarchy::{ResolvedMethod, TypeHierarchy};

// ── 查询结果类型 ──────────────────────────────────────────

/// 调用者证据 — 谁调用了某个函数
#[derive(Debug, Clone, Serialize)]
pub struct CallerEvidence {
    pub caller_function: String,
    pub caller_file: String,
    pub caller_line: usize,
    pub callee_function: String,
    pub callee_file: String,
    pub callee_line: usize,
    /// 方法调用的 receiver（obj.method() → Some("obj")）
    pub receiver: Option<String>,
    /// 是否为回调节点
    pub is_callback: bool,
}

/// 被调用者证据 — 某个函数调用了谁
#[derive(Debug, Clone, Serialize)]
pub struct CalleeEvidence {
    pub callee_function: String,
    pub callee_file: Option<String>,
    pub callee_line: Option<usize>,
    pub receiver: Option<String>,
    pub is_external: bool,
    pub is_callback: bool,
    pub is_resolved: bool, // 是否已解析到具体节点（vs 仅存调用名）
}

/// 调用路径 — BFS/DFS 确定性结果
#[derive(Debug, Clone, Serialize)]
pub struct CallPath {
    pub steps: Vec<PathStep>,
    pub total_hops: usize,
    pub crosses_files: bool,
    pub files_in_path: Vec<String>,
}

/// 路径中的单步
#[derive(Debug, Clone, Serialize)]
pub struct PathStep {
    pub function_name: String,
    pub file_path: String,
    pub line: usize,
    pub step_type: String, // "direct_call" | "callback" | "middleware" | "virtual_dispatch"
    pub code_snippet: Option<String>,
}

/// 可达性查询结果
#[derive(Debug, Clone, Serialize)]
pub struct ReachabilityResult {
    pub source_id: String,
    pub source_name: String,
    pub source_file: String,
    pub max_depth: usize,
    pub reachable_nodes: Vec<ReachableNode>,
    pub reachable_sinks: Vec<ReachableSink>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReachableNode {
    pub func_id: String,
    pub func_name: String,
    pub file_path: String,
    pub line: usize,
    pub distance: usize, // 从 source 出发的跳数
    pub is_sink: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReachableSink {
    pub func_id: String,
    pub func_name: String,
    pub file_path: String,
    pub line: usize,
    pub distance: usize,
    pub path_to_sink: Vec<String>, // 完整路径
}

/// 方法调用解析结果
#[derive(Debug, Clone, Serialize)]
pub struct ResolvedCallTarget {
    pub function_name: String,
    pub file_path: String,
    pub line: usize,
    pub resolution_method: String, // "import_alias" | "global_match" | "type_hierarchy" | "receiver_match"
    pub confidence: f32,
    pub receiver_type: Option<String>,
}

/// 类型继承链
#[derive(Debug, Clone, Serialize)]
pub struct TypeChainResult {
    pub class_name: String,
    pub kind: String,
    pub file_path: Option<String>,
    pub line: Option<usize>,
    pub parent_classes: Vec<String>,
    pub child_classes: Vec<String>,
    pub methods: Vec<MethodEvidence>,
    pub interface_implementations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MethodEvidence {
    pub name: String,
    pub file_path: String,
    pub line: usize,
    pub defined_in_class: String,
    pub is_inherited: bool,
    pub is_static: bool,
}

/// 中间件证据
#[derive(Debug, Clone, Serialize)]
pub struct MiddlewareEvidence {
    pub handler_name: String,
    pub handler_file: String,
    pub line: usize,
    pub affects_routes: Vec<RouteEvidence>,
    pub middleware_type: String, // "express_app_use" | "django_middleware"
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteEvidence {
    pub file_path: String,
    pub line: usize,
    pub route_function: Option<String>,
}

/// 回调证据
#[derive(Debug, Clone, Serialize)]
pub struct CallbackEvidence {
    pub callback_id: String,
    pub callback_name: String,
    pub file_path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub parent_function: String,
    pub parent_call_line: usize,
    pub params: Vec<String>,
    pub calls: Vec<CalleeEvidence>,
}

/// 变量流追踪结果
#[derive(Debug, Clone, Serialize)]
pub struct VariableFlowResult {
    pub variable_name: String,
    pub source_file: String,
    pub source_line: usize,
    pub source_function: String,
    pub flows_to_sinks: Vec<TaintPathEvidence>,
    pub total_sinks_reached: usize,
}

/// 污点路径证据
#[derive(Debug, Clone, Serialize)]
pub struct TaintPathEvidence {
    pub sink_function: String,
    pub sink_file: String,
    pub sink_line: usize,
    pub vulnerability_type: String,
    pub path_hops: usize,
    pub path: Vec<PathStep>,
}

// ── 调用图查询引擎 ──────────────────────────────────────

/// 调用图查询引擎
///
/// 为 LLM 审计工具提供基于 AST 解析结果的确定性图查询。
/// 从 CrossFileTaintResult 构建，暴露完整调用图、类型层次、中间件信息。
pub struct CallGraphQueryEngine {
    call_graph: Arc<CallGraph>,
    type_hierarchy: TypeHierarchy,
    middleware_model: MiddlewareModel,
    /// Import alias 信息: file_path → (local_name → ImportResolution)
    file_import_aliases: HashMap<String, HashMap<String, super::cross_file::ImportResolution>>,
    /// 直接调用者索引：callee_id → [CallerEvidence]
    direct_caller_index: HashMap<String, Vec<CallerEvidence>>,
    /// 直接被调用者索引：caller_id → [CalleeEvidence]
    direct_callee_index: HashMap<String, Vec<CalleeEvidence>>,
    /// 递归调用者缓存（按需计算）
    all_callers_cache: Mutex<HashMap<String, Vec<String>>>,
    /// 递归被调用者缓存（按需计算）
    all_callees_cache: Mutex<HashMap<String, Vec<String>>>,
    /// 调用路径缓存：(source_id, sink_id) -> Option<raw_path>
    /// 避免 LLM 多次查询同一 source→sink 时重复 BFS。
    path_cache: Mutex<HashMap<(String, String), Option<Vec<String>>>>,
    /// 可达性查询缓存：(file_path, function_name, max_depth) -> Option<ReachabilityResult>
    reachable_cache: Mutex<HashMap<(String, String, usize), Option<ReachabilityResult>>>,
    /// 变量流追踪缓存：(file_path, function_name) -> VariableFlowResult
    variable_flow_cache: Mutex<HashMap<(String, String), VariableFlowResult>>,
    /// 图统计缓存
    stats_cache: Mutex<Option<CachedGraphStats>>,
}

#[derive(Debug, Clone, Default)]
struct CachedGraphStats {
    total_nodes: usize,
    callback_nodes: usize,
    taint_sources: usize,
    taint_sinks: usize,
    total_edges: usize,
    cross_file_edges: usize,
    total_files: usize,
    type_count: usize,
    middleware_count: usize,
}

impl CallGraphQueryEngine {
    /// 从跨文件分析结果构建查询引擎
    pub fn from_result(result: &CrossFileTaintResult) -> Self {
        let (direct_caller_index, direct_callee_index) =
            Self::build_direct_indexes(&result.call_graph);
        Self {
            call_graph: result.call_graph.clone(),
            type_hierarchy: result.type_hierarchy.clone(),
            middleware_model: result.middleware_model.clone(),
            file_import_aliases: result.file_import_aliases.clone(),
            direct_caller_index,
            direct_callee_index,
            all_callers_cache: Mutex::new(HashMap::new()),
            all_callees_cache: Mutex::new(HashMap::new()),
            path_cache: Mutex::new(HashMap::new()),
            reachable_cache: Mutex::new(HashMap::new()),
            variable_flow_cache: Mutex::new(HashMap::new()),
            stats_cache: Mutex::new(None),
        }
    }

    /// 从独立组件构建（用于 daemon/测试）
    pub fn new(
        call_graph: Arc<CallGraph>,
        type_hierarchy: TypeHierarchy,
        middleware_model: MiddlewareModel,
        file_import_aliases: HashMap<String, HashMap<String, super::cross_file::ImportResolution>>,
    ) -> Self {
        let (direct_caller_index, direct_callee_index) = Self::build_direct_indexes(&call_graph);
        Self {
            call_graph,
            type_hierarchy,
            middleware_model,
            file_import_aliases,
            direct_caller_index,
            direct_callee_index,
            all_callers_cache: Mutex::new(HashMap::new()),
            all_callees_cache: Mutex::new(HashMap::new()),
            path_cache: Mutex::new(HashMap::new()),
            reachable_cache: Mutex::new(HashMap::new()),
            variable_flow_cache: Mutex::new(HashMap::new()),
            stats_cache: Mutex::new(None),
        }
    }

    fn build_direct_indexes(
        call_graph: &CallGraph,
    ) -> (
        HashMap<String, Vec<CallerEvidence>>,
        HashMap<String, Vec<CalleeEvidence>>,
    ) {
        let mut caller_index: HashMap<String, Vec<CallerEvidence>> = HashMap::new();
        let mut callee_index: HashMap<String, Vec<CalleeEvidence>> = HashMap::new();

        for (caller_id, caller_node) in &call_graph.nodes {
            let mut callee_seen = HashSet::new();
            for ct in &caller_node.calls {
                let callee_node = call_graph.nodes.get(&ct.callee);
                let is_resolved = callee_node.is_some();

                let callee_ev = CalleeEvidence {
                    callee_function: callee_node
                        .map(|n| n.name.clone())
                        .unwrap_or_else(|| ct.callee.clone()),
                    callee_file: callee_node.map(|n| n.file_path.clone()),
                    callee_line: callee_node.map(|n| n.start_line),
                    receiver: ct.receiver.clone(),
                    is_external: callee_node.map(|n| n.is_external).unwrap_or(true),
                    is_callback: callee_node.map(|n| n.is_callback).unwrap_or(false),
                    is_resolved,
                };
                let key = (ct.callee.clone(), ct.receiver.clone().unwrap_or_default());
                if callee_seen.insert(key) {
                    callee_index
                        .entry(caller_id.clone())
                        .or_default()
                        .push(callee_ev);
                }

                if let Some(target_node) = callee_node {
                    let caller_ev = CallerEvidence {
                        caller_function: caller_node.name.clone(),
                        caller_file: caller_node.file_path.clone(),
                        caller_line: caller_node.start_line,
                        callee_function: target_node.name.clone(),
                        callee_file: target_node.file_path.clone(),
                        callee_line: target_node.start_line,
                        receiver: ct.receiver.clone(),
                        is_callback: caller_node.is_callback,
                    };
                    caller_index
                        .entry(target_node.id.clone())
                        .or_default()
                        .push(caller_ev);
                }
            }
        }

        (caller_index, callee_index)
    }

    // ── 调用者查询 ──────────────────────────────────

    /// 查询：谁调用了指定函数？
    ///
    /// 根据 file_path + function_name 查找匹配的 CallGraphNode，
    /// 返回所有直接调用者（含 receiver 信息）。
    pub fn query_callers(&self, file_path: &str, function_name: &str) -> Vec<CallerEvidence> {
        let normalized_file = normalize_path(file_path);
        let target_ids = self.find_func_ids(&normalized_file, function_name);

        let mut results = Vec::new();
        let mut seen = HashSet::new();
        for target_id in &target_ids {
            if let Some(callers) = self.direct_caller_index.get(target_id) {
                for ev in callers {
                    let key = (
                        ev.caller_function.clone(),
                        ev.caller_file.clone(),
                        ev.caller_line,
                        ev.callee_function.clone(),
                    );
                    if seen.insert(key) {
                        results.push(ev.clone());
                    }
                }
            }
        }

        results
    }

    /// 递归查询：谁（直接或间接）调用了指定函数？
    pub fn query_all_callers(&self, file_path: &str, function_name: &str) -> Vec<CallerEvidence> {
        let normalized_file = normalize_path(file_path);
        let target_ids = self.find_func_ids(&normalized_file, function_name);

        let mut all_callers_set: HashSet<String> = HashSet::new();
        for target_id in &target_ids {
            self.collect_all_callers(target_id, &mut all_callers_set);
        }

        let mut results = Vec::new();
        for caller_id in &all_callers_set {
            if let Some(caller_node) = self.call_graph.nodes.get(caller_id) {
                results.push(CallerEvidence {
                    caller_function: caller_node.name.clone(),
                    caller_file: caller_node.file_path.clone(),
                    caller_line: caller_node.start_line,
                    callee_function: String::new(),
                    callee_file: String::new(),
                    callee_line: 0,
                    receiver: None,
                    is_callback: caller_node.is_callback,
                });
            }
        }

        results
    }

    fn collect_all_callers(&self, func_id: &str, visited: &mut HashSet<String>) {
        if let Ok(cache) = self.all_callers_cache.lock() {
            if let Some(cached) = cache.get(func_id).cloned() {
                visited.extend(cached);
                return;
            }
        }

        let mut local = HashSet::new();
        if let Some(node) = self.call_graph.nodes.get(func_id) {
            for caller_id in &node.called_by {
                if local.insert(caller_id.clone()) {
                    self.collect_all_callers(caller_id, &mut local);
                }
            }
        }

        if let Ok(mut cache) = self.all_callers_cache.lock() {
            cache.insert(func_id.to_string(), local.iter().cloned().collect());
        }
        visited.extend(local);
    }

    // ── 被调用者查询 ──────────────────────────────────

    /// 查询：指定函数调用了谁？
    pub fn query_callees(&self, file_path: &str, function_name: &str) -> Vec<CalleeEvidence> {
        let normalized_file = normalize_path(file_path);
        let func_ids = self.find_func_ids(&normalized_file, function_name);

        let mut results = Vec::new();
        let mut seen = HashSet::new();

        for func_id in &func_ids {
            if let Some(callees) = self.direct_callee_index.get(func_id) {
                for ev in callees {
                    let key = (
                        ev.callee_function.clone(),
                        ev.callee_file.clone(),
                        ev.receiver.clone().unwrap_or_default(),
                    );
                    if seen.insert(key) {
                        results.push(ev.clone());
                    }
                }
            }
        }

        results
    }

    /// 递归查询：指定函数直接或间接调用的所有函数
    pub fn query_all_callees(&self, file_path: &str, function_name: &str) -> Vec<CalleeEvidence> {
        let normalized_file = normalize_path(file_path);
        let func_ids = self.find_func_ids(&normalized_file, function_name);

        let mut all_callees_set: HashSet<String> = HashSet::new();
        for func_id in &func_ids {
            self.collect_all_callees(func_id, &mut all_callees_set);
        }

        let mut results = Vec::new();
        for callee_id in &all_callees_set {
            if let Some(callee_node) = self.call_graph.nodes.get(callee_id) {
                results.push(CalleeEvidence {
                    callee_function: callee_node.name.clone(),
                    callee_file: Some(callee_node.file_path.clone()),
                    callee_line: Some(callee_node.start_line),
                    receiver: None,
                    is_external: callee_node.is_external,
                    is_callback: callee_node.is_callback,
                    is_resolved: true,
                });
            }
        }

        results
    }

    fn collect_all_callees(&self, func_id: &str, visited: &mut HashSet<String>) {
        if let Ok(cache) = self.all_callees_cache.lock() {
            if let Some(cached) = cache.get(func_id).cloned() {
                visited.extend(cached);
                return;
            }
        }

        let mut local = HashSet::new();
        if let Some(node) = self.call_graph.nodes.get(func_id) {
            for ct in &node.calls {
                if local.insert(ct.callee.clone()) {
                    self.collect_all_callees(&ct.callee, &mut local);
                }
            }
        }

        if let Ok(mut cache) = self.all_callees_cache.lock() {
            cache.insert(func_id.to_string(), local.iter().cloned().collect());
        }
        visited.extend(local);
    }

    // ── 路径查询 ────────────────────────────────────

    /// 查询：从 source_func 到 sink_func 是否存在调用路径？
    ///
    /// 使用 BFS 查找最短路径，返回完整的调用路径作为确定性证据。
    pub fn find_call_path(
        &self,
        source_file: &str,
        source_function: &str,
        sink_file: &str,
        sink_function: &str,
    ) -> Option<CallPath> {
        let normalized_source = normalize_path(source_file);
        let normalized_sink = normalize_path(sink_file);

        let source_ids = self.find_func_ids(&normalized_source, source_function);
        let sink_ids = self.find_func_ids(&normalized_sink, sink_function);

        // 尝试每个 source-sink 组合
        for source_id in &source_ids {
            for sink_id in &sink_ids {
                let key = (source_id.clone(), sink_id.clone());
                // 命中缓存：Some(path) 直接返回，None 表示此前已确认无路径
                let cached = self
                    .path_cache
                    .lock()
                    .ok()
                    .and_then(|c| c.get(&key).cloned());
                let raw_path = match cached {
                    Some(Some(path)) => Some(path),
                    Some(None) => None,
                    None => {
                        let found = self.call_graph.find_call_path(source_id, sink_id);
                        if let Ok(mut cache) = self.path_cache.lock() {
                            cache.insert(key, found.clone());
                        }
                        found
                    }
                };
                if let Some(raw_path) = raw_path {
                    return Some(self.build_call_path(&raw_path));
                }
            }
        }

        None
    }

    /// 构建 CallPath 从原始路径 ID 列表
    fn build_call_path(&self, path_ids: &[String]) -> CallPath {
        let mut steps = Vec::new();
        let mut files_in_path = Vec::new();

        for (i, func_id) in path_ids.iter().enumerate() {
            if let Some(node) = self.call_graph.nodes.get(func_id) {
                let step_type = if node.is_callback {
                    "callback"
                } else if i == 0 {
                    "source"
                } else if i == path_ids.len() - 1 {
                    "sink"
                } else {
                    "direct_call"
                };

                if !files_in_path.contains(&node.file_path) {
                    files_in_path.push(node.file_path.clone());
                }

                steps.push(PathStep {
                    function_name: node.name.clone(),
                    file_path: node.file_path.clone(),
                    line: node.start_line,
                    step_type: step_type.to_string(),
                    code_snippet: None,
                });
            }
        }

        let total_hops = path_ids.len().saturating_sub(1);
        CallPath {
            total_hops,
            crosses_files: files_in_path.len() > 1,
            files_in_path,
            steps,
        }
    }

    // ── 可达性查询 ──────────────────────────────────

    /// 查询：从指定 source 函数出发，N 跳内可达的所有函数和 sink
    ///
    /// 同一 (file_path, function_name, max_depth) 的结果会被缓存，避免 LLM
    /// 在多次取证中重复 BFS。
    pub fn query_reachable(
        &self,
        file_path: &str,
        function_name: &str,
        max_depth: usize,
    ) -> Option<ReachabilityResult> {
        let normalized_file = normalize_path(file_path);
        let cache_key = (
            normalized_file.clone(),
            function_name.to_string(),
            max_depth,
        );
        if let Some(cached) = self
            .reachable_cache
            .lock()
            .ok()
            .and_then(|c| c.get(&cache_key).cloned())
        {
            return cached;
        }

        let source_ids = self.find_func_ids(&normalized_file, function_name);
        let source_id = source_ids.first()?;

        let source_node = self.call_graph.nodes.get(source_id)?;

        let sink_set: HashSet<&String> = self.call_graph.taint_sinks.iter().collect();

        let mut visited: HashMap<String, usize> = HashMap::new();
        let mut queue: VecDeque<(String, usize, Vec<String>)> = VecDeque::new();
        let mut reachable_nodes = Vec::new();
        let mut reachable_sinks = Vec::new();

        queue.push_back((source_id.clone(), 0, vec![source_id.clone()]));
        visited.insert(source_id.clone(), 0);

        while let Some((current_id, distance, path)) = queue.pop_front() {
            if distance > max_depth {
                continue;
            }

            if let Some(node) = self.call_graph.nodes.get(&current_id) {
                let is_sink = sink_set.contains(&current_id) && current_id != *source_id;

                reachable_nodes.push(ReachableNode {
                    func_id: current_id.clone(),
                    func_name: node.name.clone(),
                    file_path: node.file_path.clone(),
                    line: node.start_line,
                    distance,
                    is_sink,
                });

                if is_sink {
                    reachable_sinks.push(ReachableSink {
                        func_id: current_id.clone(),
                        func_name: node.name.clone(),
                        file_path: node.file_path.clone(),
                        line: node.start_line,
                        distance,
                        path_to_sink: path.clone(),
                    });
                }

                // 扩展邻居
                for ct in &node.calls {
                    if !visited.contains_key(&ct.callee) || visited[&ct.callee] > distance + 1 {
                        visited.insert(ct.callee.clone(), distance + 1);
                        let mut new_path = path.clone();
                        new_path.push(ct.callee.clone());
                        queue.push_back((ct.callee.clone(), distance + 1, new_path));
                    }
                }
            }
        }

        let result = ReachabilityResult {
            source_id: source_id.clone(),
            source_name: source_node.name.clone(),
            source_file: source_node.file_path.clone(),
            max_depth,
            reachable_nodes,
            reachable_sinks,
        };
        if let Ok(mut cache) = self.reachable_cache.lock() {
            cache.insert(cache_key, Some(result.clone()));
        }
        Some(result)
    }

    // ── 方法调用解析 ──────────────────────────────────

    /// 查询：obj.method() 在指定位置解析到哪个实际函数？
    ///
    /// 优先级：
    /// 1. Import alias 精确匹配（最可靠）
    /// 2. Receiver + TypeHierarchy 虚方法分发
    /// 3. 全局名称匹配（回退）
    pub fn resolve_method_call(
        &self,
        file_path: &str,
        line: usize,
        receiver: &str,
        method: &str,
    ) -> Vec<ResolvedCallTarget> {
        let normalized_file = normalize_path(file_path);
        let mut results = Vec::new();

        // Phase 1: Import alias 精确匹配
        if let Some(aliases) = self.file_import_aliases.get(&normalized_file) {
            if let Some(resolution) = aliases.get(receiver) {
                // 构建目标文件路径
                if let Some(target_file) =
                    self.resolve_module_to_file(&resolution.source_module, file_path)
                {
                    let target_normalized = normalize_path(&target_file);
                    // 在目标文件中查找匹配的函数
                    for (_, node) in &self.call_graph.nodes {
                        if normalize_path(&node.file_path) == target_normalized
                            && node.name == resolution.original_export_name
                        {
                            results.push(ResolvedCallTarget {
                                function_name: node.name.clone(),
                                file_path: node.file_path.clone(),
                                line: node.start_line,
                                resolution_method: "import_alias".to_string(),
                                confidence: 0.95,
                                receiver_type: Some(receiver.to_string()),
                            });
                        }
                    }
                }
            }
        }

        // Phase 2: TypeHierarchy 虚方法分发
        if !self.type_hierarchy.is_empty() {
            let virtual_methods = self.type_hierarchy.resolve_virtual_method(receiver, method);
            for vm in &virtual_methods {
                results.push(ResolvedCallTarget {
                    function_name: method.to_string(),
                    file_path: vm.file_path.clone(),
                    line: vm.line,
                    resolution_method: "type_hierarchy".to_string(),
                    confidence: if vm.is_direct { 0.85 } else { 0.6 },
                    receiver_type: Some(vm.type_name.clone()),
                });
            }
        }

        // Phase 3: 全局名称回退
        if results.is_empty() {
            for (_, node) in &self.call_graph.nodes {
                if node.name == method {
                    results.push(ResolvedCallTarget {
                        function_name: node.name.clone(),
                        file_path: node.file_path.clone(),
                        line: node.start_line,
                        resolution_method: "global_match".to_string(),
                        confidence: 0.4,
                        receiver_type: None,
                    });
                }
            }
        }

        // 按置信度降序
        results.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        results
    }

    // ── 类型层次查询 ──────────────────────────────────

    /// 查询：类的完整继承链
    pub fn query_type_chain(&self, class_name: &str) -> Option<TypeChainResult> {
        let type_info = self.type_hierarchy.types.get(class_name)?;

        let parent_classes = self
            .type_hierarchy
            .extends_map
            .get(class_name)
            .cloned()
            .unwrap_or_default();

        // 查找子类（谁继承了当前类）
        let child_classes: Vec<String> = self
            .type_hierarchy
            .extends_map
            .iter()
            .filter(|(_, parents)| parents.contains(&class_name.to_string()))
            .map(|(child, _)| child.clone())
            .collect();

        // 查找接口实现
        let interface_implementations = self
            .type_hierarchy
            .implementations
            .get(class_name)
            .cloned()
            .unwrap_or_default();

        // 收集所有方法（含继承的）
        let mut methods = Vec::new();
        let all_methods = self.type_hierarchy.resolve_virtual_method(class_name, "");
        // 直接定义的方法
        for method in &type_info.methods {
            methods.push(MethodEvidence {
                name: method.name.clone(),
                file_path: method.file_path.clone(),
                line: method.start_line,
                defined_in_class: class_name.to_string(),
                is_inherited: false,
                is_static: method.is_static,
            });
        }

        Some(TypeChainResult {
            class_name: class_name.to_string(),
            kind: format!("{:?}", type_info.kind),
            file_path: Some(type_info.file_path.clone()),
            line: Some(type_info.start_line),
            parent_classes,
            child_classes,
            methods,
            interface_implementations,
        })
    }

    /// 查询：获取所有已注册的类型名
    pub fn query_all_types(&self) -> Vec<String> {
        self.type_hierarchy.types.keys().cloned().collect()
    }

    // ── 中间件查询 ────────────────────────────────────

    /// 查询：哪些中间件影响指定文件的路由？
    pub fn query_middleware_for_file(&self, file_path: &str) -> Vec<MiddlewareEvidence> {
        let normalized_file = normalize_path(file_path);
        let mut results = Vec::new();

        // Express 中间件
        let route_lines: Vec<usize> = self
            .middleware_model
            .express_routes
            .get(&normalized_file)
            .cloned()
            .unwrap_or_default();

        for mw in &self.middleware_model.express_middleware {
            let mw_file_normalized = normalize_path(&mw.handler_file);

            // 同文件中间件影响所有路由
            let affects_routes: Vec<RouteEvidence> = if mw_file_normalized == normalized_file {
                route_lines
                    .iter()
                    .map(|&line| RouteEvidence {
                        file_path: normalized_file.clone(),
                        line,
                        route_function: None,
                    })
                    .collect()
            } else {
                // 跨文件中间件（如通过 import）影响目标文件的所有路由
                route_lines
                    .iter()
                    .map(|&line| RouteEvidence {
                        file_path: normalized_file.clone(),
                        line,
                        route_function: None,
                    })
                    .collect()
            };

            if !affects_routes.is_empty() || mw_file_normalized == normalized_file {
                results.push(MiddlewareEvidence {
                    handler_name: mw.handler_name.clone(),
                    handler_file: mw.handler_file.clone(),
                    line: mw.line,
                    affects_routes,
                    middleware_type: "express_app_use".to_string(),
                });
            }
        }

        // Django 中间件
        if !self.middleware_model.django_middleware.is_empty() {
            for dmw in &self.middleware_model.django_middleware {
                results.push(MiddlewareEvidence {
                    handler_name: dmw.clone(),
                    handler_file: String::new(),
                    line: 0,
                    affects_routes: vec![],
                    middleware_type: "django_middleware".to_string(),
                });
            }
        }

        results
    }

    /// 查询：获取所有 Express 中间件
    pub fn query_all_middleware(&self) -> Vec<MiddlewareEvidence> {
        let mut results = Vec::new();

        for mw in &self.middleware_model.express_middleware {
            results.push(MiddlewareEvidence {
                handler_name: mw.handler_name.clone(),
                handler_file: mw.handler_file.clone(),
                line: mw.line,
                affects_routes: vec![],
                middleware_type: "express_app_use".to_string(),
            });
        }

        for dmw in &self.middleware_model.django_middleware {
            results.push(MiddlewareEvidence {
                handler_name: dmw.clone(),
                handler_file: String::new(),
                line: 0,
                affects_routes: vec![],
                middleware_type: "django_middleware".to_string(),
            });
        }

        results
    }

    /// 查询：获取指定文件中的所有 Express 路由
    pub fn query_routes_in_file(&self, file_path: &str) -> Vec<RouteEvidence> {
        let normalized_file = normalize_path(file_path);
        self.middleware_model
            .express_routes
            .get(&normalized_file)
            .map(|lines| {
                lines
                    .iter()
                    .map(|&line| RouteEvidence {
                        file_path: normalized_file.clone(),
                        line,
                        route_function: None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    // ── 回调查询 ────────────────────────────────────

    /// 查询：函数 X 注册了哪些匿名回调？
    pub fn query_callbacks(&self, file_path: &str, function_name: &str) -> Vec<CallbackEvidence> {
        let normalized_file = normalize_path(file_path);
        let func_ids = self.find_func_ids(&normalized_file, function_name);

        let mut results = Vec::new();

        for func_id in &func_ids {
            if let Some(node) = self.call_graph.nodes.get(func_id) {
                for ct in &node.calls {
                    if let Some(callee_node) = self.call_graph.nodes.get(&ct.callee) {
                        if callee_node.is_callback {
                            let cb_calls: Vec<CalleeEvidence> = callee_node
                                .calls
                                .iter()
                                .map(|cb_ct| {
                                    if let Some(cb_callee) =
                                        self.call_graph.nodes.get(&cb_ct.callee)
                                    {
                                        CalleeEvidence {
                                            callee_function: cb_callee.name.clone(),
                                            callee_file: Some(cb_callee.file_path.clone()),
                                            callee_line: Some(cb_callee.start_line),
                                            receiver: cb_ct.receiver.clone(),
                                            is_external: cb_callee.is_external,
                                            is_callback: cb_callee.is_callback,
                                            is_resolved: true,
                                        }
                                    } else {
                                        CalleeEvidence {
                                            callee_function: cb_ct.callee.clone(),
                                            callee_file: None,
                                            callee_line: None,
                                            receiver: cb_ct.receiver.clone(),
                                            is_external: true,
                                            is_callback: false,
                                            is_resolved: false,
                                        }
                                    }
                                })
                                .collect();

                            let params: Vec<String> = callee_node
                                .parameters
                                .iter()
                                .map(|p| p.name.clone())
                                .collect();

                            results.push(CallbackEvidence {
                                callback_id: callee_node.id.clone(),
                                callback_name: callee_node.name.clone(),
                                file_path: callee_node.file_path.clone(),
                                start_line: callee_node.start_line,
                                end_line: callee_node.end_line,
                                parent_function: node.name.clone(),
                                parent_call_line: callee_node.parent_call_site.unwrap_or(0),
                                params,
                                calls: cb_calls,
                            });
                        }
                    }
                }
            }
        }

        results
    }

    // ── 变量流追踪 ────────────────────────────────────

    /// 查询：从 source 函数出发，哪些污点流到达了 sink？
    ///
    /// 利用调用图的 BFS 查找所有从 source 到任意 sink 的路径。
    pub fn trace_variable_flow(&self, file_path: &str, function_name: &str) -> VariableFlowResult {
        let normalized_file = normalize_path(file_path);
        let cache_key = (normalized_file.clone(), function_name.to_string());
        if let Some(cached) = self
            .variable_flow_cache
            .lock()
            .ok()
            .and_then(|c| c.get(&cache_key).cloned())
        {
            return cached;
        }

        let source_ids = self.find_func_ids(&normalized_file, function_name);

        let mut all_sink_paths = Vec::new();
        let sink_set: HashSet<&String> = self.call_graph.taint_sinks.iter().collect();

        let mut total_sinks = 0usize;

        for source_id in &source_ids {
            if let Some(source_node) = self.call_graph.nodes.get(source_id) {
                // BFS from source
                let mut visited: HashSet<&String> = HashSet::new();
                let mut queue: VecDeque<(String, Vec<String>)> = VecDeque::new();
                queue.push_back((source_id.clone(), vec![source_id.clone()]));
                visited.insert(source_id);

                while let Some((current_id, path)) = queue.pop_front() {
                    if sink_set.contains(&current_id) && current_id != *source_id {
                        total_sinks += 1;
                        if let Some(sink_node) = self.call_graph.nodes.get(&current_id) {
                            let vuln_type = self.infer_vuln_type_from_name(&sink_node.name);
                            let call_path = self.build_call_path(&path);

                            all_sink_paths.push(TaintPathEvidence {
                                sink_function: sink_node.name.clone(),
                                sink_file: sink_node.file_path.clone(),
                                sink_line: sink_node.start_line,
                                vulnerability_type: vuln_type,
                                path_hops: path.len().saturating_sub(1),
                                path: call_path.steps,
                            });
                        }
                    }

                    if let Some(node) = self.call_graph.nodes.get(&current_id) {
                        for ct in &node.calls {
                            if !visited.contains(&ct.callee) {
                                visited.insert(&ct.callee);
                                let mut new_path = path.clone();
                                new_path.push(ct.callee.clone());
                                queue.push_back((ct.callee.clone(), new_path));
                            }
                        }
                    }
                }
            }
        }

        let source_node = source_ids
            .first()
            .and_then(|id| self.call_graph.nodes.get(id));

        let result = VariableFlowResult {
            variable_name: function_name.to_string(),
            source_file: source_node.map(|n| n.file_path.clone()).unwrap_or_default(),
            source_line: source_node.map(|n| n.start_line).unwrap_or(0),
            source_function: source_node.map(|n| n.name.clone()).unwrap_or_default(),
            flows_to_sinks: all_sink_paths,
            total_sinks_reached: total_sinks,
        };
        if let Ok(mut cache) = self.variable_flow_cache.lock() {
            cache.insert(cache_key, result.clone());
        }
        result
    }

    // ── 调用图统计 ────────────────────────────────────

    /// 获取调用图统计概览
    pub fn query_graph_stats(&self) -> GraphStats {
        if let Ok(cache) = self.stats_cache.lock() {
            if let Some(cached) = cache.clone() {
                return GraphStats {
                    total_nodes: cached.total_nodes,
                    callback_nodes: cached.callback_nodes,
                    taint_sources: cached.taint_sources,
                    taint_sinks: cached.taint_sinks,
                    total_edges: cached.total_edges,
                    cross_file_edges: cached.cross_file_edges,
                    total_files: cached.total_files,
                    type_count: cached.type_count,
                    middleware_count: cached.middleware_count,
                };
            }
        }

        let total_nodes = self.call_graph.nodes.len();
        let callback_nodes = self
            .call_graph
            .nodes
            .values()
            .filter(|n| n.is_callback)
            .count();
        let taint_sources = self.call_graph.taint_sources.len();
        let taint_sinks = self.call_graph.taint_sinks.len();
        let total_edges: usize = self.call_graph.nodes.values().map(|n| n.calls.len()).sum();
        let cross_file_edges: usize = self
            .call_graph
            .nodes
            .values()
            .flat_map(|n| {
                n.calls.iter().filter(|ct| {
                    self.call_graph
                        .nodes
                        .get(&ct.callee)
                        .map(|callee| {
                            normalize_path(&callee.file_path) != normalize_path(&n.file_path)
                        })
                        .unwrap_or(false)
                })
            })
            .count();
        let total_files = self.call_graph.file_functions.len();
        let type_count = self.type_hierarchy.len();
        let middleware_count = self.middleware_model.express_middleware.len()
            + self.middleware_model.django_middleware.len();

        let cached = CachedGraphStats {
            total_nodes,
            callback_nodes,
            taint_sources,
            taint_sinks,
            total_edges,
            cross_file_edges,
            total_files,
            type_count,
            middleware_count,
        };
        if let Ok(mut cache) = self.stats_cache.lock() {
            *cache = Some(cached.clone());
        }

        GraphStats {
            total_nodes,
            callback_nodes,
            taint_sources,
            taint_sinks,
            total_edges,
            cross_file_edges,
            total_files,
            type_count,
            middleware_count,
        }
    }

    /// 获取所有文件列表
    pub fn query_files(&self) -> Vec<String> {
        self.call_graph.file_functions.keys().cloned().collect()
    }

    /// 获取文件中所有函数
    pub fn query_functions_in_file(&self, file_path: &str) -> Vec<FunctionInfo> {
        let normalized_file = normalize_path(file_path);
        self.call_graph
            .file_functions
            .get(&normalized_file)
            .map(|func_ids| {
                func_ids
                    .iter()
                    .filter_map(|id| self.call_graph.nodes.get(id))
                    .map(|node| FunctionInfo {
                        name: node.name.clone(),
                        id: node.id.clone(),
                        line: node.start_line,
                        end_line: node.end_line,
                        is_source: node.is_taint_source,
                        is_sink: node.is_taint_sink,
                        is_callback: node.is_callback,
                        call_count: node.calls.len(),
                        caller_count: node.called_by.len(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// 查询指定行所在的函数（最内层包围函数）。
    ///
    /// 用于 Agent 在缺少 evidence_refs 时也能获得真实函数名，进而查询调用图。
    pub fn query_enclosing_function(&self, file_path: &str, line: usize) -> Option<FunctionInfo> {
        let funcs = self.query_functions_in_file(file_path);
        if funcs.is_empty() {
            return None;
        }
        let candidates: Vec<FunctionInfo> = funcs
            .into_iter()
            .filter(|f| line >= f.line && line <= f.end_line)
            .collect();
        if candidates.is_empty() {
            return None;
        }
        candidates
            .into_iter()
            .min_by_key(|f| f.end_line.saturating_sub(f.line))
    }

    /// 获取所有 taint sources
    pub fn query_all_sources(&self) -> Vec<FunctionInfo> {
        self.call_graph
            .taint_sources
            .iter()
            .filter_map(|id| self.call_graph.nodes.get(id))
            .map(|node| FunctionInfo {
                name: node.name.clone(),
                id: node.id.clone(),
                line: node.start_line,
                end_line: node.end_line,
                is_source: true,
                is_sink: false,
                is_callback: false,
                call_count: node.calls.len(),
                caller_count: node.called_by.len(),
            })
            .collect()
    }

    /// 获取所有 taint sinks
    pub fn query_all_sinks(&self) -> Vec<FunctionInfo> {
        self.call_graph
            .taint_sinks
            .iter()
            .filter_map(|id| self.call_graph.nodes.get(id))
            .map(|node| FunctionInfo {
                name: node.name.clone(),
                id: node.id.clone(),
                line: node.start_line,
                end_line: node.end_line,
                is_source: false,
                is_sink: true,
                is_callback: false,
                call_count: node.calls.len(),
                caller_count: node.called_by.len(),
            })
            .collect()
    }

    // ── 内部辅助方法 ──────────────────────────────────

    /// 根据 file_path + function_name 查找匹配的节点 ID 列表
    fn find_func_ids(&self, normalized_file: &str, function_name: &str) -> Vec<String> {
        // 如果 caller 已经传入了完整调用图节点 ID（如 cross-file taint 产生的精确 ID），
        // 直接返回，避免被 file:method_name 的粗粒度重建覆盖。
        if function_name.contains(':') && self.call_graph.nodes.contains_key(function_name) {
            return vec![function_name.to_string()];
        }

        // 优先精确匹配 (file_path:func_name)
        let exact_id = format!("{}:{}", normalized_file, function_name);
        if self.call_graph.nodes.contains_key(&exact_id) {
            return vec![exact_id];
        }

        // 回退：在该文件中搜索同名函数
        if let Some(func_ids) = self.call_graph.file_functions.get(normalized_file) {
            let matches: Vec<String> = func_ids
                .iter()
                .filter(|id| {
                    self.call_graph
                        .nodes
                        .get(*id)
                        .map(|n| n.name == function_name)
                        .unwrap_or(false)
                })
                .cloned()
                .collect();
            if !matches.is_empty() {
                return matches;
            }
        }

        // 最终回退：全局搜索
        self.call_graph
            .nodes
            .iter()
            .filter(|(_, n)| n.name == function_name)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// 从 sink 函数名推断漏洞类型
    fn infer_vuln_type_from_name(&self, func_name: &str) -> String {
        let lower = func_name.to_lowercase();

        if lower.contains("exec") || lower.contains("system") || lower.contains("spawn") {
            "CommandInjection".to_string()
        } else if lower.contains("query") || lower.contains("sql") || lower.contains("cursor") {
            "SqlInjection".to_string()
        } else if lower.contains("eval") || lower.contains("compile") {
            "CodeInjection".to_string()
        } else if lower.contains("open")
            || lower.contains("readfile")
            || lower.contains("writefile")
        {
            "PathTraversal".to_string()
        } else if lower.contains("fetch")
            || lower.contains("httpclient")
            || lower.contains("request")
        {
            "ServerSideRequestForgery".to_string()
        } else if lower.contains("innerhtml") || lower.contains("document.write") {
            "CrossSiteScripting".to_string()
        } else if lower.contains("redirect") || lower.contains("sendredirect") {
            "OpenRedirect".to_string()
        } else if lower.contains("deserialize")
            || lower.contains("pickle")
            || lower.contains("unserialize")
        {
            "InsecureDeserialization".to_string()
        } else {
            "Generic".to_string()
        }
    }

    /// 解析模块路径到文件路径（从 CrossFileTaintAnalyzer 移植）
    fn resolve_module_to_file(&self, source_module: &str, importing_file: &str) -> Option<String> {
        use std::path::Path;

        let importing_path = Path::new(importing_file);
        let importing_dir = importing_path.parent()?;

        let resolved = if let Some(stripped) = source_module.strip_prefix("./") {
            importing_dir.join(stripped)
        } else {
            importing_dir.join(source_module)
        };

        let extensions = [
            "js", "jsx", "ts", "tsx", "py", "rs", "go", "java", "c", "cpp", "php", "rb",
        ];

        if resolved.exists() && resolved.is_file() {
            return Some(resolved.to_string_lossy().to_string());
        }

        for ext in &extensions {
            let with_ext = resolved.with_extension(ext);
            if with_ext.exists() {
                return Some(with_ext.to_string_lossy().to_string());
            }
        }

        for ext in &["js", "ts", "jsx", "tsx"] {
            let index_file = resolved.join(format!("index.{}", ext));
            if index_file.exists() {
                return Some(index_file.to_string_lossy().to_string());
            }
        }

        let init_py = resolved.join("__init__.py");
        if init_py.exists() {
            return Some(init_py.to_string_lossy().to_string());
        }

        None
    }
}

// ── 辅助输出类型 ──────────────────────────────────────────

/// 调用图统计
#[derive(Debug, Clone, Serialize)]
pub struct GraphStats {
    pub total_nodes: usize,
    pub callback_nodes: usize,
    pub taint_sources: usize,
    pub taint_sinks: usize,
    pub total_edges: usize,
    pub cross_file_edges: usize,
    pub total_files: usize,
    pub type_count: usize,
    pub middleware_count: usize,
}

/// 函数简要信息
#[derive(Debug, Clone, Serialize)]
pub struct FunctionInfo {
    pub name: String,
    pub id: String,
    pub line: usize,
    pub end_line: usize,
    pub is_source: bool,
    pub is_sink: bool,
    pub is_callback: bool,
    pub call_count: usize,
    pub caller_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::cross_file::{CallGraph, CallGraphNode};
    use crate::analysis::middleware::MiddlewareModel;
    use crate::analysis::type_hierarchy::TypeHierarchy;
    use std::sync::Arc;

    fn make_test_engine() -> CallGraphQueryEngine {
        let mut cg = CallGraph::new();

        // handler.js:handleRequest → db.js:executeQuery → exec
        cg.add_node(CallGraphNode {
            id: "handler.js:handleRequest".into(),
            name: "handleRequest".into(),
            file_path: "handler.js".into(),
            start_line: 1,
            end_line: 10,
            parameters: vec![],
            return_type: None,
            calls: vec![], // populated by add_call
            called_by: vec![],
            is_external: false,
            is_taint_source: true,
            is_taint_sink: false,
            sink_type: None,
            sink_match_source: None,
            is_callback: false,
            parent_call_site: None,
        });

        cg.add_node(CallGraphNode {
            id: "db.js:executeQuery".into(),
            name: "executeQuery".into(),
            file_path: "db.js".into(),
            start_line: 1,
            end_line: 5,
            parameters: vec![],
            return_type: None,
            calls: vec![], // populated by add_call
            called_by: vec![],
            is_external: false,
            is_taint_source: false,
            is_taint_sink: false,
            sink_type: None,
            sink_match_source: None,
            is_callback: false,
            parent_call_site: None,
        });

        cg.add_node(CallGraphNode {
            id: "db.js:exec".into(),
            name: "exec".into(),
            file_path: "db.js".into(),
            start_line: 7,
            end_line: 10,
            parameters: vec![],
            return_type: None,
            calls: vec![],
            called_by: vec![],
            is_external: false,
            is_taint_source: false,
            is_taint_sink: true,
            sink_type: None,
            sink_match_source: None,
            is_callback: false,
            parent_call_site: None,
        });

        // Add calls (also populates calls/called_by fields)
        cg.add_call("handler.js:handleRequest", "db.js:executeQuery");
        cg.add_call("db.js:executeQuery", "db.js:exec");

        // Set up file_functions
        cg.file_functions
            .insert("handler.js".into(), vec!["handler.js:handleRequest".into()]);
        cg.file_functions.insert(
            "db.js".into(),
            vec!["db.js:executeQuery".into(), "db.js:exec".into()],
        );

        CallGraphQueryEngine::new(
            Arc::new(cg),
            TypeHierarchy::new(),
            MiddlewareModel::new(),
            HashMap::new(),
        )
    }

    #[test]
    fn test_query_callers() {
        let engine = make_test_engine();
        let callers = engine.query_callers("db.js", "executeQuery");
        assert_eq!(callers.len(), 1);
        assert_eq!(callers[0].caller_function, "handleRequest");
        assert_eq!(callers[0].caller_file, "handler.js");
    }

    #[test]
    fn test_query_callees() {
        let engine = make_test_engine();
        let callees = engine.query_callees("handler.js", "handleRequest");
        assert!(
            callees.len() >= 1,
            "Expected at least 1 callee, got {}",
            callees.len()
        );
        assert!(callees.iter().any(|c| c.callee_function == "executeQuery"));
    }

    #[test]
    fn test_find_call_path() {
        let engine = make_test_engine();
        let path = engine.find_call_path("handler.js", "handleRequest", "db.js", "exec");
        assert!(path.is_some());
        let p = path.unwrap();
        assert_eq!(p.total_hops, 2);
        assert!(p.crosses_files);
        assert_eq!(p.files_in_path.len(), 2);
    }

    #[test]
    fn test_find_call_path_no_path() {
        let engine = make_test_engine();
        // exec doesn't call anything
        let path = engine.find_call_path("db.js", "exec", "handler.js", "handleRequest");
        assert!(path.is_none());
    }

    #[test]
    fn test_query_reachable() {
        let engine = make_test_engine();
        let result = engine.query_reachable("handler.js", "handleRequest", 5);
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.reachable_sinks.len(), 1);
        assert_eq!(r.reachable_sinks[0].func_name, "exec");
        assert_eq!(r.reachable_sinks[0].distance, 2);
    }

    #[test]
    fn test_graph_stats() {
        let engine = make_test_engine();
        let stats = engine.query_graph_stats();
        assert_eq!(stats.total_nodes, 3);
        assert_eq!(stats.taint_sources, 1);
        assert_eq!(stats.taint_sinks, 1);
        // edges include both the originals and the ones added by add_call
        assert!(
            stats.total_edges >= 2,
            "Expected at least 2 edges, got {}",
            stats.total_edges
        );
        assert!(
            stats.cross_file_edges >= 1,
            "Expected at least 1 cross-file edge, got {}",
            stats.cross_file_edges
        );
    }

    #[test]
    fn test_query_callbacks() {
        let mut cg = CallGraph::new();

        cg.add_node(CallGraphNode {
            id: "app.js:setup".into(),
            name: "setup".into(),
            file_path: "app.js".into(),
            start_line: 1,
            end_line: 10,
            parameters: vec![],
            return_type: None,
            calls: vec![CallTarget::new("app.js:setup:5:cb0")],
            called_by: vec![],
            is_external: false,
            is_taint_source: false,
            is_taint_sink: false,
            sink_type: None,
            sink_match_source: None,
            is_callback: false,
            parent_call_site: None,
        });

        cg.add_node(CallGraphNode {
            id: "app.js:setup:5:cb0".into(),
            name: "<callback@5>".into(),
            file_path: "app.js".into(),
            start_line: 2,
            end_line: 4,
            parameters: vec![crate::analysis::cross_file::FunctionParameter {
                name: "req".into(),
                param_type: None,
                may_be_tainted: true,
            }],
            return_type: None,
            calls: vec![CallTarget::new("exec")],
            called_by: vec!["app.js:setup".into()],
            is_external: false,
            is_taint_source: false,
            is_taint_sink: false,
            sink_type: None,
            sink_match_source: None,
            is_callback: true,
            parent_call_site: Some(5),
        });

        cg.file_functions.insert(
            "app.js".into(),
            vec!["app.js:setup".into(), "app.js:setup:5:cb0".into()],
        );
        cg.add_call("app.js:setup", "app.js:setup:5:cb0");

        let engine = CallGraphQueryEngine::new(
            Arc::new(cg),
            TypeHierarchy::new(),
            MiddlewareModel::new(),
            HashMap::new(),
        );

        let callbacks = engine.query_callbacks("app.js", "setup");
        assert_eq!(callbacks.len(), 1);
        assert_eq!(callbacks[0].callback_name, "<callback@5>");
        assert_eq!(callbacks[0].params, vec!["req"]);
        assert_eq!(callbacks[0].calls.len(), 1);
        assert_eq!(callbacks[0].calls[0].callee_function, "exec");
    }
}
