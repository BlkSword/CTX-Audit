// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Agent 工具层
//!
//! 将 `CallGraphQueryEngine` 的查询能力封装为 Specialist / Reviewer 可直接调用的
//! 确定性工具，避免重复构建调用图。

use std::sync::Arc;

use deepaudit_core::{
    CalleeEvidence, CallerEvidence, CallGraphQueryEngine, CallPath, FunctionInfo,
    MiddlewareEvidence, VariableFlowResult,
};

/// Agent 工具上下文
#[derive(Clone)]
pub struct AgentToolContext {
    query_engine: Arc<CallGraphQueryEngine>,
}

impl std::fmt::Debug for AgentToolContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentToolContext")
            .field("query_engine", &"<CallGraphQueryEngine>")
            .finish()
    }
}

impl AgentToolContext {
    pub fn new(query_engine: Arc<CallGraphQueryEngine>) -> Self {
        Self { query_engine }
    }

    /// 查询直接调用者
    pub fn query_callers(&self, file_path: &str, function_name: &str) -> Vec<CallerEvidence> {
        self.query_engine
            .query_callers(file_path, function_name)
    }

    /// 递归查询所有调用者
    pub fn query_all_callers(&self, file_path: &str, function_name: &str) -> Vec<CallerEvidence> {
        self.query_engine
            .query_all_callers(file_path, function_name)
    }

    /// 查询直接调用者
    pub fn query_callees(&self, file_path: &str, function_name: &str) -> Vec<CalleeEvidence> {
        self.query_engine
            .query_callees(file_path, function_name)
    }

    /// 递归查询所有被调用者
    pub fn query_all_callees(&self, file_path: &str, function_name: &str) -> Vec<CalleeEvidence> {
        self.query_engine
            .query_all_callees(file_path, function_name)
    }

    /// 查找 source→sink 调用路径
    pub fn find_call_path(
        &self,
        source_file: &str,
        source_function: &str,
        sink_file: &str,
        sink_function: &str,
    ) -> Option<CallPath> {
        self.query_engine.find_call_path(
            source_file,
            source_function,
            sink_file,
            sink_function,
        )
    }

    /// 追踪变量/函数从 source 出发到达的所有 sink
    pub fn trace_variable_flow(&self, file_path: &str, function_name: &str) -> VariableFlowResult {
        self.query_engine
            .trace_variable_flow(file_path, function_name)
    }

    /// 列出文件中的函数
    pub fn query_functions_in_file(&self, file_path: &str) -> Vec<FunctionInfo> {
        self.query_engine.query_functions_in_file(file_path)
    }

    /// 查询文件关联的中间件
    pub fn query_middleware_for_file(&self, file_path: &str) -> Vec<MiddlewareEvidence> {
        self.query_engine.query_middleware_for_file(file_path)
    }

    /// 判断 sink 是否可能从某个 source 可达：
    /// 若 evidence_refs 中提供了 source/sink，直接查路径；
    /// 否则返回 None，表示无法自动推断。
    pub fn try_find_attack_path(
        &self,
        source_file: &str,
        source_function: &str,
        sink_file: &str,
        sink_function: &str,
    ) -> Option<CallPath> {
        if source_function.is_empty() || sink_function.is_empty() {
            return None;
        }
        self.find_call_path(source_file, source_function, sink_file, sink_function)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deepaudit_core::CrossFileTaintAnalyzer;
    use std::path::Path;

    fn build_engine(project_path: &Path) -> Arc<CallGraphQueryEngine> {
        let mut analyzer = CrossFileTaintAnalyzer::new();
        let result = analyzer.analyze_project(project_path);
        Arc::new(CallGraphQueryEngine::from_result(&result))
    }

    #[test]
    fn test_tool_context_queries_functions() {
        let engine = build_engine(Path::new("."));
        let ctx = AgentToolContext::new(engine);
        let funcs = ctx.query_functions_in_file("Cargo.toml");
        // Cargo.toml 不是代码文件，应该没有函数索引
        assert!(funcs.is_empty());
    }

    #[test]
    fn test_tool_context_empty_source_sink_returns_none() {
        let engine = build_engine(Path::new("."));
        let ctx = AgentToolContext::new(engine);
        let path = ctx.try_find_attack_path("a.js", "", "b.js", "sink");
        assert!(path.is_none());
    }
}
