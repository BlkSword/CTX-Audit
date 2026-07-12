// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Agent 工具层
//!
//! 将 `ctx-audit-tools` 的 `ToolRegistry` 与缓存的 `CallGraphQueryEngine` 一起包装为
//! Specialist / Reviewer 可直接调用的确定性工具上下文。
//!
//! - 同步查询方法直接命中缓存的 `CallGraphQueryEngine`，避免重复构建调用图。
//! - `ToolRegistry` 保留给未来需要动态发现/执行工具（如 LLM tool-use）的场景。

use std::sync::Arc;

use ctx_audit_tools::{register_all_tools, ToolRegistry};
use deepaudit_core::{
    CallGraphQueryEngine, CallPath, CalleeEvidence, CallerEvidence, FunctionInfo,
    MiddlewareEvidence, VariableFlowResult,
};

/// Agent 工具上下文
#[derive(Clone)]
pub struct AgentToolContext {
    /// 工具注册表：包装 ctx-audit-tools 提供的所有内置工具
    registry: Arc<ToolRegistry>,
    /// 缓存的调用图查询引擎
    query_engine: Arc<CallGraphQueryEngine>,
    /// 项目路径（用于注册表工具）
    project_path: String,
}

impl std::fmt::Debug for AgentToolContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentToolContext")
            .field("registry", &"<ToolRegistry>")
            .field("query_engine", &"<CallGraphQueryEngine>")
            .field("project_path", &self.project_path)
            .finish()
    }
}

impl AgentToolContext {
    /// 从缓存的查询引擎创建工具上下文（不填充注册表，供测试使用）
    pub fn new(query_engine: Arc<CallGraphQueryEngine>) -> Self {
        Self {
            registry: Arc::new(ToolRegistry::new()),
            query_engine,
            project_path: String::new(),
        }
    }

    /// 从缓存的查询引擎创建工具上下文，并注册所有 ctx-audit-tools 内置工具
    pub async fn new_with_registry(
        query_engine: Arc<CallGraphQueryEngine>,
        project_path: impl Into<String>,
    ) -> Self {
        let project_path = project_path.into();
        let registry = Arc::new(ToolRegistry::new());
        register_all_tools(
            &registry,
            project_path.clone(),
            None,
            Some(query_engine.clone()),
        )
        .await;
        Self {
            registry,
            query_engine,
            project_path,
        }
    }

    /// 直接从项目路径构建：分析项目、生成查询引擎并注册所有工具
    pub async fn from_project(project_path: impl Into<String>) -> Self {
        let project_path = project_path.into();
        let mut analyzer = deepaudit_core::CrossFileTaintAnalyzer::new();
        let result = analyzer.analyze_project(std::path::Path::new(&project_path));
        let query_engine = Arc::new(CallGraphQueryEngine::from_result(&result));
        Self::new_with_registry(query_engine, project_path).await
    }

    /// 获取底层工具注册表
    pub fn registry(&self) -> &Arc<ToolRegistry> {
        &self.registry
    }

    /// 获取缓存的调用图查询引擎
    pub fn query_engine(&self) -> &Arc<CallGraphQueryEngine> {
        &self.query_engine
    }

    /// 执行注册表中的任意工具（异步）
    pub async fn execute_tool(
        &self,
        name: &str,
        input: serde_json::Value,
    ) -> Result<ctx_audit_tools::ToolResult, ctx_audit_tools::ToolError> {
        self.registry.execute(name, input).await
    }

    /// 查询直接调用者
    pub fn query_callers(&self, file_path: &str, function_name: &str) -> Vec<CallerEvidence> {
        self.query_engine.query_callers(file_path, function_name)
    }

    /// 递归查询所有调用者
    pub fn query_all_callers(&self, file_path: &str, function_name: &str) -> Vec<CallerEvidence> {
        self.query_engine
            .query_all_callers(file_path, function_name)
    }

    /// 查询直接调用者
    pub fn query_callees(&self, file_path: &str, function_name: &str) -> Vec<CalleeEvidence> {
        self.query_engine.query_callees(file_path, function_name)
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
        self.query_engine
            .find_call_path(source_file, source_function, sink_file, sink_function)
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

    /// 查询指定行所在的函数（最内层包围函数）
    pub fn query_enclosing_function(&self, file_path: &str, line: usize) -> Option<FunctionInfo> {
        self.query_engine.query_enclosing_function(file_path, line)
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

    #[tokio::test]
    async fn test_tool_context_wraps_registry() {
        let engine = build_engine(Path::new("."));
        let ctx = AgentToolContext::new_with_registry(engine, ".").await;
        let names = ctx.registry.list_tool_names().await;
        assert!(!names.is_empty(), "注册表应包含 ctx-audit-tools 内置工具");
        assert!(names.iter().any(|n| n == "find_call_path"));
    }
}
