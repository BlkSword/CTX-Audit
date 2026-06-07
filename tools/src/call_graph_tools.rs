// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 调用图查询工具
//!
//! 将 CallGraphQueryEngine 的查询能力暴露为 LLM 可调用的工具。
//! 每个工具返回基于 AST 解析的确定性调用图数据，为 LLM 安全审计提供可靠证据。

use async_trait::async_trait;
use std::path::Path;
use std::sync::Arc;

use crate::registry::{Tool, ToolRegistry};
use crate::bridge::{
    ToolCategory, ToolDefinition, ToolParameter, ToolParameterType, ToolResult, ToolError,
};

use deepaudit_core::{
    CrossFileTaintAnalyzer, CallGraphQueryEngine,
};

/// 延迟构建查询引擎（避免每次工具调用都重新分析项目）
fn build_query_engine(project_path: &str) -> Result<CallGraphQueryEngine, ToolError> {
    let mut analyzer = CrossFileTaintAnalyzer::new();
    let result = analyzer.analyze_project(std::path::Path::new(project_path));
    Ok(CallGraphQueryEngine::from_result(&result))
}

// ── 1. query_callers ──────────────────────────────────

/// 查询函数调用者工具
///
/// 给定 file_path + function_name，返回所有直接调用该函数的函数列表，
/// 包含调用者文件、行号、receiver 信息和解析方法。
pub struct QueryCallersTool {
    project_path: String,
}

impl QueryCallersTool {
    pub fn new(project_path: String) -> Self {
        Self { project_path }
    }
}

#[async_trait]
impl Tool for QueryCallersTool {
    fn name(&self) -> &str {
        "query_callers"
    }

    fn description(&self) -> &str {
        "查询跨文件调用图：找出所有调用指定函数的函数。输入文件路径和函数名，返回调用者列表（含文件、行号、receiver 信息）。用于从 sink 反向追踪到入口点。"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Analysis
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(self.name(), self.description(), self.category())
            .add_parameter(ToolParameter {
                name: "project_path".to_string(),
                param_type: ToolParameterType::String,
                description: "项目根目录路径".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: Some("path".to_string()),
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "file_path".to_string(),
                param_type: ToolParameterType::String,
                description: "目标函数所在的文件路径（相对于项目根目录）".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: Some("path".to_string()),
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "function_name".to_string(),
                param_type: ToolParameterType::String,
                description: "目标函数名称".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "recursive".to_string(),
                param_type: ToolParameterType::Boolean,
                description: "是否递归查找所有调用者（默认 false，仅直接调用者）".to_string(),
                required: false,
                default: Some(serde_json::json!(false)),
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ToolError> {
        let file_path = input["file_path"].as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 file_path 参数".to_string()))?;
        let function_name = input["function_name"].as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 function_name 参数".to_string()))?;
        let recursive = input["recursive"].as_bool().unwrap_or(false);

        let project_path = input["project_path"].as_str().unwrap_or(&self.project_path);
        let engine = build_query_engine(project_path)?;

        let callers = if recursive {
            engine.query_all_callers(file_path, function_name)
        } else {
            engine.query_callers(file_path, function_name)
        };

        if callers.is_empty() {
            return Ok(ToolResult::text(format!(
                "未找到调用 '{}' (文件: {}) 的函数", function_name, file_path
            )));
        }

        let summary = format!(
            "找到 {} 个{}调用 '{}' 的函数",
            callers.len(),
            if recursive { "（递归）" } else { "" },
            function_name
        );

        Ok(ToolResult::json(
            serde_json::json!({
                "target": { "file": file_path, "function": function_name },
                "count": callers.len(),
                "recursive": recursive,
                "callers": callers,
            }),
            Some(summary),
        ))
    }
}

// ── 2. query_callees ──────────────────────────────────

/// 查询函数被调用者工具
pub struct QueryCalleesTool {
    project_path: String,
}

impl QueryCalleesTool {
    pub fn new(project_path: String) -> Self {
        Self { project_path }
    }
}

#[async_trait]
impl Tool for QueryCalleesTool {
    fn name(&self) -> &str {
        "query_callees"
    }

    fn description(&self) -> &str {
        "查询跨文件调用图：找出指定函数调用了哪些函数。输入文件路径和函数名，返回被调用函数列表（含是否外部函数、是否回调、receiver）。用于从入口点追踪数据流到 sink。"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Analysis
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(self.name(), self.description(), self.category())
            .add_parameter(ToolParameter {
                name: "project_path".to_string(),
                param_type: ToolParameterType::String,
                description: "项目根目录路径".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: Some("path".to_string()),
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "file_path".to_string(),
                param_type: ToolParameterType::String,
                description: "目标函数所在的文件路径".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: Some("path".to_string()),
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "function_name".to_string(),
                param_type: ToolParameterType::String,
                description: "目标函数名称".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "recursive".to_string(),
                param_type: ToolParameterType::Boolean,
                description: "是否递归查找所有被调用者（默认 false）".to_string(),
                required: false,
                default: Some(serde_json::json!(false)),
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ToolError> {
        let file_path = input["file_path"].as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 file_path 参数".to_string()))?;
        let function_name = input["function_name"].as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 function_name 参数".to_string()))?;
        let recursive = input["recursive"].as_bool().unwrap_or(false);

        let project_path = input["project_path"].as_str().unwrap_or(&self.project_path);
        let engine = build_query_engine(project_path)?;

        let callees = if recursive {
            engine.query_all_callees(file_path, function_name)
        } else {
            engine.query_callees(file_path, function_name)
        };

        if callees.is_empty() {
            return Ok(ToolResult::text(format!(
                "'{}' (文件: {}) 未调用任何已知函数", function_name, file_path
            )));
        }

        let summary = format!(
            "'{}' 调用了 {} 个{}函数",
            function_name,
            callees.len(),
            if recursive { "（递归）" } else { "" }
        );

        Ok(ToolResult::json(
            serde_json::json!({
                "source": { "file": file_path, "function": function_name },
                "count": callees.len(),
                "recursive": recursive,
                "callees": callees,
            }),
            Some(summary),
        ))
    }
}

// ── 3. find_call_path ─────────────────────────────────

/// 查找调用路径工具
pub struct FindCallPathTool {
    project_path: String,
}

impl FindCallPathTool {
    pub fn new(project_path: String) -> Self {
        Self { project_path }
    }
}

#[async_trait]
impl Tool for FindCallPathTool {
    fn name(&self) -> &str {
        "find_call_path"
    }

    fn description(&self) -> &str {
        "在跨文件调用图中查找从 source 函数到 sink 函数的精确调用路径。返回每一步的文件、函数、行号。如果路径存在，则证明 source 到 sink 是可达的——这是确定性的污点流证据。用于验证潜在漏洞的真实性。"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Analysis
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(self.name(), self.description(), self.category())
            .add_parameter(ToolParameter {
                name: "project_path".to_string(),
                param_type: ToolParameterType::String,
                description: "项目根目录路径".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: Some("path".to_string()),
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "source_file".to_string(),
                param_type: ToolParameterType::String,
                description: "源函数所在文件路径".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: Some("path".to_string()),
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "source_function".to_string(),
                param_type: ToolParameterType::String,
                description: "源函数名称（污点入口）".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "sink_file".to_string(),
                param_type: ToolParameterType::String,
                description: "汇函数所在文件路径".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: Some("path".to_string()),
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "sink_function".to_string(),
                param_type: ToolParameterType::String,
                description: "汇函数名称（危险操作）".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ToolError> {
        let source_file = input["source_file"].as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 source_file 参数".to_string()))?;
        let source_function = input["source_function"].as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 source_function 参数".to_string()))?;
        let sink_file = input["sink_file"].as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 sink_file 参数".to_string()))?;
        let sink_function = input["sink_function"].as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 sink_function 参数".to_string()))?;

        let project_path = input["project_path"].as_str().unwrap_or(&self.project_path);
        let engine = build_query_engine(project_path)?;

        match engine.find_call_path(source_file, source_function, sink_file, sink_function) {
            Some(path) => {
                let summary = if path.crosses_files {
                    format!(
                        "找到调用路径: {} 跳, 跨越 {} 个文件",
                        path.total_hops, path.files_in_path.len()
                    )
                } else {
                    format!("找到调用路径: {} 跳 (同文件)", path.total_hops)
                };

                Ok(ToolResult::json(
                    serde_json::json!({
                        "path_exists": true,
                        "total_hops": path.total_hops,
                        "crosses_files": path.crosses_files,
                        "files_in_path": path.files_in_path,
                        "steps": path.steps,
                    }),
                    Some(summary),
                ))
            }
            None => {
                Ok(ToolResult::json(
                    serde_json::json!({
                        "path_exists": false,
                        "source": { "file": source_file, "function": source_function },
                        "sink": { "file": sink_file, "function": sink_function },
                        "message": format!(
                            "在调用图中未找到从 '{}' ({}) 到 '{}' ({}) 的路径",
                            source_function, source_file, sink_function, sink_file
                        ),
                    }),
                    Some("未找到调用路径: source 和 sink 之间没有可达的调用链".to_string()),
                ))
            }
        }
    }
}

// ── 4. resolve_method_call ────────────────────────────

/// 解析方法调用工具
pub struct ResolveMethodCallTool {
    project_path: String,
}

impl ResolveMethodCallTool {
    pub fn new(project_path: String) -> Self {
        Self { project_path }
    }
}

#[async_trait]
impl Tool for ResolveMethodCallTool {
    fn name(&self) -> &str {
        "resolve_method_call"
    }

    fn description(&self) -> &str {
        "解析 obj.method() 这样的方法调用到实际的函数实现。使用 import 别名、receiver 追踪和类型层次来找到目标函数。返回候选实现列表（含解析方法和置信度）。用于确定 db.query() 或 logger.log() 等模糊调用的精确目标。"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Analysis
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(self.name(), self.description(), self.category())
            .add_parameter(ToolParameter {
                name: "project_path".to_string(),
                param_type: ToolParameterType::String,
                description: "项目根目录路径".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: Some("path".to_string()),
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "file_path".to_string(),
                param_type: ToolParameterType::String,
                description: "包含该调用的文件路径".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: Some("path".to_string()),
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "line".to_string(),
                param_type: ToolParameterType::Integer,
                description: "调用所在的行号".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "receiver".to_string(),
                param_type: ToolParameterType::String,
                description: "方法的 receiver 变量名（如 db.query() 中的 'db'）".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "method".to_string(),
                param_type: ToolParameterType::String,
                description: "方法名（如 db.query() 中的 'query'）".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ToolError> {
        let file_path = input["file_path"].as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 file_path 参数".to_string()))?;
        let line = input["line"].as_u64()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 line 参数".to_string()))? as usize;
        let receiver = input["receiver"].as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 receiver 参数".to_string()))?;
        let method = input["method"].as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 method 参数".to_string()))?;

        let project_path = input["project_path"].as_str().unwrap_or(&self.project_path);
        let engine = build_query_engine(project_path)?;

        let targets = engine.resolve_method_call(file_path, line, receiver, method);

        if targets.is_empty() {
            return Ok(ToolResult::text(format!(
                "未找到 {}.{}() ({}:{}) 的解析目标", receiver, method, file_path, line
            )));
        }

        let best = &targets[0];
        let summary = format!(
            "找到 {} 个候选目标, 最佳: {} ({}:{} 置信度 {:.0}%) [{}]",
            targets.len(),
            best.function_name, best.file_path, best.line,
            best.confidence * 100.0, best.resolution_method
        );

        Ok(ToolResult::json(
            serde_json::json!({
                "call": {
                    "receiver": receiver,
                    "method": method,
                    "file": file_path,
                    "line": line,
                },
                "candidates": targets,
                "best_match": targets.first(),
            }),
            Some(summary),
        ))
    }
}

// ── 5. get_type_hierarchy ─────────────────────────────

/// 获取类型层次工具
pub struct GetTypeHierarchyTool {
    project_path: String,
}

impl GetTypeHierarchyTool {
    pub fn new(project_path: String) -> Self {
        Self { project_path }
    }
}

#[async_trait]
impl Tool for GetTypeHierarchyTool {
    fn name(&self) -> &str {
        "get_type_hierarchy"
    }

    fn description(&self) -> &str {
        "获取类的继承层次结构：父类、子类、接口实现、所有方法（含继承的）。用于理解虚方法分发——当看到接口类型的 receiver 时，用它找出所有可能的实现类。"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Analysis
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(self.name(), self.description(), self.category())
            .add_parameter(ToolParameter {
                name: "project_path".to_string(),
                param_type: ToolParameterType::String,
                description: "项目根目录路径".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: Some("path".to_string()),
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "class_name".to_string(),
                param_type: ToolParameterType::String,
                description: "类名".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ToolError> {
        let class_name = input["class_name"].as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 class_name 参数".to_string()))?;

        let project_path = input["project_path"].as_str().unwrap_or(&self.project_path);
        let engine = build_query_engine(project_path)?;

        match engine.query_type_chain(class_name) {
            Some(chain) => {
                let summary = format!(
                    "{} ({}) — {} 个父类, {} 个子类, {} 个方法",
                    chain.class_name, chain.kind,
                    chain.parent_classes.len(),
                    chain.child_classes.len(),
                    chain.methods.len(),
                );

                Ok(ToolResult::json(
                    serde_json::json!(chain),
                    Some(summary),
                ))
            }
            None => {
                Ok(ToolResult::text(format!(
                    "未找到类 '{}' 的类型信息（可能在项目中不存在或被排除）", class_name
                )))
            }
        }
    }
}

// ── 6. get_middleware_chain ────────────────────────────

/// 获取中间件链工具
pub struct GetMiddlewareChainTool {
    project_path: String,
}

impl GetMiddlewareChainTool {
    pub fn new(project_path: String) -> Self {
        Self { project_path }
    }
}

#[async_trait]
impl Tool for GetMiddlewareChainTool {
    fn name(&self) -> &str {
        "get_middleware_chain"
    }

    fn description(&self) -> &str {
        "获取 Express app.use() / Django MIDDLEWARE 中间件信息。返回哪些中间件影响了哪些路由文件。用于查找认证绕过漏洞——如果某个路由没有经过 authMiddleware，则可能存在未授权访问。"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Analysis
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(self.name(), self.description(), self.category())
            .add_parameter(ToolParameter {
                name: "project_path".to_string(),
                param_type: ToolParameterType::String,
                description: "项目根目录路径".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: Some("path".to_string()),
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "file_path".to_string(),
                param_type: ToolParameterType::String,
                description: "要查询的文件路径（可选，不填返回所有中间件）".to_string(),
                required: false,
                default: None,
                enum_values: None,
                format: Some("path".to_string()),
                items: None,
                properties: None,
            })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ToolError> {
        let project_path = input["project_path"].as_str().unwrap_or(&self.project_path);
        let engine = build_query_engine(project_path)?;

        if let Some(file_path) = input["file_path"].as_str() {
            let middleware = engine.query_middleware_for_file(file_path);
            let routes = engine.query_routes_in_file(file_path);

            let summary = format!(
                "文件 '{}': {} 个中间件, {} 个路由",
                file_path,
                middleware.len(),
                routes.len(),
            );

            Ok(ToolResult::json(
                serde_json::json!({
                    "file_path": file_path,
                    "middleware": middleware,
                    "routes": routes,
                }),
                Some(summary),
            ))
        } else {
            let all_mw = engine.query_all_middleware();
            let summary = format!("共检测到 {} 个中间件注册", all_mw.len());

            Ok(ToolResult::json(
                serde_json::json!({
                    "all_middleware": all_mw,
                    "count": all_mw.len(),
                }),
                Some(summary),
            ))
        }
    }
}

// ── 7. trace_variable_flow ────────────────────────────

/// 变量流追踪工具
pub struct TraceVariableFlowTool {
    project_path: String,
}

impl TraceVariableFlowTool {
    pub fn new(project_path: String) -> Self {
        Self { project_path }
    }
}

#[async_trait]
impl Tool for TraceVariableFlowTool {
    fn name(&self) -> &str {
        "trace_variable_flow"
    }

    fn description(&self) -> &str {
        "追踪污点变量在跨文件调用图中的传播路径。从 source 函数出发，找出所有可达的 sink 及其完整调用路径。返回每个 sink 的路径步骤、跳数和漏洞类型。用于快速判断一个 entry point 是否存在真正的安全风险。"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Analysis
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(self.name(), self.description(), self.category())
            .add_parameter(ToolParameter {
                name: "project_path".to_string(),
                param_type: ToolParameterType::String,
                description: "项目根目录路径".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: Some("path".to_string()),
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "file_path".to_string(),
                param_type: ToolParameterType::String,
                description: "源函数所在文件路径".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: Some("path".to_string()),
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "function_name".to_string(),
                param_type: ToolParameterType::String,
                description: "源函数名称（如 handleRequest、getUserInput 等）".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ToolError> {
        let file_path = input["file_path"].as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 file_path 参数".to_string()))?;
        let function_name = input["function_name"].as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 function_name 参数".to_string()))?;

        let project_path = input["project_path"].as_str().unwrap_or(&self.project_path);
        let engine = build_query_engine(project_path)?;

        let flow = engine.trace_variable_flow(file_path, function_name);

        let summary = if flow.total_sinks_reached > 0 {
            format!(
                "'{}' 可到达 {} 个 sink: {}",
                function_name,
                flow.total_sinks_reached,
                flow.flows_to_sinks.iter()
                    .map(|f| format!("{}({})", f.sink_function, f.vulnerability_type))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        } else {
            format!("'{}' 未到达任何 sink", function_name)
        };

        Ok(ToolResult::json(
            serde_json::json!({
                "source": {
                    "function": flow.source_function,
                    "file": flow.source_file,
                    "line": flow.source_line,
                },
                "total_sinks_reached": flow.total_sinks_reached,
                "flows_to_sinks": flow.flows_to_sinks,
            }),
            Some(summary),
        ))
    }
}

// ── 8. get_graph_stats ────────────────────────────────

/// 调用图统计工具
pub struct GetGraphStatsTool {
    project_path: String,
}

impl GetGraphStatsTool {
    pub fn new(project_path: String) -> Self {
        Self { project_path }
    }
}

#[async_trait]
impl Tool for GetGraphStatsTool {
    fn name(&self) -> &str {
        "get_graph_stats"
    }

    fn description(&self) -> &str {
        "获取跨文件调用图的统计概览：节点数、边数、跨文件边数、taint source/sink 数量、回调数量、类型数、中间件数。先用此工具了解项目规模和分析覆盖范围。"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Analysis
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(self.name(), self.description(), self.category())
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ToolError> {
        let project_path = input["project_path"].as_str().unwrap_or(&self.project_path);
        let engine = build_query_engine(project_path)?;
        let stats = engine.query_graph_stats();

        let summary = format!(
            "调用图统计: {} 个函数节点 ({} 回调), {} 条边 ({} 跨文件), {} 个 source, {} 个 sink, {} 个文件, {} 个类型, {} 个中间件",
            stats.total_nodes,
            stats.callback_nodes,
            stats.total_edges,
            stats.cross_file_edges,
            stats.taint_sources,
            stats.taint_sinks,
            stats.total_files,
            stats.type_count,
            stats.middleware_count,
        );

        Ok(ToolResult::json(
            serde_json::json!(stats),
            Some(summary),
        ))
    }
}

// ── 9. list_functions ─────────────────────────────────

/// 列出文件中的函数工具
pub struct ListFunctionsTool {
    project_path: String,
}

impl ListFunctionsTool {
    pub fn new(project_path: String) -> Self {
        Self { project_path }
    }
}

#[async_trait]
impl Tool for ListFunctionsTool {
    fn name(&self) -> &str {
        "list_functions"
    }

    fn description(&self) -> &str {
        "列出指定文件中所有被调用图索引的函数。返回每个函数的名称、行号、是否为 source/sink/callback、调用数和被调用数。用于快速浏览文件结构。"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Analysis
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(self.name(), self.description(), self.category())
            .add_parameter(ToolParameter {
                name: "project_path".to_string(),
                param_type: ToolParameterType::String,
                description: "项目根目录路径".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: Some("path".to_string()),
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "file_path".to_string(),
                param_type: ToolParameterType::String,
                description: "文件路径（相对于项目根目录）".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: Some("path".to_string()),
                items: None,
                properties: None,
            })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ToolError> {
        let file_path = input["file_path"].as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 file_path 参数".to_string()))?;

        let project_path = input["project_path"].as_str().unwrap_or(&self.project_path);
        let engine = build_query_engine(project_path)?;
        let functions = engine.query_functions_in_file(file_path);

        if functions.is_empty() {
            return Ok(ToolResult::text(format!(
                "文件 '{}' 中没有被索引的函数", file_path
            )));
        }

        let sources: Vec<_> = functions.iter().filter(|f| f.is_source).collect();
        let sinks: Vec<_> = functions.iter().filter(|f| f.is_sink).collect();
        let cbs: Vec<_> = functions.iter().filter(|f| f.is_callback).collect();

        let summary = format!(
            "文件 '{}': {} 个函数 ({} source, {} sink, {} callback)",
            file_path,
            functions.len(),
            sources.len(),
            sinks.len(),
            cbs.len(),
        );

        Ok(ToolResult::json(
            serde_json::json!({
                "file_path": file_path,
                "total": functions.len(),
                "source_count": sources.len(),
                "sink_count": sinks.len(),
                "callback_count": cbs.len(),
                "functions": functions,
            }),
            Some(summary),
        ))
    }
}

// ── 注册所有调用图查询工具 ──────────────────────────────

/// 注册所有调用图查询工具到 ToolRegistry
pub async fn register_call_graph_tools(
    registry: &Arc<ToolRegistry>,
) {
    // project_path 现在从 input JSON 中读取，构造时传空字符串
    let tools: Vec<Arc<dyn Tool>> = vec![
        Arc::new(QueryCallersTool::new(String::new())),
        Arc::new(QueryCalleesTool::new(String::new())),
        Arc::new(FindCallPathTool::new(String::new())),
        Arc::new(ResolveMethodCallTool::new(String::new())),
        Arc::new(GetTypeHierarchyTool::new(String::new())),
        Arc::new(GetMiddlewareChainTool::new(String::new())),
        Arc::new(TraceVariableFlowTool::new(String::new())),
        Arc::new(GetGraphStatsTool::new(String::new())),
        Arc::new(ListFunctionsTool::new(String::new())),
    ];

    for tool in tools {
        if let Err(e) = registry.register(tool).await {
            tracing::warn!("Failed to register call graph tool: {}", e);
        }
    }
}
