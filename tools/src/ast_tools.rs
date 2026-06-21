// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! AST 和符号检索工具
//!
//! 集成 deepaudit-core 的 AST 引擎功能到工具系统

use async_trait::async_trait;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use crate::bridge::{
    ToolCategory, ToolDefinition, ToolError, ToolParameter, ToolParameterType, ToolResult,
};
use crate::registry::{Tool, ToolRegistry};

use deepaudit_core::{ASTEngine, QueryEngine, Symbol};

/// 符号搜索工具
pub struct SearchSymbolTool {
    project_path: String,
    ast_engine: Arc<ASTEngine>,
}

impl SearchSymbolTool {
    pub fn new(project_path: String, ast_engine: Arc<ASTEngine>) -> Self {
        Self {
            project_path,
            ast_engine,
        }
    }
}

#[async_trait]
impl Tool for SearchSymbolTool {
    fn name(&self) -> &str {
        "search_symbol"
    }

    fn description(&self) -> &str {
        "搜索符号定义（函数、类、变量等）"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Search
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(self.name(), self.description(), self.category())
            .add_parameter(ToolParameter {
                name: "query".to_string(),
                param_type: ToolParameterType::String,
                description: "搜索查询（符号名称或部分名称）".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "limit".to_string(),
                param_type: ToolParameterType::Integer,
                description: "最大结果数量".to_string(),
                required: false,
                default: Some(serde_json::json!(20)),
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ToolError> {
        let query = input["query"]
            .as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 query 参数".to_string()))?;

        let limit = input["limit"].as_u64().unwrap_or(20) as usize;

        // 使用 AST 引擎搜索符号
        let symbols = self.ast_engine.search_symbols(query)
            .map_err(|e| {
                let error_msg = format!("{}", e);
                if error_msg.contains("No cache loaded") || error_msg.contains("cache") {
                    ToolError::ExecutionFailed(
                        "符号索引未就绪。请先使用 index_project 工具索引项目，或使用 text_search 工具进行文本搜索。".to_string()
                    )
                } else {
                    ToolError::ExecutionFailed(format!("符号搜索失败: {}", e))
                }
            })?;

        // 限制结果数量
        let symbols: Vec<_> = symbols.into_iter().take(limit).collect();

        if symbols.is_empty() {
            return Ok(ToolResult::text(format!("未找到匹配 '{}' 的符号", query)));
        }

        // 格式化结果
        let mut result = format!("找到 {} 个符号:\n\n", symbols.len());

        for symbol in &symbols {
            result.push_str(&format!(
                "• {} ({})\n  文件: {}:{}\n  类型: {}\n",
                symbol.name,
                symbol.kind_to_string(),
                symbol.file_path,
                symbol.start_line,
                symbol.kind_to_string()
            ));

            if !symbol.package.is_empty() {
                result.push_str(&format!("  包: {}\n", symbol.package));
            }

            if !symbol.parent_classes.is_empty() {
                result.push_str(&format!("  继承: {}\n", symbol.parent_classes.join(", ")));
            }

            result.push('\n');
        }

        Ok(ToolResult::text(result))
    }
}

/// 获取文件结构工具
pub struct GetFileStructureTool {
    project_path: String,
    ast_engine: Arc<ASTEngine>,
}

impl GetFileStructureTool {
    pub fn new(project_path: String, ast_engine: Arc<ASTEngine>) -> Self {
        Self {
            project_path,
            ast_engine,
        }
    }
}

#[async_trait]
impl Tool for GetFileStructureTool {
    fn name(&self) -> &str {
        "get_file_structure"
    }

    fn description(&self) -> &str {
        "获取文件的符号结构（类、函数、方法等）"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Analysis
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(self.name(), self.description(), self.category()).add_parameter(
            ToolParameter {
                name: "file_path".to_string(),
                param_type: ToolParameterType::String,
                description: "文件路径（相对于项目根目录）".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: Some("path".to_string()),
                items: None,
                properties: None,
            },
        )
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ToolError> {
        let file_path = input["file_path"]
            .as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 file_path 参数".to_string()))?;

        let full_path = Path::new(&self.project_path).join(file_path);

        if !full_path.exists() {
            return Ok(ToolResult::error(
                format!("文件不存在: {}", file_path),
                None,
            ));
        }

        // 获取文件结构
        let symbols = self
            .ast_engine
            .get_file_structure(&full_path.to_string_lossy())
            .map_err(|e| ToolError::ExecutionFailed(format!("获取文件结构失败: {}", e)))?;

        if symbols.is_empty() {
            return Ok(ToolResult::text(format!(
                "文件 '{}' 不包含任何符号",
                file_path
            )));
        }

        // 按类型分组
        let mut classes = Vec::new();
        let mut functions = Vec::new();
        let mut methods = Vec::new();
        let mut other = Vec::new();

        for symbol in &symbols {
            match symbol.kind {
                deepaudit_core::SymbolKind::Class => classes.push(symbol),
                deepaudit_core::SymbolKind::Function => functions.push(symbol),
                deepaudit_core::SymbolKind::Method => methods.push(symbol),
                _ => other.push(symbol),
            }
        }

        let mut result = format!("文件 '{}' 的结构:\n\n", file_path);

        if !classes.is_empty() {
            result.push_str("类:\n");
            for cls in &classes {
                result.push_str(&format!("  • {} (行 {})\n", cls.name, cls.start_line));
            }
            result.push('\n');
        }

        if !functions.is_empty() {
            result.push_str("函数:\n");
            for func in &functions {
                result.push_str(&format!("  • {} (行 {})\n", func.name, func.start_line));
            }
            result.push('\n');
        }

        if !methods.is_empty() {
            result.push_str("方法:\n");
            for method in &methods {
                result.push_str(&format!("  • {} (行 {})\n", method.name, method.start_line));
            }
            result.push('\n');
        }

        if !other.is_empty() {
            result.push_str("其他:\n");
            for item in &other {
                result.push_str(&format!(
                    "  • {} ({} 行 {})\n",
                    item.name,
                    item.kind_to_string(),
                    item.start_line
                ));
            }
        }

        Ok(ToolResult::text(result))
    }
}

/// 查找引用工具
pub struct FindReferencesTool {
    project_path: String,
    ast_engine: Arc<ASTEngine>,
}

impl FindReferencesTool {
    pub fn new(project_path: String, ast_engine: Arc<ASTEngine>) -> Self {
        Self {
            project_path,
            ast_engine,
        }
    }
}

#[async_trait]
impl Tool for FindReferencesTool {
    fn name(&self) -> &str {
        "find_references"
    }

    fn description(&self) -> &str {
        "查找符号的所有引用位置"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Search
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(self.name(), self.description(), self.category()).add_parameter(
            ToolParameter {
                name: "symbol_name".to_string(),
                param_type: ToolParameterType::String,
                description: "符号名称（函数/方法名）".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            },
        )
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ToolError> {
        let symbol_name = input["symbol_name"]
            .as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 symbol_name 参数".to_string()))?;

        // 查找调用点
        let call_sites = self
            .ast_engine
            .find_call_sites(symbol_name)
            .map_err(|e| ToolError::ExecutionFailed(format!("查找引用失败: {}", e)))?;

        if call_sites.is_empty() {
            return Ok(ToolResult::text(format!("未找到 '{}' 的引用", symbol_name)));
        }

        let mut result = format!("找到 {} 个 '{}' 的引用:\n\n", call_sites.len(), symbol_name);

        // 按文件分组
        let mut by_file: HashMap<String, Vec<&Symbol>> = HashMap::new();
        for site in &call_sites {
            by_file
                .entry(site.file_path.clone())
                .or_insert_with(Vec::new)
                .push(site);
        }

        for (file, sites) in by_file {
            result.push_str(&format!("文件: {}\n", file));
            for site in sites {
                result.push_str(&format!("  • 行 {}\n", site.start_line));
            }
            result.push('\n');
        }

        Ok(ToolResult::text(result))
    }
}

/// 获取调用图工具
pub struct GetCallGraphTool {
    project_path: String,
    ast_engine: Arc<ASTEngine>,
}

impl GetCallGraphTool {
    pub fn new(project_path: String, ast_engine: Arc<ASTEngine>) -> Self {
        Self {
            project_path,
            ast_engine,
        }
    }
}

#[async_trait]
impl Tool for GetCallGraphTool {
    fn name(&self) -> &str {
        "get_call_graph"
    }

    fn description(&self) -> &str {
        "获取函数的调用图"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Analysis
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(self.name(), self.description(), self.category())
            .add_parameter(ToolParameter {
                name: "entry".to_string(),
                param_type: ToolParameterType::String,
                description: "入口函数名称".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "max_depth".to_string(),
                param_type: ToolParameterType::Integer,
                description: "最大深度".to_string(),
                required: false,
                default: Some(serde_json::json!(5)),
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ToolError> {
        let entry = input["entry"]
            .as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 entry 参数".to_string()))?;

        let max_depth = input["max_depth"].as_u64().unwrap_or(5) as usize;

        // 获取调用图
        let call_graph = self
            .ast_engine
            .get_call_graph(entry, max_depth)
            .map_err(|e| ToolError::ExecutionFailed(format!("获取调用图失败: {}", e)))?;

        let result = serde_json::to_string_pretty(&call_graph)
            .unwrap_or_else(|_| "无法序列化调用图".to_string());

        Ok(ToolResult::text(result))
    }
}

/// 获取类层次结构工具
pub struct GetClassHierarchyTool {
    project_path: String,
    ast_engine: Arc<ASTEngine>,
}

impl GetClassHierarchyTool {
    pub fn new(project_path: String, ast_engine: Arc<ASTEngine>) -> Self {
        Self {
            project_path,
            ast_engine,
        }
    }
}

#[async_trait]
impl Tool for GetClassHierarchyTool {
    fn name(&self) -> &str {
        "get_class_hierarchy"
    }

    fn description(&self) -> &str {
        "获取类的继承层次结构"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Analysis
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(self.name(), self.description(), self.category()).add_parameter(
            ToolParameter {
                name: "class_name".to_string(),
                param_type: ToolParameterType::String,
                description: "类名".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            },
        )
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ToolError> {
        let class_name = input["class_name"]
            .as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 class_name 参数".to_string()))?;

        // 获取类层次结构
        let hierarchy = self
            .ast_engine
            .get_class_hierarchy(class_name)
            .map_err(|e| ToolError::ExecutionFailed(format!("获取类层次结构失败: {}", e)))?;

        // 检查是否是错误
        if let Some(error) = hierarchy.get("error") {
            if let Some(msg) = error.as_str() {
                return Ok(ToolResult::error(msg.to_string(), None));
            }
        }

        let result = serde_json::to_string_pretty(&hierarchy)
            .unwrap_or_else(|_| "无法序列化类层次结构".to_string());

        Ok(ToolResult::text(result))
    }
}

/// 索引项目工具
pub struct IndexProjectTool {
    project_path: String,
    ast_engine: Arc<ASTEngine>,
}

impl IndexProjectTool {
    pub fn new(project_path: String, ast_engine: Arc<ASTEngine>) -> Self {
        Self {
            project_path,
            ast_engine,
        }
    }
}

#[async_trait]
impl Tool for IndexProjectTool {
    fn name(&self) -> &str {
        "index_project"
    }

    fn description(&self) -> &str {
        "索引项目以启用符号搜索和分析"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Analysis
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(self.name(), self.description(), self.category())
    }

    async fn execute(&self, _input: serde_json::Value) -> Result<ToolResult, ToolError> {
        // 扫描项目
        let file_count = self
            .ast_engine
            .scan_project(&self.project_path)
            .map_err(|e| ToolError::ExecutionFailed(format!("项目索引失败: {}", e)))?;

        // 获取统计信息
        let stats = self
            .ast_engine
            .get_statistics()
            .map_err(|e| ToolError::ExecutionFailed(format!("获取统计信息失败: {}", e)))?;

        let result = format!(
            "项目索引完成！\n\n处理文件数: {}\n总符号数: {}\n\n现在可以使用符号搜索功能。",
            file_count,
            stats["total_nodes"].as_u64().unwrap_or(0)
        );

        Ok(ToolResult::text(result))
    }
}

/// 注册所有 AST 工具
pub async fn register_ast_tools(
    registry: &Arc<ToolRegistry>,
    project_path: String,
    ast_engine: Arc<ASTEngine>,
) {
    let tools: Vec<Arc<dyn Tool>> = vec![
        Arc::new(SearchSymbolTool::new(
            project_path.clone(),
            ast_engine.clone(),
        )),
        Arc::new(GetFileStructureTool::new(
            project_path.clone(),
            ast_engine.clone(),
        )),
        Arc::new(FindReferencesTool::new(
            project_path.clone(),
            ast_engine.clone(),
        )),
        Arc::new(GetCallGraphTool::new(
            project_path.clone(),
            ast_engine.clone(),
        )),
        Arc::new(GetClassHierarchyTool::new(
            project_path.clone(),
            ast_engine.clone(),
        )),
        Arc::new(IndexProjectTool::new(
            project_path.clone(),
            ast_engine.clone(),
        )),
    ];

    for tool in tools {
        if let Err(e) = registry.register(tool).await {
            tracing::warn!("Failed to register AST tool: {}", e);
        }
    }
}
