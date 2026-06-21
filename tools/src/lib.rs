// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! CTX-Audit 工具系统
//!
//! 支持内置工具和外部工具适配器

pub mod ast_tools;
pub mod bridge;
pub mod call_graph_tools;
pub mod executor;
pub mod external;
pub mod pattern_tools;
pub mod registry;
pub mod search_tools;
pub mod taint_tools;

// 重新导出常用类型
pub use ast_tools::register_ast_tools;
pub use bridge::{register_all_tools, register_built_in_tools};
pub use executor::ToolExecutor;
pub use pattern_tools::register_pattern_tools;
pub use registry::{Tool, ToolRegistry};
pub use search_tools::register_search_tools;
pub use taint_tools::register_taint_tools;

// 重新导出模型类型
pub use bridge::{
    FindingData, ToolCategory, ToolDefinition, ToolError, ToolErrorCode, ToolParameter,
    ToolParameterType, ToolResult,
};

/// 工具系统版本
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
