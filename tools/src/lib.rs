// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! CTX-Audit 工具系统
//!
//! 支持内置工具和外部工具适配器

pub mod registry;
pub mod executor;
pub mod bridge;
pub mod external;
pub mod ast_tools;
pub mod write_tools;
pub mod shell_tools;
pub mod search_tools;
pub mod taint_tools;
pub mod pattern_tools;

// 重新导出常用类型
pub use registry::{ToolRegistry, Tool};
pub use executor::ToolExecutor;
pub use bridge::{register_built_in_tools, register_all_tools};
pub use ast_tools::register_ast_tools;
pub use write_tools::register_write_tools;
pub use shell_tools::register_shell_tools;
pub use search_tools::register_search_tools;
pub use taint_tools::register_taint_tools;
pub use pattern_tools::register_pattern_tools;

// 重新导出模型类型
pub use bridge::{
    ToolCategory, ToolDefinition, ToolParameter, ToolParameterType,
    ToolResult, ToolError, ToolErrorCode, FindingData,
};

/// 工具系统版本
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
