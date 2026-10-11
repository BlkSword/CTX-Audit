// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! CTX-Audit 工具系统
//!
//! 支持内置工具和外部工具适配器

#[cfg(feature = "legacy-tools")]
pub mod ast_tools;
pub mod bridge;
#[cfg(feature = "legacy-tools")]
pub mod call_graph_tools;
pub mod code_intel_tools;
pub mod executor;
pub mod external;
pub mod index_cache;
#[cfg(feature = "legacy-tools")]
pub mod pattern_tools;
pub mod registry;
#[cfg(feature = "legacy-tools")]
pub mod search_tools;
pub mod signal_chain;
pub mod symbol_index;
#[cfg(feature = "legacy-tools")]
pub mod taint_tools;
pub mod text_scan;

// 重新导出常用类型
#[cfg(feature = "legacy-tools")]
pub use ast_tools::register_ast_tools;
pub use bridge::{legacy_tools_enabled, register_all_tools, register_built_in_tools};
pub use code_intel_tools::{
    is_code_intel_tool, register_code_intel_tools, CODE_INTEL_TOOL_SURFACE,
};
pub use executor::ToolExecutor;
#[cfg(feature = "legacy-tools")]
pub use pattern_tools::register_pattern_tools;
pub use registry::{Tool, ToolRegistry};
#[cfg(feature = "legacy-tools")]
pub use search_tools::register_search_tools;
pub use signal_chain::{
    scan_path as scan_signal_chain, scan_source as scan_signal_chain_source, Construct,
    ConstructSet, SignalChainCandidate, SignalChainOptions, SignalChainReport,
    SIGNAL_CHAIN_SCHEMA,
};
#[cfg(feature = "legacy-tools")]
pub use taint_tools::register_taint_tools;

// 重新导出模型类型
pub use bridge::{
    FindingData, ToolCategory, ToolDefinition, ToolError, ToolErrorCode, ToolParameter,
    ToolParameterType, ToolResult,
};

/// 工具系统版本
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
