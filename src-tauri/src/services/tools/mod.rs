//! 工具系统模块
//!
//! 提供 Agent 工具注册、执行和管理功能

pub mod bridge;
pub mod executor;
pub mod external;
pub mod registry;

// 重新导出常用类型
pub use bridge::*;
pub use executor::ToolExecutor;
pub use external::{ExternalTool, ExternalToolAdapter};
pub use registry::{ToolRegistry, global_tool_registry as GLOBAL_TOOL_REGISTRY};
