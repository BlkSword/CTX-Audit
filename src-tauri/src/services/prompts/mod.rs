//! Prompt 系统模块
//!
//! 管理 Prompt 模板的加载、构建和变量替换

pub mod builder;
pub mod loader;

// 重新导出常用类型
pub use builder::{PromptBuilder, PromptContext};
pub use loader::{PromptLoader, PromptTemplate, global_loader};
