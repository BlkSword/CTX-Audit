//! CTX-Audit Core - 共享核心逻辑库
//!
//! 这个库包含了 CTX-Audit 的所有核心功能，可以被 Web 版 (Axum) 使用

// 声明 src/ 目录下的模块
mod ast;
mod scanner;
mod rules;
mod diff;

// 重新导出常用类型
pub use ast::{ASTEngine, ASTParser, CacheManager, QueryEngine, Symbol};
pub use diff::DiffEngine;
pub use scanner::{Finding, Scanner, ScannerManager, scan_directory};

// 规则系统
pub use rules::{loader::RuleLoader, model::Rule, scanner::RuleScanner};

pub mod error {
    use thiserror::Error;

    #[derive(Error, Debug)]
    pub enum CoreError {
        #[error("IO error: {0}")]
        Io(#[from] std::io::Error),

        #[error("Parse error: {0}")]
        Parse(String),

        #[error("AST error: {0}")]
        Ast(String),

        #[error("Scanner error: {0}")]
        Scanner(String),
    }

    pub type Result<T> = std::result::Result<T, CoreError>;
}
