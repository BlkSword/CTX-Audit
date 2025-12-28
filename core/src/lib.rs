// CTX-Audit Core Library
// 核心功能库，包含AST引擎、扫描器、规则系统和差异对比

mod ast;
mod scanner;
mod rules;
mod diff;

// 重新导出常用类型
pub use ast::{ASTEngine, ASTParser, CacheData, CacheManager, FileIndex, QueryEngine, Symbol, SymbolKind};
pub use diff::DiffEngine;
pub use scanner::{Finding, Scanner, scan_directory};
pub use scanner::manager::ScannerManager;

// 规则系统
pub use rules::{loader::load_rules_from_dir, model::Rule, scanner::RuleScanner};

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
