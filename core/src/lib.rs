// CTX-Audit Core Library
// 核心功能库，包含AST引擎、扫描器、规则系统、差异对比、索引系统和代码分析

mod ast;
mod scanner;
pub mod rules;
mod diff;
pub mod indexing;
pub mod analysis;
pub mod sarif;
pub mod watcher;

// 重新导出常用类型
pub use ast::{
    ASTEngine, ASTParser, CacheData, CacheManager, FileIndex, QueryEngine, Symbol, SymbolKind,
    NodeInfo, Assignment, CallInfo, ArgInfo, ReturnInfo, FunctionBody, TypedParam,
};
pub use diff::DiffEngine;
pub use scanner::{Finding, Scanner, ScanResult, scan_directory, scan_directory_deep, scan_directory_with_attack_surface, scan_directory_with_rules, scan_directory_deep_with_rules};
pub use scanner::manager::ScannerManager;
pub use scanner::regex_scanner::RegexScanner;
pub use scanner::sca_scanner::ScaScanner;

// 规则系统
pub use rules::{loader::load_rules_from_dir, model::Rule, scanner::RuleScanner};
pub use rules::taint_model::TaintRuleSet;
pub use rules::taint_loader::load_taint_rules_from_dir;

// 索引系统
pub use indexing::{CodeChunk, CodeChunker, ChunkType, ChunkConfig, VectorStore, SearchResult};
pub use indexing::vector_store::VectorStoreError;

// 代码分析
pub use analysis::{
    TaintAnalyzer, TaintSource, TaintSink, TaintFlow, TaintResult,
    EnhancedTaintAnalyzer, VariableTaint,
    AstTaintAnalyzer, AccessPath, AliasMap,
    DataFlowAnalysis, FlowGraph, FlowNode,
    ImportResolver, SymbolReference, CrossFileReference,
    FunctionSummary, CrossFileTaintAnalyzer,
    ContextAssembler, FileContext, CallerInfo, CalleeInfo, TrustBoundaryInfo,
    AttackSurfaceMapper, AttackSurface, AttackSurfaceStats,
    EntryPoint, EntryType, TrustBoundary,
};

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
