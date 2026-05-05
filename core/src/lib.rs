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

// ── 分层导出：按消费者角色分组 ──────────────────────────

/// 扫描接口 — 扫描项目、获取漏洞发现
pub mod scanning {
    pub use crate::scanner::{
        Finding, Scanner, ScanResult,
        scan_directory, scan_directory_deep,
        scan_directory_with_attack_surface,
        scan_directory_with_rules, scan_directory_deep_with_rules,
    };
    pub use crate::scanner::manager::ScannerManager;
    pub use crate::scanner::regex_scanner::RegexScanner;
    pub use crate::scanner::sca_scanner::{ScaScanner, ScaScanOptions, ScaSeverityMapping};
}

/// 污点分析接口 — 数据流追踪、跨文件分析、别名解析
pub mod taint {
    pub use crate::analysis::{
        TaintAnalyzer, TaintSource, TaintSink, TaintFlow, TaintResult,
        FlowLocation, FlowNode, FlowNodeType, PropagationStep, PropagationStepType,
        Severity, TaintCategory, VulnerabilityType, AstPattern,
        EnhancedTaintAnalyzer, VariableTaint,
        PropagationStep as EnhancedPropagationStep,
        PropagationStepType as EnhancedPropagationStepType,
        AstTaintAnalyzer, AccessPath, AliasMap,
        DataFlowAnalysis, FlowGraph, FlowNode as DataFlowNode,
        EnhancedFlowGraph, EnhancedFlowNode, EnhancedNodeType, ControlFlowEdge, EdgeType,
        CrossFileTaintAnalyzer, CrossFileTaintResult, CrossFileAnalysisStats,
        CallGraph, CallGraphNode, FunctionParameter,
        InterproceduralTaintFlow, InterproceduralStep, InterproceduralStepType,
        FunctionSummary, SinkReachability, SummaryPropagationResult,
        ContextAssembler, FileContext, CallerInfo, CalleeInfo, TrustBoundaryInfo,
    };
}

/// AST 接口 — 解析、索引、符号查询
pub mod ast_api {
    pub use crate::ast::{
        ASTEngine, ASTParser, CacheData, CacheManager, FileIndex, QueryEngine,
        Symbol, SymbolKind, NodeInfo, Assignment, CallInfo, ArgInfo, ReturnInfo,
        FunctionBody, TypedParam,
    };
    pub use crate::diff::DiffEngine;
}

/// 攻击面 + 风险模式接口 — 入口点分析、风险评分、架构级风险检测
pub mod attack_surface {
    pub use crate::analysis::{
        AttackSurfaceMapper, AttackSurface, AttackSurfaceStats,
        EntryPoint, EntryType, TrustBoundary, EntryContext,
        RiskPatternScanner, RiskPatternMatch, RiskPattern, PatternCondition,
        AffectedEntry, EvidenceSnippet,
    };
}

// ── 向后兼容：保留顶层 re-export ─────────────────────────
// 新代码应使用上方的分组模块（scanning::, taint::, ast_api::, attack_surface::）

pub use ast::{
    ASTEngine, ASTParser, CacheData, CacheManager, FileIndex, QueryEngine, Symbol, SymbolKind,
    NodeInfo, Assignment, CallInfo, ArgInfo, ReturnInfo, FunctionBody, TypedParam,
};
pub use diff::DiffEngine;
pub use scanner::{Finding, Scanner, ScanResult, scan_directory, scan_directory_deep, scan_directory_with_attack_surface, scan_directory_with_rules, scan_directory_deep_with_rules};
pub use scanner::manager::ScannerManager;
pub use scanner::regex_scanner::RegexScanner;
pub use scanner::sca_scanner::{ScaScanner, ScaScanOptions, ScaSeverityMapping};

// 规则系统
pub use rules::{loader::load_rules_from_dir, model::Rule, model::RuleSet, scanner::RuleScanner};
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
    EntryPoint, EntryType, TrustBoundary, EntryContext,
    RiskPatternScanner, RiskPatternMatch, RiskPattern, PatternCondition,
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
