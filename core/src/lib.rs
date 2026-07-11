// CTX-Audit Core Library
// 核心功能库，包含AST引擎、扫描器、规则系统、差异对比、索引系统和代码分析

pub mod analysis;
mod ast;
mod diff;
pub mod indexing;
pub mod rules;
pub mod sarif;
pub mod scan_cache;
mod scanner;
pub mod watcher;

// ── 分层导出：按消费者角色分组 ──────────────────────────

/// 扫描接口 — 扫描项目、获取漏洞发现
pub mod scanning {
    pub use crate::scanner::manager::ScannerManager;
    pub use crate::scanner::regex_scanner::RegexScanner;
    pub use crate::scanner::sca_scanner::{ScaScanOptions, ScaScanner, ScaSeverityMapping};
    pub use crate::scanner::{
        scan_directory, scan_directory_deep, scan_directory_deep_with_rules,
        scan_directory_deep_with_rules_progress, scan_directory_with_attack_surface,
        scan_directory_with_opts, scan_directory_with_rules, scan_directory_with_rules_progress,
        EvidenceRefs, Finding, ProgressCallback, SanitizerEvidence, ScanOptions, ScanPhase,
        ScanProgress, ScanResult, Scanner, SourceSinkEvidence,
    };
}

/// 污点分析接口 — 数据流追踪、跨文件分析、别名解析
pub mod taint {
    pub use crate::analysis::{
        AccessPath, AliasMap, AstPattern, AstTaintAnalyzer, CallGraph, CallGraphNode,
        CallGraphQueryEngine, CallPath, CallTarget, CallbackEvidence, CalleeEvidence, CalleeInfo,
        CallerEvidence, CallerInfo, ContextAssembler, ControlFlowEdge, CrossFileAnalysisStats,
        CrossFileTaintAnalyzer, CrossFileTaintResult, DataFlowAnalysis, EdgeType,
        EnhancedFlowGraph, EnhancedFlowNode, EnhancedNodeType, EnhancedTaintAnalyzer, FileContext,
        FlowGraph, FlowLocation, FlowNode, FlowNode as DataFlowNode, FlowNodeType, FunctionInfo,
        FunctionParameter, FunctionSummary, GraphStats, ImportResolution, InterproceduralStep,
        InterproceduralStepType, InterproceduralTaintFlow, MethodEvidence, MiddlewareEvidence,
        PathStep, PropagationStep, PropagationStep as EnhancedPropagationStep, PropagationStepType,
        PropagationStepType as EnhancedPropagationStepType, ReachabilityResult, ReachableNode,
        ReachableSink, ResolvedCallTarget, RouteEvidence, Sanitizer, Severity, SinkReachability,
        SummaryPropagationResult, TaintAnalyzer, TaintCategory, TaintFlow, TaintPathEvidence,
        TaintResult, TaintSink, TaintSource, TrustBoundaryInfo, TypeChainResult,
        VariableFlowResult, VariableTaint, VulnerabilityType,
    };
}

/// AST 接口 — 解析、索引、符号查询
pub mod ast_api {
    pub use crate::ast::{
        ASTEngine, ASTParser, ArgInfo, Assignment, CacheData, CacheManager, CallInfo, FileIndex,
        FunctionBody, NodeInfo, QueryEngine, ReturnInfo, Symbol, SymbolKind, TypedParam,
    };
    pub use crate::diff::DiffEngine;
}

/// 攻击面 + 风险模式接口 — 入口点分析、风险评分、架构级风险检测
pub mod attack_surface {
    pub use crate::analysis::{
        AffectedEntry, AttackSurface, AttackSurfaceMapper, AttackSurfaceStats, EntryContext,
        EntryPoint, EntryType, EvidenceSnippet, PatternCondition, RiskPattern, RiskPatternMatch,
        RiskPatternScanner, TrustBoundary,
    };
}

// ── 向后兼容：保留顶层 re-export ─────────────────────────
// 新代码应使用上方的分组模块（scanning::, taint::, ast_api::, attack_surface::）

pub use ast::{
    ASTEngine, ASTParser, ArgInfo, Assignment, CacheData, CacheManager, CallInfo, FileIndex,
    FunctionBody, NodeInfo, QueryEngine, ReturnInfo, Symbol, SymbolKind, TypedParam,
};
pub use diff::DiffEngine;
pub use scanner::manager::ScannerManager;
pub use scanner::regex_scanner::RegexScanner;
pub use scanner::sca_scanner::{ScaScanOptions, ScaScanner, ScaSeverityMapping};
pub use scanner::{
    scan_directory, scan_directory_deep, scan_directory_deep_with_rules,
    scan_directory_deep_with_rules_progress, scan_directory_with_attack_surface,
    scan_directory_with_opts, scan_directory_with_rules, scan_directory_with_rules_progress,
    Finding, ProgressCallback, ScanOptions, ScanPhase, ScanProgress, ScanResult, Scanner,
};

// 规则系统
pub use rules::taint_loader::load_taint_rules_from_dir;
pub use rules::taint_model::TaintRuleSet;
pub use rules::{loader::load_rules_from_dir, model::Rule, model::RuleSet, scanner::RuleScanner};

// 索引系统
pub use indexing::vector_store::VectorStoreError;
pub use indexing::{ChunkConfig, ChunkType, CodeChunk, CodeChunker, SearchResult, VectorStore};

// 代码分析
pub use analysis::{
    AccessPath, AliasMap, AstTaintAnalyzer, AttackSurface, AttackSurfaceMapper, AttackSurfaceStats,
    CallGraphQueryEngine, CallPath, CallTarget, CallbackEvidence, CalleeEvidence, CalleeInfo,
    CallerEvidence, CallerInfo, ContextAssembler, CrossFileReference, CrossFileTaintAnalyzer,
    DataFlowAnalysis, EnhancedTaintAnalyzer, EntryContext, EntryPoint, EntryType, FileContext,
    FlowGraph, FlowNode, FunctionInfo, FunctionSummary, GraphStats, ImportResolution,
    ImportResolver, MiddlewareEvidence, PathStep, PatternCondition, ReachabilityResult,
    ResolvedCallTarget, RiskPattern, RiskPatternMatch, RiskPatternScanner, SymbolReference,
    TaintAnalyzer, TaintFlow, TaintPathEvidence, TaintResult, TaintSink, TaintSource,
    TrustBoundary, TrustBoundaryInfo, TypeChainResult, VariableFlowResult, VariableTaint,
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
