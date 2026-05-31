// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 代码分析模块
//!
//! 提供污点分析、数据流分析和跨文件分析能力

pub mod taint;
pub mod enhanced_taint;
pub mod dataflow;
pub mod enhanced_dataflow;
pub mod ast_taint;
pub mod cross_file;
pub mod cache;
pub mod imports;
pub mod alias;
pub mod async_flow;
pub mod attack_surface;
pub mod risk_patterns;
pub mod cpg;
pub mod type_hierarchy;
pub mod middleware;

pub use cpg::{
    FunctionCPG, FunctionSignature, CPGNodeMeta, ConditionInfo,
    CPGBuilder, CodePropertyGraph, BranchContext,
    PathSensitiveState, PathCondition, VarTaintState,
    compute_summary_from_cpg,
};
pub use alias::{AccessPath, AliasMap};
pub use async_flow::{CallbackTaintHint, CallbackHintType, detect_callback_hints};
pub use taint::{
    TaintAnalyzer, TaintSource, TaintSink, TaintFlow, TaintResult,
    FlowLocation, FlowNode, FlowNodeType, PropagationStep, PropagationStepType,
    Severity, TaintCategory, VulnerabilityType, AstPattern,
};
pub use enhanced_taint::{
    EnhancedTaintAnalyzer, VariableTaint, PropagationStep as EnhancedPropagationStep,
    PropagationStepType as EnhancedPropagationStepType,
};
pub use ast_taint::AstTaintAnalyzer;
pub use dataflow::{DataFlowAnalysis, FlowFact, FlowGraph, FlowNode as DataFlowNode};
pub use enhanced_dataflow::{
    EnhancedFlowGraph, EnhancedFlowNode, EnhancedNodeType, ControlFlowEdge, EdgeType,
};
pub use cross_file::{
    CallGraph, CallGraphNode, FunctionParameter,
    CrossFileTaintAnalyzer, CrossFileTaintResult, CrossFileAnalysisStats,
    InterproceduralTaintFlow, InterproceduralStep, InterproceduralStepType,
    FunctionSummary, SinkReachability, SummaryPropagationResult,
    ContextAssembler, FileContext, CallerInfo, CalleeInfo, TrustBoundaryInfo,
};
pub use cache::{
    CacheEntry, CacheStats, MemoryCache,
    AstCache, AstCacheEntry, CachedSymbol,
    AnalysisCache, AnalysisCacheEntry,
    TaintCache, TaintCacheEntry,
    CacheManager, TotalCacheStats,
    get_file_mtime, compute_file_hash,
};
pub use imports::{ImportResolver, SymbolReference, CrossFileReference};
pub use attack_surface::{
    AttackSurfaceMapper, AttackSurface, AttackSurfaceStats,
    EntryPoint, EntryType, TrustBoundary, EntryContext,
};
pub use risk_patterns::{
    RiskPattern, RiskPatternMatch, RiskPatternScanner,
    AffectedEntry, EvidenceSnippet, PatternCondition,
};
pub use type_hierarchy::{TypeHierarchy, TypeInfo, TypeKind, MethodSignature, ResolvedMethod};
