// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 代码分析模块
//!
//! 提供污点分析、数据流分析和跨文件分析能力

pub mod alias;
pub mod ast_taint;
pub mod async_flow;
pub mod attack_surface;
pub mod cache;
pub mod cpg;
pub mod cross_file;
pub mod framework_detector;
pub mod dataflow;
pub mod enhanced_dataflow;
pub mod enhanced_taint;
pub mod imports;
pub mod middleware;
pub mod query;
pub mod risk_patterns;
pub mod taint;
pub mod type_hierarchy;

pub use alias::{AccessPath, AliasMap};
pub use ast_taint::{AstTaintAnalyzer, FileTaintReport};
pub use async_flow::{detect_callback_hints, CallbackHintType, CallbackTaintHint};
pub use attack_surface::{
    AttackSurface, AttackSurfaceMapper, AttackSurfaceStats, EntryContext, EntryPoint, EntryType,
    TrustBoundary,
};
pub use cache::{
    compute_file_hash, get_file_mtime, AnalysisCache, AnalysisCacheEntry, AstCache, AstCacheEntry,
    CacheEntry, CacheManager, CacheStats, CachedSymbol, MemoryCache, TaintCache, TaintCacheEntry,
    TotalCacheStats,
};
pub use cpg::{
    compute_summary_from_cpg, BranchContext, CPGBuilder, CPGNodeMeta, CodePropertyGraph,
    ConditionInfo, FunctionCPG, FunctionSignature, PathCondition, PathSensitiveState,
    VarTaintState,
};
pub use cross_file::{
    CallGraph, CallGraphNode, CallTarget, CalleeInfo, CallerInfo, ContextAssembler,
    CrossFileAnalysisStats, CrossFileTaintAnalyzer, CrossFileTaintResult, FileContext,
    FunctionParameter, FunctionSummary, ImportResolution, InterproceduralStep,
    InterproceduralStepType, InterproceduralTaintFlow, SinkReachability, SummaryPropagationResult,
    TrustBoundaryInfo,
};
pub use dataflow::{DataFlowAnalysis, FlowFact, FlowGraph, FlowNode as DataFlowNode};
pub use enhanced_dataflow::{
    ControlFlowEdge, EdgeType, EnhancedFlowGraph, EnhancedFlowNode, EnhancedNodeType,
};
pub use enhanced_taint::{
    EnhancedTaintAnalyzer, PropagationStep as EnhancedPropagationStep,
    PropagationStepType as EnhancedPropagationStepType, VariableTaint,
};
pub use imports::{CrossFileReference, ImportResolver, SymbolReference};
pub use query::{
    CallGraphQueryEngine, CallPath, CallbackEvidence, CalleeEvidence, CallerEvidence, FunctionInfo,
    GraphStats, MethodEvidence, MiddlewareEvidence, PathStep, ReachabilityResult, ReachableNode,
    ReachableSink, ResolvedCallTarget, RouteEvidence, TaintPathEvidence, TypeChainResult,
    VariableFlowResult,
};
pub use risk_patterns::{
    AffectedEntry, EvidenceSnippet, PatternCondition, RiskPattern, RiskPatternMatch,
    RiskPatternScanner,
};
pub use taint::{
    AstPattern, FlowLocation, FlowNode, FlowNodeType, PropagationStep, PropagationStepType,
    Sanitizer, Severity, TaintAnalyzer, TaintCategory, TaintFlow, TaintResult, TaintSink,
    TaintSource, VulnerabilityType,
};
pub use type_hierarchy::{MethodSignature, ResolvedMethod, TypeHierarchy, TypeInfo, TypeKind};
pub use framework_detector::{detect_project_profile, ProjectProfile, SecurityFramework};
