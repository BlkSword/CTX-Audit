// analysis/mod.rs - 分析模块
//
// 该模块提供各种分析功能

pub mod business_logic;
pub mod global_flow;
pub mod git_history;
pub mod token_budget;

pub use business_logic::{
    BusinessLogicAnalyzer,
    IDORVulnerability,
    AuthorizationDetector,
    StateMachineAnalyzer,
    BusinessRuleExtractor,
    BusinessLogicFinding, ApiEndpointInfo, BusinessLogicAnalysisResult,
};
pub use global_flow::{
    GlobalFlowGraph, FlowNode, NodeType, SecurityProperties,
    FlowEdge, EdgeType, EntryPoint, EntryPointType,
    GlobalTaintResult, TaintSource, TaintSourceType,
    TaintSink, TaintPath, TaintPathStep, NodeId,
    CrossFileReference, CrossFileType,
};
pub use git_history::{
    GitHistoryAnalyzer, VulnerabilityFix, FixPattern,
    SimilarVulnerabilityCandidate, CommitDiff, LineChange,
};
