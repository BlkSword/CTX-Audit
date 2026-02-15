// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 代码分析模块
//!
//! 提供污点分析、数据流分析和跨文件分析能力

pub mod taint;
pub mod dataflow;
pub mod imports;

pub use taint::{TaintAnalyzer, TaintSource, TaintSink, TaintFlow, TaintResult};
pub use dataflow::{DataFlowAnalysis, FlowFact, FlowGraph, FlowNode};
pub use imports::{ImportResolver, SymbolReference, CrossFileReference};
