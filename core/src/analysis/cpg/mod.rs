// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 代码属性图（Code Property Graph）模块
//!
//! 将 CFG + AST 元数据 + 别名映射 + 调用图融合为统一可查询结构。
//! 为路径敏感污点分析和精确函数摘要提供基础设施。

mod builder;
mod path_taint;
mod query;
mod summary;

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::analysis::alias::AliasMap;
use crate::analysis::cross_file::CallGraph;
use crate::analysis::enhanced_dataflow::EnhancedFlowGraph;
use crate::ast::symbol::{Assignment, CallInfo, TypedParam};

pub use builder::CPGBuilder;
pub use path_taint::{PathCondition, PathSensitiveState, VarTaintState};
pub use query::{BranchContext, CodePropertyGraph};
pub use summary::compute_summary_from_cpg;

/// 单函数 CPG — CFG + 节点元数据 + 别名映射
#[derive(Debug, Clone)]
pub struct FunctionCPG {
    /// 底层控制流图
    pub cfg: EnhancedFlowGraph,
    /// CFG 节点附加的 AST 元数据，key 为 CFG node ID
    pub node_meta: HashMap<usize, CPGNodeMeta>,
    /// 函数内别名映射
    pub alias_map: AliasMap,
    /// 函数签名
    pub signature: FunctionSignature,
    /// CFG 节点行号 → 文件绝对行号的偏移（绝对行号 = CFG 节点行号 + line_offset）。
    /// 整文件构建为 0；函数体片段构建为 body_start_line - 1。
    /// node_meta 中的 assignment/call_info 统一存文件绝对行号；
    /// CFG 节点行号为函数体相对行号，消费方匹配时需自行加 line_offset。
    pub line_offset: usize,
}

/// CFG 节点附加的 AST 元数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CPGNodeMeta {
    /// tree-sitter 节点类型名
    pub ast_kind: String,
    /// 若节点对应赋值语句，保存赋值信息
    pub assignment: Option<Assignment>,
    /// 若节点对应函数调用，保存调用信息
    pub call_info: Option<CallInfo>,
    /// 若节点是条件分支头，保存条件表达式分析结果
    pub condition: Option<ConditionInfo>,
}

/// 条件表达式信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionInfo {
    /// 条件表达式文本
    pub expr: String,
    /// 条件中引用的变量
    pub used_vars: Vec<String>,
    /// 条件中的函数调用
    pub calls: Vec<String>,
    /// 条件是否包含净化器类调用（如 isSafe(x)、validate(input)）
    pub is_sanitizer_check: bool,
}

/// 函数签名
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSignature {
    /// 函数名
    pub name: String,
    /// 文件路径
    pub file_path: String,
    /// 起始行号
    pub start_line: usize,
    /// 结束行号
    pub end_line: usize,
    /// 函数参数（含类型注解）
    pub params: Vec<TypedParam>,
}

impl FunctionSignature {
    /// 构建唯一标识 "file_path:func_name:start_line"
    pub fn id(&self) -> String {
        format!("{}:{}:{}", self.file_path, self.name, self.start_line)
    }
}
