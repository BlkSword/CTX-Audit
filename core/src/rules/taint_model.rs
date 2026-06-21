// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 污点规则 YAML 数据模型
//!
//! 定义从 YAML 文件加载污点 source/sink/sanitizer 的数据结构。
//! 复用 `TaintSource`/`TaintSink`（已有 Serialize/Deserialize），
//! 实现零转换反序列化。

use crate::analysis::taint::{TaintSink, TaintSource};
use serde::{Deserialize, Serialize};

/// 污点规则集（YAML 顶层容器）
///
/// YAML 示例：
/// ```yaml
/// kind: taint-rules
/// name: "Generic Taint Rules"
/// version: "1.0"
/// sources:
///   - id: "http_request"
///     ...
/// sinks:
///   - id: "sql_exec"
///     ...
/// sanitizers:
///   - pattern: "escape"
///     description: "Escape function"
/// ```
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TaintRuleSet {
    /// 文档类型标识符（固定为 "taint-rules"，区分于 RuleSet）
    pub kind: String,
    /// 规则集名称
    pub name: String,
    /// 规则集版本
    pub version: String,
    /// 污点源定义
    #[serde(default)]
    pub sources: Vec<TaintSource>,
    /// 污点汇定义
    #[serde(default)]
    pub sinks: Vec<TaintSink>,
    /// 净化函数定义
    #[serde(default)]
    pub sanitizers: Vec<TaintSanitizerDef>,
}

/// 净化函数定义
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TaintSanitizerDef {
    /// 匹配模式（函数名片段）
    pub pattern: String,
    /// 描述
    #[serde(default)]
    pub description: String,
}
