// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! SARIF 2.1.0 输出引擎
//!
//! 提供统一的 SARIF 输出，支持：
//! - 规则注册表 (rules)
//! - 污点路径可视化 (codeFlows)
//! - 结构化修复建议 (fixes)
//!
//! # 使用方式
//!
//! ```rust,ignore
//! use deepaudit_core::sarif::{SarifConverter, FindingInput};
//!
//! let converter = SarifConverter::new();
//! let findings = vec![FindingInput { ... }];
//! let json = converter.convert_to_json(&findings)?;
//! std::fs::write("report.sarif", json)?;
//! ```

mod converter;
mod rules;
mod types;

// 公共接口
pub use converter::{
    taint_flow_to_summary, FindingInput, FixSuggestion, FixType, FlowLocationSummary,
    FlowStepSummary, SarifConverter, TaintFlowSummary,
};
pub use rules::{built_in_rules, find_rule_index};
pub use types::*;
