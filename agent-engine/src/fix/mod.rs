// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 自动修复模块
//!
//! 提供漏洞修复建议和代码生成

mod repair_generator;

pub use repair_generator::{
    RepairGenerator, RepairSuggestion, RepairStrategy, RepairTemplate, RepairTemplateLibrary,
    RepairConfig,
};
