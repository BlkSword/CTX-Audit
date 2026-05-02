// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Regex Scanner — 已废弃
//!
//! 功能已合并到 RuleScanner (rules/todo-detection.yaml 等)。
//! 保留此文件仅为兼容性，不再被调用。

use super::{Finding, Scanner};
use async_trait::async_trait;
use std::path::PathBuf;

pub struct RegexScanner;

impl RegexScanner {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Scanner for RegexScanner {
    fn name(&self) -> String {
        "RegexScanner".to_string()
    }

    async fn scan_file(&self, _path: &PathBuf, _content: &str) -> Vec<Finding> {
        // 已废弃：所有 pattern 已迁移到 YAML 规则
        Vec::new()
    }
}
