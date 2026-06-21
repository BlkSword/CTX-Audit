// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 工具执行器

use std::sync::Arc;
use std::time::Instant;

use crate::bridge::ToolError;
use crate::bridge::ToolResult;
use crate::registry::ToolRegistry;

/// 工具执行器
pub struct ToolExecutor {
    registry: Arc<ToolRegistry>,
}

impl ToolExecutor {
    /// 创建新的执行器
    pub fn new(registry: Arc<ToolRegistry>) -> Self {
        Self { registry }
    }

    /// 执行工具（带计时）
    pub async fn execute(
        &self,
        name: &str,
        input: serde_json::Value,
    ) -> Result<ToolResult, ToolError> {
        let start = Instant::now();

        // 执行工具
        let mut result = self.registry.execute(name, input).await?;

        // 添加执行时长
        let duration_ms = start.elapsed().as_millis() as u64;
        result.duration_ms = Some(duration_ms);

        Ok(result)
    }
}
