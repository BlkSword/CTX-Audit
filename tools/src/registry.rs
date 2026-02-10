// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 工具注册表

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// 导入 bridge 中定义的类型
use crate::bridge::{
    ToolCategory, ToolDefinition, ToolParameter, ToolParameterType,
    ToolResult, ToolError, FindingData,
};

/// 工具 Trait
#[async_trait]
pub trait Tool: Send + Sync {
    /// 获取工具名称
    fn name(&self) -> &str;

    /// 获取工具描述
    fn description(&self) -> &str;

    /// 获取工具类别
    fn category(&self) -> ToolCategory;

    /// 获取工具定义
    fn definition(&self) -> ToolDefinition;

    /// 执行工具
    async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ToolError>;
}

/// 工具注册表
pub struct ToolRegistry {
    tools: RwLock<HashMap<String, Arc<dyn Tool>>>,
}

impl ToolRegistry {
    /// 创建新的注册表
    pub fn new() -> Self {
        Self {
            tools: RwLock::new(HashMap::new()),
        }
    }

    /// 注册工具
    pub async fn register(&self, tool: Arc<dyn Tool>) -> Result<(), ToolError> {
        let name = tool.name().to_string();
        let mut tools = self.tools.write().await;
        tools.insert(name, tool);
        Ok(())
    }

    /// 获取工具
    pub fn get_tool(&self, name: &str) -> Option<Arc<dyn Tool>> {
        // 注意：这里需要同步访问，但由于 Rust 的限制，我们使用 try_read
        if let Ok(tools) = self.tools.try_read() {
            tools.get(name).cloned()
        } else {
            None
        }
    }

    /// 执行工具
    pub async fn execute(
        &self,
        name: &str,
        input: serde_json::Value,
    ) -> Result<ToolResult, ToolError> {
        let tools = self.tools.read().await;
        let tool = tools
            .get(name)
            .ok_or_else(|| ToolError::ToolNotFound(name.to_string()))?;
        tool.execute(input).await
    }

    /// 获取工具定义列表
    pub async fn get_definitions(&self) -> Vec<ToolDefinition> {
        let tools = self.tools.read().await;
        tools.values().map(|t| t.definition()).collect()
    }

    /// 获取所有工具
    pub async fn list_tools(&self) -> Vec<Arc<dyn Tool>> {
        let tools = self.tools.read().await;
        tools.values().cloned().collect()
    }

    /// 获取所有工具名称
    pub async fn list_tool_names(&self) -> Vec<String> {
        let tools = self.tools.read().await;
        tools.keys().cloned().collect()
    }

    /// 获取工具数量
    pub async fn tool_count(&self) -> usize {
        let tools = self.tools.read().await;
        tools.len()
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}
