//! 工具注册表
//!
//! 全局工具注册和管理

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::models::tools::{ToolCategory, ToolDefinition, ToolError, ToolResult};

/// 工具 trait
#[async_trait]
pub trait Tool: Send + Sync {
    /// 获取工具名称
    fn name(&self) -> &str;

    /// 获取工具描述
    fn description(&self) -> &str;

    /// 获取工具类别
    fn category(&self) -> ToolCategory;

    /// 获取工具定义
    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(self.name(), self.description(), self.category())
    }

    /// 执行工具
    async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ToolError>;

    /// 验证参数（可选）
    fn validate(&self, input: &serde_json::Value) -> Result<(), ToolError> {
        let schema = &self.definition().input_schema;

        // 检查必需参数
        for required_param in &schema.required {
            if !input.get(required_param).is_some() {
                return Err(ToolError::invalid_argument(format!(
                    "缺少必需参数: {}",
                    required_param
                )));
            }
        }

        // 检查参数类型
        if let Some(obj) = input.as_object() {
            for (key, value) in obj {
                if let Some(param_def) = schema.properties.get(key) {
                    self.validate_param_type(key, value, param_def)?;
                }
            }
        }

        Ok(())
    }

    /// 验证参数类型
    fn validate_param_type(
        &self,
        name: &str,
        value: &serde_json::Value,
        param_def: &crate::models::tools::ToolParameter,
    ) -> Result<(), ToolError> {
        use crate::models::tools::ToolParameterType;

        let is_valid = match param_def.param_type {
            ToolParameterType::String => value.is_string(),
            ToolParameterType::Number => value.is_number(),
            ToolParameterType::Integer => value.is_i64(),
            ToolParameterType::Boolean => value.is_boolean(),
            ToolParameterType::Array => value.is_array(),
            ToolParameterType::Object => value.is_object(),
            ToolParameterType::Null => value.is_null(),
        };

        if !is_valid {
            return Err(ToolError::invalid_argument(format!(
                "参数 '{}' 类型错误，期望 {:?}，实际得到 {:?}",
                name,
                param_def.param_type,
                value
            )));
        }

        Ok(())
    }
}

/// 工具注册表
pub struct ToolRegistry {
    /// 注册的工具
    tools: Arc<RwLock<HashMap<String, Arc<dyn Tool>>>>,

    /// 工具索引（按类别）
    by_category: Arc<RwLock<HashMap<ToolCategory, Vec<String>>>>,
}

impl ToolRegistry {
    /// 创建新的注册表
    pub fn new() -> Self {
        Self {
            tools: Arc::new(RwLock::new(HashMap::new())),
            by_category: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 注册工具
    pub async fn register(&self, tool: Arc<dyn Tool>) -> Result<(), ToolError> {
        let name = tool.name().to_string();
        let category = tool.category();

        // 检查是否已注册
        {
            let tools = self.tools.read().await;
            if tools.contains_key(&name) {
                return Err(ToolError::new(
                    crate::models::tools::ToolErrorCode::InternalError,
                    format!("工具已注册: {}", name),
                ));
            }
        }

        // 添加工具
        {
            let mut tools = self.tools.write().await;
            tools.insert(name.clone(), tool);
        }

        // 更新类别索引
        {
            let mut by_category = self.by_category.write().await;
            by_category
                .entry(category)
                .or_insert_with(Vec::new)
                .push(name.clone());
        }

        tracing::info!("Tool registered: {} ({})", name, category);
        Ok(())
    }

    /// 获取工具
    pub async fn get_tool(&self, name: &str) -> Option<Arc<dyn Tool>> {
        let tools = self.tools.read().await;
        tools.get(name).cloned()
    }

    /// 检查工具是否存在
    pub async fn has_tool(&self, name: &str) -> bool {
        let tools = self.tools.read().await;
        tools.contains_key(name)
    }

    /// 列出所有工具名称
    pub async fn list_tools(&self) -> Vec<String> {
        let tools = self.tools.read().await;
        tools.keys().cloned().collect()
    }

    /// 获取所有工具定义
    pub async fn get_definitions(&self) -> Vec<ToolDefinition> {
        let tools = self.tools.read().await;
        tools
            .values()
            .map(|tool| tool.definition())
            .collect()
    }

    /// 按类别获取工具
    pub async fn get_by_category(&self, category: ToolCategory) -> Vec<Arc<dyn Tool>> {
        let by_category = self.by_category.read().await;
        let tools = self.tools.read().await;

        if let Some(names) = by_category.get(&category) {
            names
                .iter()
                .filter_map(|name| tools.get(name).cloned())
                .collect()
        } else {
            Vec::new()
        }
    }

    /// 获取工具定义（按类别）
    pub async fn get_definitions_by_category(&self, category: ToolCategory) -> Vec<ToolDefinition> {
        let tools = self.get_by_category(category).await;
        tools.into_iter().map(|t| t.definition()).collect()
    }

    /// 注销工具
    pub async fn unregister(&self, name: &str) -> Result<(), ToolError> {
        // 移除工具
        let category = {
            let tools = self.tools.read().await;
            tools.get(name).map(|t| t.category())
        };

        if let Some(cat) = category {
            {
                let mut tools = self.tools.write().await;
                tools.remove(name);
            }

            // 更新类别索引
            {
                let mut by_category = self.by_category.write().await;
                if let Some(names) = by_category.get_mut(&cat) {
                    names.retain(|n| n != name);
                    if names.is_empty() {
                        by_category.remove(&cat);
                    }
                }
            }

            tracing::info!("Tool unregistered: {}", name);
            Ok(())
        } else {
            Err(ToolError::not_found(format!("工具不存在: {}", name)))
        }
    }

    /// 执行工具
    pub async fn execute(
        &self,
        name: &str,
        input: serde_json::Value,
    ) -> Result<ToolResult, ToolError> {
        let tool = self
            .get_tool(name)
            .await
            .ok_or_else(|| ToolError::not_found(format!("工具不存在: {}", name)))?;

        // 验证参数
        tool.validate(&input)?;

        // 执行工具
        tool.execute(input).await
    }

    /// 获取统计信息
    pub async fn stats(&self) -> ToolRegistryStats {
        let tools = self.tools.read().await;
        let by_category = self.by_category.read().await;

        let mut counts = HashMap::new();
        for (category, names) in by_category.iter() {
            counts.insert(category.to_string(), names.len());
        }

        ToolRegistryStats {
            total_tools: tools.len(),
            by_category: counts,
        }
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// 工具注册表统计信息
#[derive(Debug, Clone, serde::Serialize)]
pub struct ToolRegistryStats {
    /// 总工具数
    pub total_tools: usize,

    /// 按类别统计
    pub by_category: HashMap<String, usize>,
}

/// 全局工具注册表
pub fn global_tool_registry() -> &'static ToolRegistry {
    use std::sync::OnceLock;
    static REGISTRY: OnceLock<ToolRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let registry = ToolRegistry::new();
        // 内置工具会在初始化时注册
        registry
    })
}

/// 全局工具注册表宏（用于方便访问）
#[macro_export]
macro_rules! global_tools {
    () => {
        $crate::services::tools::global_tool_registry()
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // 测试工具
    struct TestTool;

    #[async_trait]
    impl Tool for TestTool {
        fn name(&self) -> &str {
            "test_tool"
        }

        fn description(&self) -> &str {
            "A test tool"
        }

        fn category(&self) -> ToolCategory {
            ToolCategory::Custom
        }

        async fn execute(&self, _input: serde_json::Value) -> Result<ToolResult, ToolError> {
            Ok(ToolResult::text("Test result"))
        }
    }

    #[tokio::test]
    async fn test_registry() {
        let registry = ToolRegistry::new();
        let tool = Arc::new(TestTool);

        // 注册工具
        registry
            .register(tool)
            .await
            .expect("Failed to register tool");

        // 验证注册
        assert!(registry.has_tool("test_tool").await);

        // 获取工具
        let retrieved = registry.get_tool("test_tool").await;
        assert!(retrieved.is_some());

        // 执行工具
        let result = registry
            .execute("test_tool", serde_json::json!({}))
            .await
            .expect("Failed to execute tool");
        assert_eq!(result.get_text(), "Test result");
    }
}
