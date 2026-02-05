//! Agent 注册表
//!
//! 管理所有 Agent 类型的注册和创建

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::models::agent::{AgentConfig, AgentType};

use super::base::Agent;
use crate::services::llm::LLMClient;

/// Agent 工厂函数类型
pub type AgentFactory = Arc<
    dyn Fn(Arc<dyn LLMClient>, AgentConfig) -> Arc<dyn Agent>
        + Send
        + Sync,
>;

/// Agent 信息
#[derive(Debug, Clone)]
pub struct AgentInfo {
    /// Agent 类型
    pub agent_type: AgentType,

    /// Agent 显示名称
    pub display_name: String,

    /// Agent 描述
    pub description: String,

    /// Agent 类别
    pub category: String,

    /// 是否启用
    pub enabled: bool,
}

/// Agent 注册表
pub struct AgentRegistry {
    /// 注册的 Agent 工厂
    factories: RwLock<HashMap<String, AgentFactory>>,

    /// Agent 信息
    info: RwLock<HashMap<String, AgentInfo>>,
}

impl AgentRegistry {
    /// 创建新的注册表
    pub fn new() -> Self {
        Self {
            factories: RwLock::new(HashMap::new()),
            info: RwLock::new(HashMap::new()),
        }
    }

    /// 注册 Agent 工厂
    pub async fn register(
        &self,
        agent_type: &str,
        factory: AgentFactory,
        info: AgentInfo,
    ) -> Result<(), String> {
        let mut factories = self.factories.write().await;
        let mut info_map = self.info.write().await;

        factories.insert(agent_type.to_string(), factory);
        info_map.insert(agent_type.to_string(), info);

        tracing::info!("Agent 注册成功: {}", agent_type);
        Ok(())
    }

    /// 创建 Agent 实例
    pub async fn create_agent(
        &self,
        agent_type: &str,
        llm: Arc<dyn LLMClient>,
        config: AgentConfig,
    ) -> Result<Arc<dyn Agent>, String> {
        let factories = self.factories.read().await;

        let factory = factories
            .get(agent_type)
            .ok_or_else(|| format!("未注册的 Agent 类型: {}", agent_type))?;

        Ok(factory(llm, config))
    }

    /// 获取 Agent 信息
    pub async fn get_info(&self, agent_type: &str) -> Option<AgentInfo> {
        let info = self.info.read().await;
        info.get(agent_type).cloned()
    }

    /// 列出所有已注册的 Agent
    pub async fn list_agents(&self) -> Vec<AgentInfo> {
        let info = self.info.read().await;
        info.values().cloned().collect()
    }

    /// 检查 Agent 是否已注册
    pub async fn is_registered(&self, agent_type: &str) -> bool {
        let factories = self.factories.read().await;
        factories.contains_key(agent_type)
    }

    /// 注销 Agent
    pub async fn unregister(&self, agent_type: &str) -> Result<(), String> {
        let mut factories = self.factories.write().await;
        let mut info = self.info.write().await;

        factories
            .remove(agent_type)
            .ok_or_else(|| format!("Agent 未注册: {}", agent_type))?;
        info.remove(agent_type);

        tracing::info!("Agent 注销: {}", agent_type);
        Ok(())
    }
}

impl Default for AgentRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// 全局 Agent 注册表单例
pub fn global_registry() -> &'static AgentRegistry {
    use std::sync::OnceLock;
    static REGISTRY: OnceLock<AgentRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let registry = AgentRegistry::new();

        // 在这里注册内置的 Agent
        // 注册会在初始化时完成

        registry
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_registry() {
        let registry = AgentRegistry::new();

        // 注册一个测试 Agent
        let info = AgentInfo {
            agent_type: AgentType::Analysis,
            display_name: "测试 Agent".to_string(),
            description: "用于测试的 Agent".to_string(),
            category: "test".to_string(),
            enabled: true,
        };

        // 创建一个简单的工厂函数
        let factory: AgentFactory = Arc::new(|_llm, _config| {
            // 这里应该返回实际的 Agent 实例
            // 暂时 panic，因为测试中不会真正调用
            panic!("Not implemented in test")
        });

        registry
            .register("test_agent", factory, info)
            .await
            .unwrap();

        // 验证注册成功
        assert!(registry.is_registered("test_agent").await);

        // 获取信息
        let agent_info = registry.get_info("test_agent").await;
        assert!(agent_info.is_some());
        assert_eq!(agent_info.unwrap().display_name, "测试 Agent");
    }
}
