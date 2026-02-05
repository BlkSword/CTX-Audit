//! 图形控制器
//!
//! 管理 Agent 树结构，提供 Agent 之间的层次化关系

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::models::agent::{AgentType, AgentStatus};

/// Agent 树节点
#[derive(Debug, Clone)]
pub struct AgentNode {
    /// 节点 ID（Agent ID）
    pub id: String,

    /// Agent 类型
    pub agent_type: AgentType,

    /// 父节点 ID
    pub parent_id: Option<String>,

    /// 子节点 ID 列表
    pub children: Vec<String>,

    /// 当前状态
    pub status: AgentStatus,

    /// 节点创建时间
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// 节点完成时间
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,

    /// 节点元数据
    pub metadata: HashMap<String, serde_json::Value>,
}

impl AgentNode {
    /// 创建新的节点
    pub fn new(id: String, agent_type: AgentType, parent_id: Option<String>) -> Self {
        Self {
            id: id.clone(),
            agent_type,
            parent_id: parent_id.clone(),
            children: Vec::new(),
            status: AgentStatus::Created,
            created_at: chrono::Utc::now(),
            completed_at: None,
            metadata: HashMap::new(),
        }
    }

    /// 添加子节点
    pub fn add_child(&mut self, child_id: String) {
        self.children.push(child_id);
    }

    /// 更新状态
    pub fn update_status(&mut self, status: AgentStatus) {
        self.status = status;
        if matches!(
            status,
            AgentStatus::Completed | AgentStatus::Failed | AgentStatus::Stopped
        ) {
            self.completed_at = Some(chrono::Utc::now());
        }
    }

    /// 是否已完成
    pub fn is_completed(&self) -> bool {
        matches!(
            self.status,
            AgentStatus::Completed | AgentStatus::Failed | AgentStatus::Stopped
        )
    }
}

/// Agent 树可视化数据
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentTreeData {
    /// 节点数据
    pub nodes: Vec<TreeNodeData>,

    /// 边数据
    pub edges: Vec<TreeEdgeData>,
}

/// 树节点数据
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TreeNodeData {
    /// 节点 ID
    pub id: String,

    /// Agent 类型
    #[serde(rename = "type")]
    pub agent_type: String,

    /// 当前状态
    pub status: String,

    /// 显示标签
    pub label: String,

    /// 节点元数据
    pub metadata: HashMap<String, serde_json::Value>,
}

/// 树边数据
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TreeEdgeData {
    /// 源节点 ID
    pub from: String,

    /// 目标节点 ID
    pub to: String,

    /// 边类型（parent-child, message 等）
    #[serde(rename = "type")]
    pub edge_type: String,
}

/// 图形控制器
///
/// 管理 Agent 树的创建、更新和查询
pub struct GraphController {
    /// 所有节点
    nodes: Arc<RwLock<HashMap<String, AgentNode>>>,

    /// 根节点 ID
    root_id: Arc<RwLock<Option<String>>>,
}

impl GraphController {
    /// 创建新的图形控制器
    pub fn new() -> Self {
        Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            root_id: Arc::new(RwLock::new(None)),
        }
    }

    /// 创建根节点（Orchestrator）
    pub async fn create_root(&self, id: String) -> Result<(), String> {
        let mut root_id = self.root_id.write().await;
        if root_id.is_some() {
            return Err("根节点已存在".to_string());
        }

        let node = AgentNode::new(id.clone(), AgentType::Orchestrator, None);
        self.nodes.write().await.insert(id.clone(), node);
        *root_id = Some(id);

        Ok(())
    }

    /// 创建子节点
    pub async fn create_node(
        &self,
        id: String,
        agent_type: AgentType,
        parent_id: String,
    ) -> Result<(), String> {
        // 检查父节点是否存在
        let nodes = self.nodes.read().await;
        if !nodes.contains_key(&parent_id) {
            return Err(format!("父节点不存在: {}", parent_id));
        }
        drop(nodes);

        // 创建新节点
        let node = AgentNode::new(id.clone(), agent_type, Some(parent_id.clone()));

        // 更新父节点的子节点列表
        let mut nodes = self.nodes.write().await;
        if let Some(parent) = nodes.get_mut(&parent_id) {
            parent.add_child(id.clone());
        }
        nodes.insert(id, node);

        Ok(())
    }

    /// 更新节点状态
    pub async fn update_node_status(
        &self,
        id: &str,
        status: AgentStatus,
    ) -> Result<(), String> {
        let nodes = self.nodes.read().await;
        if !nodes.contains_key(id) {
            return Err(format!("节点不存在: {}", id));
        }
        drop(nodes);

        let mut nodes = self.nodes.write().await;
        if let Some(node) = nodes.get_mut(id) {
            node.update_status(status);
        }

        Ok(())
    }

    /// 获取节点
    pub async fn get_node(&self, id: &str) -> Option<AgentNode> {
        let nodes = self.nodes.read().await;
        nodes.get(id).cloned()
    }

    /// 获取所有子节点
    pub async fn get_children(&self, id: &str) -> Vec<AgentNode> {
        let nodes = self.nodes.read().await;
        if let Some(node) = nodes.get(id) {
            let mut children = Vec::new();
            for child_id in &node.children {
                if let Some(child) = nodes.get(child_id) {
                    children.push(child.clone());
                }
            }
            children
        } else {
            Vec::new()
        }
    }

    /// 获取父节点
    pub async fn get_parent(&self, id: &str) -> Option<AgentNode> {
        let nodes = self.nodes.read().await;
        if let Some(node) = nodes.get(id) {
            if let Some(parent_id) = &node.parent_id {
                nodes.get(parent_id).cloned()
            } else {
                None
            }
        } else {
            None
        }
    }

    /// 获取根节点
    pub async fn get_root(&self) -> Option<AgentNode> {
        let root_id = self.root_id.read().await;
        if let Some(id) = root_id.as_ref() {
            let nodes = self.nodes.read().await;
            nodes.get(id).cloned()
        } else {
            None
        }
    }

    /// 获取节点路径（从根到节点）
    pub async fn get_path(&self, id: &str) -> Vec<String> {
        let mut path = Vec::new();
        let mut current_id = id.to_string();

        loop {
            path.push(current_id.clone());

            let nodes = self.nodes.read().await;
            if let Some(node) = nodes.get(&current_id) {
                if let Some(parent_id) = &node.parent_id {
                    current_id = parent_id.clone();
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        path.reverse();
        path
    }

    /// 获取树的可视化数据
    pub async fn get_tree_data(&self) -> AgentTreeData {
        let nodes = self.nodes.read().await;
        let mut tree_nodes = Vec::new();
        let mut tree_edges = Vec::new();

        for (id, node) in nodes.iter() {
            // 节点数据
            tree_nodes.push(TreeNodeData {
                id: id.clone(),
                agent_type: node.agent_type.to_string(),
                status: node.status.to_string(),
                label: format!("{} ({})", node.agent_type, id),
                metadata: node.metadata.clone(),
            });

            // 边数据
            if let Some(parent_id) = &node.parent_id {
                tree_edges.push(TreeEdgeData {
                    from: parent_id.clone(),
                    to: id.clone(),
                    edge_type: "parent-child".to_string(),
                });
            }
        }

        AgentTreeData {
            nodes: tree_nodes,
            edges: tree_edges,
        }
    }

    /// 获取节点统计
    pub async fn get_stats(&self) -> GraphStats {
        let nodes = self.nodes.read().await;
        let total = nodes.len();
        let mut by_type = HashMap::new();
        let mut by_status = HashMap::new();
        let mut running = 0;
        let mut completed = 0;

        for node in nodes.values() {
            *by_type.entry(node.agent_type.to_string()).or_insert(0) += 1;
            *by_status.entry(node.status.to_string()).or_insert(0) += 1;

            if node.status == AgentStatus::Running {
                running += 1;
            }
            if node.is_completed() {
                completed += 1;
            }
        }

        GraphStats {
            total_nodes: total,
            nodes_by_type: by_type,
            nodes_by_status: by_status,
            running_nodes: running,
            completed_nodes: completed,
        }
    }

    /// 清空所有节点
    pub async fn clear(&self) {
        self.nodes.write().await.clear();
        *self.root_id.write().await = None;
    }

    /// 删除节点（及其子节点）
    pub async fn remove_node(&self, id: &str) -> Result<(), String> {
        // 不能删除根节点
        let root_id = self.root_id.read().await;
        if let Some(root) = root_id.as_ref() {
            if root == id {
                return Err("不能删除根节点".to_string());
            }
        }
        drop(root_id);

        // 递归删除所有子节点
        self.remove_node_recursive(id).await?;

        // 从父节点的子节点列表中移除
        let parent_id = {
            let nodes = self.nodes.read().await;
            if let Some(node) = nodes.get(id) {
                node.parent_id.clone()
            } else {
                None
            }
        };

        if let Some(parent_id) = parent_id {
            let mut nodes = self.nodes.write().await;
            if let Some(parent) = nodes.get_mut(&parent_id) {
                parent.children.retain(|c| c != id);
            }
        }

        Ok(())
    }

    /// 递归删除节点
    async fn remove_node_recursive(&self, id: &str) -> Result<(), String> {
        let children = self.get_children(id).await;
        for child in children {
            Box::pin(self.remove_node_recursive(&child.id)).await?;
        }

        let mut nodes = self.nodes.write().await;
        nodes.remove(id);
        Ok(())
    }
}

impl Default for GraphController {
    fn default() -> Self {
        Self::new()
    }
}

/// 图形统计信息
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GraphStats {
    /// 总节点数
    pub total_nodes: usize,

    /// 按类型统计
    pub nodes_by_type: HashMap<String, usize>,

    /// 按状态统计
    pub nodes_by_status: HashMap<String, usize>,

    /// 运行中的节点数
    pub running_nodes: usize,

    /// 已完成的节点数
    pub completed_nodes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_graph_controller() {
        let controller = GraphController::new();

        // 创建根节点
        controller
            .create_root("orchestrator".to_string())
            .await
            .unwrap();

        // 创建子节点
        controller
            .create_node("recon".to_string(), AgentType::Recon, "orchestrator".to_string())
            .await
            .unwrap();

        controller
            .create_node(
                "analysis".to_string(),
                AgentType::Analysis,
                "orchestrator".to_string(),
            )
            .await
            .unwrap();

        // 验证结构
        let root = controller.get_root().await.unwrap();
        assert_eq!(root.id, "orchestrator");
        assert_eq!(root.children.len(), 2);

        let children = controller.get_children("orchestrator").await;
        assert_eq!(children.len(), 2);

        // 获取统计
        let stats = controller.get_stats().await;
        assert_eq!(stats.total_nodes, 3);
    }
}
