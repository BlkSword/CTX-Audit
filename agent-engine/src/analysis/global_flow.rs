// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 全局数据流追踪
//!
//! 跨文件、跨模块的完整数据流分析

use crate::audit_state::{VulnerabilityCandidate, PropagationStepInfo};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// 全局数据流图谱
pub struct GlobalFlowGraph {
    /// 节点：函数/方法/类
    nodes: HashMap<NodeId, FlowNode>,

    /// 边：数据流向
    edges: Vec<FlowEdge>,

    /// 入口点索引
    entry_points: Vec<EntryPoint>,

    /// 项目路径
    project_path: String,
}

/// 流节点
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowNode {
    /// 节点 ID
    pub id: NodeId,

    /// 文件路径
    pub file_path: String,

    /// 函数/方法名
    pub symbol: String,

    /// 节点类型
    pub node_type: NodeType,

    /// 安全属性
    pub security_props: SecurityProperties,

    /// 输入参数
    pub inputs: Vec<Parameter>,

    /// 输出
    pub outputs: Vec<Output>,

    /// 起始行号
    pub start_line: usize,

    /// 结束行号
    pub end_line: usize,
}

/// 节点 ID
#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct NodeId {
    /// 文件路径
    pub file_path: String,

    /// 符号名
    pub symbol: String,
}

/// 节点类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NodeType {
    /// 函数
    Function,

    /// 方法
    Method,

    /// 类
    Class,

    /// 模块
    Module,

    /// Lambda/闭包
    Lambda,
}

/// 安全属性
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityProperties {
    /// 是否接受用户输入
    pub accepts_user_input: bool,

    /// 是否有验证
    pub has_validation: bool,

    /// 是否是危险汇
    pub is_dangerous_sink: bool,

    /// 框架安全标记
    pub framework_protection: Vec<String>,
}

/// 参数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    /// 参数名
    pub name: String,

    /// 参数类型
    pub param_type: String,

    /// 是否污点
    pub is_tainted: bool,
}

/// 输出
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Output {
    /// 变量名
    pub name: String,

    /// 输出类型
    pub output_type: String,

    /// 是否污点
    pub is_tainted: bool,
}

/// 流边
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowEdge {
    /// 源节点
    pub from: NodeId,

    /// 目标节点
    pub to: NodeId,

    /// 边类型
    pub edge_type: EdgeType,

    /// 数据变量名
    pub data_variable: Option<String>,
}

/// 边类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EdgeType {
    /// 函数调用
    Call,

    /// 数据流
    DataFlow,

    /// 继承
    Inherit,

    /// 导入
    Import,
}

/// 入口点
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryPoint {
    /// 节点 ID
    pub node_id: NodeId,

    /// 入口类型
    pub entry_type: EntryPointType,

    /// 请求路径（对于 Web 应用）
    pub route_path: Option<String>,
}

/// 入口点类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EntryPointType {
    /// HTTP 路由
    HttpRoute,

    /// 命令行参数
    CommandLine,

    /// 定时任务
    CronJob,

    /// 消息队列
    MessageQueue,

    /// WebSocket 连接
    WebSocket,
}

/// 跨文件引用
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossFileReference {
    /// 源文件
    pub from_file: String,

    /// 源符号
    pub from_symbol: String,

    /// 目标文件
    pub to_file: String,

    /// 目标符号
    pub to_symbol: String,

    /// 引用类型
    pub ref_type: CrossFileType,
}

/// 跨文件引用类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CrossFileType {
    /// 函数调用
    FunctionCall,

    /// 类继承
    ClassInherit,

    /// 模块导入
    ModuleImport,

    /// 变量引用
    VariableReference,
}

/// 全局污点追踪结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalTaintResult {
    /// 污点源
    pub sources: Vec<TaintSource>,

    /// 污点汇
    pub sinks: Vec<TaintSink>,

    /// 完整路径
    pub paths: Vec<TaintPath>,

    /// 漏洞候选
    pub candidates: Vec<VulnerabilityCandidate>,
}

/// 污点源（全局）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSource {
    /// 节点 ID
    pub node_id: NodeId,

    /// 变量名
    pub variable: String,

    /// 源类型
    pub source_type: TaintSourceType,

    /// 描述
    pub description: String,
}

/// 污点源类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TaintSourceType {
    /// HTTP 请求
    HttpRequest,

    /// 用户输入
    UserInput,

    /// 文件读取
    FileRead,

    /// 环境变量
    EnvironmentVariable,

    /// 数据库查询
    DatabaseQuery,

    /// 网络请求
    NetworkRequest,
}

/// 污点汇（全局）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSink {
    /// 节点 ID
    pub node_id: NodeId,

    /// 汇类型
    pub sink_type: String,

    /// 严重程度
    pub severity: String,

    /// 描述
    pub description: String,
}

/// 污点路径（跨文件）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintPath {
    /// 路径 ID
    pub id: String,

    /// 路径步骤
    pub steps: Vec<TaintPathStep>,

    /// 漏洞类型
    pub vulnerability_type: String,

    /// 置信度
    pub confidence: f32,
}

/// 污点路径步骤
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintPathStep {
    /// 节点 ID
    pub node_id: NodeId,

    /// 变量名
    pub variable: String,

    /// 操作类型
    pub operation: String,

    /// 是否有净化
    pub has_sanitization: bool,

    /// 行号
    pub line: usize,
}

impl GlobalFlowGraph {
    /// 创建新的全局流图
    pub fn new(project_path: String) -> Self {
        Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
            entry_points: Vec::new(),
            project_path,
        }
    }

    /// 添加节点
    pub fn add_node(&mut self, node: FlowNode) {
        let id = node.id.clone();
        self.nodes.insert(id, node);
    }

    /// 添加边
    pub fn add_edge(&mut self, edge: FlowEdge) {
        self.edges.push(edge);
    }

    /// 添加入口点
    pub fn add_entry_point(&mut self, entry: EntryPoint) {
        self.entry_points.push(entry);
    }

    /// 获取节点
    pub fn get_node(&self, id: &NodeId) -> Option<&FlowNode> {
        self.nodes.get(id)
    }

    /// 获取所有节点
    pub fn nodes(&self) -> &HashMap<NodeId, FlowNode> {
        &self.nodes
    }

    /// 获取所有边
    pub fn edges(&self) -> &[FlowEdge] {
        &self.edges
    }

    /// 获取所有入口点
    pub fn entry_points(&self) -> &[EntryPoint] {
        &self.entry_points
    }

    /// 查找从入口点到危险汇的路径
    pub fn find_paths_to_sinks(&self) -> Vec<TaintPath> {
        let mut paths = Vec::new();

        for entry in &self.entry_points {
            if let Some(node) = self.nodes.get(&entry.node_id) {
                // 从入口点开始，追踪污点传播
                let entry_paths = self.trace_taint_from_node(&node.id);
                paths.extend(entry_paths);
            }
        }

        paths
    }

    /// 从指定节点追踪污点传播
    fn trace_taint_from_node(&self, start_id: &NodeId) -> Vec<TaintPath> {
        let mut paths = Vec::new();
        let mut visited = HashSet::new();
        let mut current_path = Vec::new();

        self.dfs_trace(start_id, &mut visited, &mut current_path, &mut paths);

        paths
    }

    /// DFS 追踪污点
    fn dfs_trace(
        &self,
        current_id: &NodeId,
        visited: &mut HashSet<NodeId>,
        current_path: &mut Vec<TaintPathStep>,
        all_paths: &mut Vec<TaintPath>,
    ) {
        visited.insert(current_id.clone());

        if let Some(node) = self.nodes.get(current_id) {
            // 检查是否是危险汇
            if node.security_props.is_dangerous_sink {
                // 创建完整路径
                all_paths.push(TaintPath {
                    id: format!("path_{}", all_paths.len()),
                    steps: current_path.clone(),
                    vulnerability_type: "taint".to_string(),
                    confidence: 0.7,
                });
            }

            // 追踪到下游节点
            for edge in &self.edges {
                if edge.from == *current_id && !visited.contains(&edge.to) {
                    if let Some(to_node) = self.nodes.get(&edge.to) {
                        let step = TaintPathStep {
                            node_id: to_node.id.clone(),
                            variable: edge.data_variable.clone().unwrap_or_default(),
                            operation: format!("{:?}", edge.edge_type),
                            has_sanitization: to_node.security_props.has_validation,
                            line: to_node.start_line,
                        };

                        current_path.push(step);
                        self.dfs_trace(&edge.to, visited, current_path, all_paths);
                        current_path.pop();
                    }
                }
            }
        }

        visited.remove(current_id);
    }

    /// 构建全局污点追踪结果
    pub fn build_taint_result(&self) -> GlobalTaintResult {
        // 收集所有污点源
        let sources = self.collect_taint_sources();

        // 收集所有污点汇
        let sinks = self.collect_taint_sinks();

        // 查找所有路径
        let paths = self.find_paths_to_sinks();

        // 生成漏洞候选
        let candidates = self.generate_candidates(&paths);

        GlobalTaintResult {
            sources,
            sinks,
            paths,
            candidates,
        }
    }

    /// 收集污点源
    fn collect_taint_sources(&self) -> Vec<TaintSource> {
        let mut sources = Vec::new();

        for (id, node) in &self.nodes {
            if node.security_props.accepts_user_input {
                sources.push(TaintSource {
                    node_id: id.clone(),
                    variable: node.inputs.iter()
                        .find(|p| p.is_tainted)
                        .map(|p| p.name.clone())
                        .unwrap_or_default(),
                    source_type: TaintSourceType::UserInput,
                    description: format!("{} accepts user input", node.symbol),
                });
            }
        }

        sources
    }

    /// 收集污点汇
    fn collect_taint_sinks(&self) -> Vec<TaintSink> {
        let mut sinks = Vec::new();

        for (id, node) in &self.nodes {
            if node.security_props.is_dangerous_sink {
                sinks.push(TaintSink {
                    node_id: id.clone(),
                    sink_type: "dangerous_function".to_string(),
                    severity: "High".to_string(),
                    description: format!("{} is a dangerous sink", node.symbol),
                });
            }
        }

        sinks
    }

    /// 生成漏洞候选
    fn generate_candidates(&self, paths: &[TaintPath]) -> Vec<VulnerabilityCandidate> {
        paths.iter().map(|path| {
            let first_step = path.steps.first();
            let last_step = path.steps.last();

            VulnerabilityCandidate {
                id: format!("global_{}", path.id),
                vulnerability_type: path.vulnerability_type.clone(),
                severity: "High".to_string(),
                confidence: path.confidence,
                source: "global_taint_analysis".to_string(),
                file_path: first_step.map(|s| s.node_id.file_path.clone()).unwrap_or_default(),
                line: first_step.map(|s| s.line).unwrap_or(0),
                code_snippet: None,
                propagation_path: Some(
                    path.steps.iter().map(|step| {
                        PropagationStepInfo {
                            line: step.line,
                            symbol: step.variable.clone(),
                            code: None,
                        }
                    }).collect()
                ),
                verification_status: crate::audit_state::VerificationStatus::Pending,
                verification_result: None,
            }
        }).collect()
    }

    /// 扫描项目文件（简化版）
    pub fn scan_project_files(project_path: &str) -> Vec<String> {
        let mut files = Vec::new();

        // 简化实现：只返回常见的代码文件
        let extensions = [".rs", ".py", ".js", ".ts", ".java", ".go"];

        if let Ok(entries) = std::fs::read_dir(project_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(ext) = path.extension() {
                        if extensions.contains(&ext.to_string_lossy().as_ref()) {
                            if let Some(path_str) = path.to_str() {
                                files.push(path_str.to_string());
                            }
                        }
                    }
                }
            }
        }

        files
    }

    /// 解析跨文件引用
    pub fn resolve_cross_file_references(&mut self) -> Vec<CrossFileReference> {
        let mut refs = Vec::new();

        // 简化实现：基于导入语句检测跨文件引用
        for (node_id, node) in &self.nodes {
            // 检查输入参数的类型是否来自其他文件
            for param in &node.inputs {
                if param.param_type.contains("::") {
                    let parts: Vec<&str> = param.param_type.split("::").collect();
                    if parts.len() >= 2 {
                        let module = parts[0];
                        let symbol = parts.last().unwrap_or(&"");

                        // 尝试找到对应的模块文件
                        let possible_file = format!("{}/{}.rs", self.project_path, module.replace("::", "/"));
                        if Path::new(&possible_file).exists() {
                            refs.push(CrossFileReference {
                                from_file: node.file_path.clone(),
                                from_symbol: node.symbol.clone(),
                                to_file: possible_file,
                                to_symbol: symbol.to_string(),
                                ref_type: CrossFileType::ModuleImport,
                            });
                        }
                    }
                }
            }
        }

        refs
    }

    /// 构建调用图
    pub fn build_call_graph(&mut self) {
        // 简化实现：基于已有边构建
        let mut call_edges = Vec::new();

        for edge in &self.edges {
            if edge.edge_type == EdgeType::Call {
                call_edges.push(edge.clone());
            }
        }
    }

    /// 标记安全属性
    pub fn annotate_security_properties(&mut self) {
        // 标记危险函数
        let dangerous_patterns = [
            "execute", "exec", "eval", "system", "query", "sql",
            "shell", "command", "render_template", "serialize",
        ];

        for node in self.nodes.values_mut() {
            // 检查是否是危险汇
            let symbol_lower = node.symbol.to_lowercase();
            node.security_props.is_dangerous_sink = dangerous_patterns
                .iter()
                .any(|pattern| symbol_lower.contains(pattern));

            // 检查是否有验证
            node.security_props.has_validation = node.symbol.to_lowercase().contains("validate")
                || node.symbol.to_lowercase().contains("sanitize");
        }
    }
}

impl Default for GlobalFlowGraph {
    fn default() -> Self {
        Self::new(".".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_flow_graph_creation() {
        let graph = GlobalFlowGraph::new("/test".to_string());
        assert_eq!(graph.nodes.len(), 0);
        assert_eq!(graph.edges.len(), 0);
    }

    #[test]
    fn test_add_node() {
        let mut graph = GlobalFlowGraph::new("/test".to_string());

        let node = FlowNode {
            id: NodeId {
                file_path: "test.rs".to_string(),
                symbol: "test_function".to_string(),
            },
            file_path: "test.rs".to_string(),
            symbol: "test_function".to_string(),
            node_type: NodeType::Function,
            security_props: SecurityProperties {
                accepts_user_input: false,
                has_validation: false,
                is_dangerous_sink: false,
                framework_protection: vec![],
            },
            inputs: vec![],
            outputs: vec![],
            start_line: 1,
            end_line: 10,
        };

        graph.add_node(node);
        assert_eq!(graph.nodes.len(), 1);
    }

    #[test]
    fn test_add_edge() {
        let mut graph = GlobalFlowGraph::new("/test".to_string());

        let from = NodeId {
            file_path: "a.rs".to_string(),
            symbol: "func_a".to_string(),
        };
        let to = NodeId {
            file_path: "b.rs".to_string(),
            symbol: "func_b".to_string(),
        };

        let edge = FlowEdge {
            from: from.clone(),
            to: to.clone(),
            edge_type: EdgeType::Call,
            data_variable: Some("data".to_string()),
        };

        graph.add_edge(edge);
        assert_eq!(graph.edges.len(), 1);
    }
}
