//! Agent 引擎核心模块
//!
//! 提供 Agent 管理和执行的核心功能

pub mod agents;
pub mod base;
pub mod graph_controller;
pub mod message_bus;
pub mod react_parser;
pub mod registry;
pub mod state;

// 重新导出常用类型
pub use agents::{AnalysisAgent, OrchestratorAgent, ReconAgent, VerificationAgent};
pub use base::{Agent, ReactAgent};
pub use graph_controller::{AgentTreeData, GraphController, TreeNodeData, TreeEdgeData};
pub use message_bus::MessageBus;
pub use react_parser::{ParseError, ReactParser, ReactStep};
pub use registry::{AgentInfo, AgentRegistry};
pub use state::{AgentState, AgentStateHandle};
