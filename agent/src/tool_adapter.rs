// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 工具适配器：ToolDefinition → OpenAI function-calling schema + 执行
//!
//! 复用 `ToolDefinition::to_mcp_schema()` 的输出作为 parameters；
//! 执行走 `ToolRegistry::execute`；参数 JSON 解析失败时把错误回喂模型而不是崩溃；
//! 工具输出统一截断（8KB）。

use std::sync::Arc;

use ctx_audit_tools::{ToolDefinition, ToolRegistry};

use crate::confirm::ToolGate;
use crate::provider::ToolCall;

/// 工具输出截断上限（字节）
pub const MAX_TOOL_OUTPUT_BYTES: usize = 8 * 1024;

/// 单个 ToolDefinition 转 OpenAI function-calling schema
pub fn to_openai_tool(def: &ToolDefinition) -> serde_json::Value {
    serde_json::json!({
        "type": "function",
        "function": {
            "name": def.name,
            "description": def.description,
            "parameters": def.to_mcp_schema(),
        }
    })
}

/// 批量转换工具 schema
pub fn tools_schema(defs: &[ToolDefinition]) -> Vec<serde_json::Value> {
    defs.iter().map(to_openai_tool).collect()
}

/// 一次工具执行的产出（回喂模型 + 落会话）
#[derive(Debug, Clone)]
pub struct ToolOutput {
    /// 调用 ID
    pub call_id: String,
    /// 工具名
    pub name: String,
    /// 输出文本（已截断）
    pub content: String,
    /// 是否错误
    pub is_error: bool,
}

/// 工具适配器
pub struct ToolAdapter {
    registry: Arc<ToolRegistry>,
    gate: ToolGate,
    /// 工具白名单（M4 子 agent）：None = 全部工具；
    /// Some 时 schema 层只暴露白名单内工具，执行层拦截白名单外调用
    whitelist: Option<std::collections::HashSet<String>>,
}

impl ToolAdapter {
    /// 创建适配器
    pub fn new(registry: Arc<ToolRegistry>, gate: ToolGate) -> Self {
        Self {
            registry,
            gate,
            whitelist: None,
        }
    }

    /// 派生白名单子适配器（共享 registry 与 gate，schema/执行双层过滤）
    pub fn with_whitelist(&self, whitelist: Option<Vec<String>>) -> Self {
        Self {
            registry: Arc::clone(&self.registry),
            gate: self.gate.clone(),
            whitelist: whitelist.map(|names| names.into_iter().collect()),
        }
    }

    /// 底层 registry（子 agent 派生用）
    pub fn registry(&self) -> &Arc<ToolRegistry> {
        &self.registry
    }

    /// 审批闸门（子 agent 派生用）
    pub fn gate(&self) -> &ToolGate {
        &self.gate
    }

    /// 获取工具的 OpenAI schema（白名单内工具）
    pub async fn tool_schemas(&self) -> Vec<serde_json::Value> {
        let defs = self.registry.get_definitions().await;
        let defs: Vec<_> = match &self.whitelist {
            Some(allow) => defs
                .into_iter()
                .filter(|d| allow.contains(&d.name))
                .collect(),
            None => defs,
        };
        tools_schema(&defs)
    }

    /// 执行一次工具调用
    ///
    /// 任何失败（gate 拒绝 / 参数解析失败 / 工具不存在 / 执行错误）
    /// 都转化为 is_error 的 ToolOutput 回喂模型，不向上抛错。
    pub async fn execute(&self, call: &ToolCall) -> ToolOutput {
        // ── 白名单拦截（子 agent：schema 层不暴露，执行层再拦一次兜底） ──
        if let Some(ref allow) = self.whitelist {
            if !allow.contains(&call.name) {
                return ToolOutput {
                    call_id: call.id.clone(),
                    name: call.name.clone(),
                    content: format!(
                        "工具 {} 不在本子 agent 的白名单内，已拒绝执行；请使用可用工具或直接输出结论",
                        call.name
                    ),
                    is_error: true,
                };
            }
        }

        // ── 审批闸门 ──
        if let Err(reason) = self.gate.check(&call.name) {
            return ToolOutput {
                call_id: call.id.clone(),
                name: call.name.clone(),
                content: reason,
                is_error: true,
            };
        }

        // ── 参数解析：失败回喂模型而不是崩溃 ──
        let args = if call.arguments.trim().is_empty() {
            serde_json::json!({})
        } else {
            match serde_json::from_str::<serde_json::Value>(&call.arguments) {
                Ok(v) => v,
                Err(e) => {
                    return ToolOutput {
                        call_id: call.id.clone(),
                        name: call.name.clone(),
                        content: format!(
                            "参数 JSON 解析失败: {}；原始参数: {}。请修正参数格式后重试",
                            e,
                            truncate_output(&call.arguments, 500)
                        ),
                        is_error: true,
                    };
                }
            }
        };

        // ── 执行 ──
        match self.registry.execute(&call.name, args).await {
            Ok(result) => ToolOutput {
                call_id: call.id.clone(),
                name: call.name.clone(),
                content: truncate_output(result.get_text(), MAX_TOOL_OUTPUT_BYTES),
                is_error: result.is_error,
            },
            Err(e) => ToolOutput {
                call_id: call.id.clone(),
                name: call.name.clone(),
                content: format!("工具执行失败: {}", e),
                is_error: true,
            },
        }
    }
}

/// 按字节上限安全截断（不切断 UTF-8 字符）
pub fn truncate_output(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    // 在 max_bytes 内找最后一个 char 边界
    let mut end = max_bytes;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n...[输出过长已截断，原始 {} 字节]", &text[..end], text.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use ctx_audit_tools::{
        Tool, ToolCategory, ToolError, ToolParameter, ToolParameterType, ToolResult,
    };

    /// 构造一个真实结构的 ToolDefinition 验证 schema 转换
    fn sample_definition() -> ToolDefinition {
        ToolDefinition::new("read_file", "读取文件内容", ToolCategory::File)
            .add_parameter(ToolParameter {
                name: "path".to_string(),
                param_type: ToolParameterType::String,
                description: "文件路径".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "limit".to_string(),
                param_type: ToolParameterType::Integer,
                description: "最大行数".to_string(),
                required: false,
                default: Some(serde_json::json!(100)),
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
    }

    /// schema 转换：name/description/parameters/required/default
    #[test]
    fn test_to_openai_tool_schema() {
        let schema = to_openai_tool(&sample_definition());
        assert_eq!(schema["type"], "function");
        assert_eq!(schema["function"]["name"], "read_file");
        assert_eq!(schema["function"]["description"], "读取文件内容");

        let params = &schema["function"]["parameters"];
        assert_eq!(params["type"], "object");
        assert_eq!(params["properties"]["path"]["type"], "string");
        assert_eq!(params["properties"]["limit"]["type"], "integer");
        assert_eq!(params["properties"]["limit"]["default"], 100);
        assert_eq!(params["required"], serde_json::json!(["path"]));
    }

    /// 输出截断：短文本原样、长文本截断且不切断 UTF-8
    #[test]
    fn test_truncate_output() {
        assert_eq!(truncate_output("abc", 10), "abc");

        let long = "汉".repeat(100); // 300 字节
        let truncated = truncate_output(&long, 100);
        // 100 不是 3 的倍数，应回退到 99 字节（33 个汉字）
        assert!(truncated.contains("已截断"));
        assert!(truncated.starts_with(&"汉".repeat(33)));
    }

    /// 测试用 echo 工具
    struct EchoTool;

    #[async_trait]
    impl Tool for EchoTool {
        fn name(&self) -> &str {
            "echo_tool"
        }
        fn description(&self) -> &str {
            "回显输入"
        }
        fn category(&self) -> ToolCategory {
            ToolCategory::Custom
        }
        fn definition(&self) -> ToolDefinition {
            ToolDefinition::new("echo_tool", "回显输入", ToolCategory::Custom)
        }
        async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ToolError> {
            Ok(ToolResult::text(format!("echo: {}", input)))
        }
    }

    async fn make_adapter(mode: crate::confirm::ApprovalMode) -> ToolAdapter {
        let registry = Arc::new(ToolRegistry::new());
        registry.register(Arc::new(EchoTool)).await.unwrap();
        ToolAdapter::new(registry, ToolGate::new(mode))
    }

    /// 正常执行路径
    #[tokio::test]
    async fn test_execute_success() {
        let adapter = make_adapter(crate::confirm::ApprovalMode::Auto).await;
        let call = ToolCall {
            id: "c1".into(),
            name: "echo_tool".into(),
            arguments: r#"{"msg":"hi"}"#.into(),
        };
        let out = adapter.execute(&call).await;
        assert!(!out.is_error);
        assert!(out.content.contains("echo:"));
    }

    /// 参数 JSON 解析失败 → 错误回喂模型，不 panic
    #[tokio::test]
    async fn test_execute_bad_arguments_feeds_back() {
        let adapter = make_adapter(crate::confirm::ApprovalMode::Auto).await;
        let call = ToolCall {
            id: "c2".into(),
            name: "echo_tool".into(),
            arguments: "{not valid json".into(),
        };
        let out = adapter.execute(&call).await;
        assert!(out.is_error);
        assert!(out.content.contains("参数 JSON 解析失败"));
    }

    /// 工具不存在 → 错误回喂
    #[tokio::test]
    async fn test_execute_unknown_tool() {
        let adapter = make_adapter(crate::confirm::ApprovalMode::Auto).await;
        let call = ToolCall {
            id: "c3".into(),
            name: "no_such_tool".into(),
            arguments: "{}".into(),
        };
        let out = adapter.execute(&call).await;
        assert!(out.is_error);
        assert!(out.content.contains("工具执行失败"));
    }

    /// Gate 模式拒绝写工具
    #[tokio::test]
    async fn test_execute_gate_denies_write() {
        let adapter = make_adapter(crate::confirm::ApprovalMode::Gate).await;
        let call = ToolCall {
            id: "c4".into(),
            name: "report_finding".into(),
            arguments: "{}".into(),
        };
        let out = adapter.execute(&call).await;
        assert!(out.is_error);
        assert!(out.content.contains("已拒绝执行"));
    }

    /// 白名单（M4 子 agent）：schema 层只暴露白名单内工具
    #[tokio::test]
    async fn test_whitelist_filters_schemas() {
        let adapter = make_adapter(crate::confirm::ApprovalMode::Auto).await;
        let sub = adapter.with_whitelist(Some(vec!["echo_tool".to_string()]));
        let schemas = sub.tool_schemas().await;
        assert_eq!(schemas.len(), 1);
        assert_eq!(schemas[0]["function"]["name"], "echo_tool");

        // 空白名单 → 不暴露任何工具
        let none = adapter.with_whitelist(Some(vec![]));
        assert!(none.tool_schemas().await.is_empty());

        // 父适配器不受影响
        assert_eq!(adapter.tool_schemas().await.len(), 1);
    }

    /// 白名单：执行层拦截白名单外调用（模型执意请求也兜底）
    #[tokio::test]
    async fn test_whitelist_blocks_execution() {
        let adapter = make_adapter(crate::confirm::ApprovalMode::Auto).await;

        // echo_tool 已注册但不在白名单 → 拦截回喂
        let sub = adapter.with_whitelist(Some(vec!["other_tool".to_string()]));
        let call = ToolCall {
            id: "w1".into(),
            name: "echo_tool".into(),
            arguments: "{}".into(),
        };
        let out = sub.execute(&call).await;
        assert!(out.is_error);
        assert!(out.content.contains("白名单"));

        // 白名单内 → 正常执行
        let sub2 = adapter.with_whitelist(Some(vec!["echo_tool".to_string()]));
        let out = sub2.execute(&call).await;
        assert!(!out.is_error);
    }
}
