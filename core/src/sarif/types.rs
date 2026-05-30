// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! SARIF 2.1.0 强类型定义
//!
//! 对齐 https://json.schemastore.org/sarif-2.1.0.json

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// SARIF 日志根对象
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLog {
    pub version: String,
    #[serde(rename = "$schema")]
    pub schema: String,
    pub runs: Vec<Run>,
}

impl SarifLog {
    pub fn new(runs: Vec<Run>) -> Self {
        Self {
            version: "2.1.0".to_string(),
            schema: "https://json.schemastore.org/sarif-2.1.0.json".to_string(),
            runs,
        }
    }
}

/// 单次运行
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Run {
    pub tool: Tool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub invocations: Vec<Invocation>,
    pub results: Vec<SarifResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_severity: Option<String>,
}

/// 工具信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    pub driver: ToolComponent,
}

/// 工具组件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolComponent {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<ReportingDescriptor>,
}

/// 规则描述符
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportingDescriptor {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_description: Option<Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_description: Option<Message>,
    #[serde(rename = "helpUri", skip_serializing_if = "Option::is_none")]
    pub help_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<PropertyBag>,
}

/// 调用记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invocation {
    #[serde(rename = "executionSuccessful")]
    pub execution_successful: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time: Option<String>,
    #[serde(rename = "exitCode", skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_execution_notifications: Option<Vec<Notification>>,
}

/// 通知
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub level: String,
    pub message: Message,
}

/// SARIF 结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    #[serde(rename = "ruleIndex", skip_serializing_if = "Option::is_none")]
    pub rule_index: Option<usize>,
    pub level: String,
    pub message: Message,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<Location>,
    #[serde(rename = "codeFlows", skip_serializing_if = "Vec::is_empty")]
    pub code_flows: Vec<CodeFlow>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fixes: Vec<Fix>,
    #[serde(rename = "relatedLocations", skip_serializing_if = "Vec::is_empty")]
    pub related_locations: Vec<Location>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub suppressions: Vec<Suppression>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<PropertyBag>,
}

/// 消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub text: String,
}

impl Message {
    pub fn new(text: impl Into<String>) -> Self {
        Self { text: text.into() }
    }
}

/// 位置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    #[serde(rename = "physicalLocation")]
    pub physical_location: PhysicalLocation,
}

/// 物理位置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: ArtifactLocation,
    pub region: Region,
}

/// 制品位置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactLocation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(rename = "uriBaseId", skip_serializing_if = "Option::is_none")]
    pub uri_base_id: Option<String>,
}

/// 区域
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Region {
    #[serde(rename = "startLine")]
    pub start_line: u32,
    #[serde(rename = "startColumn", skip_serializing_if = "Option::is_none")]
    pub start_column: Option<u32>,
    #[serde(rename = "endLine", skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    #[serde(rename = "endColumn", skip_serializing_if = "Option::is_none")]
    pub end_column: Option<u32>,
    #[serde(rename = "byteOffset", skip_serializing_if = "Option::is_none")]
    pub byte_offset: Option<u32>,
    #[serde(rename = "byteLength", skip_serializing_if = "Option::is_none")]
    pub byte_length: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<ArtifactContent>,
}

/// 制品内容
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactContent {
    pub text: String,
}

/// 代码流 — 污点路径
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeFlow {
    #[serde(rename = "threadFlows")]
    pub thread_flows: Vec<ThreadFlow>,
}

/// 线程流
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadFlow {
    pub locations: Vec<ThreadFlowLocation>,
}

/// 线程流位置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadFlowLocation {
    pub location: Location,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    #[serde(rename = "nestingLevel")]
    pub nesting_level: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<PropertyBag>,
}

/// 修复建议
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fix {
    pub description: Message,
    #[serde(rename = "artifactChanges")]
    pub artifact_changes: Vec<ArtifactChange>,
}

/// 制品变更
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactChange {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: ArtifactLocation,
    pub replacements: Vec<Replacement>,
}

/// 替换
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Replacement {
    #[serde(rename = "deletedRegion")]
    pub deleted_region: Region,
    #[serde(rename = "insertedContent", skip_serializing_if = "Option::is_none")]
    pub inserted_content: Option<ArtifactContent>,
}

/// 抑制
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suppression {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,
}

/// 属性包
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyBag {
    #[serde(flatten)]
    pub additional_properties: HashMap<String, serde_json::Value>,
}

impl PropertyBag {
    pub fn new() -> Self {
        Self {
            additional_properties: HashMap::new(),
        }
    }

    pub fn with(mut self, key: String, value: serde_json::Value) -> Self {
        self.additional_properties.insert(key, value);
        self
    }
}

impl Default for PropertyBag {
    fn default() -> Self {
        Self::new()
    }
}
