// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 事件模型

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 漏洞数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingData {
    /// 漏洞 ID
    pub id: Option<String>,

    /// 漏洞标题
    pub title: Option<String>,

    /// 漏洞描述
    pub description: String,

    /// 严重程度
    pub severity: String,

    /// 类别
    pub category: String,

    /// CWE ID
    pub cwe_id: Option<String>,

    /// 文件路径
    pub file_path: String,

    /// 起始行号
    pub start_line: u32,

    /// 结束行号
    pub end_line: Option<u32>,

    /// 代码片段
    pub code_snippet: Option<String>,

    /// 修复建议
    pub recommendation: Option<String>,

    /// 状态
    pub status: String,

    /// 验证状态
    pub verification_status: Option<String>,

    /// 发现者
    pub discovered_by: Option<String>,

    /// 额外信息
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}
