// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 内置 SARIF 规则注册表
//!
//! 从 TaintAnalyzer 的 sink 定义映射为 SARIF ReportingDescriptor

use super::types::{Message, PropertyBag, ReportingDescriptor};

/// 内置安全规则
pub fn built_in_rules() -> Vec<ReportingDescriptor> {
    vec![
        ReportingDescriptor {
            id: "CWE-89".into(),
            name: Some("SQL Injection".into()),
            short_description: Some(Message::new(
                "User input flows into SQL query without proper sanitization",
            )),
            full_description: Some(Message::new(
                "The software constructs all or part of an SQL command using externally-influenced input \
                 from an upstream component, but it does not neutralize or incorrectly neutralizes \
                 special elements that could modify the intended SQL command.",
            )),
            help_uri: Some("https://cwe.mitre.org/data/definitions/89.html".into()),
            properties: Some(
                PropertyBag::new()
                    .with("category".into(), serde_json::json!("injection"))
                    .with("severity".into(), serde_json::json!("critical")),
            ),
        },
        ReportingDescriptor {
            id: "CWE-78".into(),
            name: Some("OS Command Injection".into()),
            short_description: Some(Message::new(
                "User input flows into OS command execution without proper sanitization",
            )),
            full_description: Some(Message::new(
                "The software constructs all or part of an OS command using externally-influenced input \
                 from an upstream component, but it does not neutralize or incorrectly neutralizes \
                 special elements that could modify the intended OS command.",
            )),
            help_uri: Some("https://cwe.mitre.org/data/definitions/78.html".into()),
            properties: Some(
                PropertyBag::new()
                    .with("category".into(), serde_json::json!("injection"))
                    .with("severity".into(), serde_json::json!("critical")),
            ),
        },
        ReportingDescriptor {
            id: "CWE-22".into(),
            name: Some("Path Traversal".into()),
            short_description: Some(Message::new(
                "User input is used to construct a file path without proper validation",
            )),
            full_description: Some(Message::new(
                "The software uses external input to construct a pathname that is intended to identify \
                 a file or directory that is located underneath a restricted parent directory, \
                 but the software does not properly neutralize special elements within the pathname.",
            )),
            help_uri: Some("https://cwe.mitre.org/data/definitions/22.html".into()),
            properties: Some(
                PropertyBag::new()
                    .with("category".into(), serde_json::json!("path-manipulation"))
                    .with("severity".into(), serde_json::json!("high")),
            ),
        },
        ReportingDescriptor {
            id: "CWE-79".into(),
            name: Some("Cross-Site Scripting (XSS)".into()),
            short_description: Some(Message::new(
                "User input is rendered in HTML output without proper escaping",
            )),
            full_description: Some(Message::new(
                "The software does not neutralize or incorrectly neutralizes user-controllable input \
                 before it is placed in output that is used as a web page that is served to other users.",
            )),
            help_uri: Some("https://cwe.mitre.org/data/definitions/79.html".into()),
            properties: Some(
                PropertyBag::new()
                    .with("category".into(), serde_json::json!("xss"))
                    .with("severity".into(), serde_json::json!("high")),
            ),
        },
        ReportingDescriptor {
            id: "CWE-918".into(),
            name: Some("Server-Side Request Forgery (SSRF)".into()),
            short_description: Some(Message::new(
                "User input controls the target of an outgoing HTTP request",
            )),
            full_description: Some(Message::new(
                "The software constructs HTTP requests from user-supplied input without proper validation, \
                 allowing the attacker to make the server send requests to unintended destinations.",
            )),
            help_uri: Some("https://cwe.mitre.org/data/definitions/918.html".into()),
            properties: Some(
                PropertyBag::new()
                    .with("category".into(), serde_json::json!("ssrf"))
                    .with("severity".into(), serde_json::json!("high")),
            ),
        },
        ReportingDescriptor {
            id: "CWE-94".into(),
            name: Some("Code Injection".into()),
            short_description: Some(Message::new(
                "User input is passed to a code evaluation function without proper sanitization",
            )),
            full_description: Some(Message::new(
                "The software constructs all or part of a code segment using externally-influenced input \
                 from an upstream component, but it does not neutralize or incorrectly neutralizes \
                 special elements that could modify the syntax or behavior of the intended code segment.",
            )),
            help_uri: Some("https://cwe.mitre.org/data/definitions/94.html".into()),
            properties: Some(
                PropertyBag::new()
                    .with("category".into(), serde_json::json!("injection"))
                    .with("severity".into(), serde_json::json!("critical")),
            ),
        },
    ]
}

/// 根据 rule_id 查找规则索引
pub fn find_rule_index(rules: &[ReportingDescriptor], rule_id: &str) -> Option<usize> {
    rules.iter().position(|r| r.id == rule_id)
}
