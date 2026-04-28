use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub language: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe: Option<String>,
    /// OWASP Top 10 映射（如 "A03:2021-Injection"）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owasp: Option<String>,
    /// 修复建议
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// 参考链接
    #[serde(skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RuleSet {
    pub name: String,
    pub version: String,
    pub rules: Vec<Rule>,
}
