use serde::{Deserialize, Serialize};

/// 语言特定模式 — 允许一条规则对不同语言使用不同正则
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LanguagePattern {
    pub language: String,
    pub pattern: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub language: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// 多语言模式列表（优先于 pattern）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patterns: Option<Vec<LanguagePattern>>,
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
    /// 可选的净化函数/模式列表。
    /// 当规则命中后，如果匹配位置之前出现任一 sanitizer 模式，引擎会跳过该发现。
    /// 这是通用的规则级去误报机制，任何 regex/AST 规则均可声明。
    #[serde(default)]
    pub sanitizers: Vec<String>,
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
