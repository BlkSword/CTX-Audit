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
    /// sanitizer 作用域：false（默认）仅看命中点之前的文本；
    /// true 则全文件任一处出现即豁免——适用于"缺失检查"类规则
    /// （校验调用在文件任意位置都算该项目已接入防护，分支级缺失交给判定层）
    #[serde(default)]
    pub sanitizer_file_scope: bool,
    /// sanitizer 匹配语义：`any`（默认）任一 sanitizer 出现即豁免；
    /// `all` 要求全部 sanitizer 都出现才豁免——用于"防护完整性"检查：
    /// 危险集合必须被完整覆盖（如 CWE-88 要求 LD_/DYLD_/LDR_/_RLD/=() 全集），
    /// 只覆盖子集视为防护不完整，仍报告。
    #[serde(default)]
    pub sanitizer_match: SanitizerMatch,
    /// true 时每个文件最多保留一个命中（缺失检查类规则：检查有无是文件级语义，
    /// 多个命中只是同一问题的重复报告）
    #[serde(default)]
    pub once_per_file: bool,
    /// true 时丢弃命中点位于字符串字面量内的 finding——sink 调用形态的规则
    /// 匹配的是代码而非数据，字符串里的 "system()" 只是文本（如错误消息）。
    /// 凭证类规则不要开：字符串字面量正是它们的目标。
    #[serde(default)]
    pub exclude_string_literals: bool,
    /// true 时 sanitizer 检查扩展到 PHP include/require 链解析出的守卫文件
    /// （backlog 10.13）：校验常放在 bootstrap include 的全局安全文件中
    /// （如 csrf.php 对所有 POST 统一校验），单文件检查会把全局防护误判为缺失。
    /// 仅对 .php 文件生效；链解析有界（深度≤3、文件≤16）。
    #[serde(default)]
    pub sanitizer_include_chain: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum SanitizerMatch {
    /// 任一 sanitizer 出现即豁免（默认，兼容旧规则）
    #[default]
    Any,
    /// 全部 sanitizer 都出现才豁免（防护完整性检查）
    All,
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
