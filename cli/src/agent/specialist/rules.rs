// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Specialist 规则热加载
//!
//! 允许从 `rules/specialists/*.yaml` 加载 CWE 专家规则，无需重新编译即可
//! 扩展 sink/safe/barrier 模式。

use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};

/// 单个 Specialist 的规则集
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecialistRuleSet {
    pub name: String,
    #[serde(default)]
    pub cwe_ids: Vec<String>,
    #[serde(default)]
    pub vuln_type_keywords: Vec<String>,
    #[serde(default)]
    pub sink_patterns: Vec<String>,
    #[serde(default)]
    pub safe_patterns: Vec<String>,
    #[serde(default)]
    pub barrier_keywords: Vec<String>,
}

impl SpecialistRuleSet {
    /// 空规则集
    pub fn empty(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            cwe_ids: Vec::new(),
            vuln_type_keywords: Vec::new(),
            sink_patterns: Vec::new(),
            safe_patterns: Vec::new(),
            barrier_keywords: Vec::new(),
        }
    }

    /// 编译 sink 正则
    pub fn compiled_sinks(&self) -> Result<Vec<Regex>> {
        compile_patterns(&self.sink_patterns)
    }

    /// 编译 safe 正则
    pub fn compiled_safe(&self) -> Result<Vec<Regex>> {
        compile_patterns(&self.safe_patterns)
    }

    /// barrier 关键词集合
    pub fn barrier_set(&self) -> HashSet<String> {
        self.barrier_keywords
            .iter()
            .map(|s| s.to_lowercase())
            .collect()
    }

    /// 判断 vuln_type 是否命中本 specialist
    pub fn matches_vuln_type(&self, vuln_type: &str) -> bool {
        let vt = vuln_type.to_lowercase();
        self.cwe_ids
            .iter()
            .any(|id| vt.contains(&id.to_lowercase()))
            || self
                .vuln_type_keywords
                .iter()
                .any(|kw| vt.contains(&kw.to_lowercase()))
    }
}

/// 从目录加载所有 specialist 规则
pub fn load_specialist_rules_from_dir(dir: &Path) -> Result<HashMap<String, SpecialistRuleSet>> {
    let mut map = HashMap::new();
    if !dir.exists() {
        return Ok(map);
    }

    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("读取 specialist 规则目录失败: {:?}", dir))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("yaml") {
            continue;
        }
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("读取 specialist 规则失败: {:?}", path))?;
        let rule: SpecialistRuleSet = serde_yaml::from_str(&content)
            .with_context(|| format!("解析 specialist 规则失败: {:?}", path))?;
        if rule.name.is_empty() {
            continue;
        }
        map.insert(rule.name.clone(), rule);
    }

    Ok(map)
}

/// 编译字符串正则列表
fn compile_patterns(patterns: &[String]) -> Result<Vec<Regex>> {
    patterns
        .iter()
        .map(|p| Regex::new(p).with_context(|| format!("无效正则: {}", p)))
        .collect()
}

/// 默认 SQLi 规则（热加载失败时回退）
pub fn default_sqli_rules() -> SpecialistRuleSet {
    serde_yaml::from_str(include_str!("../../../../rules/specialists/sqli.yaml")).unwrap()
}

/// 默认 XSS 规则（热加载失败时回退）
pub fn default_xss_rules() -> SpecialistRuleSet {
    serde_yaml::from_str(include_str!("../../../../rules/specialists/xss.yaml")).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_rules_load() {
        let sqli = default_sqli_rules();
        assert!(!sqli.sink_patterns.is_empty());
        assert!(sqli.matches_vuln_type("CWE-89"));
        assert!(sqli.matches_vuln_type("SQL Injection"));

        let xss = default_xss_rules();
        assert!(!xss.sink_patterns.is_empty());
        assert!(xss.matches_vuln_type("CWE-79"));
        assert!(xss.matches_vuln_type("reflected_xss"));
    }

    #[test]
    fn test_compile_patterns() {
        let sqli = default_sqli_rules();
        assert!(!sqli.compiled_sinks().unwrap().is_empty());
        assert!(!sqli.compiled_safe().unwrap().is_empty());
    }
}
