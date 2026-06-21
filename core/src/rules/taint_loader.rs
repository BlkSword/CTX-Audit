// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 污点规则加载器
//!
//! 从 YAML 文件目录加载 TaintRuleSet，聚合成统一的 LoadedTaintRules。
//! 目录不存在或无匹配文件时返回空结果（不报错）。

use anyhow::{Context, Result};
use std::path::Path;
use walkdir::WalkDir;

use crate::analysis::taint::{TaintSink, TaintSource};
use crate::rules::taint_model::TaintRuleSet;

/// 加载后的聚合结果
pub struct LoadedTaintRules {
    /// 所有合并的污点源
    pub sources: Vec<TaintSource>,
    /// 所有合并的污点汇
    pub sinks: Vec<TaintSink>,
    /// 所有合并的净化函数模式
    pub sanitizer_patterns: Vec<String>,
}

/// 从目录加载所有污点规则 YAML 文件
///
/// 递归遍历目录，解析所有 `.yaml`/`.yml` 文件为 `TaintRuleSet`，
/// 合并 sources、sinks、sanitizers。
/// 目录不存在时返回空结果。
pub fn load_taint_rules_from_dir<P: AsRef<Path>>(path: P) -> Result<LoadedTaintRules> {
    let mut sources = Vec::new();
    let mut sinks = Vec::new();
    let mut sanitizer_patterns = Vec::new();

    let path = path.as_ref();
    if !path.exists() {
        return Ok(LoadedTaintRules {
            sources,
            sinks,
            sanitizer_patterns,
        });
    }

    for entry in WalkDir::new(path) {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        if !entry.file_type().is_file() {
            continue;
        }

        let file_path = entry.path();
        let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "yaml" && ext != "yml" {
            continue;
        }

        let content = match std::fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        match serde_yaml::from_str::<TaintRuleSet>(&content) {
            Ok(rule_set) => {
                tracing::debug!(
                    "Loaded taint rules: {} ({} sources, {} sinks, {} sanitizers)",
                    rule_set.name,
                    rule_set.sources.len(),
                    rule_set.sinks.len(),
                    rule_set.sanitizers.len(),
                );
                sources.extend(rule_set.sources);
                sinks.extend(rule_set.sinks);
                for san in rule_set.sanitizers {
                    sanitizer_patterns.push(san.pattern);
                }
            }
            Err(e) => {
                // 非 taint-rules 格式的 YAML 文件（如普通 Rule），跳过不报错
                tracing::debug!("Skipped non-taint YAML file {:?}: {}", file_path, e);
            }
        }
    }

    Ok(LoadedTaintRules {
        sources,
        sinks,
        sanitizer_patterns,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_taint_rule_set() {
        let yaml = r#"
kind: taint-rules
name: "Test Rules"
version: "1.0"
sources:
  - id: "test_source"
    name: "Test Source"
    description: "A test source"
    patterns: ["req.body", "req.query"]
    languages: ["*"]
    severity: "High"
    category: "UserInput"
    ast_patterns: []
sinks:
  - id: "test_sink"
    name: "Test Sink"
    description: "A test sink"
    patterns: ["eval(", "exec("]
    languages: ["*"]
    vulnerability_type: "CodeInjection"
    severity: "Critical"
    cwe_id: "CWE-94"
    sensitive_params: [0]
    ast_patterns: []
sanitizers:
  - pattern: "escape"
    description: "Escape function"
"#;
        let rule_set: TaintRuleSet = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(rule_set.sources.len(), 1);
        assert_eq!(rule_set.sinks.len(), 1);
        assert_eq!(rule_set.sanitizers.len(), 1);
        assert_eq!(rule_set.sources[0].id, "test_source");
        assert_eq!(
            rule_set.sinks[0].vulnerability_type,
            crate::analysis::taint::VulnerabilityType::CodeInjection
        );
    }

    #[test]
    fn test_nonexistent_dir_returns_empty() {
        let rules = load_taint_rules_from_dir("/nonexistent/path/that/does/not/exist").unwrap();
        assert!(rules.sources.is_empty());
        assert!(rules.sinks.is_empty());
        assert!(rules.sanitizer_patterns.is_empty());
    }

    #[test]
    fn test_regular_rule_yaml_not_parsed_as_taint() {
        // 确保普通 Rule YAML 不会被误解析为 TaintRuleSet
        let yaml = r#"
id: "test-rule"
name: "Test Rule"
description: "desc"
severity: "high"
language: "all"
pattern: "test"
"#;
        let result = serde_yaml::from_str::<TaintRuleSet>(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_sources_sinks() {
        let yaml = r#"
kind: taint-rules
name: "Empty"
version: "1.0"
"#;
        let rule_set: TaintRuleSet = serde_yaml::from_str(yaml).unwrap();
        assert!(rule_set.sources.is_empty());
        assert!(rule_set.sinks.is_empty());
    }

    #[test]
    fn test_load_actual_framework_rules() {
        // 测试加载项目中的实际框架规则文件
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let rules_dir = std::path::Path::new(&manifest_dir)
            .parent()
            .unwrap()
            .join("rules")
            .join("taint");

        if !rules_dir.exists() {
            eprintln!("Skipping framework rules test: {:?} not found", rules_dir);
            return;
        }

        let loaded = load_taint_rules_from_dir(&rules_dir).unwrap();

        // 应该有 generic + 框架规则包的内容
        assert!(
            !loaded.sources.is_empty(),
            "Should have sources from rule files"
        );
        assert!(
            !loaded.sinks.is_empty(),
            "Should have sinks from rule files"
        );
        assert!(
            !loaded.sanitizer_patterns.is_empty(),
            "Should have sanitizers"
        );

        // 验证关键框架特定的 source 存在
        let source_ids: Vec<&str> = loaded.sources.iter().map(|s| s.id.as_str()).collect();
        assert!(
            source_ids
                .iter()
                .any(|id| id.contains("formdata") || id.contains("react")),
            "Should have React/FormData sources, got: {:?}",
            source_ids
        );

        // 验证关键框架特定的 sink 存在
        let sink_ids: Vec<&str> = loaded.sinks.iter().map(|s| s.id.as_str()).collect();
        assert!(
            sink_ids
                .iter()
                .any(|id| id.contains("django") || id.contains("spring")),
            "Should have Django/Spring sinks, got: {:?}",
            sink_ids
        );

        // 验证新增语言规则被加载
        assert!(
            sink_ids.iter().any(|id| id.starts_with("rust_")),
            "Should have Rust sinks, got: {:?}",
            sink_ids
        );
        assert!(
            sink_ids.iter().any(|id| id.starts_with("go_")),
            "Should have Go sinks, got: {:?}",
            sink_ids
        );
        assert!(
            sink_ids.iter().any(|id| id.starts_with("java_")),
            "Should have Java sinks, got: {:?}",
            sink_ids
        );
        assert!(
            sink_ids.iter().any(|id| id.starts_with("c_")),
            "Should have C/C++ sinks, got: {:?}",
            sink_ids
        );

        println!(
            "Loaded {} sources, {} sinks, {} sanitizers from {:?}",
            loaded.sources.len(),
            loaded.sinks.len(),
            loaded.sanitizer_patterns.len(),
            rules_dir,
        );
    }
}
