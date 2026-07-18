// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 内置嵌入规则
//!
//! 将仓库根目录的 `rules/` 通过 `include_dir` 打包进二进制。
//! 当文件系统上的规则目录查找失败（例如在仓库外运行、
//! `cargo install` 安装后的任意目录）时，回退到这些嵌入规则，
//! 保证规则扫描与污点分析在任何工作目录下都可用。

use include_dir::{include_dir, Dir, DirEntry};

use crate::rules::model::{Rule, RuleSet};
use crate::rules::taint_loader::LoadedTaintRules;
use crate::rules::taint_model::TaintRuleSet;

/// 嵌入的规则目录（仓库根 `rules/`）
static EMBEDDED_RULES: Dir = include_dir!("$CARGO_MANIFEST_DIR/../rules");

/// 递归收集目录下所有 YAML 文件的 (相对路径, 内容)
fn collect_yaml_files(dir: &'static Dir<'static>, out: &mut Vec<(String, String)>) {
    for entry in dir.entries() {
        match entry {
            DirEntry::File(file) => {
                let path = file.path();
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext == "yaml" || ext == "yml" {
                    if let Some(content) = file.contents_utf8() {
                        out.push((path.to_string_lossy().replace('\\', "/"), content.to_string()));
                    }
                }
            }
            DirEntry::Dir(subdir) => collect_yaml_files(subdir, out),
        }
    }
}

/// 嵌入的模式规则 YAML（顶层 + 子目录，语义同 `load_rules_from_dir("rules")`）
fn embedded_pattern_yaml_files() -> Vec<(String, String)> {
    let mut files = Vec::new();
    collect_yaml_files(&EMBEDDED_RULES, &mut files);
    files
}

/// 嵌入的污点规则 YAML（仅 `taint/` 子目录）
fn embedded_taint_yaml_files() -> Vec<(String, String)> {
    let mut files = Vec::new();
    if let Some(taint_dir) = EMBEDDED_RULES.get_dir("taint") {
        collect_yaml_files(taint_dir, &mut files);
    }
    files
}

/// 加载嵌入的模式规则（与 `loader::load_rules_from_dir` 相同的解析与跳过语义）
pub fn load_embedded_pattern_rules() -> Vec<Rule> {
    let mut rules = Vec::new();
    for (path, content) in embedded_pattern_yaml_files() {
        if let Ok(rule_set) = serde_yaml::from_str::<RuleSet>(&content) {
            rules.extend(rule_set.rules);
        } else if let Ok(rule) = serde_yaml::from_str::<Rule>(&content) {
            rules.push(rule);
        } else {
            tracing::debug!("Skipping non-pattern-rule embedded file: {}", path);
        }
    }
    rules
}

/// 加载嵌入的污点规则（与 `taint_loader::load_taint_rules_from_dir` 相同的聚合语义）
pub fn load_embedded_taint_rules() -> LoadedTaintRules {
    let mut sources = Vec::new();
    let mut sinks = Vec::new();
    let mut sanitizer_patterns = Vec::new();

    for (path, content) in embedded_taint_yaml_files() {
        match serde_yaml::from_str::<TaintRuleSet>(&content) {
            Ok(rule_set) => {
                tracing::debug!(
                    "Loaded embedded taint rules: {} ({} sources, {} sinks, {} sanitizers)",
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
                tracing::debug!("Skipped non-taint embedded YAML {}: {}", path, e);
            }
        }
    }

    LoadedTaintRules {
        sources,
        sinks,
        sanitizer_patterns,
    }
}

/// 嵌入污点规则 YAML 的原始内容（供 CLI/MCP 侧在文件系统目录缺失时兜底解析）
pub fn embedded_taint_yaml_contents() -> Vec<String> {
    embedded_taint_yaml_files()
        .into_iter()
        .map(|(_, content)| content)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_pattern_rules_loaded() {
        let rules = load_embedded_pattern_rules();
        assert!(
            rules.len() >= 30,
            "嵌入的模式规则数量异常: {}",
            rules.len()
        );
    }

    #[test]
    fn test_embedded_taint_rules_loaded() {
        let loaded = load_embedded_taint_rules();
        assert!(!loaded.sources.is_empty(), "嵌入污点规则应包含 sources");
        assert!(!loaded.sinks.is_empty(), "嵌入污点规则应包含 sinks");
        assert!(
            !loaded.sanitizer_patterns.is_empty(),
            "嵌入污点规则应包含 sanitizers"
        );
        // 框架规则包（frameworks/ 子目录）也应被递归收集
        let sink_ids: Vec<&str> = loaded.sinks.iter().map(|s| s.id.as_str()).collect();
        assert!(
            sink_ids.iter().any(|id| id.starts_with("java_")),
            "应包含 Java 框架 sink: {:?}",
            &sink_ids[..sink_ids.len().min(10)]
        );
    }
}
