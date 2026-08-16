use crate::rules::model::{Rule, RuleSet};
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

pub fn load_rules_from_dir<P: AsRef<Path>>(path: P) -> Result<Vec<Rule>> {
    let mut rules = Vec::new();

    for entry in WalkDir::new(path) {
        let entry = entry?;
        if entry.file_type().is_file() {
            let path = entry.path();
            if let Some(extension) = path.extension() {
                if extension == "yaml" || extension == "yml" {
                    let content = fs::read_to_string(path)
                        .with_context(|| format!("Failed to read rule file: {:?}", path))?;

                    // Try to parse as RuleSet first, then as single Rule
                    if let Ok(rule_set) = serde_yaml::from_str::<RuleSet>(&content) {
                        rules.extend(rule_set.rules);
                    } else if let Ok(rule) = serde_yaml::from_str::<Rule>(&content) {
                        rules.push(rule);
                    } else {
                        // 10.20 低可用项：规则 schema 化校验。形似规则文件但解析失败时
                        // 必须告警而非静默跳过——R12 教训（枚举未加变体 -> 整个文件
                        // 静默失败 -> 0 flows）的根治手段是启动时让错误可见。
                        let looks_like_rule = content.contains("rules:")
                            || content.contains("\nid:")
                            || content.contains("\nname:");
                        if looks_like_rule {
                            tracing::error!(
                                "规则文件 {:?} 解析失败，已跳过；请检查 YAML schema/枚举值",
                                path
                            );
                        } else {
                            tracing::debug!("Skipping non-pattern-rule file: {:?}", path);
                        }
                    }
                }
            }
        }
    }

    Ok(rules)
}
