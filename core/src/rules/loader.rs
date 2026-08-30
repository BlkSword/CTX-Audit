use crate::rules::model::{Rule, RuleSet};
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

/// 判断是否为不应由模式规则加载器处理的 YAML 文件
fn is_non_rule_file(path: &Path) -> bool {
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if file_name == "risk-patterns.yaml" {
        return true;
    }
    path.components().any(|c| {
        matches!(c.as_os_str().to_str(), Some("audit-packs") | Some("specialists") | Some("taint"))
    })
}

pub fn load_rules_from_dir<P: AsRef<Path>>(path: P) -> Result<Vec<Rule>> {
    let mut rules = Vec::new();

    for entry in WalkDir::new(path) {
        let entry = entry?;
        if entry.file_type().is_file() {
            let path = entry.path();
            // 跳过非模式规则目录/文件：审计证据包、specialist、taint YAML、
            // risk-patterns.yaml 由各自的加载器/工具负责。
            if is_non_rule_file(path) {
                continue;
            }
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
