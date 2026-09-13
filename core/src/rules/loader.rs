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

/// 收集路径下的规则文件（文件本身或目录递归），并保持排序确定性。
fn collect_rule_files_from_path(path: &Path, out: &mut Vec<std::path::PathBuf>) {
    if path.is_file() {
        out.push(path.to_path_buf());
    } else if path.is_dir() {
        let mut found: Vec<std::path::PathBuf> = Vec::new();
        for entry in WalkDir::new(path).into_iter().flatten() {
            if entry.file_type().is_file() {
                found.push(entry.path().to_path_buf());
            }
        }
        found.sort();
        out.extend(found);
    }
    out.sort();
}

/// 只加载 `CTX_AUDIT_RULES_EXTRA` 指向的额外规则（供内置规则回退路径合并）。
///
/// 回放/扫描在任意 cwd 下运行时常常找不到 `rules/` 目录而走内置嵌入规则，
/// 此时项目专属规则仍必须生效，否则"任务级规则提示"会静默丢失。
pub fn load_extra_rules() -> Vec<Rule> {
    let mut rules = Vec::new();
    let Some(extra) = std::env::var_os("CTX_AUDIT_RULES_EXTRA") else {
        return rules;
    };
    let path = std::path::PathBuf::from(&extra);
    if !path.exists() {
        tracing::warn!("CTX_AUDIT_RULES_EXTRA 指向的路径不存在：{:?}", path);
        return rules;
    }
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    collect_rule_files_from_path(&path, &mut files);
    for file in files {
        let Ok(content) = fs::read_to_string(&file) else {
            continue;
        };
        if let Ok(rule_set) = serde_yaml::from_str::<RuleSet>(&content) {
            rules.extend(rule_set.rules);
        } else if let Ok(rule) = serde_yaml::from_str::<Rule>(&content) {
            rules.push(rule);
        } else {
            tracing::error!("额外规则文件 {:?} 解析失败，已跳过", file);
        }
    }
    if !rules.is_empty() {
        tracing::info!("已加载项目专属规则 {:?}：{} 条", path, rules.len());
    }
    rules
}

pub fn load_rules_from_dir<P: AsRef<Path>>(path: P) -> Result<Vec<Rule>> {
    let mut rules = Vec::new();

    // 确定性：WalkDir 枚举顺序取决于文件系统；多规则命中同一处时的取名/去重
    // 需要稳定顺序（同类问题已在 taint 规则加载器修复：跨机 findings 224 vs 229）。
    let mut rule_files: Vec<std::path::PathBuf> = Vec::new();
    // 主规则目录可能不存在（例如回放在任意 cwd 下运行）——此时仍要继续处理
    // 额外规则（CTX_AUDIT_RULES_EXTRA），不能因为主目录缺失就整体报错。
    if path.as_ref().exists() {
        for entry in WalkDir::new(path.as_ref()).into_iter().flatten() {
            if entry.file_type().is_file() {
                rule_files.push(entry.path().to_path_buf());
            }
        }
    } else {
        tracing::debug!("主规则目录不存在，仅加载额外规则：{:?}", path.as_ref());
    }
    rule_files.sort();

    // 项目/任务级补充规则：`CTX_AUDIT_RULES_EXTRA` 指向额外 YAML 文件或目录，
    // 与主规则合并（用于给回放任务注入项目特定规则，不必重编译/改全局规则）。
    if let Some(extra) = std::env::var_os("CTX_AUDIT_RULES_EXTRA") {
        let extra_path = std::path::PathBuf::from(&extra);
        if extra_path.exists() {
            collect_rule_files_from_path(&extra_path, &mut rule_files);
            tracing::info!("已合并额外规则路径 {:?}（待加载文件 {} 个）", extra_path, rule_files.len());
        } else {
            tracing::warn!("CTX_AUDIT_RULES_EXTRA 指向的路径不存在：{:?}", extra_path);
        }
    }

    for file_path in &rule_files {
        {
            let path: &Path = file_path.as_path();
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
