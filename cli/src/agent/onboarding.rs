// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 项目启动引导：识别非生产代码目录并让用户确认排除
//!
//! 在审计开始前，扫描项目目录结构，按启发式规则提出可能是测试、示例、
//! 第三方库等非生产代码的目录。若配置中启用了 LLM，会先让 LLM 对候选目录
//! 做预分类，再请用户确认，最后将结果持久化到
//! `<project_path>/.ctx-audit/project-config.toml`。

use std::collections::HashSet;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};

use crate::agent::llm_client::LlmClient;
use crate::terminal::TerminalRenderer;

/// 已知非生产目录名称（大小写不敏感）
const KNOWN_NON_PRODUCTION_NAMES: &[&str] = &[
    "test",
    "tests",
    "__tests__",
    "spec",
    "specs",
    "e2e",
    "cypress",
    "playwright",
    "fixtures",
    "mocks",
    "mock",
    "examples",
    "example",
    "demo",
    "demos",
    "tutorial",
    "tutorials",
    "storybook",
    "stories",
    "benchmarks",
    "benchmark",
    "vendor",
    "vendors",
    "libs",
    "plugins",
    "it",
];

/// 启动引导入口。
/// 返回用户确认要排除的目录模式列表（已转换为路径片段，如 "/test/"）。
/// 若非交互环境（stdin 不是 tty）或没有候选目录，直接返回空列表。
pub async fn maybe_prompt_non_production_paths(
    project_path: &Path,
    renderer: &mut TerminalRenderer,
    llm_client: Option<Arc<dyn LlmClient>>,
) -> Result<Vec<String>> {
    if !is_interactive() {
        return Ok(Vec::new());
    }

    let candidates = detect_non_production_dirs(project_path);
    if candidates.is_empty() {
        return Ok(Vec::new());
    }

    // 如果启用了 LLM，先用 LLM 对候选目录做预分类
    let suggestions = if let Some(llm) = llm_client {
        classify_with_llm(&candidates, llm.as_ref())
            .await
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let confirmed = prompt_user(&candidates, &suggestions, renderer)?;
    if !confirmed.is_empty() {
        save_project_config(project_path, &confirmed)?;
    }

    Ok(confirmed)
}

/// 启发式检测候选目录。
/// 从项目根目录开始递归扫描，最多深入 6 层，按目录名称识别非生产代码目录。
fn detect_non_production_dirs(project_path: &Path) -> Vec<String> {
    let mut found = HashSet::new();
    if project_path.is_dir() {
        walk_dirs(project_path, project_path, 0, 6, &mut found);
    }
    let mut result: Vec<String> = found.into_iter().collect();
    result.sort();
    result
}

fn walk_dirs(
    dir: &Path,
    project_path: &Path,
    depth: usize,
    max_depth: usize,
    found: &mut HashSet<String>,
) {
    if depth > max_depth {
        return;
    }
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                check_dir(&path, project_path, found);
                walk_dirs(&path, project_path, depth + 1, max_depth, found);
            }
        }
    }
}

fn check_dir(path: &Path, project_path: &Path, found: &mut HashSet<String>) {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return;
    };
    let lower = name.to_lowercase();
    if KNOWN_NON_PRODUCTION_NAMES.contains(&lower.as_str()) {
        if let Some(pattern) = dir_to_pattern(path, project_path) {
            found.insert(pattern);
        }
    }
}

/// 把绝对目录路径转换成统一的路径片段，如 "/test/"、"/src/it/"
fn dir_to_pattern(dir: &Path, project_path: &Path) -> Option<String> {
    let relative = dir.strip_prefix(project_path).ok()?;
    let normalized = relative.to_string_lossy().replace('\\', "/").to_lowercase();
    if normalized.is_empty() {
        return None;
    }
    Some(format!("/{}/", normalized))
}

/// 调用 LLM 对候选目录做预分类，返回建议排除的目录索引（0-based）。
async fn classify_with_llm(candidates: &[String], llm: &dyn LlmClient) -> Result<Vec<usize>> {
    if candidates.is_empty() {
        return Ok(Vec::new());
    }

    let list: String = candidates
        .iter()
        .enumerate()
        .map(|(i, c)| format!("{}. {}", i + 1, c))
        .collect::<Vec<_>>()
        .join(
            "
",
        );

    const SCHEMA: &str = r#"{"non_production_indices": [1, 3]}"#;
    let prompt = format!(
        "你是一个代码审计助手。下面是一个项目中的部分目录列表。请判断哪些目录属于非生产代码（例如测试、示例、演示、mock/fixture、第三方库、文档、storybook 等），应当从安全审计范围中排除。只返回 JSON，格式为 {schema}，数组元素为目录序号（从 1 开始）。如果都不应排除，返回空数组。

{list}
",
        schema = SCHEMA,
        list = list
    );

    let value = llm.chat_json(&prompt).await?;
    let indices = value
        .get("non_production_indices")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_u64().map(|n| (n as usize).saturating_sub(1)))
                .filter(|&idx| idx < candidates.len())
                .collect()
        })
        .unwrap_or_default();

    Ok(indices)
}
/// 交互式询问用户。
/// `suggestions` 是 LLM 建议排除的目录索引（0-based）。
fn prompt_user(
    candidates: &[String],
    suggestions: &[usize],
    renderer: &mut TerminalRenderer,
) -> Result<Vec<String>> {
    renderer.info("审计开始前，发现以下疑似非生产代码目录（测试、示例、第三方库等）：");
    for (i, c) in candidates.iter().enumerate() {
        let marker = if suggestions.contains(&i) {
            " [建议排除]"
        } else {
            ""
        };
        println!("  {}. {}{}", i + 1, c, marker);
    }
    if !suggestions.is_empty() {
        println!();
        println!(
            "LLM 建议排除 {} 个目录（标记为 [建议排除]）。",
            suggestions.len()
        );
    }
    println!();
    println!(
        "操作选项：\n  y - 接受建议/全部排除\n  n - 不排除\n  数字列表（如 1,3）- 只排除指定项\n  输入示例：1,3,5"
    );
    print!("请选择 [y/n/数字列表]: ");
    io::stdout().flush().context("刷新输出失败")?;

    let stdin = io::stdin();
    let mut line = String::new();
    stdin
        .lock()
        .read_line(&mut line)
        .context("读取用户输入失败")?;
    let input = line.trim();

    if input.eq_ignore_ascii_case("n") || input.is_empty() {
        renderer.info("已跳过非生产目录排除。");
        return Ok(Vec::new());
    }

    if input.eq_ignore_ascii_case("y") {
        let chosen = if suggestions.is_empty() {
            candidates.to_vec()
        } else {
            suggestions.iter().map(|&i| candidates[i].clone()).collect()
        };
        renderer.info(&format!("已确认排除 {} 个目录。", chosen.len()));
        return Ok(chosen);
    }

    // 解析数字列表
    let mut confirmed = Vec::new();
    for part in input.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Ok(idx) = part.parse::<usize>() {
            if idx > 0 && idx <= candidates.len() {
                confirmed.push(candidates[idx - 1].clone());
            }
        }
    }

    if confirmed.is_empty() {
        renderer.info("未选择有效项，已跳过排除。");
    } else {
        renderer.info(&format!("已确认排除 {} 个目录。", confirmed.len()));
    }

    Ok(confirmed)
}

/// 保存到 <project_path>/.ctx-audit/project-config.toml
fn save_project_config(project_path: &Path, patterns: &[String]) -> Result<()> {
    let dir = project_path.join(".ctx-audit");
    std::fs::create_dir_all(&dir).context("创建 .ctx-audit 目录失败")?;

    let path = dir.join("project-config.toml");
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let mut doc: toml::Table = existing.parse().unwrap_or_default();

    // 确保 [scan] 段存在
    let scan = doc
        .entry("scan")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()))
        .as_table_mut()
        .context("[scan] 必须是表")?;

    // 读取现有模式并合并
    let mut merged: Vec<String> = Vec::new();
    if let Some(existing_patterns) = scan.get("non_production_path_patterns") {
        if let Some(arr) = existing_patterns.as_array() {
            for v in arr {
                if let Some(s) = v.as_str() {
                    merged.push(s.to_string());
                }
            }
        }
    }
    for p in patterns {
        if !merged.contains(p) {
            merged.push(p.clone());
        }
    }

    let arr: Vec<toml::Value> = merged.into_iter().map(toml::Value::String).collect();
    scan.insert(
        "non_production_path_patterns".to_string(),
        toml::Value::Array(arr),
    );

    let content = toml::to_string_pretty(&doc).context("序列化 TOML 失败")?;
    std::fs::write(&path, content).context("写入 project-config.toml 失败")?;

    Ok(())
}

/// 加载项目级配置中的非生产路径模式
pub fn load_project_non_production_patterns(project_path: &Path) -> Vec<String> {
    let path = project_path.join(".ctx-audit/project-config.toml");
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let doc: toml::Table = match content.parse() {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    doc.get("scan")
        .and_then(|v| v.get("non_production_path_patterns"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn is_interactive() -> bool {
    // 简单判断 stdin 是否是终端
    io::stdin().is_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_project() -> PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let id = format!(
            "{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dir = std::env::temp_dir()
            .join("ctx-audit-onboarding-test")
            .join(id);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_detect_non_production_dirs() {
        let project = temp_project();
        std::fs::create_dir_all(project.join("tests")).unwrap();
        std::fs::create_dir_all(project.join("src/examples")).unwrap();
        std::fs::create_dir_all(project.join("src/main/resources/static/js/libs")).unwrap();

        let candidates = detect_non_production_dirs(&project);
        assert!(candidates.contains(&"/tests/".to_string()));
        assert!(candidates.contains(&"/src/examples/".to_string()));
        assert!(candidates.contains(&"/src/main/resources/static/js/libs/".to_string()));
    }

    #[test]
    fn test_save_and_load_project_config() {
        let project = temp_project();
        let patterns = vec!["/tests/".to_string(), "/examples/".to_string()];
        save_project_config(&project, &patterns).unwrap();

        let loaded = load_project_non_production_patterns(&project);
        assert!(loaded.contains(&"/tests/".to_string()));
        assert!(loaded.contains(&"/examples/".to_string()));

        // 再次保存应合并而非重复
        save_project_config(&project, &vec!["/fixtures/".to_string()]).unwrap();
        let loaded = load_project_non_production_patterns(&project);
        assert_eq!(loaded.len(), 3);
    }

    #[test]
    fn test_dir_to_pattern() {
        let project = PathBuf::from("/tmp/proj");
        assert_eq!(
            dir_to_pattern(&PathBuf::from("/tmp/proj/src/test"), &project),
            Some("/src/test/".to_string())
        );
    }
}
