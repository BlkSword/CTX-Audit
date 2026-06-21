// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! rules 命令实现
//!
//! 管理和验证自定义检测规则

use miette::Result;

use crate::terminal::TerminalRenderer;

/// 列出所有加载的规则
pub async fn list(rules_dir: Option<String>) -> Result<()> {
    let mut renderer = TerminalRenderer::new();

    let search_dirs = match &rules_dir {
        Some(dir) => vec![dir.clone()],
        None => vec![".ctx-audit/rules".to_string(), "rules".to_string()],
    };

    let mut total = 0;

    for dir in &search_dirs {
        let path = std::path::Path::new(dir);
        if !path.exists() {
            continue;
        }

        renderer.info(&format!("规则目录: {}", dir));

        match deepaudit_core::rules::loader::load_rules_from_dir(path) {
            Ok(rules) => {
                renderer.info(&format!("  加载了 {} 条规则", rules.len()));
                for rule in &rules {
                    let cwe = rule.cwe.as_deref().unwrap_or("-");
                    let lang = &rule.language;
                    renderer.info(&format!(
                        "  [{:?}] {} ({}) — {} [{}]",
                        rule.severity, rule.id, cwe, rule.name, lang
                    ));
                }
                total += rules.len();
            }
            Err(e) => {
                renderer.error(&format!("  加载失败: {}", e));
            }
        }
    }

    renderer.success(&format!("共 {} 条规则", total));

    if total == 0 {
        renderer.info("提示: 在项目目录下创建 .ctx-audit/rules/ 目录，放入 YAML 规则文件");
        renderer.info("规则格式参考: https://github.com/BlkSword/CTX-Audit/tree/main/rules");
    }

    Ok(())
}

/// 验证规则文件
pub async fn validate(rules_dir: Option<String>) -> Result<()> {
    let mut renderer = TerminalRenderer::new();

    let dir = rules_dir.unwrap_or_else(|| "rules".to_string());
    let path = std::path::Path::new(&dir);

    if !path.exists() {
        renderer.error(&format!("规则目录不存在: {}", dir));
        return Err(miette::miette!("规则目录不存在"));
    }

    renderer.info(&format!("验证规则目录: {}", dir));

    let mut valid = 0;
    let mut invalid = 0;

    fn visit_yaml_files(dir: &std::path::Path, cb: &mut dyn FnMut(&std::path::Path)) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    visit_yaml_files(&path, cb);
                } else if path.is_file() {
                    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                    if ext == "yaml" || ext == "yml" {
                        cb(&path);
                    }
                }
            }
        }
    }

    visit_yaml_files(path, &mut |file_path| {
        let content = match std::fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(e) => {
                renderer.error(&format!("读取失败 {}: {}", file_path.display(), e));
                invalid += 1;
                return;
            }
        };

        let file_name = file_path.file_name().unwrap_or_default().to_string_lossy();

        if serde_yaml::from_str::<deepaudit_core::rules::model::RuleSet>(&content).is_ok()
            || serde_yaml::from_str::<deepaudit_core::rules::model::Rule>(&content).is_ok()
            || content.contains("kind: taint-rules")
        // taint rules have different schema
        {
            renderer.success(&format!("  ✓ {}", file_name));
            valid += 1;
        } else {
            renderer.error(&format!("  ✗ {} — YAML 解析失败", file_name));
            invalid += 1;
        }
    });

    renderer.info(&format!("验证完成: {} 有效, {} 无效", valid, invalid));

    if invalid > 0 {
        return Err(miette::miette!("{} 个规则文件无效", invalid));
    }

    Ok(())
}
