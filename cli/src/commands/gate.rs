// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! `ctx-audit gate` —— PR 安全漂移闸门：对比 base/head 两棵源码树。

use miette::{miette, IntoDiagnostic, Result};
use std::path::{Path, PathBuf};

/// 用 git worktree 把某个 ref 导出成临时目录。
fn export_ref(repo: &Path, reference: &str) -> Result<PathBuf> {
    let pid = std::process::id();
    let safe: String = reference
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let dir = std::env::temp_dir().join(format!("ctx-gate-{}-{}", safe, pid));
    let _ = std::fs::remove_dir_all(&dir);
    if let Some(parent) = dir.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .arg("worktree")
        .arg("add")
        .arg("--detach")
        .arg(&dir)
        .arg(reference)
        .output()
        .into_diagnostic()?;
    if !out.status.success() {
        return Err(miette!(
            "git worktree 导出失败 ref={}: {}",
            reference,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(dir)
}

fn cleanup_ref(repo: &Path, dir: &Path) {
    let _ = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .arg("worktree")
        .arg("remove")
        .arg("--force")
        .arg(dir)
        .output();
    let _ = std::fs::remove_dir_all(dir);
}

pub async fn execute(
    base: String,
    head: String,
    format: String,
    fail_on_block: bool,
    git: Option<String>,
) -> Result<()> {
    let (base_root, head_root, cleanup) = if let Some(repo) = git {
        let repo = PathBuf::from(&repo);
        if !repo.exists() {
            return Err(miette!("git 仓库路径不存在: {}", repo.display()));
        }
        let b = export_ref(&repo, &base)?;
        let h = export_ref(&repo, &head)?;
        (b.clone(), h.clone(), Some((repo, vec![b, h])))
    } else {
        let b = PathBuf::from(&base);
        let h = PathBuf::from(&head);
        for (name, p) in [("base", &b), ("head", &h)] {
            if !p.exists() {
                return Err(miette!("{} 路径不存在: {}", name, p.display()));
            }
        }
        (b, h, None)
    };

    let report = ctx_audit_tools::gate_report(&base_root, &head_root).map_err(|e| miette!("{}", e))?;
    let blocks = report["summary"]["blocks"].as_u64().unwrap_or(0);

    match format.to_ascii_lowercase().as_str() {
        "md" | "markdown" => println!("{}", ctx_audit_tools::gate_markdown(&report)),
        _ => println!("{}", serde_json::to_string_pretty(&report).into_diagnostic()?),
    }

    if let Some((repo, dirs)) = cleanup {
        for d in dirs {
            cleanup_ref(&repo, &d);
        }
    }

    if blocks > 0 && fail_on_block {
        // CI 语义：有阻断判决时返回 2（与编译错误/门禁失败区分）
        std::process::exit(2);
    }
    Ok(())
}
