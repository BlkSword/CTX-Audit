// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! `audit` 子命令实现
//!
//! 提供 `ctx-audit audit --agent <project>` 入口，启动本地审计 Agent。

use std::path::PathBuf;

use miette::{IntoDiagnostic, Result};

use crate::agent::{run_audit, AuditConfig};
use crate::output::OutputFormat;

/// 执行 audit 命令
pub async fn execute(
    path: String,
    agent: bool,
    deep: bool,
    min_severity: Option<String>,
    max_findings: Option<usize>,
    specialist: bool,
    review_mode: Option<String>,
    investigate: bool,
    max_investigation_steps: Option<usize>,
    auto_goal: bool,
    strategy: Option<String>,
    max_goals: Option<usize>,
    max_exploration_actions: Option<usize>,
    output_format: &str,
    output_path: Option<String>,
) -> Result<()> {
    let project_path = PathBuf::from(&path);
    if !project_path.exists() {
        return Err(miette::miette!("项目路径不存在: {}", path));
    }

    let format = OutputFormat::from_str(output_format).unwrap_or(OutputFormat::Text);

    if !agent {
        // 非 agent 模式：预留为未来普通审计/报告子命令，目前提示使用 --agent
        return Err(miette::miette!(
            "当前 audit 子命令仅支持 --agent 模式。请使用 `ctx-audit audit --agent <project>`"
        ));
    }

    let mut config = AuditConfig::new(
        project_path,
        deep,
        min_severity,
        max_findings,
        format,
        output_path,
    );
    config.specialist_enabled = specialist;
    config.investigator_enabled = investigate;
    if let Some(mode) = review_mode {
        config.review_mode = mode;
    }
    config.max_investigation_steps = max_investigation_steps;
    config.auto_goal = auto_goal;
    config.strategy = strategy;
    config.max_goals = max_goals;
    config.max_exploration_actions = max_exploration_actions;

    match run_audit(config).await {
        Ok(report) => {
            eprintln!(
                "Agent 审计完成: {} 个 finding，已调查 {}",
                report.total_findings, report.investigated_count
            );
            Ok(())
        }
        Err(e) => Err(miette::miette!("Agent 审计失败: {}", e)),
    }
}
