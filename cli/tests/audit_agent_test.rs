// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Agent 审计端到端测试

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn cli_bin() -> String {
    let exe = std::env::current_exe().unwrap();
    let dir = exe.parent().unwrap().parent().unwrap();
    dir.join("ctx-audit").to_string_lossy().to_string()
}

fn unique_test_dir() -> std::path::PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let dir = std::env::temp_dir().join(format!("ctx-audit-agent-it-{}", ts));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 在临时 JS 项目上运行 audit --agent，验证能生成 audit_log.json
#[test]
fn test_audit_agent_runs_end_to_end() {
    let project = unique_test_dir();

    // 构造一个明显的 eval(userInput) 污点汇点
    let src = project.join("app.js");
    std::fs::write(
        &src,
        r#"
const express = require('express');
const app = express();

app.get('/greet', (req, res) => {
    const userInput = req.query.name;
    eval(userInput);
    res.send('ok');
});

app.listen(3000);
"#,
    )
    .unwrap();

    let output = Command::new(cli_bin())
        .args([
            "audit",
            "--agent",
            project.to_str().unwrap(),
            "--max-findings",
            "5",
            "--min-severity",
            "medium",
        ])
        .output()
        .expect("Failed to run audit --agent");

    if !output.status.success() {
        eprintln!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("stderr: {}", String::from_utf8_lossy(&output.stderr));
    }
    assert!(output.status.success());

    let audit_log = project.join(".ctx-audit").join("audit_log.json");
    assert!(
        audit_log.exists(),
        "audit_log.json should be created under project .ctx-audit"
    );

    let blackboard = project.join(".ctx-audit").join("blackboard.json");
    assert!(
        blackboard.exists(),
        "blackboard.json should be created under project .ctx-audit"
    );

    let content = std::fs::read_to_string(&audit_log).unwrap();
    let entries: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    assert!(
        !entries.is_empty(),
        "audit log should contain at least one verdict"
    );

    for entry in &entries {
        let verdict = entry["verdict"].as_str().unwrap_or("");
        assert!(
            ["true_positive", "false_positive", "needs_review"].contains(&verdict),
            "verdict should be one of true_positive/false_positive/needs_review, got {}",
            verdict
        );
        assert!(
            entry["reasoning"].as_str().unwrap_or("").len() > 0,
            "each entry should have reasoning"
        );
    }

    // 清理
    let _ = std::fs::remove_dir_all(&project);
}

/// 启用 --specialist 时，audit_log 中应包含 specialist_result 字段
#[test]
fn test_audit_agent_specialist_produces_result() {
    let project = unique_test_dir();

    let src = project.join("app.js");
    std::fs::write(
        &src,
        r#"
const express = require('express');
const app = express();

app.get('/greet', (req, res) => {
    document.getElementById('out').innerHTML = req.query.name;
    res.send('ok');
});

app.listen(3000);
"#,
    )
    .unwrap();

    // 将 XSS 规则复制到项目级规则目录，确保集成测试环境能找到规则
    let workspace_rules = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("rules")
        .join("xss-detection.yaml");
    let project_rules_dir = project.join(".ctx-audit").join("rules");
    std::fs::create_dir_all(&project_rules_dir).unwrap();
    std::fs::copy(
        workspace_rules,
        project_rules_dir.join("xss-detection.yaml"),
    )
    .unwrap();

    let output = Command::new(cli_bin())
        .args([
            "audit",
            "--agent",
            "--specialist",
            project.to_str().unwrap(),
            "--max-findings",
            "5",
            "--min-severity",
            "medium",
        ])
        .output()
        .expect("Failed to run audit --agent --specialist");

    if !output.status.success() {
        eprintln!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("stderr: {}", String::from_utf8_lossy(&output.stderr));
    }
    assert!(output.status.success());

    let audit_log = project.join(".ctx-audit").join("audit_log.json");
    let content = std::fs::read_to_string(&audit_log).unwrap();
    let entries: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    assert!(!entries.is_empty());
    let entries: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    assert!(!entries.is_empty());

    let mut found_specialist = false;
    for entry in &entries {
        if let Some(sp) = entry.get("specialist_result") {
            if !sp.is_null() {
                found_specialist = true;
                assert_eq!(sp["specialist_name"].as_str().unwrap(), "xss");
            }
        }
    }
    assert!(
        found_specialist,
        "至少一条审计记录应包含 xss specialist_result"
    );

    let _ = std::fs::remove_dir_all(&project);
}
