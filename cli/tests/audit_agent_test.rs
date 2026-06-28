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
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("ctx-audit-agent-it-{}-{}", ts, n));
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

/// 启用 --review-mode debate 时，blackboard 应更新 pheromone 且 audit_log 包含 reviews
#[test]
fn test_audit_agent_review_mode_debate_updates_blackboard() {
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
            "--review-mode",
            "debate",
            project.to_str().unwrap(),
            "--max-findings",
            "5",
            "--min-severity",
            "medium",
        ])
        .output()
        .expect("Failed to run audit --agent --review-mode debate");

    if !output.status.success() {
        eprintln!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("stderr: {}", String::from_utf8_lossy(&output.stderr));
    }
    assert!(output.status.success());

    let audit_log = project.join(".ctx-audit").join("audit_log.json");
    let content = std::fs::read_to_string(&audit_log).unwrap();
    let entries: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    assert!(!entries.is_empty());

    let mut found_review = false;
    for entry in &entries {
        if let Some(reviews) = entry.get("reviews") {
            if let Some(arr) = reviews.as_array() {
                if !arr.is_empty() {
                    found_review = true;
                }
            }
        }
    }
    assert!(found_review, "debate 模式下 audit_log 应包含 reviews");

    let blackboard_path = project.join(".ctx-audit").join("blackboard.json");
    let blackboard: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&blackboard_path).unwrap()).unwrap();
    let pheromone = blackboard
        .get("pheromone")
        .and_then(|p| p.get("entries"))
        .and_then(|e| e.as_object())
        .expect("blackboard 应包含 pheromone.entries");
    assert!(
        pheromone.contains_key("CWE-79"),
        "pheromone 应包含 CWE-79 条目"
    );

    let _ = std::fs::remove_dir_all(&project);
}
/// 启用 --investigate 时，audit_log 中应包含 investigation_steps 字段
#[test]
fn test_audit_agent_investigator_produces_steps_field() {
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
            "--investigate",
            "--max-investigation-steps",
            "3",
            project.to_str().unwrap(),
            "--max-findings",
            "5",
            "--min-severity",
            "medium",
        ])
        .output()
        .expect("Failed to run audit --agent --investigate");

    if !output.status.success() {
        eprintln!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("stderr: {}", String::from_utf8_lossy(&output.stderr));
    }
    assert!(output.status.success());

    let audit_log = project.join(".ctx-audit").join("audit_log.json");
    let content = std::fs::read_to_string(&audit_log).unwrap();
    let entries: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    assert!(!entries.is_empty());

    for entry in &entries {
        assert!(
            entry.get("investigation_steps").is_some(),
            "investigate 模式下 audit_log 每条记录都应包含 investigation_steps"
        );
    }

    let _ = std::fs::remove_dir_all(&project);
}
/// 默认启用 --auto-goal 时，audit 应生成包含目标导向行动的 audit_log
#[test]
fn test_audit_agent_auto_goal_generates_audit_log() {
    let project = unique_test_dir();

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
    let content = std::fs::read_to_string(&audit_log).unwrap();
    let entries: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    assert!(
        !entries.is_empty(),
        "auto-goal 模式下应至少调查一个 finding"
    );

    let _ = std::fs::remove_dir_all(&project);
}

/// 使用 --no-auto-goal 可回退到传统 Supervisor 行为
#[test]
fn test_audit_agent_no_auto_goal_fallback() {
    let project = unique_test_dir();

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
            "--no-auto-goal",
            project.to_str().unwrap(),
            "--max-findings",
            "5",
            "--min-severity",
            "medium",
        ])
        .output()
        .expect("Failed to run audit --agent --no-auto-goal");

    if !output.status.success() {
        eprintln!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("stderr: {}", String::from_utf8_lossy(&output.stderr));
    }
    assert!(output.status.success());

    let audit_log = project.join(".ctx-audit").join("audit_log.json");
    let content = std::fs::read_to_string(&audit_log).unwrap();
    let entries: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    assert!(!entries.is_empty());

    let _ = std::fs::remove_dir_all(&project);
}
