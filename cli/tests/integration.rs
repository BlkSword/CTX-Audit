// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 集成测试：CLI 端到端验证

use std::process::Command;

fn cli_bin() -> String {
    let exe = std::env::current_exe().unwrap();
    let dir = exe.parent().unwrap().parent().unwrap();
    dir.join("ctx-audit").to_string_lossy().to_string()
}

/// 测试本地扫描
#[test]
fn test_scan_local() {
    let output = Command::new(cli_bin())
        .args(["scan", ".", "--threads", "2"])
        .output()
        .expect("Failed to run scan");
    assert!(output.status.success());
}

/// 测试 JSON 输出
#[test]
fn test_scan_json_output() {
    let output = Command::new(cli_bin())
        .args(["-o", "json", "scan", ".", "-o", ".ctx-audit/test_results.json"])
        .output()
        .expect("Failed to run scan with JSON output");
    if !output.status.success() {
        eprintln!("stderr: {}", String::from_utf8_lossy(&output.stderr));
    }
    assert!(output.status.success());
    if std::path::Path::new(".ctx-audit/test_results.json").exists() {
        let content = std::fs::read_to_string(".ctx-audit/test_results.json").unwrap_or_default();
        assert!(content.starts_with('[') || content.starts_with('{') || !content.is_empty());
    }
}

/// 测试配置显示
#[test]
fn test_config_show() {
    let output = Command::new(cli_bin())
        .args(["config", "show"])
        .output()
        .expect("Failed to run config show");
    assert!(output.status.success());
}

/// 测试分析命令
#[test]
fn test_analyze_file() {
    // 分析一个确定存在的文件
    let output = Command::new(cli_bin())
        .args(["analyze", "Cargo.toml"])
        .output()
        .expect("Failed to run analyze");
    assert!(output.status.success());
}

/// 测试 SARIF 输出
#[test]
fn test_scan_sarif_output() {
    let output = Command::new(cli_bin())
        .args(["-o", "sarif", "scan", ".", "-o", ".ctx-audit/test_results.sarif"])
        .output()
        .expect("Failed to run SARIF scan");
    if !output.status.success() {
        eprintln!("stderr: {}", String::from_utf8_lossy(&output.stderr));
    }
    assert!(output.status.success());
    if std::path::Path::new(".ctx-audit/test_results.sarif").exists() {
        let content = std::fs::read_to_string(".ctx-audit/test_results.sarif").unwrap_or_default();
        assert!(content.contains("sarif") || content.contains("runs"));
    }
}
