// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! CVE 回放反哺机械层（M4）
//!
//! 确定性流程，无 LLM 决策：
//! ① clone 仓库到 `<feedback_root>/<cve_id>/repo`（已存在则复用）；
//! ② checkout vulnerable ref → 全量扫描（taint + cross-file，与 runner 同款 core API）；
//! ③ checkout fixed ref → 全量扫描；
//! ④ 对比：漏洞版是否命中预期规则/漏洞类型、修复版是否豁免、全仓回归统计；
//! ⑤ 产出 `replay-report-<cve_id>.json`（命中/漏报/误报结论 + 原始数据）。
//!
//! 红线：规则草案的生成与合入永久人工，本层只出报告 JSON。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use deepaudit_core::scanning::classify_file_role;
use deepaudit_core::scanning::{scan_directory_deep_with_rules_progress, Finding, ScanOptions};

// ── 任务与报告模型 ──────────────────────────────────────

/// CVE 回放任务（JSON 反序列化）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackTask {
    /// CVE 编号（报告命名与目录隔离用）
    pub cve_id: String,
    /// 仓库 git URL 或本地路径
    pub git_url: String,
    /// 漏洞版本 ref（commit/tag/branch）
    pub vulnerable_ref: String,
    /// 修复版本 ref
    pub fixed_ref: String,
    /// 预期命中的规则 ID 列表（按 finding.detector 包含匹配）
    #[serde(default)]
    pub expected_rule_ids: Vec<String>,
    /// 预期命中的漏洞类型列表（按 finding.vuln_type 匹配）
    #[serde(default)]
    pub expected_vuln_types: Vec<String>,
}

/// 单条简化 finding（报告与跨版本对比用）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct SimpleFinding {
    /// 文件路径
    pub file_path: String,
    /// 起始行
    pub line_start: usize,
    /// 漏洞类型
    pub vuln_type: String,
    /// 检测器/规则
    pub detector: String,
    /// 严重度
    pub severity: String,
}

/// 预期命中明细
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedHit {
    /// 匹配依据（规则 ID 或漏洞类型）
    pub matched_by: String,
    /// 命中条数
    pub hits: usize,
    /// 样本（文件:行号，上限 5 条）
    pub samples: Vec<String>,
}

/// 单个 ref 的扫描摘要
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefScanSummary {
    /// ref 名
    pub ref_name: String,
    /// findings 总数
    pub total: usize,
    /// 按严重度统计
    pub by_severity: BTreeMap<String, usize>,
    /// 按文件角色统计
    pub by_file_role: BTreeMap<String, usize>,
    /// 预期命中明细
    pub expected_hits: Vec<ExpectedHit>,
    /// 简化 findings（全量，供回归对比与人工复核）
    pub findings: Vec<SimpleFinding>,
}

/// 回放结论
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    /// 漏洞版是否命中预期（true = 引擎能检出该 CVE）
    pub vulnerable_hit_expected: bool,
    /// 修复版是否豁免（true = 修复后不再命中，无误报残留）
    pub fixed_exempt: bool,
    /// 总结论：pass / missed_detection / fix_still_flagged / missed_and_flagged
    pub conclusion: String,
}

/// 跨版本回归统计
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionStats {
    /// 漏洞版 findings 总数
    pub vulnerable_total: usize,
    /// 修复版 findings 总数
    pub fixed_total: usize,
    /// 修复版新增（漏洞版没有的同位置同类型 finding）
    pub new_in_fixed: usize,
    /// 修复版消除
    pub resolved_in_fixed: usize,
}

/// 回放报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayReport {
    /// CVE 编号
    pub cve_id: String,
    /// 仓库
    pub git_url: String,
    /// 漏洞版本 ref
    pub vulnerable_ref: String,
    /// 修复版本 ref
    pub fixed_ref: String,
    /// 生成时间
    pub generated_at: DateTime<Utc>,
    /// 漏洞版扫描摘要
    pub vulnerable: RefScanSummary,
    /// 修复版扫描摘要
    pub fixed: RefScanSummary,
    /// 结论
    pub verdict: Verdict,
    /// 回归统计
    pub regression: RegressionStats,
}

/// 回放错误
#[derive(Debug, thiserror::Error)]
pub enum FeedbackError {
    /// IO 错误
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),

    /// git 操作失败
    #[error("git 操作失败: {0}")]
    Git(String),

    /// 扫描失败
    #[error("扫描失败: {0}")]
    Scan(String),

    /// 任务 JSON 解析失败
    #[error("任务 JSON 解析失败: {0}")]
    Parse(String),
}

/// 报告文件路径：`<feedback_root>/replay-report-<cve_id>.json`
pub fn report_path(feedback_root: &Path, cve_id: &str) -> PathBuf {
    feedback_root.join(format!("replay-report-{}.json", cve_id))
}

/// 执行一个 CVE 回放任务，返回报告与报告文件路径
pub async fn run_replay(
    task: &FeedbackTask,
    feedback_root: &Path,
) -> Result<(ReplayReport, PathBuf), FeedbackError> {
    let work_dir = feedback_root.join(&task.cve_id);
    let repo_dir = work_dir.join("repo");
    std::fs::create_dir_all(&work_dir)?;

    // ── ① clone（已存在则复用，保持离线可重放） ──
    if repo_dir.exists() {
        tracing::info!("回放仓库已存在，复用: {}", repo_dir.display());
    } else {
        git(&["clone", &task.git_url, &repo_dir.to_string_lossy()], None).await?;
    }

    // ── ② 漏洞版扫描 ──
    git(&["checkout", "--quiet", &task.vulnerable_ref], Some(&repo_dir)).await?;
    let vulnerable_findings = scan_repo(&repo_dir).await?;
    let vulnerable = summarize(&task.vulnerable_ref, &vulnerable_findings, task);
    tracing::info!(
        "CVE {} 漏洞版（{}）扫描完成: {} findings，预期命中 {} 组",
        task.cve_id,
        task.vulnerable_ref,
        vulnerable.total,
        vulnerable.expected_hits.len()
    );

    // ── ③ 修复版扫描 ──
    git(&["checkout", "--quiet", &task.fixed_ref], Some(&repo_dir)).await?;
    let fixed_findings = scan_repo(&repo_dir).await?;
    let fixed = summarize(&task.fixed_ref, &fixed_findings, task);
    tracing::info!(
        "CVE {} 修复版（{}）扫描完成: {} findings，预期命中 {} 组",
        task.cve_id,
        task.fixed_ref,
        fixed.total,
        fixed.expected_hits.len()
    );

    // ── ④ 对比与结论 ──
    let verdict = Verdict {
        vulnerable_hit_expected: !vulnerable.expected_hits.is_empty(),
        fixed_exempt: fixed.expected_hits.is_empty(),
        conclusion: conclusion(!vulnerable.expected_hits.is_empty(), fixed.expected_hits.is_empty())
            .to_string(),
    };
    let regression = regression_stats(&vulnerable.findings, &fixed.findings);

    let report = ReplayReport {
        cve_id: task.cve_id.clone(),
        git_url: task.git_url.clone(),
        vulnerable_ref: task.vulnerable_ref.clone(),
        fixed_ref: task.fixed_ref.clone(),
        generated_at: Utc::now(),
        vulnerable,
        fixed,
        verdict,
        regression,
    };

    // ── ⑤ 出报告 JSON ──
    let path = report_path(feedback_root, &task.cve_id);
    let json = serde_json::to_string_pretty(&report)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(&path, json)?;
    tracing::info!("CVE {} 回放报告: {}（{}）", task.cve_id, path.display(), report.verdict.conclusion);

    Ok((report, path))
}

/// 总结论判定
fn conclusion(vulnerable_hit: bool, fixed_exempt: bool) -> &'static str {
    match (vulnerable_hit, fixed_exempt) {
        (true, true) => "pass",
        (false, true) => "missed_detection",
        (true, false) => "fix_still_flagged",
        (false, false) => "missed_and_flagged",
    }
}

/// 执行 git 命令（失败带 stderr）
async fn git(args: &[&str], cwd: Option<&Path>) -> Result<(), FeedbackError> {
    let mut cmd = tokio::process::Command::new("git");
    cmd.args(args);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let output = cmd
        .output()
        .await
        .map_err(|e| FeedbackError::Git(format!("启动 git 失败: {}", e)))?;
    if !output.status.success() {
        return Err(FeedbackError::Git(format!(
            "git {} 失败: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// 全量扫描（与 runner 扫描阶段同款 core API）
async fn scan_repo(repo_dir: &Path) -> Result<Vec<Finding>, FeedbackError> {
    let mut opts = ScanOptions::default();
    opts.enable_taint = true;
    opts.enable_cross_file = true;
    let result = scan_directory_deep_with_rules_progress(
        &repo_dir.to_string_lossy(),
        None,
        None,
        None,
        Some(opts),
        None,
    )
    .await
    .map_err(|e| FeedbackError::Scan(e.to_string()))?;
    Ok(result.findings)
}

/// finding 是否命中预期（detector 含规则 ID 或 vuln_type 匹配）
fn is_expected_hit(f: &Finding, task: &FeedbackTask) -> Option<String> {
    for rule_id in &task.expected_rule_ids {
        if f.detector == *rule_id || f.detector.contains(rule_id.as_str()) {
            return Some(format!("rule:{}", rule_id));
        }
    }
    for vuln_type in &task.expected_vuln_types {
        if f.vuln_type == *vuln_type || f.vuln_type.contains(vuln_type.as_str()) {
            return Some(format!("vuln_type:{}", vuln_type));
        }
    }
    None
}

/// 汇总单版扫描结果
fn summarize(ref_name: &str, findings: &[Finding], task: &FeedbackTask) -> RefScanSummary {
    let mut by_severity: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_file_role: BTreeMap<String, usize> = BTreeMap::new();
    // matched_by → (hits, samples)
    let mut hits_map: BTreeMap<String, (usize, Vec<String>)> = BTreeMap::new();
    let mut simple = Vec::with_capacity(findings.len());
    for f in findings {
        let role = classify_file_role(&f.file_path).to_string();
        *by_file_role.entry(role.clone()).or_insert(0) += 1;
        *by_severity.entry(f.severity.clone()).or_insert(0) += 1;
        if role == "production" {
            if let Some(matched_by) = is_expected_hit(f, task) {
                let entry = hits_map.entry(matched_by).or_insert((0, Vec::new()));
                entry.0 += 1;
                if entry.1.len() < 5 {
                    entry.1.push(format!("{}:{}", f.file_path, f.line_start));
                }
            }
        }
        simple.push(SimpleFinding {
            file_path: f.file_path.clone(),
            line_start: f.line_start,
            vuln_type: f.vuln_type.clone(),
            detector: f.detector.clone(),
            severity: f.severity.clone(),
        });
    }
    simple.sort();

    RefScanSummary {
        ref_name: ref_name.to_string(),
        total: findings.len(),
        by_severity,
        by_file_role,
        expected_hits: hits_map
            .into_iter()
            .map(|(matched_by, (hits, samples))| ExpectedHit {
                matched_by,
                hits,
                samples,
            })
            .collect(),
        findings: simple,
    }
}

/// 跨版本回归统计（finding 身份 = 文件 + 起始行 + 漏洞类型）
fn regression_stats(
    vulnerable: &[SimpleFinding],
    fixed: &[SimpleFinding],
) -> RegressionStats {
    let key = |f: &SimpleFinding| (f.file_path.clone(), f.line_start, f.vuln_type.clone());
    let vuln_keys: BTreeSet<_> = vulnerable.iter().map(key.clone()).collect();
    let fixed_keys: BTreeSet<_> = fixed.iter().map(key).collect();

    RegressionStats {
        vulnerable_total: vulnerable.len(),
        fixed_total: fixed.len(),
        new_in_fixed: fixed_keys.difference(&vuln_keys).count(),
        resolved_in_fixed: vuln_keys.difference(&fixed_keys).count(),
    }
}

// ── 测试 ────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// 用本地临时 git 仓库造 vulnerable/fixed 两个 commit：
    /// 漏洞版塞 python 命令注入，修复版改为无害输出
    struct CveRepo {
        root: PathBuf,
        repo_src: PathBuf,
        vulnerable_ref: String,
        fixed_ref: String,
    }

    fn git_sync(args: &[&str], cwd: &Path) -> String {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(cwd)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git 应可执行");
        assert!(
            output.status.success(),
            "git {} 失败: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    fn make_cve_repo(tag: &str) -> CveRepo {
        let root = std::env::temp_dir().join(format!(
            "ctx-audit-feedback-test-{}-{}",
            tag,
            uuid::Uuid::new_v4()
        ));
        let repo_src = root.join("repo-src");
        std::fs::create_dir_all(&repo_src).unwrap();

        git_sync(&["init", "--quiet"], &repo_src);
        // 漏洞版：命令注入
        std::fs::write(
            repo_src.join("app.py"),
            "import os\ncmd = input('cmd:')\nos.system(cmd)\n",
        )
        .unwrap();
        git_sync(
            &["-c", "user.name=t", "-c", "user.email=t@t", "add", "-A"],
            &repo_src,
        );
        git_sync(
            &["-c", "user.name=t", "-c", "user.email=t@t", "commit", "--quiet", "-m", "vulnerable"],
            &repo_src,
        );
        let vulnerable_ref = git_sync(&["rev-parse", "HEAD"], &repo_src);

        // 修复版：移除危险调用
        std::fs::write(repo_src.join("app.py"), "print('fixed')\n").unwrap();
        git_sync(
            &["-c", "user.name=t", "-c", "user.email=t@t", "add", "-A"],
            &repo_src,
        );
        git_sync(
            &["-c", "user.name=t", "-c", "user.email=t@t", "commit", "--quiet", "-m", "fix"],
            &repo_src,
        );
        let fixed_ref = git_sync(&["rev-parse", "HEAD"], &repo_src);

        CveRepo {
            root,
            repo_src,
            vulnerable_ref,
            fixed_ref,
        }
    }

    impl Drop for CveRepo {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.root).ok();
        }
    }

    fn make_task(repo: &CveRepo) -> FeedbackTask {
        FeedbackTask {
            cve_id: "CVE-TEST-0001".to_string(),
            git_url: repo.repo_src.to_string_lossy().to_string(),
            vulnerable_ref: repo.vulnerable_ref.clone(),
            fixed_ref: repo.fixed_ref.clone(),
            expected_rule_ids: vec!["command-injection".to_string()],
            expected_vuln_types: vec!["CWE-78".to_string()],
        }
    }

    /// 完整回放：漏洞版命中预期、修复版豁免、结论 pass、报告 JSON 落盘
    #[tokio::test]
    async fn test_replay_full_flow() {
        let repo = make_cve_repo("full");
        let task = make_task(&repo);
        let feedback_root = repo.root.join("feedback");

        let (report, path) = run_replay(&task, &feedback_root)
            .await
            .expect("回放应成功");

        // 结论：漏洞版命中 + 修复版豁免 → pass
        assert!(
            report.verdict.vulnerable_hit_expected,
            "漏洞版应命中 command-injection: {}",
            serde_json::to_string(&report.vulnerable.expected_hits).unwrap()
        );
        assert!(
            report.verdict.fixed_exempt,
            "修复版应豁免: {}",
            serde_json::to_string(&report.fixed.expected_hits).unwrap()
        );
        assert_eq!(report.verdict.conclusion, "pass");

        // 回归统计：修复版总数应少于漏洞版（命令注入被消除）
        assert!(report.vulnerable.total >= 1);
        assert!(report.regression.fixed_total < report.regression.vulnerable_total);
        assert!(report.regression.resolved_in_fixed >= 1);
        assert_eq!(report.regression.new_in_fixed, 0);

        // 报告 JSON 落盘且可解析回同一结论
        assert!(path.exists());
        assert_eq!(path, report_path(&feedback_root, "CVE-TEST-0001"));
        let on_disk: ReplayReport =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(on_disk.verdict.conclusion, "pass");
        assert_eq!(on_disk.cve_id, "CVE-TEST-0001");
    }

    /// 预期规则写错：漏洞版不命中 → missed_detection 结论
    #[tokio::test]
    async fn test_replay_missed_detection() {
        let repo = make_cve_repo("missed");
        let mut task = make_task(&repo);
        task.expected_rule_ids = vec!["no-such-rule".to_string()];
        task.expected_vuln_types = vec![];
        let feedback_root = repo.root.join("feedback");

        let (report, _) = run_replay(&task, &feedback_root).await.unwrap();
        assert!(!report.verdict.vulnerable_hit_expected);
        assert!(report.verdict.fixed_exempt);
        assert_eq!(report.verdict.conclusion, "missed_detection");
    }

    /// 预期匹配：detector 包含匹配与 vuln_type 匹配
    #[test]
    fn test_expected_hit_matching() {
        let task = FeedbackTask {
            cve_id: "X".into(),
            git_url: "x".into(),
            vulnerable_ref: "a".into(),
            fixed_ref: "b".into(),
            expected_rule_ids: vec!["command-injection".into()],
            expected_vuln_types: vec!["CWE-78".into()],
        };
        let f = Finding {
            detector: "RegexRule: command-injection".into(),
            vuln_type: "CWE-78".into(),
            ..Default::default()
        };
        assert!(is_expected_hit(&f, &task).is_some());

        let f2 = Finding {
            detector: "AstTaintScanner".into(),
            vuln_type: "command_injection".into(),
            ..Default::default()
        };
        assert!(is_expected_hit(&f2, &task).is_none());

        // 仅按漏洞类型匹配
        let task2 = FeedbackTask {
            expected_rule_ids: vec![],
            expected_vuln_types: vec!["command_injection".into()],
            ..task
        };
        assert!(is_expected_hit(&f2, &task2).is_some());
    }

    /// 回归统计：同位置同类型为同一 finding
    #[test]
    fn test_regression_stats() {
        let a = SimpleFinding {
            file_path: "a.py".into(),
            line_start: 1,
            vuln_type: "CWE-78".into(),
            detector: "d".into(),
            severity: "high".into(),
        };
        let b = SimpleFinding {
            file_path: "b.py".into(),
            line_start: 2,
            vuln_type: "CWE-79".into(),
            detector: "d".into(),
            severity: "mid".into(),
        };
        let stats = regression_stats(&[a.clone(), b.clone()], std::slice::from_ref(&a));
        assert_eq!(stats.vulnerable_total, 2);
        assert_eq!(stats.fixed_total, 1);
        assert_eq!(stats.resolved_in_fixed, 1);
        assert_eq!(stats.new_in_fixed, 0);
    }
}
