// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! daemon 命令实现
//!
//! 管理安全分析守护进程

use miette::Result;

use crate::terminal::TerminalRenderer;
use ctx_audit_daemon::client::{DaemonClient, HeartbeatStatus};
use ctx_audit_daemon::protocol::Response;

/// 启动守护进程
pub async fn start(project: Option<String>) -> Result<()> {
    let mut renderer = TerminalRenderer::new();

    // 先查心跳文件判断状态
    match DaemonClient::check_heartbeat() {
        HeartbeatStatus::Alive { pid, .. } => {
            // 心跳正常，确认 TCP 可连
            if DaemonClient::is_running().await {
                renderer.warning(&format!("守护进程已在运行 (PID: {})", pid));
                show_status(&mut renderer).await?;
                return Ok(());
            }
            // 心跳正常但 TCP 连不上 → daemon 可能僵死，清理残留
            renderer.warning(&format!("检测到残留心跳 (PID: {})，清理中...", pid));
            DaemonClient::cleanup_stale_files();
        }
        HeartbeatStatus::Stale { pid, .. } => {
            renderer.warning(&format!(
                "检测到过期心跳 (PID: {})，daemon 可能已崩溃，清理残留文件",
                pid
            ));
            DaemonClient::cleanup_stale_files();
        }
        HeartbeatStatus::ShuttingDown => {
            renderer.warning("守护进程正在关闭中，稍后重试");
            return Ok(());
        }
        HeartbeatStatus::NoHeartbeat => {}
    }

    renderer.info("正在启动安全分析守护进程...");

    // 构建参数
    let mut daemon_args = vec!["ctx-audit-daemon".to_string()];
    if let Some(ref p) = project {
        daemon_args.push("--project".to_string());
        daemon_args.push(p.clone());
    }

    // 分离启动守护进程
    let daemon_bin = std::env::current_exe()
        .map(|p| {
            let bin_dir = p.parent().unwrap_or(std::path::Path::new("."));
            bin_dir
                .join("ctx-audit-daemon")
                .to_string_lossy()
                .to_string()
        })
        .unwrap_or_else(|_| "ctx-audit-daemon".to_string());

    let mut cmd = std::process::Command::new(&daemon_bin);
    cmd.args(&daemon_args[1..]);

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x00000008); // DETACHED_PROCESS
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }

    match cmd.spawn() {
        Ok(child) => {
            renderer.info(&format!("守护进程已启动 (PID: {})", child.id()));
        }
        Err(e) => {
            renderer.error(&format!("启动守护进程失败: {}", e));
            renderer.info("提示: 请确认 ctx-audit-daemon 二进制文件已编译 (cargo build)");
            return Err(miette::miette!("启动失败: {}", e));
        }
    }

    // 等待守护进程就绪（优先用心跳文件检测）
    renderer.info("等待守护进程就绪...");
    for i in 0..20 {
        tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
        if DaemonClient::is_running().await {
            renderer.success("守护进程已就绪");
            show_status(&mut renderer).await?;
            return Ok(());
        }
        if i % 4 == 3 {
            renderer.info("  仍在等待...");
        }
    }

    renderer.warning("守护进程启动超时（可能仍在初始化中）");
    renderer.info("使用 'ctx-audit daemon status' 检查状态");
    Ok(())
}

/// 查询守护进程状态
pub async fn status() -> Result<()> {
    let mut renderer = TerminalRenderer::new();

    // 先通过心跳文件快速判断
    match DaemonClient::check_heartbeat() {
        HeartbeatStatus::Alive {
            pid,
            version,
            uptime_secs,
            age_secs,
            ..
        } => {
            renderer.success(&format!(
                "心跳正常 (PID: {}, v{}, 运行 {}秒, 心跳 {}秒前)",
                pid, version, uptime_secs, age_secs
            ));
        }
        HeartbeatStatus::Stale { pid, age_secs, .. } => {
            renderer.warning(&format!(
                "心跳过期 (PID: {}, {}秒前) — daemon 可能已崩溃",
                pid, age_secs
            ));
            renderer.info("尝试 TCP 连接确认...");
        }
        HeartbeatStatus::ShuttingDown => {
            renderer.warning("守护进程正在关闭中");
            return Ok(());
        }
        HeartbeatStatus::NoHeartbeat => {
            renderer.warning("守护进程未运行（无心跳文件）");
            renderer.info("使用 'ctx-audit daemon start' 启动");
            return Ok(());
        }
    }

    // TCP 连接获取详细状态
    show_status(&mut renderer).await
}

async fn show_status(renderer: &mut TerminalRenderer) -> Result<()> {
    let mut client = match DaemonClient::connect().await {
        Ok(c) => c,
        Err(_) => {
            renderer.warning("无法连接守护进程（TCP 连接失败）");
            renderer.info("守护进程可能已崩溃，残留文件可通过 'ctx-audit daemon start' 自动清理");
            return Ok(());
        }
    };

    let response = client.ping().await.map_err(|e| miette::miette!("{}", e))?;

    match response {
        Response::Pong {
            version,
            uptime_secs,
        } => {
            renderer.success(&format!("守护进程运行中 (v{})", version));
            renderer.info(&format!("  运行时间: {}秒", uptime_secs));
        }
        _ => {
            renderer.info("守护进程响应异常");
        }
    }

    // 查询详细信息
    match client.status().await {
        Ok(Response::StatusInfo {
            pid,
            uptime_secs,
            loaded_projects,
            cache_stats,
        }) => {
            renderer.info(&format!("  PID: {}", pid));
            renderer.info(&format!("  运行时间: {}秒", uptime_secs));
            renderer.info(&format!(
                "  已加载项目: {}",
                if loaded_projects.is_empty() {
                    "无".to_string()
                } else {
                    loaded_projects.join(", ")
                }
            ));
            renderer.info(&format!(
                "  缓存: AST={}, Taint={}, Scan={}",
                cache_stats.ast_cache_entries,
                cache_stats.taint_cache_entries,
                cache_stats.scan_cache_entries,
            ));
        }
        _ => {}
    }

    Ok(())
}

/// 查询守护进程的增量索引状态
///
/// 只读：服务端用文件快照的只读预览判定变更，不会推进 baseline。
pub async fn incremental(project: Option<String>) -> Result<()> {
    let mut renderer = TerminalRenderer::new();

    let mut client = match DaemonClient::connect().await {
        Ok(c) => c,
        Err(e) => {
            renderer.warning("无法连接守护进程（TCP 连接失败）");
            renderer.info(&format!("  {}", e));
            renderer.info("提示: 先运行 'ctx-audit daemon start'");
            return Ok(());
        }
    };

    // 未指定项目时取守护进程已加载的第一个项目
    let project = match project {
        Some(p) => p,
        None => match client.status().await {
            Ok(Response::StatusInfo {
                loaded_projects, ..
            }) => match loaded_projects.first() {
                Some(p) => p.clone(),
                None => {
                    renderer.warning("守护进程未加载任何项目");
                    renderer.info("提示: 用 'ctx-audit daemon incremental --project <path>' 指定项目");
                    return Ok(());
                }
            },
            Ok(other) => {
                renderer.info(&format!("守护进程响应异常: {:?}", other));
                return Ok(());
            }
            Err(e) => {
                renderer.error(&format!("查询状态失败: {}", e));
                return Ok(());
            }
        },
    };

    match client.incremental_status(project.clone()).await {
        Ok(Response::IncrementalStatusInfo { status }) => {
            renderer.info(&format!("项目: {}", project));
            renderer.info(&format!(
                "  模式: {}",
                status
                    .get("mode")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
            ));
            renderer.info(&format!(
                "  已缓存文件: {} / findings: {} / 快照文件: {}",
                status
                    .get("files_cached")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                status
                    .get("cached_findings")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                status
                    .get("snapshot_files")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            ));
            renderer.info(&format!(
                "  待重编译: {} (新增 {} / 修改 {} / 删除 {})",
                status
                    .get("pending_recompile")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                status["pending"]["added"].as_u64().unwrap_or(0),
                status["pending"]["changed"].as_u64().unwrap_or(0),
                status["pending"]["deleted"].as_u64().unwrap_or(0),
            ));
            if let Some(sample) = status["pending"]["sample"].as_array() {
                if !sample.is_empty() {
                    let list: Vec<&str> = sample.iter().filter_map(|v| v.as_str()).collect();
                    renderer.info(&format!("  样本: {}", list.join(", ")));
                }
            }
            renderer.info(&format!(
                "  最近扫描: {}",
                match status.get("last_scan") {
                    Some(v) if !v.is_null() => format!(
                        "{}ms / 重扫 {} / 缓存 {} / 增量 {}",
                        v["duration_ms"].as_u64().unwrap_or(0),
                        v["files_scanned"].as_u64().unwrap_or(0),
                        v["files_cached"].as_u64().unwrap_or(0),
                        v["was_incremental"].as_bool().unwrap_or(false),
                    ),
                    _ => "无记录（冷启动）".to_string(),
                }
            ));
            if let Some(rules) = status.get("rules_dir").and_then(|v| v.as_str()) {
                renderer.info(&format!("  规则目录: {}", rules));
            }
            renderer.info("完整 JSON:");
            renderer.info(&serde_json::to_string_pretty(&status).unwrap_or_default());
        }
        Ok(Response::Error { code, message }) => {
            renderer.error(&format!("查询失败 [{}]: {}", code, message));
        }
        Ok(other) => {
            renderer.info(&format!("守护进程响应异常: {:?}", other));
        }
        Err(e) => {
            renderer.error(&format!("增量状态查询失败: {}", e));
        }
    }

    Ok(())
}

/// 停止守护进程
pub async fn stop() -> Result<()> {
    let mut renderer = TerminalRenderer::new();

    // 先查心跳
    match DaemonClient::check_heartbeat() {
        HeartbeatStatus::NoHeartbeat | HeartbeatStatus::ShuttingDown => {
            renderer.warning("守护进程未运行");
            DaemonClient::cleanup_stale_files();
            return Ok(());
        }
        HeartbeatStatus::Stale { pid, .. } => {
            renderer.warning(&format!("守护进程心跳已过期 (PID: {})，清理残留文件", pid));
            DaemonClient::cleanup_stale_files();
            return Ok(());
        }
        HeartbeatStatus::Alive { .. } => {}
    }

    let mut client = match DaemonClient::connect().await {
        Ok(c) => c,
        Err(_) => {
            renderer.warning("无法连接守护进程，清理残留文件");
            DaemonClient::cleanup_stale_files();
            return Ok(());
        }
    };

    renderer.info("正在停止守护进程...");
    match client.shutdown().await {
        Ok(Response::Ack { .. }) => {
            // 等待进程退出
            for _ in 0..10 {
                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                if !DaemonClient::is_running().await {
                    renderer.success("守护进程已停止");
                    return Ok(());
                }
            }
            renderer.warning("守护进程可能仍在关闭中");
        }
        Ok(other) => {
            renderer.info(&format!("守护进程响应: {:?}", other));
        }
        Err(e) => {
            renderer.error(&format!("关闭请求失败: {}", e));
        }
    }

    Ok(())
}
