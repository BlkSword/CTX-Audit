// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! daemon 命令实现
//!
//! 管理安全分析守护进程

use miette::Result;

use crate::terminal::TerminalRenderer;
use ctx_audit_daemon::client::DaemonClient;
use ctx_audit_daemon::protocol::Response;

/// 启动守护进程
pub async fn start(project: Option<String>) -> Result<()> {
    let mut renderer = TerminalRenderer::new();

    // 检查是否已在运行
    if DaemonClient::is_running().await {
        renderer.warning("守护进程已在运行");
        // 查询状态
        show_status(&mut renderer).await?;
        return Ok(());
    }

    // 清理旧的 PID 文件
    let pid_path = std::path::Path::new(".ctx-audit/daemon.pid");
    if pid_path.exists() {
        let _ = std::fs::remove_file(pid_path);
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
            bin_dir.join("ctx-audit-daemon").to_string_lossy().to_string()
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

    // 等待守护进程就绪
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
    show_status(&mut renderer).await
}

async fn show_status(renderer: &mut TerminalRenderer) -> Result<()> {
    let mut client = match DaemonClient::connect().await {
        Ok(c) => c,
        Err(_) => {
            renderer.warning("守护进程未运行");
            renderer.info("使用 'ctx-audit daemon start' 启动");
            return Ok(());
        }
    };

    let response = client.ping().await.map_err(|e| miette::miette!("{}", e))?;

    match response {
        Response::Pong { version, uptime_secs } => {
            renderer.success(&format!("守护进程运行中 (v{})", version));
            renderer.info(&format!("  运行时间: {}秒", uptime_secs));
        }
        _ => {
            renderer.info("守护进程响应异常");
        }
    }

    // 查询详细信息
    match client.status().await {
        Ok(Response::StatusInfo { pid, uptime_secs, loaded_projects, cache_stats }) => {
            renderer.info(&format!("  PID: {}", pid));
            renderer.info(&format!("  运行时间: {}秒", uptime_secs));
            renderer.info(&format!("  已加载项目: {}",
                if loaded_projects.is_empty() { "无".to_string() } else { loaded_projects.join(", ") }
            ));
            renderer.info(&format!("  缓存: AST={}, Taint={}, Scan={}",
                cache_stats.ast_cache_entries,
                cache_stats.taint_cache_entries,
                cache_stats.scan_cache_entries,
            ));
        }
        _ => {}
    }

    Ok(())
}

/// 停止守护进程
pub async fn stop() -> Result<()> {
    let mut renderer = TerminalRenderer::new();

    let mut client = match DaemonClient::connect().await {
        Ok(c) => c,
        Err(_) => {
            renderer.warning("守护进程未运行");
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
