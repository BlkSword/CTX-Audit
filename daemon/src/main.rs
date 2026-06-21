// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! CTX-Audit 守护进程入口

use std::sync::Arc;

use clap::Parser;
use tracing::info;

use ctx_audit_daemon::{engine::AnalysisEngine, server::Server, state::DaemonState, VERSION};

#[derive(Parser, Debug)]
#[command(name = "ctx-audit-daemon")]
#[command(version = VERSION)]
#[command(about = "CTX-Audit security analysis daemon")]
struct Args {
    /// 监听地址
    #[arg(long, default_value = "127.0.0.1:19527")]
    addr: String,

    /// 预加载项目路径
    #[arg(short, long)]
    project: Option<String>,

    /// 启用详细日志
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // 注册 panic hook：panic 时记录日志并尝试自动重启
    let restart_args: Vec<String> = std::env::args().collect();
    std::panic::set_hook(Box::new(move |info| {
        let payload = info.payload();
        let msg = if let Some(s) = payload.downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else {
            "unknown panic".to_string()
        };
        eprintln!("[PANIC] {}", msg);

        // 写 panic 日志
        let log_line = format!("[{}] PANIC: {}\n", chrono::Utc::now().to_rfc3339(), msg);
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(".ctx-audit/daemon.log")
        {
            use std::io::Write;
            let _ = f.write_all(log_line.as_bytes());
        }

        // 尝试自动重启（spawn 新进程后退出）
        if std::env::var("CTX_AUDUDIT_RESTARTING").is_err() {
            eprintln!("[PANIC] 尝试自动重启...");
            let _ = std::process::Command::new(&restart_args[0])
                .args(&restart_args[1..])
                .env("CTX_AUDUDIT_RESTARTING", "1")
                .spawn();
        }
    }));

    // 进程锁：检测是否已有 daemon 在运行
    let pid_path = std::path::Path::new(".ctx-audit/daemon.pid");
    if pid_path.exists() {
        if let Ok(content) = std::fs::read_to_string(pid_path) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(pid) = val.get("pid").and_then(|v| v.as_u64()) {
                    // 检查进程是否存活
                    if is_process_alive(pid as u32) {
                        eprintln!("守护进程已在运行 (PID: {})", pid);
                        std::process::exit(1);
                    }
                    // 进程已死，清理残留
                    let _ = std::fs::remove_file(pid_path);
                    let hb_path = std::path::Path::new(".ctx-audit/heartbeat.json");
                    let _ = std::fs::remove_file(hb_path);
                }
            }
        }
    }

    // 端口探测
    if tokio::net::TcpStream::connect(&args.addr).await.is_ok() {
        eprintln!("端口 {} 已被占用，可能已有守护进程在运行", args.addr);
        std::process::exit(1);
    }

    // 确保目录存在
    let _ = std::fs::create_dir_all(".ctx-audit");

    // 初始化日志（同时输出到文件和 stderr）
    let log_path = std::path::Path::new(".ctx-audit/daemon.log");
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .ok();

    let level = if args.verbose { "debug" } else { "info" };
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));

    if let Some(file) = log_file {
        use tracing_subscriber::layer::SubscriberExt;
        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_target(false)
            .with_ansi(false)
            .with_writer(std::sync::Mutex::new(file));
        let stderr_layer = tracing_subscriber::fmt::layer()
            .with_target(false)
            .with_writer(std::io::stderr);

        let combined = tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .with(stderr_layer);
        tracing::subscriber::set_global_default(combined)
            .map_err(|e| anyhow::anyhow!("日志初始化失败: {}", e))?;
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_target(false)
            .init();
    }

    info!("CTX-Audit Daemon v{} 启动", VERSION);

    // 创建状态和引擎
    let state = Arc::new(DaemonState::new());
    let engine = Arc::new(AnalysisEngine::new());

    // 预加载项目
    if let Some(project_path) = args.project {
        info!("预加载项目: {}", project_path);
        let mut projects = state.projects.write().await;
        projects.insert(
            project_path.clone(),
            ctx_audit_daemon::state::ProjectState::new(project_path),
        );
    }

    // 创建并启动服务器
    let server = Server::new(state, engine).with_addr(args.addr);
    let addr = server.addr().to_string();
    info!("IPC 监听: {}", addr);

    server.run().await?;

    Ok(())
}

/// 检测进程是否存活
fn is_process_alive(pid: u32) -> bool {
    #[cfg(windows)]
    {
        // Windows: tasklist 检查
        std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {}", pid), "/NH"])
            .output()
            .map(|o| {
                let out = String::from_utf8_lossy(&o.stdout);
                out.contains(&pid.to_string())
            })
            .unwrap_or(false)
    }
    #[cfg(unix)]
    {
        // Unix: kill(pid, 0) 检查进程存在（不发送信号）
        unsafe { libc::kill(pid as i32, 0) == 0 }
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = pid;
        false
    }
}
