// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! CTX-Audit 守护进程入口

use std::sync::Arc;

use clap::Parser;
use tracing::info;

use ctx_audit_daemon::{state::DaemonState, engine::AnalysisEngine, server::Server, VERSION};

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

    // 初始化日志
    let level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level))
        )
        .with_target(false)
        .init();

    info!("CTX-Audit Daemon v{} 启动", VERSION);

    // 创建状态和引擎
    let state = Arc::new(DaemonState::new());
    let engine = Arc::new(AnalysisEngine::new());

    // 预加载项目
    if let Some(project_path) = args.project {
        info!("预加载项目: {}", project_path);
        let mut projects = state.projects.write().await;
        projects.insert(project_path.clone(), ctx_audit_daemon::state::ProjectState::new(project_path));
    }

    // 创建并启动服务器
    let server = Server::new(state, engine).with_addr(args.addr);
    let addr = server.addr().to_string();
    info!("IPC 监听: {}", addr);

    server.run().await?;

    Ok(())
}
