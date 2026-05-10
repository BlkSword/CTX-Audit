// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! IPC 服务器
//!
//! Named Pipe (Windows) / Unix Socket (Unix) 服务端

use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tracing::{info, error, debug};

use crate::engine::AnalysisEngine;
use crate::protocol::{CacheStats, Envelope, Request, Response};
use crate::state::DaemonState;

/// IPC 服务器默认端口（用 TCP loopback 替代 Named Pipe，跨平台统一）
const DEFAULT_ADDR: &str = "127.0.0.1:19527";

/// IPC 服务器
pub struct Server {
    state: Arc<DaemonState>,
    engine: Arc<AnalysisEngine>,
    addr: String,
    shutdown: tokio::sync::watch::Receiver<bool>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
}

impl Server {
    pub fn new(state: Arc<DaemonState>, engine: Arc<AnalysisEngine>) -> Self {
        let (shutdown_tx, shutdown) = tokio::sync::watch::channel(false);
        Self {
            state,
            engine,
            addr: DEFAULT_ADDR.to_string(),
            shutdown,
            shutdown_tx,
        }
    }

    pub fn with_addr(mut self, addr: String) -> Self {
        self.addr = addr;
        self
    }

    /// 获取关闭信号发送器
    pub fn shutdown_handle(&self) -> tokio::sync::watch::Sender<bool> {
        self.shutdown_tx.clone()
    }

    /// 启动服务器
    pub async fn run(mut self) -> anyhow::Result<()> {
        let listener = TcpListener::bind(&self.addr).await?;
        info!("守护进程 IPC 监听: {}", self.addr);

        // 写 PID 文件
        write_pid_file(&self.addr)?;

        // 启动心跳任务
        let heartbeat_handle = spawn_heartbeat_task(
            self.state.clone(),
            self.engine.clone(),
            self.shutdown.clone(),
        );

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, addr)) => {
                            debug!("客户端连接: {}", addr);
                            let state = self.state.clone();
                            let engine = self.engine.clone();
                            let shutdown_tx = self.shutdown_tx.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_client(stream, state, engine, shutdown_tx).await {
                                    error!("客户端处理错误: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("接受连接失败: {}", e);
                        }
                    }
                }
                _ = self.shutdown.changed() => {
                    info!("收到关闭信号");
                    break;
                }
            }
        }

        // 清理
        let _ = heartbeat_handle.await;
        let _ = std::fs::remove_file(pid_file_path());
        let _ = std::fs::remove_file(heartbeat_file_path());
        info!("守护进程已停止");
        Ok(())
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }
}

/// 处理单个客户端连接
async fn handle_client(
    stream: tokio::net::TcpStream,
    state: Arc<DaemonState>,
    engine: Arc<AnalysisEngine>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let request: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let err = Envelope::new("error", Response::Error {
                    code: "parse_error".to_string(),
                    message: format!("无效请求: {}", e),
                });
                writer.write_all(format!("{}\n", serde_json::to_string(&err)?).as_bytes()).await?;
                continue;
            }
        };

        let response = handle_request(request, &state, &engine, &shutdown_tx).await;
        let envelope = Envelope::new(uuid::Uuid::new_v4().to_string(), response);
        let json = serde_json::to_string(&envelope)?;
        writer.write_all(format!("{}\n", json).as_bytes()).await?;
        writer.flush().await?;
    }

    Ok(())
}

/// 处理请求
async fn handle_request(
    request: Request,
    state: &DaemonState,
    engine: &AnalysisEngine,
    shutdown_tx: &tokio::sync::watch::Sender<bool>,
) -> Response {
    match request {
        Request::Ping => Response::Pong {
            version: crate::VERSION.to_string(),
            uptime_secs: state.uptime_secs(),
        },

        Request::Status => {
            let projects = state.projects.read().await;
            let (ast_count, scan_count) = engine.cache_stats().await;
            Response::StatusInfo {
                pid: state.pid,
                uptime_secs: state.uptime_secs(),
                loaded_projects: projects.keys().cloned().collect(),
                cache_stats: CacheStats {
                    ast_cache_entries: ast_count,
                    taint_cache_entries: 0,
                    scan_cache_entries: scan_count,
                },
            }
        }

        Request::Shutdown => {
            let _ = shutdown_tx.send(true);
            Response::Ack {
                message: "shutting_down".to_string(),
            }
        },

        Request::LoadProject { path } => {
            let mut projects = state.projects.write().await;
            if projects.contains_key(&path) {
                Response::Ack { message: "already_loaded".to_string() }
            } else {
                projects.insert(path.clone(), crate::state::ProjectState::new(path.clone()));
                info!("项目已加载: {}", path);
                Response::Ack { message: "loaded".to_string() }
            }
        }

        Request::Scan { path, deep, severity_filter, pattern_filter } => {
            match engine.scan(&path, deep).await {
                Ok(output) => {
                    let mut findings = output.findings;

                    if let Some(ref sev) = severity_filter {
                        findings.retain(|f| f.severity.eq_ignore_ascii_case(sev));
                    }
                    if let Some(ref pat) = pattern_filter {
                        findings.retain(|f| f.file_path.contains(pat.as_str()));
                    }

                    Response::ScanResult {
                        findings: findings.into_iter().map(|f| serde_json::to_value(f).unwrap_or_default()).collect(),
                        duration_ms: output.duration_ms,
                        files_scanned: output.files_scanned,
                    }
                }
                Err(e) => Response::Error {
                    code: "scan_failed".to_string(),
                    message: e.to_string(),
                },
            }
        }

        Request::Analyze { file_path, start_line, end_line, show_ast, show_symbols } => {
            match engine.analyze_file(&file_path, start_line, end_line, show_ast, show_symbols) {
                Ok(content) => Response::AnalysisResult { content },
                Err(e) => Response::Error {
                    code: "analyze_failed".to_string(),
                    message: e.to_string(),
                },
            }
        }

        Request::TraceTaint { file_path } => {
            match engine.trace_taint(&file_path) {
                Ok(flows) => {
                    let flow_values: Vec<serde_json::Value> = flows.iter().map(|f| {
                        serde_json::json!({
                            "source": f.source.symbol,
                            "source_line": f.source.line,
                            "sink": f.sink.symbol,
                            "sink_line": f.sink.line,
                            "vulnerability_type": format!("{:?}", f.vulnerability_type),
                        })
                    }).collect();
                    Response::TaintResult { flows: flow_values }
                }
                Err(e) => Response::Error {
                    code: "taint_failed".to_string(),
                    message: e.to_string(),
                },
            }
        }

        Request::QuerySymbols { query, limit } => {
            // 使用第一个已加载项目的索引
            let projects = state.projects.read().await;
            let project_path = projects.keys().next().cloned().unwrap_or_default();
            drop(projects);

            if project_path.is_empty() {
                return Response::Error {
                    code: "no_project".to_string(),
                    message: "请先加载项目 (LoadProject)".to_string(),
                };
            }

            match engine.query_symbols(&project_path, &query, limit).await {
                Ok(symbols) => Response::SymbolResults { symbols },
                Err(e) => Response::Error {
                    code: "query_failed".to_string(),
                    message: e.to_string(),
                },
            }
        }

        Request::GetCallGraph { entry, depth } => {
            let projects = state.projects.read().await;
            let project_path = projects.keys().next().cloned().unwrap_or_default();
            drop(projects);

            if project_path.is_empty() {
                return Response::Error {
                    code: "no_project".to_string(),
                    message: "请先加载项目 (LoadProject)".to_string(),
                };
            }

            match engine.get_call_graph(&project_path, &entry, depth).await {
                Ok(graph) => Response::CallGraphResult { graph },
                Err(e) => Response::Error {
                    code: "callgraph_failed".to_string(),
                    message: e.to_string(),
                },
            }
        }

        Request::CrossFileAnalysis { path } => {
            match engine.cross_file_analysis(&path) {
                Ok(result) => Response::CrossFileTaintResult { result },
                Err(e) => Response::Error {
                    code: "cross_file_failed".to_string(),
                    message: e.to_string(),
                },
            }
        }

        Request::WatchStart { path, ignore_patterns: _ } => {
            // Phase 4: 守护进程内部文件监控
            Response::WatchStarted { path }
        }

        Request::WatchStop { path } => {
            Response::WatchStopped { path }
        }
    }
}

/// PID 文件路径
fn pid_file_path() -> std::path::PathBuf {
    std::path::Path::new(".ctx-audit/daemon.pid").to_path_buf()
}

/// 心跳文件路径
pub fn heartbeat_file_path() -> std::path::PathBuf {
    std::path::Path::new(".ctx-audit/heartbeat.json").to_path_buf()
}

/// 心跳默认间隔（秒）
const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 5;

/// 写入心跳文件（在 async 上下文中调用）
async fn write_heartbeat_async(state: &DaemonState, engine: &AnalysisEngine) {
    let path = heartbeat_file_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mem_stats = engine.memory_stats().await;
    let content = serde_json::json!({
        "pid": state.pid,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "version": crate::VERSION,
        "uptime_secs": state.uptime_secs(),
        "cache_stats": {
            "ast_entries": mem_stats.ast_count,
            "scan_entries": mem_stats.scan_count,
        },
        "memory": {
            "ast_engines": mem_stats.ast_count,
            "ast_estimated_bytes": mem_stats.ast_bytes,
            "scan_caches": mem_stats.scan_count,
        },
    });
    if let Err(e) = std::fs::write(&path, serde_json::to_string_pretty(&content).unwrap_or_default()) {
        debug!("心跳写入失败: {}", e);
    }
}

/// 启动心跳后台任务
pub fn spawn_heartbeat_task(
    state: Arc<DaemonState>,
    engine: Arc<AnalysisEngine>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    let heartbeat_secs = read_daemon_config_u64("heartbeat_interval_secs", DEFAULT_HEARTBEAT_INTERVAL_SECS);

    tokio::spawn(async move {
        let interval = tokio::time::Duration::from_secs(heartbeat_secs);
        let mut tick: u64 = 0;
        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {
                    write_heartbeat_async(&state, &engine).await;
                    tick += 1;
                    if tick % 12 == 0 {
                        engine.evict_idle_ast_engines();
                        engine.evict_idle_scan_caches();
                    }
                }
                _ = shutdown_rx.changed() => {
                    // 退出前写最后一次心跳（标记为 shutting_down）
                    let path = heartbeat_file_path();
                    let content = serde_json::json!({
                        "pid": state.pid,
                        "timestamp": chrono::Utc::now().to_rfc3339(),
                        "status": "shutting_down",
                    });
                    let _ = std::fs::write(&path, serde_json::to_string_pretty(&content).unwrap_or_default());
                    info!("心跳任务已停止");
                    break;
                }
            }
        }
    })
}

/// 写 PID 文件
fn write_pid_file(addr: &str) -> anyhow::Result<()> {
    let path = pid_file_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = serde_json::json!({
        "pid": std::process::id(),
        "addr": addr,
        "started_at": chrono::Utc::now().to_rfc3339(),
        "version": crate::VERSION,
    });
    std::fs::write(&path, serde_json::to_string_pretty(&content)?)?;
    Ok(())
}

/// 读取 PID 文件（供客户端检测守护进程状态）
pub fn read_pid_file() -> Option<serde_json::Value> {
    let path = pid_file_path();
    if path.exists() {
        std::fs::read_to_string(&path).ok()
            .and_then(|s| serde_json::from_str(&s).ok())
    } else {
        None
    }
}

/// 从配置文件读取 daemon.* 字段（u64 类型）
fn read_daemon_config_u64(key: &str, default: u64) -> u64 {
    dirs::config_dir()
        .map(|dir| dir.join("ctx-audit").join("config.toml"))
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|content| toml::from_str::<toml::Value>(&content).ok())
        .and_then(|val| val.get("daemon")?.get(key)?.as_integer().map(|v| v as u64))
        .unwrap_or(default)
}
