// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! IPC 服务器
//!
//! Named Pipe (Windows) / Unix Socket (Unix) 服务端

use std::collections::HashMap;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::engine::AnalysisEngine;
use crate::protocol::{CacheStats, Envelope, Request, RequestCommand, Response};
use crate::state::DaemonState;
use deepaudit_core::watcher::{FileWatcher, WatcherConfig};

/// IPC 服务器默认端口（用 TCP loopback 替代 Named Pipe，跨平台统一）
const DEFAULT_ADDR: &str = "127.0.0.1:19527";

/// 活跃的文件监控器: project_path → cancel_tx
type WatcherHandle = tokio::sync::watch::Sender<bool>;

/// IPC 服务器
pub struct Server {
    state: Arc<DaemonState>,
    engine: Arc<AnalysisEngine>,
    addr: String,
    auth_token: String,
    shutdown: tokio::sync::watch::Receiver<bool>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    /// 活跃的文件监控器
    watchers: Arc<RwLock<HashMap<String, WatcherHandle>>>,
}

impl Server {
    pub fn new(state: Arc<DaemonState>, engine: Arc<AnalysisEngine>) -> Self {
        let (shutdown_tx, shutdown) = tokio::sync::watch::channel(false);
        let auth_token = uuid::Uuid::new_v4().to_string();
        Self {
            state,
            engine,
            addr: DEFAULT_ADDR.to_string(),
            auth_token,
            shutdown,
            shutdown_tx,
            watchers: Arc::new(RwLock::new(HashMap::new())),
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

        // 写 PID 文件和认证令牌
        write_pid_file(&self.addr)?;
        write_token_file(&self.auth_token)?;
        info!("认证令牌已写入: {}", token_file_path().display());

        // 启动心跳任务
        let heartbeat_handle = spawn_heartbeat_task(
            self.state.clone(),
            self.engine.clone(),
            self.shutdown.clone(),
        );

        let auth_token = Arc::new(self.auth_token.clone());
        let watchers = self.watchers.clone();

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, addr)) => {
                            debug!("客户端连接: {}", addr);
                            let state = self.state.clone();
                            let engine = self.engine.clone();
                            let shutdown_tx = self.shutdown_tx.clone();
                            let auth = auth_token.clone();
                            let watchers = watchers.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_client(stream, state, engine, shutdown_tx, &auth, watchers).await {
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

        // 停止所有文件监控器
        let active_watchers = self.watchers.read().await;
        for (path, cancel_tx) in active_watchers.iter() {
            let _ = cancel_tx.send(true);
            info!("已停止文件监控: {}", path);
        }

        // 清理
        let _ = heartbeat_handle.await;
        let _ = std::fs::remove_file(pid_file_path());
        let _ = std::fs::remove_file(heartbeat_file_path());
        let _ = std::fs::remove_file(token_file_path());
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
    auth_token: &str,
    watchers: Arc<RwLock<HashMap<String, WatcherHandle>>>,
) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let request: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let err = Envelope::new(
                    "error",
                    Response::Error {
                        code: "parse_error".to_string(),
                        message: format!("无效请求: {}", e),
                    },
                );
                writer
                    .write_all(format!("{}\n", serde_json::to_string(&err)?).as_bytes())
                    .await?;
                continue;
            }
        };

        // 认证检查（Ping 除外）
        if !matches!(request.command, RequestCommand::Ping) {
            if !validate_token(&request, auth_token) {
                let err = Envelope::new(
                    "error",
                    Response::Error {
                        code: "unauthorized".to_string(),
                        message: "认证失败: 无效或缺失 auth_token".to_string(),
                    },
                );
                writer
                    .write_all(format!("{}\n", serde_json::to_string(&err)?).as_bytes())
                    .await?;
                continue;
            }
        }

        let response = handle_request(
            request.command,
            &state,
            &engine,
            &shutdown_tx,
            watchers.clone(),
        )
        .await;
        let envelope = Envelope::new(uuid::Uuid::new_v4().to_string(), response);
        let json = serde_json::to_string(&envelope)?;
        writer.write_all(format!("{}\n", json).as_bytes()).await?;
        writer.flush().await?;
    }

    Ok(())
}

/// 验证认证令牌
fn validate_token(request: &Request, expected: &str) -> bool {
    match &request.auth_token {
        Some(token) if token == expected => true,
        _ => {
            warn!("认证失败: 令牌不匹配或缺失");
            false
        }
    }
}

/// 处理请求
async fn handle_request(
    command: RequestCommand,
    state: &DaemonState,
    engine: &Arc<AnalysisEngine>,
    shutdown_tx: &tokio::sync::watch::Sender<bool>,
    watchers: Arc<RwLock<HashMap<String, WatcherHandle>>>,
) -> Response {
    match command {
        RequestCommand::Ping => Response::Pong {
            version: crate::VERSION.to_string(),
            uptime_secs: state.uptime_secs(),
        },

        RequestCommand::Status => {
            let projects = state.projects.read().await;
            let (ast_count, scan_count) = engine.cache_stats().await;
            let watcher_count = watchers.read().await.len();
            Response::StatusInfo {
                pid: state.pid,
                uptime_secs: state.uptime_secs(),
                loaded_projects: projects.keys().cloned().collect(),
                cache_stats: CacheStats {
                    ast_cache_entries: ast_count,
                    taint_cache_entries: engine.taint_cache_count().await,
                    scan_cache_entries: scan_count + watcher_count,
                },
            }
        }

        RequestCommand::Shutdown => {
            let _ = shutdown_tx.send(true);
            Response::Ack {
                message: "shutting_down".to_string(),
            }
        }

        RequestCommand::LoadProject { path } => {
            let mut projects = state.projects.write().await;
            if projects.contains_key(&path) {
                Response::Ack {
                    message: "already_loaded".to_string(),
                }
            } else {
                projects.insert(path.clone(), crate::state::ProjectState::new(path.clone()));
                info!("项目已加载: {}", path);
                // 后台触发 AST 索引（不阻塞响应）
                let eng = Arc::clone(engine);
                let path_clone = path.clone();
                tokio::spawn(async move {
                    if let Err(e) = eng.ensure_indexed(&path_clone).await {
                        warn!("项目预索引失败: {} — {}", path_clone, e);
                    }
                });
                Response::Ack {
                    message: "loaded".to_string(),
                }
            }
        }

        RequestCommand::Scan {
            path,
            deep,
            enable_taint,
            enable_cross_file,
            severity_filter,
            pattern_filter,
        } => {
            let eff_taint = enable_taint || deep || enable_cross_file;
            let eff_cross_file = enable_cross_file || deep;
            match engine.scan(&path, eff_taint, eff_cross_file).await {
                Ok(output) => {
                    let mut findings = output.findings;

                    if let Some(ref sev) = severity_filter {
                        findings.retain(|f| f.severity.eq_ignore_ascii_case(sev));
                    }
                    if let Some(ref pat) = pattern_filter {
                        findings.retain(|f| f.file_path.contains(pat.as_str()));
                    }

                    Response::ScanResult {
                        findings: findings
                            .into_iter()
                            .map(|f| serde_json::to_value(f).unwrap_or_default())
                            .collect(),
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

        RequestCommand::Analyze {
            file_path,
            start_line,
            end_line,
            show_ast,
            show_symbols,
        } => match engine.analyze_file(&file_path, start_line, end_line, show_ast, show_symbols) {
            Ok(content) => Response::AnalysisResult { content },
            Err(e) => Response::Error {
                code: "analyze_failed".to_string(),
                message: e.to_string(),
            },
        },

        RequestCommand::TraceTaint { file_path } => match engine.trace_taint(&file_path) {
            Ok(flows) => {
                let flow_values: Vec<serde_json::Value> = flows
                    .iter()
                    .map(|f| {
                        serde_json::json!({
                            "source": f.source.symbol,
                            "source_line": f.source.line,
                            "sink": f.sink.symbol,
                            "sink_line": f.sink.line,
                            "vulnerability_type": format!("{:?}", f.vulnerability_type),
                        })
                    })
                    .collect();
                Response::TaintResult { flows: flow_values }
            }
            Err(e) => Response::Error {
                code: "taint_failed".to_string(),
                message: e.to_string(),
            },
        },

        RequestCommand::QuerySymbols { query, limit } => {
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

        RequestCommand::GetCallGraph { entry, depth } => {
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

        RequestCommand::CrossFileAnalysis { path } => match engine.cross_file_analysis(&path) {
            Ok(result) => Response::CrossFileTaintResult { result },
            Err(e) => Response::Error {
                code: "cross_file_failed".to_string(),
                message: e.to_string(),
            },
        },

        RequestCommand::WatchStart {
            path,
            ignore_patterns,
        } => {
            // 检查是否已有监控
            {
                let active = watchers.read().await;
                if active.contains_key(&path) {
                    return Response::WatchStarted { path };
                }
            }

            let watcher_config = WatcherConfig {
                project_path: path.clone(),
                sarif_output_path: format!(".ctx-audit/{}.sarif", sanitize_project_name(&path)),
                ignore_patterns: if ignore_patterns.is_empty() {
                    vec![
                        "node_modules".into(),
                        ".git".into(),
                        "target".into(),
                        "build".into(),
                        "dist".into(),
                        "__pycache__".into(),
                        ".next".into(),
                        "vendor".into(),
                    ]
                } else {
                    ignore_patterns
                },
                debounce_ms: 2000,
                severity_filter: None,
            };

            let (cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(false);
            let path_clone = path.clone();

            // 后台监控循环
            let _handle = tokio::spawn(async move {
                let mut watcher = FileWatcher::new(watcher_config);
                match watcher.initial_scan() {
                    Ok(delta) => {
                        info!(
                            "[文件监控] {}: 初始扫描完成, {} 个文件",
                            path_clone, delta.total_files
                        );
                    }
                    Err(e) => {
                        warn!("[文件监控] {}: 初始扫描失败: {}", path_clone, e);
                    }
                }

                let poll_interval = tokio::time::Duration::from_secs(2);
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(poll_interval) => {
                            match watcher.detect_changes() {
                                Ok(delta) if delta.has_changes() => {
                                    let result = watcher.incremental_scan(&delta);
                                    if !result.findings.is_empty() {
                                        info!(
                                            "[文件监控] {}: 发现 {} 个新漏洞 (扫描 {} 个文件, {}ms)",
                                            path_clone, result.findings.len(),
                                            result.scanned_files, result.duration_ms
                                        );
                                    }
                                    let _ = watcher.initial_scan();
                                }
                                Ok(_) => {}
                                Err(e) => {
                                    warn!("[文件监控] 变更检测失败: {} — {}", path_clone, e);
                                }
                            }
                        }
                        _ = cancel_rx.changed() => {
                            info!("[文件监控] {}: 收到停止信号", path_clone);
                            break;
                        }
                    }
                }
            });

            let mut active = watchers.write().await;
            active.insert(path.clone(), cancel_tx);

            info!("文件监控已启动: {}", path);
            Response::WatchStarted { path }
        }

        RequestCommand::WatchStop { path } => {
            let mut active = watchers.write().await;
            if let Some(cancel_tx) = active.remove(&path) {
                let _ = cancel_tx.send(true);
                info!("文件监控已停止: {}", path);
                Response::WatchStopped { path }
            } else {
                Response::Error {
                    code: "not_watching".to_string(),
                    message: format!("未对路径 '{}' 进行监控", path),
                }
            }
        }

        // ── 调用图查询命令 ──────────────────────────
        RequestCommand::QueryCallers {
            project_path,
            file_path,
            function_name,
            recursive,
        } => {
            match engine.graph_query_callers(
                &project_path,
                &file_path,
                &function_name,
                recursive.unwrap_or(false),
            ) {
                Ok(result) => Response::GraphQueryResult { result },
                Err(e) => Response::Error {
                    code: "graph_query_failed".into(),
                    message: e.to_string(),
                },
            }
        }

        RequestCommand::QueryCallees {
            project_path,
            file_path,
            function_name,
            recursive,
        } => {
            match engine.graph_query_callees(
                &project_path,
                &file_path,
                &function_name,
                recursive.unwrap_or(false),
            ) {
                Ok(result) => Response::GraphQueryResult { result },
                Err(e) => Response::Error {
                    code: "graph_query_failed".into(),
                    message: e.to_string(),
                },
            }
        }

        RequestCommand::FindCallPath {
            project_path,
            source_file,
            source_function,
            sink_file,
            sink_function,
        } => {
            match engine.graph_find_call_path(
                &project_path,
                &source_file,
                &source_function,
                &sink_file,
                &sink_function,
            ) {
                Ok(result) => Response::GraphQueryResult { result },
                Err(e) => Response::Error {
                    code: "graph_query_failed".into(),
                    message: e.to_string(),
                },
            }
        }

        RequestCommand::GetGraphStats { project_path } => {
            match engine.graph_get_stats(&project_path) {
                Ok(result) => Response::GraphQueryResult { result },
                Err(e) => Response::Error {
                    code: "graph_query_failed".into(),
                    message: e.to_string(),
                },
            }
        }

        RequestCommand::ListFileFunctions {
            project_path,
            file_path,
        } => match engine.graph_list_functions(&project_path, &file_path) {
            Ok(result) => Response::GraphQueryResult { result },
            Err(e) => Response::Error {
                code: "graph_query_failed".into(),
                message: e.to_string(),
            },
        },

        RequestCommand::TraceVariableFlow {
            project_path,
            file_path,
            function_name,
        } => match engine.graph_trace_flow(&project_path, &file_path, &function_name) {
            Ok(result) => Response::GraphQueryResult { result },
            Err(e) => Response::Error {
                code: "graph_query_failed".into(),
                message: e.to_string(),
            },
        },
    }
}

/// 将项目路径转为安全的文件名
fn sanitize_project_name(path: &str) -> String {
    path.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string()
}

/// 令牌文件路径
fn token_file_path() -> std::path::PathBuf {
    std::path::Path::new(".ctx-audit/daemon.token").to_path_buf()
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

/// 写入认证令牌文件
fn write_token_file(token: &str) -> anyhow::Result<()> {
    let path = token_file_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // 仅 owner 可读写
    std::fs::write(&path, token)?;
    Ok(())
}

/// 读取认证令牌文件（供客户端使用）
pub fn read_token_file() -> Option<String> {
    let path = token_file_path();
    if path.exists() {
        std::fs::read_to_string(&path)
            .ok()
            .map(|s| s.trim().to_string())
    } else {
        None
    }
}

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
    if let Err(e) = std::fs::write(
        &path,
        serde_json::to_string_pretty(&content).unwrap_or_default(),
    ) {
        debug!("心跳写入失败: {}", e);
    }
}

/// 启动心跳后台任务
pub fn spawn_heartbeat_task(
    state: Arc<DaemonState>,
    engine: Arc<AnalysisEngine>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    let heartbeat_secs =
        read_daemon_config_u64("heartbeat_interval_secs", DEFAULT_HEARTBEAT_INTERVAL_SECS);

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
        std::fs::read_to_string(&path)
            .ok()
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
