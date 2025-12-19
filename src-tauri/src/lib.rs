use ignore::Walk;
use rayon::prelude::*;
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use std::collections::HashMap;
use std::fs;
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_shell::process::CommandChild;
use tauri_plugin_shell::process::CommandEvent;
use tauri_plugin_shell::ShellExt;
use tokio::sync::oneshot;
use tokio::time::{timeout, Duration};
use anyhow;

pub mod ast;
mod scanner;
pub mod diff;

struct DeepAuditState {
    child: Mutex<Option<CommandChild>>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Result<String, String>>>>,
    stdout_buffer: Mutex<String>,
}

fn extract_mcp_text(value: &serde_json::Value) -> String {
    if let Some(result) = value.get("result") {
        if let Some(content) = result.get("content").and_then(|c| c.as_array()) {
            let mut out = String::new();
            for item in content {
                if let Some(text) = item.get("text").and_then(|t| t.as_str()) {
                    out.push_str(text);
                }
            }
            return out;
        }
        if let Some(text) = result.as_str() {
            return text.to_string();
        }
        return result.to_string();
    }

    value.to_string()
}

async fn handle_python_stdout(app: &AppHandle, chunk: String) {
    let state = app.state::<DeepAuditState>();
    let mut buffer = state.stdout_buffer.lock().unwrap();
    buffer.push_str(&chunk);

    loop {
        let Some(pos) = buffer.find('\n') else {
            break;
        };
        let line = buffer.drain(..=pos).collect::<String>();
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parsed: serde_json::Result<serde_json::Value> = serde_json::from_str(line);
        match parsed {
            Ok(json) => {
                if json.get("jsonrpc").and_then(|v| v.as_str()) == Some("2.0") {
                    let id = json.get("id").and_then(|v| v.as_u64());
                    if let Some(id) = id {
                        let sender = {
                            let mut pending = state.pending.lock().unwrap();
                            pending.remove(&id)
                        };

                        if let Some(sender) = sender {
                            if let Some(err) = json.get("error") {
                                let msg = err
                                    .get("message")
                                    .and_then(|m| m.as_str())
                                    .unwrap_or("MCP 调用失败");
                                let _ = sender.send(Err(msg.to_string()));
                            } else {
                                let text = extract_mcp_text(&json);
                                let _ = sender.send(Ok(text));
                            }
                            continue;
                        }
                    }
                }

                let _ = app.emit("mcp-message", line.to_string());
            }
            Err(_) => {
                let _ = app.emit("mcp-message", line.to_string());
            }
        }
    }
}

async fn init_db(app: &AppHandle) -> Result<SqlitePool, String> {
    let app_data_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    if !app_data_dir.exists() {
        fs::create_dir_all(&app_data_dir).map_err(|e| e.to_string())?;
    }
    let db_path = app_data_dir.join("deep_audit.db");

    // Create the file if it doesn't exist
    if !db_path.exists() {
        fs::File::create(&db_path).map_err(|e| e.to_string())?;
    }

    let db_url = format!("sqlite://{}", db_path.to_string_lossy());

    let pool = SqlitePoolOptions::new()
        .connect(&db_url)
        .await
        .map_err(|e| e.to_string())?;

    sqlx::query(
        "
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER,
            file_path TEXT,
            line INTEGER,
            severity TEXT,
            message TEXT,
            remediation TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(project_id) REFERENCES projects(id)
        );
    ",
    )
    .execute(&pool)
    .await
    .map_err(|e| e.to_string())?;

    Ok(pool)
}

#[tauri::command]
async fn open_project(
    app: AppHandle,
    state: State<'_, DeepAuditState>,
    pool: State<'_, SqlitePool>,
) -> Result<String, String> {
    // Open Folder Dialog
    let (tx, rx) = oneshot::channel();
    app.dialog().file().pick_folder(move |folder_path| {
        let _ = tx.send(folder_path);
    });

    let folder_path = rx.await.map_err(|e| e.to_string())?;

    let path = match folder_path {
        Some(p) => p.to_string(),
        None => return Ok("".to_string()), // Cancelled
    };

    // Save project to DB
    let _ = sqlx::query("INSERT INTO projects (path) VALUES (?)")
        .bind(&path)
        .execute(pool.inner())
        .await;

    // Start scanning in background with parallel processing
    let path_clone = path.clone();
    let app_handle_scan = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        Walk::new(&path_clone).par_bridge().for_each(|result| {
            if let Ok(entry) = result {
                if entry.file_type().map_or(false, |ft| ft.is_file()) {
                    let p = entry.path();
                    if let Ok(msg) = scanner::scan_file(p) {
                        let _ = app_handle_scan
                            .emit("mcp-message", format!("Rust Scan {}: {}", p.display(), msg));
                    }
                }
            }
        });
    });

    // Start Python Sidecar if not running
    // We lock the mutex to check if child exists
    let mut child_guard = state.child.lock().unwrap();
    if child_guard.is_none() {
        // Assume python-sidecar/agent.py is in the root of the repo
        // In dev, we are in src-tauri, so ../python-sidecar/agent.py
        let script_path = "../python-sidecar/agent.py";

        let (mut rx, child) = app
            .shell()
            .command("python")
            .args(&[script_path])
            .env("PYTHONUTF8", "1")
            .env("PYTHONIOENCODING", "utf-8")
            .spawn()
            .map_err(|e| e.to_string())?;

        *child_guard = Some(child);

        // Send Initialize sequence
        if let Some(c) = child_guard.as_mut() {
            let init_msg = "{\"jsonrpc\": \"2.0\", \"method\": \"initialize\", \"params\": {\"protocolVersion\": \"2024-11-05\", \"capabilities\": {}, \"clientInfo\": {\"name\": \"DeepAuditClient\", \"version\": \"1.0.0\"}}, \"id\": 0}\n";
            let _ = c.write(init_msg.as_bytes());

            let initialized_msg = "{\"jsonrpc\": \"2.0\", \"method\": \"notifications/initialized\", \"params\": {}}\n";
            let _ = c.write(initialized_msg.as_bytes());
        }

        // Spawn listener
        let app_handle = app.clone();
        tauri::async_runtime::spawn(async move {
            while let Some(event) = rx.recv().await {
                match event {
                    CommandEvent::Stdout(line) => {
                        let text = String::from_utf8_lossy(&line).to_string();
                        handle_python_stdout(&app_handle, text).await;
                    }
                    CommandEvent::Stderr(line) => {
                        let text = String::from_utf8_lossy(&line);
                        let _ = app_handle.emit("mcp-message", text.to_string());
                    }
                    _ => {}
                }
            }
        });
    }

    Ok(path)
}

#[tauri::command]
async fn call_mcp_tool(
    state: State<'_, DeepAuditState>,
    tool_name: String,
    arguments: String, // JSON string
) -> Result<String, String> {
    // Log tool call attempt
    println!("Calling MCP Tool: {} with args: {}", tool_name, arguments);

    let id: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX);

    let (tx, rx) = oneshot::channel::<Result<String, String>>();

    {
        let mut pending = state.pending.lock().unwrap();
        pending.insert(id, tx);
    }

    let write_result = {
        let mut child_guard = state.child.lock().unwrap();
        if let Some(child) = child_guard.as_mut() {
            let msg = format!(
                "{{\"jsonrpc\": \"2.0\", \"method\": \"tools/call\", \"params\": {{\"name\": \"{}\", \"arguments\": {}}}, \"id\": {}}}\n",
                tool_name, arguments, id
            );

            child.write(msg.as_bytes()).map_err(|e| e.to_string())
        } else {
            Err("MCP 服务器未运行".to_string())
        }
    };

    if let Err(e) = write_result {
        let mut pending = state.pending.lock().unwrap();
        pending.remove(&id);
        return Err(e);
    }

    match timeout(Duration::from_secs(120), rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err("MCP 响应通道已关闭".to_string()),
        Err(_) => {
            let mut pending = state.pending.lock().unwrap();
            pending.remove(&id);
            Err("MCP 调用超时".to_string())
        }
    }
}

#[tauri::command]
async fn read_file_content(path: String) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| e.to_string())
}

#[derive(serde::Serialize)]
struct SearchResult {
    file: String,
    line: usize,
    content: String,
}

#[tauri::command]
async fn search_files(query: String, path: String) -> Result<Vec<SearchResult>, String> {
    if query.is_empty() || path.is_empty() {
        return Ok(Vec::new());
    }

    let results = tauri::async_runtime::spawn_blocking(move || {
        let walker = ignore::WalkBuilder::new(&path).build();

        walker
            .par_bridge()
            .flat_map(|result| {
                match result {
                    Ok(entry) if entry.file_type().map_or(false, |ft| ft.is_file()) => {
                        let file_path = entry.path();
                        let query = query.as_str();

                        let mut file_results = Vec::new();
                        if let Ok(file) = fs::File::open(file_path) {
                            let reader = std::io::BufReader::new(file);
                            use std::io::BufRead;

                            for (index, line) in reader.lines().enumerate() {
                                if let Ok(content) = line {
                                    if content.contains(query) {
                                        file_results.push(SearchResult {
                                            file: file_path.to_string_lossy().to_string(),
                                            line: index + 1,
                                            content: content.trim().to_string(),
                                        });
                                        // Safety break if too many results per file
                                        if file_results.len() > 100 {
                                            break;
                                        }
                                    }
                                }
                            }
                        }

                        file_results
                    }
                    _ => Vec::new(),
                }
            })
            .collect::<Vec<_>>()
            .into_iter()
            .take(1000)
            .collect()
    })
    .await
    .map_err(|e| e.to_string())?;

    Ok(results)
}

#[tauri::command]
async fn get_mcp_status(state: State<'_, DeepAuditState>) -> Result<String, String> {
    let child = state.child.lock().unwrap();
    if child.is_some() {
        Ok("运行中".to_string())
    } else {
        Ok("已停止".to_string())
    }
}

#[tauri::command]
async fn list_mcp_tools() -> Result<Vec<String>, String> {
    Ok(vec![
        "build_ast_index".to_string(),
        "run_security_scan".to_string(),
        "get_analysis_report".to_string(),
        "find_call_sites".to_string(),
        "get_call_graph".to_string(),
        "read_file".to_string(),
        "list_files".to_string(),
        "search_files".to_string(),
        "get_code_structure".to_string(),
        "search_symbol".to_string(),
        "get_class_hierarchy".to_string(),
    ])
}

use crate::diff::{DiffEngine, GitIntegration, ComparisonConfig, ComparisonRequest, DiffViewMode};

#[tauri::command]
async fn compare_files_or_directories(
    source_a: String,
    source_b: String,
    ignore_whitespace: Option<bool>,
    ignore_case: Option<bool>,
    view_mode: Option<String>,
    context_lines: Option<u32>,
    enable_syntax_highlight: Option<bool>,
    detect_renames: Option<bool>,
    rename_similarity_threshold: Option<f32>,
) -> Result<String, String> {
    let config = ComparisonConfig {
        ignore_whitespace: ignore_whitespace.unwrap_or(false),
        ignore_case: ignore_case.unwrap_or(false),
        view_mode: match view_mode.as_deref() {
            Some("side-by-side") => DiffViewMode::SideBySide,
            Some("unified") => DiffViewMode::Unified,
            Some("compact") => DiffViewMode::Compact,
            _ => DiffViewMode::SideBySide,
        },
        context_lines: context_lines.unwrap_or(3),
        enable_syntax_highlight: enable_syntax_highlight.unwrap_or(true),
        detect_renames: detect_renames.unwrap_or(true),
        rename_similarity_threshold: rename_similarity_threshold.unwrap_or(0.8),
    };

    let request = ComparisonRequest {
        source_a,
        source_b,
        config,
        is_git_comparison: false,
        git_params: None,
    };

    let engine = DiffEngine::new(request.config.clone());
    let result = engine.compare(request)
        .map_err(|e| format!("比较失败: {}", e))?;

    serde_json::to_string(&result)
        .map_err(|e| format!("序列化结果失败: {}", e))
}

#[tauri::command]
async fn compare_git_versions(
    repository_path: String,
    left_ref: String,
    right_ref: String,
    file_paths: Option<Vec<String>>,
    ignore_whitespace: Option<bool>,
    ignore_case: Option<bool>,
    view_mode: Option<String>,
    context_lines: Option<u32>,
    enable_syntax_highlight: Option<bool>,
) -> Result<String, String> {
    let config = ComparisonConfig {
        ignore_whitespace: ignore_whitespace.unwrap_or(false),
        ignore_case: ignore_case.unwrap_or(false),
        view_mode: match view_mode.as_deref() {
            Some("side-by-side") => DiffViewMode::SideBySide,
            Some("unified") => DiffViewMode::Unified,
            Some("compact") => DiffViewMode::Compact,
            _ => DiffViewMode::SideBySide,
        },
        context_lines: context_lines.unwrap_or(3),
        enable_syntax_highlight: enable_syntax_highlight.unwrap_or(true),
        detect_renames: true,
        rename_similarity_threshold: 0.8,
    };

    let git_params = crate::diff::GitComparisonParams {
        repository_path,
        left_ref,
        right_ref,
        file_paths: file_paths.unwrap_or_default(),
    };

    let request = ComparisonRequest {
        source_a: git_params.left_ref.clone(),
        source_b: git_params.right_ref.clone(),
        config,
        is_git_comparison: true,
        git_params: Some(git_params),
    };

    let engine = DiffEngine::new(request.config.clone());
    let result = engine.compare(request)
        .map_err(|e| format!("Git比较失败: {}", e))?;

    serde_json::to_string(&result)
        .map_err(|e| format!("序列化结果失败: {}", e))
}

#[tauri::command]
async fn get_git_refs(repository_path: String) -> Result<String, String> {
    let git_integration = GitIntegration::new();
    let refs = git_integration.get_refs(&repository_path)
        .map_err(|e| format!("获取Git引用失败: {}", e))?;

    serde_json::to_string(&refs)
        .map_err(|e| format!("序列化Git引用失败: {}", e))
}

#[tauri::command]
async fn restart_mcp_server(
    app: AppHandle,
    state: State<'_, DeepAuditState>,
) -> Result<String, String> {
    let mut child_guard = state.child.lock().unwrap();

    // Kill existing Python process if running
    if let Some(child) = child_guard.take() {
        let _ = child.kill();
    }

    {
        let mut pending = state.pending.lock().unwrap();
        pending.clear();
        let mut buffer = state.stdout_buffer.lock().unwrap();
        buffer.clear();
    }

    // Start Python Sidecar
    let script_path = "../python-sidecar/agent.py";

    let (mut rx, child) = app
        .shell()
        .command("python")
        .args(&[script_path])
        .env("PYTHONUTF8", "1")
        .env("PYTHONIOENCODING", "utf-8")
        .spawn()
        .map_err(|e| e.to_string())?;

    *child_guard = Some(child);

    // Send Initialize sequence
    if let Some(c) = child_guard.as_mut() {
        let init_msg = "{\"jsonrpc\": \"2.0\", \"method\": \"initialize\", \"params\": {\"protocolVersion\": \"2024-11-05\", \"capabilities\": {}, \"clientInfo\": {\"name\": \"DeepAuditClient\", \"version\": \"1.0.0\"}}, \"id\": 0}\n";
        let _ = c.write(init_msg.as_bytes());

        let initialized_msg =
            "{\"jsonrpc\": \"2.0\", \"method\": \"notifications/initialized\", \"params\": {}}\n";
        let _ = c.write(initialized_msg.as_bytes());
    }

    // Spawn listener
    let app_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                CommandEvent::Stdout(line) => {
                    let text = String::from_utf8_lossy(&line).to_string();
                    handle_python_stdout(&app_handle, text).await;
                }
                CommandEvent::Stderr(line) => {
                    let text = String::from_utf8_lossy(&line);
                    let _ = app_handle.emit("mcp-message", text.to_string());
                }
                _ => {}
            }
        }
    });

    log::info!("Python MCP Server restarted successfully");
    Ok("Python MCP Server restarted successfully".to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .setup(|app| {
            let pool =
                tauri::async_runtime::block_on(init_db(app.handle())).expect("failed to init db");
            app.manage(pool);
            Ok(())
        })
        .manage(DeepAuditState {
            child: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            stdout_buffer: Mutex::new(String::new()),
        })
        .invoke_handler(tauri::generate_handler![
            open_project,
            read_file_content,
            search_files,
            get_mcp_status,
            list_mcp_tools,
            restart_mcp_server,
            call_mcp_tool,
            compare_files_or_directories,
            compare_git_versions,
            get_git_refs,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
