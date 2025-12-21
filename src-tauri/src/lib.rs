use crate::scanners::Finding;
use ignore::Walk;
use rayon::prelude::*;
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use std::fs;
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;
use tokio::sync::oneshot;

pub mod ast;
pub mod diff;
pub mod mcp;
pub mod rules;
mod scanner;
pub mod scanners;

use mcp::service::{call_tool, start_mcp_server};
use mcp::McpState;
use rules::loader::load_rules_from_dir;
use rules::model::Rule;
use rules::scanner::RuleScanner;
use scanners::{manager::ScannerManager, regex_scanner::RegexScanner};

struct DeepAuditState {
    mcp: Arc<McpState>,
    scanner_manager: Arc<ScannerManager>,
    rules: Arc<Vec<Rule>>,
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
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER,
            finding_id TEXT UNIQUE, -- UUID
            file_path TEXT,
            line_start INTEGER,
            line_end INTEGER,
            detector TEXT, -- e.g., 'semgrep', 'llm'
            vuln_type TEXT, -- CWE
            severity TEXT, -- High, Medium, Low
            description TEXT,
            analysis_trail TEXT, -- JSON
            llm_output TEXT,
            status TEXT DEFAULT 'new', -- new, confirmed, fixed, ignored
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
    let result = sqlx::query("INSERT INTO projects (path) VALUES (?)")
        .bind(&path)
        .execute(pool.inner())
        .await
        .map_err(|e| e.to_string())?;

    let project_id = result.last_insert_rowid();

    // Start scanning in background with parallel processing
    let path_clone = path.clone();
    let app_handle_scan = app.clone();
    let scanner_manager = state.scanner_manager.clone();
    let db_pool = pool.inner().clone();

    tauri::async_runtime::spawn(async move {
        let (tx_findings, mut rx_findings) = tokio::sync::mpsc::channel::<Vec<Finding>>(100);

        // Spawn the CPU-bound walking/scanning in a separate blocking thread
        let scanner_manager_inner = scanner_manager.clone();
        let app_handle_scan_file = app_handle_scan.clone();
        tauri::async_runtime::spawn_blocking(move || {
            Walk::new(&path_clone).par_bridge().for_each(|result| {
                if let Ok(entry) = result {
                    if entry.file_type().map_or(false, |ft| ft.is_file()) {
                        let p = entry.path();

                        // Notify frontend about the file immediately for tree construction
                        let _ = app_handle_scan_file
                            .emit("file-found", p.to_string_lossy().to_string());

                        if let Ok(content) = fs::read_to_string(p) {
                            // Run scanners
                            let findings = tauri::async_runtime::block_on(async {
                                scanner_manager_inner
                                    .scan_file(&p.to_path_buf(), &content)
                                    .await
                            });

                            if !findings.is_empty() {
                                let _ = tx_findings.blocking_send(findings);
                            }
                        }
                    }
                }
            });
        });

        // Consume findings and save to DB
        while let Some(findings) = rx_findings.recv().await {
            for finding in findings {
                let _ = sqlx::query(
                    "INSERT INTO findings (project_id, finding_id, file_path, line_start, line_end, detector, vuln_type, severity, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
                )
                .bind(project_id)
                .bind(&finding.finding_id)
                .bind(&finding.file_path)
                .bind(finding.line_start as i64)
                .bind(finding.line_end as i64)
                .bind(&finding.detector)
                .bind(&finding.vuln_type)
                .bind(&finding.severity)
                .bind(&finding.description)
                .execute(&db_pool)
                .await;

                let _ = app_handle_scan.emit("scan-finding", &finding);
            }
        }
        let _ = app_handle_scan.emit("scan-complete", ());
    });

    // Start Python Sidecar if not running
    let _ = start_mcp_server(&app, state.mcp.clone()).await;

    Ok(path)
}

#[tauri::command]
async fn call_mcp_tool(
    app: AppHandle,
    state: State<'_, DeepAuditState>,
    tool_name: String,
    arguments: String, // JSON string
) -> Result<String, String> {
    if tool_name == "run_local_scan" {
        let args: serde_json::Value =
            serde_json::from_str(&arguments).map_err(|e| e.to_string())?;
        let directory = args
            .get("directory")
            .and_then(|v| v.as_str())
            .unwrap_or(".");
        let path = directory.to_string();

        let scanner_manager = state.scanner_manager.clone();
        let findings = scanner_manager.scan_directory(&path).await;

        for finding in &findings {
            let _ = app.emit("scan-finding", finding);
        }

        return serde_json::to_string(&findings).map_err(|e| e.to_string());
    }

    call_tool(&state.mcp, tool_name, arguments).await
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
    let child = state.mcp.child.lock().unwrap();
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

use crate::diff::{ComparisonConfig, ComparisonRequest, DiffEngine, DiffViewMode, GitIntegration};

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
    let result = engine
        .compare(request)
        .map_err(|e| format!("比较失败: {}", e))?;

    serde_json::to_string(&result).map_err(|e| format!("序列化结果失败: {}", e))
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
    let result = engine
        .compare(request)
        .map_err(|e| format!("Git比较失败: {}", e))?;

    serde_json::to_string(&result).map_err(|e| format!("序列化结果失败: {}", e))
}

#[tauri::command]
async fn get_git_refs(repository_path: String) -> Result<String, String> {
    let git_integration = GitIntegration::new();
    let refs = git_integration
        .get_refs(&repository_path)
        .map_err(|e| format!("获取Git引用失败: {}", e))?;

    serde_json::to_string(&refs).map_err(|e| format!("序列化Git引用失败: {}", e))
}

#[tauri::command]
async fn restart_mcp_server(
    app: AppHandle,
    state: State<'_, DeepAuditState>,
) -> Result<String, String> {
    {
        let mut child_guard = state.mcp.child.lock().unwrap();

        // Kill existing Python process if running
        if let Some(child) = child_guard.take() {
            let _ = child.kill();
        }
    } // child_guard is dropped here

    {
        let mut pending = state.mcp.pending.lock().unwrap();
        pending.clear();
        let mut buffer = state.mcp.stdout_buffer.lock().unwrap();
        buffer.clear();
    }

    // Start Python Sidecar
    start_mcp_server(&app, state.mcp.clone()).await?;

    let msg = format!(
        "Python MCP Server restarted successfully. Interface: http://localhost:{}/sse",
        crate::mcp::MCP_PORT
    );
    log::info!("{}", msg);
    Ok(msg)
}

#[tauri::command]
async fn get_loaded_rules(state: State<'_, DeepAuditState>) -> Result<Vec<Rule>, String> {
    Ok(state.rules.as_ref().clone())
}

#[tauri::command]
async fn save_rule(rule: Rule) -> Result<String, String> {
    if rule.id.is_empty() {
        return Err("Rule ID cannot be empty".to_string());
    }

    // Try to find the rules directory
    let possible_paths = vec!["../rules", "rules", "../../rules"];

    let mut rules_dir = std::path::PathBuf::from("rules");
    let mut found = false;

    for path in possible_paths {
        let p = std::path::PathBuf::from(path);
        if p.exists() && p.is_dir() {
            rules_dir = p;
            found = true;
            break;
        }
    }

    if !found {
        // If not found, try to create "rules" in current directory
        if let Err(e) = std::fs::create_dir_all(&rules_dir) {
            return Err(format!("Failed to create rules directory: {}", e));
        }
    }

    let file_path = rules_dir.join(format!("{}.yaml", rule.id));

    let yaml = serde_yaml::to_string(&rule).map_err(|e| e.to_string())?;

    std::fs::write(&file_path, yaml).map_err(|e| e.to_string())?;

    Ok(format!("Rule saved to {}", file_path.display()))
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
        .manage({
            let mcp = Arc::new(McpState::new());

            // Load rules
            // Try multiple paths for robustness (dev vs prod)
            let possible_paths = vec![
                "../rules",
                "rules",
                "../../rules", // Just in case
            ];

            let mut loaded_rules = Vec::new();
            for path in possible_paths {
                if let Ok(rules) = load_rules_from_dir(path) {
                    if !rules.is_empty() {
                        log::info!("Loaded {} rules from {}", rules.len(), path);
                        loaded_rules.extend(rules);
                        break; // Stop after finding first valid rule set
                    }
                }
            }

            let mut manager = ScannerManager::new();
            manager.register_scanner(RegexScanner::new());

            if !loaded_rules.is_empty() {
                manager.register_scanner(RuleScanner::new(loaded_rules.clone()));
            } else {
                log::warn!("No rules loaded.");
            }

            DeepAuditState {
                mcp,
                scanner_manager: Arc::new(manager),
                rules: Arc::new(loaded_rules),
            }
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
            get_loaded_rules,
            save_rule,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
