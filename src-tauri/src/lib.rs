use ignore::Walk;
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use std::fs;
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_shell::process::CommandChild;
use tauri_plugin_shell::process::CommandEvent;
use tauri_plugin_shell::ShellExt;

mod scanner;

struct DeepAuditState {
    child: Mutex<Option<CommandChild>>,
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
    // blocking_pick_folder returns Option<FilePath>
    let folder_path = app.dialog().file().blocking_pick_folder();

    let path = match folder_path {
        Some(p) => p.to_string(),
        None => return Ok("".to_string()), // Cancelled
    };

    // Save project to DB
    let _ = sqlx::query("INSERT INTO projects (path) VALUES (?)")
        .bind(&path)
        .execute(pool.inner())
        .await;

    // Start scanning in background
    let path_clone = path.clone();
    let app_handle_scan = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        for result in Walk::new(&path_clone) {
            if let Ok(entry) = result {
                if entry.file_type().map_or(false, |ft| ft.is_file()) {
                    let p = entry.path();
                    if let Ok(msg) = scanner::scan_file(p) {
                        let _ = app_handle_scan
                            .emit("mcp-message", format!("Rust Scan {}: {}", p.display(), msg));
                    }
                }
            }
        }
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
            .spawn()
            .map_err(|e| e.to_string())?;

        *child_guard = Some(child);

        // Spawn listener
        let app_handle = app.clone();
        tauri::async_runtime::spawn(async move {
            while let Some(event) = rx.recv().await {
                match event {
                    CommandEvent::Stdout(line) => {
                        let text = String::from_utf8_lossy(&line);
                        println!("Python Stdout: {}", text);
                        app_handle.emit("mcp-message", text.to_string()).unwrap();
                    }
                    CommandEvent::Stderr(line) => {
                        let text = String::from_utf8_lossy(&line);
                        eprintln!("Python Stderr: {}", text);
                    }
                    _ => {}
                }
            }
        });
    }

    // Send "analyze" command to Python
    if let Some(child) = child_guard.as_mut() {
        let msg = format!(
            "{{\"jsonrpc\": \"2.0\", \"method\": \"analyze\", \"params\": {{\"path\": \"{}\"}}}}\n",
            path.replace("\\", "\\\\")
        );
        child.write(msg.as_bytes()).map_err(|e| e.to_string())?;
    }

    Ok(path)
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
        let mut results = Vec::new();
        let walker = ignore::WalkBuilder::new(&path).build();

        for result in walker {
            match result {
                Ok(entry) => {
                    if entry.file_type().map_or(false, |ft| ft.is_file()) {
                        let file_path = entry.path();
                        if let Ok(file) = fs::File::open(file_path) {
                            let reader = std::io::BufReader::new(file);
                            use std::io::BufRead;

                            for (index, line) in reader.lines().enumerate() {
                                if let Ok(content) = line {
                                    if content.contains(&query) {
                                        results.push(SearchResult {
                                            file: file_path.to_string_lossy().to_string(),
                                            line: index + 1,
                                            content: content.trim().to_string(),
                                        });
                                        // Safety break if too many results
                                        if results.len() > 1000 {
                                            return results;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Err(_) => {}
            }
        }
        results
    })
    .await
    .map_err(|e| e.to_string())?;

    Ok(results)
}

#[tauri::command]
async fn get_mcp_status(state: State<'_, DeepAuditState>) -> Result<String, String> {
    let child = state.child.lock().unwrap();
    if child.is_some() {
        Ok("Running".to_string())
    } else {
        Ok("Stopped".to_string())
    }
}

#[tauri::command]
async fn list_mcp_tools() -> Result<Vec<String>, String> {
    Ok(vec![
        "analyze_project".to_string(),
        "explain_vulnerability".to_string(),
        "read_file".to_string(),
        "search_files".to_string(),
    ])
}

#[tauri::command]
async fn restart_mcp_server(state: State<'_, DeepAuditState>) -> Result<String, String> {
    let mut child_guard = state.child.lock().unwrap();
    if let Some(child) = child_guard.take() {
        let _ = child.kill();
    }
    Ok(
        "MCP Server Stopped. It will auto-restart on next project action.http://127.0.0.1:8765"
            .to_string(),
    )
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
        })
        .invoke_handler(tauri::generate_handler![
            open_project,
            read_file_content,
            search_files,
            get_mcp_status,
            list_mcp_tools,
            restart_mcp_server
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
