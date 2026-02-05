// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::Manager;
use tracing_subscriber::prelude::*;

mod commands;
mod models;
mod services;

use services::database::Database;
use services::llm::LLMFactory;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // 初始化日志
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ctx_audit=debug,sqlx=warn".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .setup(|app| {
            // 初始化数据库
            let app_dir = app.path().app_data_dir().expect("Failed to get app dir");
            std::fs::create_dir_all(&app_dir).expect("Failed to create app dir");
            let db_path = app_dir.join("audit.db");

            let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");
            let db = rt.block_on(Database::new(&db_path)).expect("Failed to initialize database");
            app.manage(db);

            // 初始化 LLM Factory
            let llm_factory = std::sync::Arc::new(tokio::sync::Mutex::new(LLMFactory::with_default_config()));
            app.manage(llm_factory);

            tracing::info!("CTX-Audit Desktop initialized");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Projects
            commands::project::list_projects,
            commands::project::get_project_by_id,
            commands::project::get_project_by_path,
            commands::project::create_project,
            commands::project::open_directory,
            commands::project::delete_project,
            // Files
            commands::files::read_file,
            commands::files::list_directory,
            commands::files::select_directory,
            // Scanner
            commands::scanner::run_scan,
            commands::scanner::get_findings,
            // Audit (Rust Agent Engine)
            commands::audit::start_audit,
            commands::audit::get_audit_status,
            commands::audit::pause_audit,
            commands::audit::cancel_audit,
            commands::audit::get_audit_result,
            commands::audit::get_audit_events,
            commands::audit::get_agent_tree,
            // Realtime Audit
            commands::realtime_audit::get_file_findings,
            commands::realtime_audit::update_finding_status,
            commands::realtime_audit::scan_file,
            commands::realtime_audit::get_project_stats,
            commands::realtime_audit::get_project_files,
            // Indexer
            commands::indexer::index_project,
            commands::indexer::get_file_symbols,
            commands::indexer::search_symbol,
            commands::indexer::get_call_graph,
            // LLM
            commands::llm::test_llm_connection,
            commands::llm::test_llm_config,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn main() {
    run()
}
