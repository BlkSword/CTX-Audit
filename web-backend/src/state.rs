use deepaudit_core::ASTEngine;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Pool, Sqlite};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AppState {
    pub ast_engine: Arc<Mutex<ASTEngine>>,
    pub db: Pool<Sqlite>,
}

impl AppState {
    pub async fn new() -> anyhow::Result<Self> {
        // 初始化 AST 引擎
        let ast_engine = ASTEngine::new(".deepaudit_cache");
        let ast_engine = Arc::new(Mutex::new(ast_engine));

        // 初始化数据库
        let db = init_db().await?;

        Ok(Self { ast_engine, db })
    }
}

async fn init_db() -> anyhow::Result<Pool<Sqlite>> {
    // 获取当前工作目录
    let current_dir = std::env::current_dir()?;
    let db_path = current_dir.join("deepaudit_web.db");

    println!("Database path: {}", db_path.display());

    // 使用 SqliteConnectOptions 来确保数据库文件可以被创建
    let options = SqliteConnectOptions::from_str(&format!("sqlite://{}", db_path.display()))?
        .create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to database: {}", e))?;

    // 创建表
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            path TEXT NOT NULL UNIQUE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER,
            finding_id TEXT UNIQUE,
            file_path TEXT,
            line_start INTEGER,
            line_end INTEGER,
            detector TEXT,
            vuln_type TEXT,
            severity TEXT,
            description TEXT,
            code_snippet TEXT,
            status TEXT DEFAULT 'new',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(project_id) REFERENCES projects(id)
        );

        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER,
            status TEXT DEFAULT 'pending',
            files_scanned INTEGER DEFAULT 0,
            findings_found INTEGER DEFAULT 0,
            started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            completed_at DATETIME,
            FOREIGN KEY(project_id) REFERENCES projects(id)
        );
        "#,
    )
    .execute(&pool)
    .await
    .map_err(|e| anyhow::anyhow!("Failed to create tables: {}", e))?;

    println!("Database initialized successfully");

    Ok(pool)
}
