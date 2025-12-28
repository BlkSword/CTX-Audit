use deepaudit_core::ASTEngine;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Pool, Sqlite};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;

/// AST缓存状态跟踪
#[derive(Default)]
pub struct AstCacheState {
    pub current_project_id: Option<i64>,
    pub current_project_path: Option<String>,
    pub symbol_count: usize,
}

#[derive(Clone)]
pub struct AppState {
    pub ast_engine: Arc<Mutex<ASTEngine>>,
    pub db: Pool<Sqlite>,
    pub ast_cache_state: Arc<Mutex<AstCacheState>>,
}

impl AppState {
    pub async fn new() -> anyhow::Result<Self> {
        // 初始化 AST 引擎
        let ast_engine = ASTEngine::new(".deepaudit_cache");
        let ast_engine = Arc::new(Mutex::new(ast_engine));

        // 初始化数据库
        let db = init_db().await?;

        Ok(Self {
            ast_engine,
            db,
            ast_cache_state: Arc::new(Mutex::new(AstCacheState::default())),
        })
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

        -- AST 索引历史表
        CREATE TABLE IF NOT EXISTS ast_indices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            index_version TEXT NOT NULL,
            total_symbols INTEGER DEFAULT 0,
            total_files INTEGER DEFAULT 0,
            index_data TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(project_id) REFERENCES projects(id)
        );

        -- 符号表（支持历史查询）
        CREATE TABLE IF NOT EXISTS symbols (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            ast_index_id INTEGER NOT NULL,
            symbol_id TEXT NOT NULL,
            symbol_name TEXT NOT NULL,
            symbol_type TEXT NOT NULL,
            file_path TEXT NOT NULL,
            line_number INTEGER,
            end_line INTEGER,
            parent_name TEXT,
            metadata TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(project_id) REFERENCES projects(id),
            FOREIGN KEY(ast_index_id) REFERENCES ast_indices(id)
        );

        -- 代码图谱表
        CREATE TABLE IF NOT EXISTS code_graphs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            graph_type TEXT NOT NULL,
            entry_point TEXT,
            graph_data TEXT NOT NULL,
            node_count INTEGER DEFAULT 0,
            edge_count INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(project_id) REFERENCES projects(id)
        );

        -- 调用关系表
        CREATE TABLE IF NOT EXISTS call_relations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            graph_id INTEGER NOT NULL,
            caller_function TEXT NOT NULL,
            callee_function TEXT NOT NULL,
            file_path TEXT NOT NULL,
            line_number INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(project_id) REFERENCES projects(id),
            FOREIGN KEY(graph_id) REFERENCES code_graphs(id)
        );

        -- 创建索引以提高查询性能
        CREATE INDEX IF NOT EXISTS idx_symbols_project ON symbols(project_id);
        CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(symbol_name);
        CREATE INDEX IF NOT EXISTS idx_symbols_type ON symbols(symbol_type);
        CREATE INDEX IF NOT EXISTS idx_graphs_project ON code_graphs(project_id);
        CREATE INDEX IF NOT EXISTS idx_graphs_type ON code_graphs(graph_type);
        CREATE INDEX IF NOT EXISTS idx_calls_project ON call_relations(project_id);
        CREATE INDEX IF NOT EXISTS idx_indices_project ON ast_indices(project_id);
        "#,
    )
    .execute(&pool)
    .await
    .map_err(|e| anyhow::anyhow!("Failed to create tables: {}", e))?;

    println!("Database initialized successfully");

    Ok(pool)
}
