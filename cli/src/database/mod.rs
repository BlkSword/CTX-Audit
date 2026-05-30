// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 数据库模块
//!
//! 提供 SQLite 数据库连接、表创建、迁移工具

mod models;
mod schema;
mod migrations;
mod queries;

pub use models::{Finding, FindingStatus, Severity, AuditStatus, UpdateFinding, DbConversation, DbConversationMessage, CreateConversation, CreateConversationMessage, CreateProject, CreateFinding};
pub use schema::*;
pub use migrations::*;
pub use queries::*;

use anyhow::{Context, Result};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use sqlx::{Sqlite, Pool, Row};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tracing::{debug, info};

/// 数据库管理器
pub struct Database {
    pool: Pool<Sqlite>,
    path: PathBuf,
}

impl Database {
    /// 创建新的数据库实例
    pub async fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();

        // 确保父目录存在
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("Failed to create database directory: {:?}", parent))?;
        }

        // 配置 SQLite 连接选项
        let options = SqliteConnectOptions::from_str(path.to_str().unwrap())?
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal);

        // 创建连接池
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await
            .with_context(|| format!("Failed to connect to database: {:?}", path))?;

        info!("Database connected: {:?}", path);

        Ok(Self { pool, path: path.to_path_buf() })
    }

    /// 创建一个内存数据库占位符（用于测试或临时场景）
    pub async fn new_in_memory() -> Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await?;

        Ok(Self {
            pool,
            path: PathBuf::from(":memory:"),
        })
    }

    /// 获取默认数据库路径
    pub fn default_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| anyhow::anyhow!("Failed to get config directory"))?;

        let ctx_audit_dir = config_dir.join("ctx-audit");
        Ok(ctx_audit_dir.join("audit.db"))
    }

    /// 使用默认路径创建数据库
    pub async fn with_default_path() -> Result<Self> {
        let path = Self::default_path()?;
        Self::new(path).await
    }

    /// 初始化数据库（创建表）
    pub async fn initialize(&self) -> Result<()> {
        debug!("Initializing database schema");

        // 创建所有表
        sqlx::query(include_str!("schema/projects.sql"))
            .execute(&self.pool)
            .await?;

        sqlx::query(include_str!("schema/audit_sessions.sql"))
            .execute(&self.pool)
            .await?;

        sqlx::query(include_str!("schema/findings.sql"))
            .execute(&self.pool)
            .await?;

        sqlx::query(include_str!("schema/agent_events.sql"))
            .execute(&self.pool)
            .await?;

        sqlx::query(include_str!("schema/project_files.sql"))
            .execute(&self.pool)
            .await?;

        sqlx::query(include_str!("schema/symbols.sql"))
            .execute(&self.pool)
            .await?;

        sqlx::query(include_str!("schema/conversations.sql"))
            .execute(&self.pool)
            .await?;

        info!("Database schema initialized");

        // 运行迁移
        self.run_migrations().await?;

        Ok(())
    }

    /// 运行数据库迁移
    pub async fn run_migrations(&self) -> Result<()> {
        run_migrations(&self.pool).await
    }

    /// 获取连接池
    pub fn pool(&self) -> &Pool<Sqlite> {
        &self.pool
    }

    /// 获取数据库路径
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 关闭数据库连接
    pub async fn close(&self) {
        self.pool.close().await;
    }
}

/// 从 Tauri 数据库迁移
pub async fn migrate_from_tauri() -> Result<()> {
    let tauri_config_dir = dirs::config_dir()
        .ok_or_else(|| anyhow::anyhow!("Failed to get config directory"))?
        .join("com.ctx-audit.desktop");

    let tauri_db_path = tauri_config_dir.join("audit.db");

    if !tauri_db_path.exists() {
        info!("No Tauri database found at {:?}", tauri_db_path);
        return Ok(());
    }

    info!("Found Tauri database at {:?}", tauri_db_path);

    // 连接到 Tauri 数据库
    let tauri_options = SqliteConnectOptions::from_str(
        tauri_db_path.to_str().unwrap(),
    )?
    .read_only(true);

    let tauri_pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(tauri_options)
        .await
        .context("Failed to connect to Tauri database")?;

    // 读取 audits 数据
    let audit_rows = sqlx::query(
        "SELECT id, project_id, status, severity, created_at FROM audits",
    )
    .fetch_all(&tauri_pool)
    .await
    .unwrap_or_default();

    info!("Migrating {} audit records from Tauri", audit_rows.len());

    // 读取 settings
    let setting_rows = sqlx::query(
        "SELECT key, value FROM settings",
    )
    .fetch_all(&tauri_pool)
    .await
    .unwrap_or_default();

    // 写入新数据库（使用默认路径）
    let db = Database::with_default_path().await?;
    db.initialize().await?;

    for row in &audit_rows {
        let id: String = row.get("id");
        let project_id: Option<String> = row.get("project_id");
        let status: String = row.try_get::<String, _>("status").unwrap_or_default();
        let created_at: String = row.try_get::<String, _>("created_at").unwrap_or_default();

        let _ = sqlx::query(
            "INSERT OR IGNORE INTO audit_sessions (id, project_id, status, created_at)
             VALUES (?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&project_id)
        .bind(&status)
        .bind(&created_at)
        .execute(db.pool())
        .await;
    }

    // 迁移 settings
    for row in &setting_rows {
        let key: String = row.get("key");
        let value: String = row.get("value");

        let _ = sqlx::query(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
        )
        .bind(&key)
        .bind(&value)
        .execute(db.pool())
        .await;
    }

    tauri_pool.close().await;
    db.close().await;

    info!(
        "Migration complete: {} audits, {} settings",
        audit_rows.len(),
        setting_rows.len()
    );

    Ok(())
}
