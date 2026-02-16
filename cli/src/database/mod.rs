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
use sqlx::{Sqlite, Pool};
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

    // TODO: 实现数据迁移逻辑
    // 1. 连接到 Tauri 数据库
    // 2. 读取所有数据
    // 3. 写入新数据库
    // 4. 验证迁移成功

    Ok(())
}
