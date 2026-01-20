// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

use crate::commands::{Finding, Project};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Pool, Sqlite};
use std::path::Path;
use std::str::FromStr;

/// 数据库服务
pub struct Database {
    pool: Pool<Sqlite>,
}

impl Database {
    /// 创建新的数据库实例
    pub async fn new<P: AsRef<Path>>(path: P) -> Result<Self, sqlx::Error> {
        let db_path = path.as_ref();

        // 确保父目录存在
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        // 使用 SqliteConnectOptions 来确保数据库文件可以被创建
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", db_path.display()))?
            .create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;

        // 创建表
        init_tables(&pool).await?;

        Ok(Self { pool })
    }

    /// 列出所有项目
    pub async fn list_projects(&self) -> Result<Vec<Project>, sqlx::Error> {
        sqlx::query_as::<_, Project>(
            r#"
            SELECT id, uuid, name, path, datetime(created_at) as created_at
            FROM projects
            ORDER BY created_at DESC
            "#
        )
        .fetch_all(&self.pool)
        .await
    }

    /// 创建项目
    pub async fn create_project(
        &self,
        uuid: &str,
        name: &str,
        path: &str,
    ) -> Result<Project, sqlx::Error> {
        let result = sqlx::query(
            "INSERT INTO projects (uuid, name, path) VALUES (?, ?, ?)"
        )
        .bind(uuid)
        .bind(name)
        .bind(path)
        .execute(&self.pool)
        .await?;

        let id = result.last_insert_rowid();
        self.get_project_by_id(id).await
    }

    /// 获取项目
    pub async fn get_project_by_id(&self, id: i64) -> Result<Project, sqlx::Error> {
        sqlx::query_as::<_, Project>(
            r#"
            SELECT id, uuid, name, path, datetime(created_at) as created_at
            FROM projects
            WHERE id = ?
            "#
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await
    }

    /// 删除项目
    pub async fn delete_project(&self, uuid: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM projects WHERE uuid = ?")
            .bind(uuid)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// 创建扫描记录
    pub async fn create_scan(&self, project_id: i64) -> Result<i64, sqlx::Error> {
        let result = sqlx::query(
            "INSERT INTO scans (project_id, status, files_scanned, findings_found) VALUES (?, 'pending', 0, 0)"
        )
        .bind(project_id)
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    /// 更新扫描记录
    pub async fn update_scan(
        &self,
        scan_id: i64,
        status: &str,
        files_scanned: usize,
        findings_found: usize,
    ) -> Result<(), sqlx::Error> {
        let files = files_scanned as i64;
        let findings = findings_found as i64;

        sqlx::query(
            "UPDATE scans SET status = ?, files_scanned = ?, findings_found = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?"
        )
        .bind(status)
        .bind(files)
        .bind(findings)
        .bind(scan_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// 保存发现结果
    pub async fn save_finding(&self, scan_id: i64, finding: &Finding) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO findings (scan_id, finding_id, file_path, line_start, line_end, detector, vuln_type, severity, description, code_snippet, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(scan_id)
        .bind(&finding.id)
        .bind(&finding.file_path)
        .bind(finding.line_start as i64)
        .bind(finding.line_end as i64)
        .bind(&finding.detector)
        .bind(&finding.vuln_type)
        .bind(&finding.severity)
        .bind(&finding.description)
        .bind(&finding.code_snippet)
        .bind(&finding.status)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// 获取发现结果
    pub async fn get_findings(&self, project_id: i64) -> Result<Vec<Finding>, sqlx::Error> {
        sqlx::query_as::<_, Finding>(
            r#"
            SELECT id, file_path, line_start, line_end, detector, vuln_type, severity, description, code_snippet, status, datetime(created_at) as created_at
            FROM findings
            WHERE project_id = ?
            ORDER BY created_at DESC
            "#
        )
        .bind(project_id)
        .fetch_all(&self.pool)
        .await
    }
}

/// 初始化数据库表
async fn init_tables(pool: &Pool<Sqlite>) -> Result<(), sqlx::Error> {
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
            scan_id INTEGER,
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
            FOREIGN KEY(scan_id) REFERENCES scans(id),
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

        CREATE INDEX IF NOT EXISTS idx_symbols_project ON symbols(project_id);
        CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(symbol_name);
        CREATE INDEX IF NOT EXISTS idx_symbols_type ON symbols(symbol_type);
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}
