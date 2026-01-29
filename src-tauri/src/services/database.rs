// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

use crate::commands::{Finding, FindingStatus, Project};
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

    // ==================== 实时审计相关方法 ====================

    /// 获取文件的所有漏洞
    pub async fn get_file_findings(
        &self,
        file_path: &str,
        project_id: i64,
    ) -> Result<Vec<Finding>, sqlx::Error> {
        sqlx::query_as::<_, Finding>(
            r#"
            SELECT id, file_path, line_start, line_end, detector, vuln_type, severity, description, code_snippet, status, datetime(created_at) as created_at
            FROM findings
            WHERE file_path = ? AND project_id = ?
            ORDER BY line_start ASC
            "#
        )
        .bind(file_path)
        .bind(project_id)
        .fetch_all(&self.pool)
        .await
    }

    /// 更新漏洞状态
    pub async fn update_finding_status(
        &self,
        finding_id: &str,
        status: FindingStatus,
        user_note: Option<String>,
    ) -> Result<(), sqlx::Error> {
        let status_str = match status {
            FindingStatus::New => "new",
            FindingStatus::Fixed => "fixed",
            FindingStatus::FalsePositive => "false_positive",
            FindingStatus::Ignored => "ignored",
            FindingStatus::Verified => "verified",
        };

        // 更新 findings 表
        sqlx::query("UPDATE findings SET status = ? WHERE id = ?")
            .bind(status_str)
            .bind(finding_id)
            .execute(&self.pool)
            .await?;

        // 插入或更新 finding_markers 表
        sqlx::query(
            r#"
            INSERT INTO finding_markers (finding_id, file_path, status, user_note, updated_at)
            VALUES (?, (SELECT file_path FROM findings WHERE id = ?), ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(finding_id) DO UPDATE SET
                status = excluded.status,
                user_note = excluded.user_note,
                updated_at = CURRENT_TIMESTAMP
            "#
        )
        .bind(finding_id)
        .bind(finding_id)
        .bind(status_str)
        .bind(user_note)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// 保存扫描结果
    pub async fn save_scan_results(
        &self,
        project_id: i64,
        file_path: &str,
        findings: &[Finding],
        content_hash: &str,
    ) -> Result<(), sqlx::Error> {
        // 保存每个漏洞
        for finding in findings {
            sqlx::query(
                r#"
                INSERT OR REPLACE INTO findings (finding_id, file_path, project_id, line_start, line_end, detector, vuln_type, severity, description, code_snippet, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#
            )
            .bind(&finding.id)
            .bind(file_path)
            .bind(project_id)
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
        }

        Ok(())
    }

    /// 获取文件扫描缓存
    pub async fn get_file_scan_cache(
        &self,
        file_path: &str,
    ) -> Result<Option<FileScanCache>, sqlx::Error> {
        #[derive(sqlx::FromRow)]
        struct CacheRow {
            id: i64,
            file_path: String,
            content_hash: String,
            findings_json: String,
            scanned_at: String,
        }

        let row = sqlx::query_as::<_, CacheRow>(
            r#"
            SELECT id, file_path, content_hash, findings_json, datetime(scanned_at) as scanned_at
            FROM file_scan_cache
            WHERE file_path = ?
            ORDER BY scanned_at DESC
            LIMIT 1
            "#
        )
        .bind(file_path)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| FileScanCache {
            id: r.id,
            file_path: r.file_path,
            content_hash: r.content_hash,
            findings_json: r.findings_json,
            scanned_at: r.scanned_at,
        }))
    }

    /// 更新文件扫描缓存
    pub async fn update_file_scan_cache(
        &self,
        file_path: &str,
        content_hash: &str,
        findings_json: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT OR REPLACE INTO file_scan_cache (file_path, content_hash, findings_json, scanned_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            "#
        )
        .bind(file_path)
        .bind(content_hash)
        .bind(findings_json)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// 获取项目统计信息
    pub async fn get_project_stats(
        &self,
        project_id: i64,
    ) -> Result<ProjectStats, sqlx::Error> {
        #[derive(sqlx::FromRow)]
        struct StatsRow {
            total_files: i64,
            total_findings: i64,
            critical: i64,
            high: i64,
            medium: i64,
            low: i64,
            info: i64,
        }

        let row = sqlx::query_as::<_, StatsRow>(
            r#"
            SELECT
                (SELECT COUNT(DISTINCT file_path) FROM findings WHERE project_id = ?) as total_files,
                (SELECT COUNT(*) FROM findings WHERE project_id = ?) as total_findings,
                (SELECT COUNT(*) FROM findings WHERE project_id = ? AND severity = 'critical') as critical,
                (SELECT COUNT(*) FROM findings WHERE project_id = ? AND severity = 'high') as high,
                (SELECT COUNT(*) FROM findings WHERE project_id = ? AND severity = 'medium') as medium,
                (SELECT COUNT(*) FROM findings WHERE project_id = ? AND severity = 'low') as low,
                (SELECT COUNT(*) FROM findings WHERE project_id = ? AND severity = 'info') as info
            "#
        )
        .bind(project_id)
        .bind(project_id)
        .bind(project_id)
        .bind(project_id)
        .bind(project_id)
        .bind(project_id)
        .bind(project_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(ProjectStats {
            total_files: row.total_files,
            total_findings: row.total_findings,
            by_severity: SeverityStats {
                critical: row.critical,
                high: row.high,
                medium: row.medium,
                low: row.low,
                info: row.info,
            },
        })
    }

    /// 获取项目文件列表
    pub async fn get_project_files(
        &self,
        project_id: i64,
    ) -> Result<Vec<ProjectFile>, sqlx::Error> {
        #[derive(sqlx::FromRow)]
        struct FileRow {
            path: String,
            name: String,
            language: String,
            findings_count: i64,
            last_modified: String,
        }

        let rows = sqlx::query_as::<_, FileRow>(
            r#"
            SELECT
                file_path as path,
                file_name as name,
                language,
                findings_count,
                datetime(last_modified) as last_modified
            FROM project_files
            WHERE project_id = ?
            ORDER BY findings_count DESC, name ASC
            "#
        )
        .bind(project_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| ProjectFile {
            path: r.path,
            name: r.name,
            language: r.language,
            findings_count: r.findings_count,
            last_modified: r.last_modified,
        }).collect())
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

        CREATE TABLE IF NOT EXISTS finding_markers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id TEXT NOT NULL UNIQUE,
            file_path TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'new',
            user_note TEXT,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(finding_id) REFERENCES findings(id)
        );

        CREATE TABLE IF NOT EXISTS file_scan_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT NOT NULL UNIQUE,
            content_hash TEXT NOT NULL,
            findings_json TEXT NOT NULL,
            scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS project_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            file_path TEXT NOT NULL UNIQUE,
            file_name TEXT NOT NULL,
            language TEXT NOT NULL,
            findings_count INTEGER DEFAULT 0,
            last_modified DATETIME DEFAULT CURRENT_TIMESTAMP,
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
        CREATE INDEX IF NOT EXISTS idx_findings_file ON findings(file_path);
        CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
        CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}

// ==================== 辅助类型 ====================

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileScanCache {
    pub id: i64,
    pub file_path: String,
    pub content_hash: String,
    pub findings_json: String,
    pub scanned_at: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProjectStats {
    pub total_files: i64,
    pub total_findings: i64,
    pub by_severity: SeverityStats,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SeverityStats {
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub info: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProjectFile {
    pub path: String,
    pub name: String,
    pub language: String,
    pub findings_count: i64,
    pub last_modified: String,
}
