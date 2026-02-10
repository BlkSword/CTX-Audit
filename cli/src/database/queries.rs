// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 数据库查询操作

use super::models::*;
use anyhow::Result;
use sqlx::{Pool, Sqlite};

/// 项目查询
pub struct ProjectQueries;

impl ProjectQueries {
    /// 创建项目
    pub async fn create(pool: &Pool<Sqlite>, project: &CreateProject) -> Result<Project> {
        let now = chrono::Utc::now().to_rfc3339();
        let row = sqlx::query_as::<_, Project>(
            r#"
            INSERT INTO projects (uuid, name, path, description, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            RETURNING *
            "#,
        )
        .bind(&project.uuid)
        .bind(&project.name)
        .bind(&project.path)
        .bind(&project.description)
        .bind(&now)
        .bind(&now)
        .fetch_one(pool)
        .await?;

        Ok(row)
    }

    /// 列出所有项目
    pub async fn list(pool: &Pool<Sqlite>) -> Result<Vec<Project>> {
        let projects = sqlx::query_as::<_, Project>(
            "SELECT * FROM projects ORDER BY updated_at DESC"
        )
        .fetch_all(pool)
        .await?;

        Ok(projects)
    }

    /// 根据路径获取项目
    pub async fn get_by_path(pool: &Pool<Sqlite>, path: &str) -> Result<Option<Project>> {
        let project = sqlx::query_as::<_, Project>(
            "SELECT * FROM projects WHERE path = ?"
        )
        .bind(path)
        .fetch_optional(pool)
        .await?;

        Ok(project)
    }

    /// 根据 UUID 获取项目
    pub async fn get_by_uuid(pool: &Pool<Sqlite>, uuid: &str) -> Result<Option<Project>> {
        let project = sqlx::query_as::<_, Project>(
            "SELECT * FROM projects WHERE uuid = ?"
        )
        .bind(uuid)
        .fetch_optional(pool)
        .await?;

        Ok(project)
    }

    /// 根据 ID 获取项目
    pub async fn get_by_id(pool: &Pool<Sqlite>, id: i64) -> Result<Option<Project>> {
        let project = sqlx::query_as::<_, Project>(
            "SELECT * FROM projects WHERE id = ?"
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;

        Ok(project)
    }

    /// 删除项目
    pub async fn delete(pool: &Pool<Sqlite>, id: i64) -> Result<()> {
        sqlx::query("DELETE FROM projects WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;

        Ok(())
    }

    /// 更新项目活跃状态
    pub async fn set_active(pool: &Pool<Sqlite>, id: i64, is_active: bool) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "UPDATE projects SET is_active = ?, updated_at = ? WHERE id = ?"
        )
        .bind(is_active)
        .bind(&now)
        .bind(id)
        .execute(pool)
        .await?;

        Ok(())
    }
}

/// 审计会话查询
pub struct AuditSessionQueries;

impl AuditSessionQueries {
    /// 创建审计会话
    pub async fn create(
        pool: &Pool<Sqlite>,
        project_id: i64,
        uuid: &str,
        session_type: &str,
    ) -> Result<AuditSession> {
        let now = chrono::Utc::now().to_rfc3339();
        let row = sqlx::query_as::<_, AuditSession>(
            r#"
            INSERT INTO audit_sessions (uuid, project_id, session_type, status, started_at)
            VALUES (?, ?, ?, 'pending', ?)
            RETURNING *
            "#,
        )
        .bind(uuid)
        .bind(project_id)
        .bind(session_type)
        .bind(&now)
        .fetch_one(pool)
        .await?;

        Ok(row)
    }

    /// 更新会话状态
    pub async fn update_status(
        pool: &Pool<Sqlite>,
        id: i64,
        status: &str,
        error_message: Option<&str>,
    ) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "UPDATE audit_sessions SET status = ?, completed_at = ?, error_message = ? WHERE id = ?"
        )
        .bind(status)
        .bind(&now)
        .bind(error_message)
        .bind(id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// 根据 ID 获取会话
    pub async fn get_by_id(pool: &Pool<Sqlite>, id: i64) -> Result<Option<AuditSession>> {
        let session = sqlx::query_as::<_, AuditSession>(
            "SELECT * FROM audit_sessions WHERE id = ?"
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;

        Ok(session)
    }

    /// 列出项目的所有审计会话
    pub async fn list_by_project(pool: &Pool<Sqlite>, project_id: i64) -> Result<Vec<AuditSession>> {
        let sessions = sqlx::query_as::<_, AuditSession>(
            "SELECT * FROM audit_sessions WHERE project_id = ? ORDER BY started_at DESC"
        )
        .bind(project_id)
        .fetch_all(pool)
        .await?;

        Ok(sessions)
    }
}

/// 漏洞查询
pub struct FindingQueries;

impl FindingQueries {
    /// 创建漏洞
    pub async fn create(pool: &Pool<Sqlite>, finding: &CreateFinding) -> Result<Finding> {
        let now = chrono::Utc::now().to_rfc3339();
        let row = sqlx::query_as::<_, Finding>(
            r#"
            INSERT INTO findings (
                finding_id, project_id, session_id, scan_id, file_path,
                severity, category, title, description, start_line, end_line,
                code_snippet, status, confidence, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)
            RETURNING *
            "#,
        )
        .bind(&finding.finding_id)
        .bind(finding.project_id)
        .bind(finding.session_id)
        .bind(&finding.scan_id)
        .bind(&finding.file_path)
        .bind(&finding.severity)
        .bind(&finding.category)
        .bind(&finding.title)
        .bind(&finding.description)
        .bind(finding.start_line)
        .bind(finding.end_line)
        .bind(&finding.code_snippet)
        .bind(&finding.confidence)
        .bind(&now)
        .bind(&now)
        .fetch_one(pool)
        .await?;

        Ok(row)
    }

    /// 列出漏洞
    pub async fn list(
        pool: &Pool<Sqlite>,
        project_id: Option<i64>,
        severity: Option<&str>,
        status: Option<&str>,
        file_path: Option<&str>,
    ) -> Result<Vec<Finding>> {
        let mut query = String::from("SELECT * FROM findings WHERE 1=1");
        let mut params = Vec::new();

        if let Some(pid) = project_id {
            query.push_str(&format!(" AND project_id = {}", pid));
        }
        if let Some(s) = severity {
            query.push_str(" AND severity = ?");
            params.push(s.to_string());
        }
        if let Some(s) = status {
            query.push_str(" AND status = ?");
            params.push(s.to_string());
        }
        if let Some(f) = file_path {
            query.push_str(" AND file_path LIKE ?");
            params.push(format!("%{}%", f));
        }

        query.push_str(" ORDER BY created_at DESC");

        let mut q = sqlx::query_as::<_, Finding>(&query);
        for p in params {
            q = q.bind(p);
        }

        let findings = q.fetch_all(pool).await?;
        Ok(findings)
    }

    /// 根据 ID 获取漏洞
    pub async fn get_by_id(pool: &Pool<Sqlite>, id: i64) -> Result<Option<Finding>> {
        let finding = sqlx::query_as::<_, Finding>(
            "SELECT * FROM findings WHERE id = ?"
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;

        Ok(finding)
    }

    /// 根据 finding_id 获取漏洞
    pub async fn get_by_finding_id(pool: &Pool<Sqlite>, finding_id: &str) -> Result<Option<Finding>> {
        let finding = sqlx::query_as::<_, Finding>(
            "SELECT * FROM findings WHERE finding_id = ?"
        )
        .bind(finding_id)
        .fetch_optional(pool)
        .await?;

        Ok(finding)
    }

    /// 更新漏洞
    pub async fn update(pool: &Pool<Sqlite>, id: i64, update: &UpdateFinding) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let mut query = String::from("UPDATE findings SET updated_at = ?");
        let mut params = vec![now];

        if let Some(status) = &update.status {
            query.push_str(", status = ?");
            params.push(status.clone());
        }
        if let Some(note) = &update.note {
            query.push_str(", note = ?");
            params.push(note.clone());
        }
        if let Some(fp) = update.false_positive {
            query.push_str(", false_positive = ?");
            params.push(if fp { "1" } else { "0" }.to_string());
        }

        query.push_str(" WHERE id = ?");
        params.push(id.to_string());

        let mut q = sqlx::query(&query);
        for p in params {
            q = q.bind(p);
        }

        q.execute(pool).await?;
        Ok(())
    }

    /// 删除漏洞
    pub async fn delete(pool: &Pool<Sqlite>, id: i64) -> Result<()> {
        sqlx::query("DELETE FROM findings WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;

        Ok(())
    }

    /// 统计漏洞数量
    pub async fn count_by_severity(pool: &Pool<Sqlite>, project_id: Option<i64>) -> Result<Vec<(String, i64)>> {
        let query = if let Some(pid) = project_id {
            "SELECT severity, COUNT(*) as count FROM findings WHERE project_id = ? GROUP BY severity"
        } else {
            "SELECT severity, COUNT(*) as count FROM findings GROUP BY severity"
        };

        let mut q = sqlx::query_as::<_, (String, i64)>(query);
        if let Some(pid) = project_id {
            q = q.bind(pid);
        }

        let counts = q.fetch_all(pool).await?;
        Ok(counts)
    }
}

/// Agent 事件查询
pub struct AgentEventQueries;

impl AgentEventQueries {
    /// 记录事件
    pub async fn log(
        pool: &Pool<Sqlite>,
        session_id: i64,
        event_type: &str,
        agent_type: Option<&str>,
        data: Option<&str>,
    ) -> Result<AgentEvent> {
        let row = sqlx::query_as::<_, AgentEvent>(
            r#"
            INSERT INTO agent_events (session_id, event_type, agent_type, data)
            VALUES (?, ?, ?, ?)
            RETURNING *
            "#,
        )
        .bind(session_id)
        .bind(event_type)
        .bind(agent_type)
        .bind(data)
        .fetch_one(pool)
        .await?;

        Ok(row)
    }

    /// 获取会话的所有事件
    pub async fn list_by_session(pool: &Pool<Sqlite>, session_id: i64) -> Result<Vec<AgentEvent>> {
        let events = sqlx::query_as::<_, AgentEvent>(
            "SELECT * FROM agent_events WHERE session_id = ? ORDER BY timestamp ASC"
        )
        .bind(session_id)
        .fetch_all(pool)
        .await?;

        Ok(events)
    }
}

/// 项目文件查询
pub struct ProjectFileQueries;

impl ProjectFileQueries {
    /// 索引文件
    pub async fn index(
        pool: &Pool<Sqlite>,
        project_id: i64,
        file_path: &str,
        language: Option<&str>,
        size: i64,
    ) -> Result<ProjectFile> {
        let now = chrono::Utc::now().to_rfc3339();
        let row = sqlx::query_as::<_, ProjectFile>(
            r#"
            INSERT INTO project_files (project_id, file_path, language, size, indexed_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(project_id, file_path) DO UPDATE SET
                language = excluded.language,
                size = excluded.size,
                indexed_at = excluded.indexed_at
            RETURNING *
            "#,
        )
        .bind(project_id)
        .bind(file_path)
        .bind(language)
        .bind(size)
        .bind(&now)
        .fetch_one(pool)
        .await?;

        Ok(row)
    }

    /// 获取项目的所有文件
    pub async fn list_by_project(pool: &Pool<Sqlite>, project_id: i64) -> Result<Vec<ProjectFile>> {
        let files = sqlx::query_as::<_, ProjectFile>(
            "SELECT * FROM project_files WHERE project_id = ? ORDER BY file_path"
        )
        .bind(project_id)
        .fetch_all(pool)
        .await?;

        Ok(files)
    }

    /// 根据路径获取文件
    pub async fn get_by_path(
        pool: &Pool<Sqlite>,
        project_id: i64,
        file_path: &str,
    ) -> Result<Option<ProjectFile>> {
        let file = sqlx::query_as::<_, ProjectFile>(
            "SELECT * FROM project_files WHERE project_id = ? AND file_path = ?"
        )
        .bind(project_id)
        .bind(file_path)
        .fetch_optional(pool)
        .await?;

        Ok(file)
    }
}

/// 符号查询
pub struct SymbolQueries;

impl SymbolQueries {
    /// 创建符号
    pub async fn create(
        pool: &Pool<Sqlite>,
        project_id: i64,
        file_path: &str,
        symbol_name: &str,
        symbol_type: &str,
        line_number: i32,
    ) -> Result<Symbol> {
        let now = chrono::Utc::now().to_rfc3339();
        let row = sqlx::query_as::<_, Symbol>(
            r#"
            INSERT INTO symbols (project_id, file_path, symbol_name, symbol_type, line_number, indexed_at)
            VALUES (?, ?, ?, ?, ?, ?)
            RETURNING *
            "#,
        )
        .bind(project_id)
        .bind(file_path)
        .bind(symbol_name)
        .bind(symbol_type)
        .bind(line_number)
        .bind(&now)
        .fetch_one(pool)
        .await?;

        Ok(row)
    }

    /// 搜索符号
    pub async fn search(
        pool: &Pool<Sqlite>,
        project_id: i64,
        query: &str,
    ) -> Result<Vec<Symbol>> {
        let symbols = sqlx::query_as::<_, Symbol>(
            "SELECT * FROM symbols WHERE project_id = ? AND symbol_name LIKE ? ORDER BY symbol_name"
        )
        .bind(project_id)
        .bind(format!("%{}%", query))
        .fetch_all(pool)
        .await?;

        Ok(symbols)
    }

    /// 获取文件的所有符号
    pub async fn list_by_file(
        pool: &Pool<Sqlite>,
        project_id: i64,
        file_path: &str,
    ) -> Result<Vec<Symbol>> {
        let symbols = sqlx::query_as::<_, Symbol>(
            "SELECT * FROM symbols WHERE project_id = ? AND file_path = ? ORDER BY line_number"
        )
        .bind(project_id)
        .bind(file_path)
        .fetch_all(pool)
        .await?;

        Ok(symbols)
    }
}
