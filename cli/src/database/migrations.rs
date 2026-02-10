// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 数据库迁移

use anyhow::Result;

/// 数据库迁移
pub struct Migration {
    pub version: i32,
    pub name: &'static str,
    pub sql: &'static str,
}

/// 获取所有迁移
pub fn get_migrations() -> Vec<Migration> {
    vec![
        Migration {
            version: 1,
            name: "initial_schema",
            sql: "",
            // 初始 schema 在 mod.rs 中通过 include_str! 加载
        },
        // 添加更多迁移
        Migration {
            version: 2,
            name: "add_finding_confidence_index",
            sql: r#"
                CREATE INDEX IF NOT EXISTS idx_findings_confidence ON findings(confidence);
            "#,
        },
    ]
}

/// 运行迁移
pub async fn run_migrations(pool: &sqlx::Pool<sqlx::Sqlite>) -> Result<()> {
    // 创建迁移历史表
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        "#,
    )
    .execute(pool)
    .await?;

    // 获取已应用的迁移
    let applied: Vec<(i32,)> = sqlx::query_as("SELECT version FROM schema_migrations ORDER BY version")
        .fetch_all(pool)
        .await?;

    let applied_versions: std::collections::HashSet<i32> = applied.into_iter().map(|(v,)| v).collect();

    // 运行未应用的迁移
    for migration in get_migrations() {
        if applied_versions.contains(&migration.version) {
            continue;
        }

        tracing::info!(
            "Applying migration {}: {}",
            migration.version,
            migration.name
        );

        if !migration.sql.is_empty() {
            sqlx::query(migration.sql).execute(pool).await?;
        }

        sqlx::query(
            "INSERT INTO schema_migrations (version, name) VALUES (?, ?)",
        )
        .bind(migration.version)
        .bind(migration.name)
        .execute(pool)
        .await?;
    }

    Ok(())
}
