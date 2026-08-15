-- 审计会话表
CREATE TABLE IF NOT EXISTS audit_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL UNIQUE,
    project_id INTEGER NOT NULL,
    session_type TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL DEFAULT (datetime('now')),
    completed_at TEXT,
    total_iterations INTEGER,
    tokens_used INTEGER,
    error_message TEXT,
    metadata TEXT,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

-- 审计会话索引
CREATE INDEX IF NOT EXISTS idx_audit_sessions_uuid ON audit_sessions(uuid);
CREATE INDEX IF NOT EXISTS idx_audit_sessions_project_id ON audit_sessions(project_id);
CREATE INDEX IF NOT EXISTS idx_audit_sessions_status ON audit_sessions(status);
CREATE INDEX IF NOT EXISTS idx_audit_sessions_started_at ON audit_sessions(started_at);
