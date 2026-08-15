-- 漏洞发现表
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL UNIQUE,
    project_id INTEGER NOT NULL,
    session_id INTEGER,
    scan_id TEXT,
    file_path TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT,
    title TEXT NOT NULL,
    description TEXT,
    start_line INTEGER,
    end_line INTEGER,
    code_snippet TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    confidence TEXT,
    false_positive INTEGER DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    note TEXT,
    metadata TEXT,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (session_id) REFERENCES audit_sessions(id) ON DELETE SET NULL
);

-- 漏洞索引
CREATE INDEX IF NOT EXISTS idx_findings_finding_id ON findings(finding_id);
CREATE INDEX IF NOT EXISTS idx_findings_project_id ON findings(project_id);
CREATE INDEX IF NOT EXISTS idx_findings_session_id ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_file_path ON findings(file_path);
