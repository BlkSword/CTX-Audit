-- 项目文件表
CREATE TABLE IF NOT EXISTS project_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    language TEXT,
    size INTEGER,
    last_modified TEXT,
    findings_count INTEGER DEFAULT 0,
    indexed_at TEXT,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    UNIQUE(project_id, file_path)
);

-- 项目文件索引
CREATE INDEX IF NOT EXISTS idx_project_files_project_id ON project_files(project_id);
CREATE INDEX IF NOT EXISTS idx_project_files_file_path ON project_files(file_path);
CREATE INDEX IF NOT EXISTS idx_project_files_language ON project_files(language);
