-- 符号定义表
CREATE TABLE IF NOT EXISTS symbols (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    symbol_name TEXT NOT NULL,
    symbol_type TEXT NOT NULL,
    line_number INTEGER NOT NULL,
    parent_name TEXT,
    signature TEXT,
    documentation TEXT,
    indexed_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

-- 符号索引
CREATE INDEX IF NOT EXISTS idx_symbols_project_id ON symbols(project_id);
CREATE INDEX IF NOT EXISTS idx_symbols_file_path ON symbols(file_path);
CREATE INDEX IF NOT EXISTS idx_symbols_symbol_name ON symbols(symbol_name);
CREATE INDEX IF NOT EXISTS idx_symbols_symbol_type ON symbols(symbol_type);
