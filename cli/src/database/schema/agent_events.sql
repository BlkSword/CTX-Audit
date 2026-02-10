-- Agent 事件表
CREATE TABLE IF NOT EXISTS agent_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    agent_type TEXT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    data TEXT,
    FOREIGN KEY (session_id) REFERENCES audit_sessions(id) ON DELETE CASCADE
);

-- Agent 事件索引
CREATE INDEX IF NOT EXISTS idx_agent_events_session_id ON agent_events(session_id);
CREATE INDEX IF NOT EXISTS idx_agent_events_event_type ON agent_events(event_type);
CREATE INDEX IF NOT EXISTS idx_agent_events_timestamp ON agent_events(timestamp);
