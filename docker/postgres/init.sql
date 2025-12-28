-- CTX-Audit Agent 数据库初始化脚本

-- 启用 pgvector 扩展（用于向量相似度搜索，如果已安装）
-- CREATE EXTENSION IF NOT EXISTS vector;

-- 审计会话表
CREATE TABLE IF NOT EXISTS audit_sessions (
    id VARCHAR(255) PRIMARY KEY,
    project_id VARCHAR(255) NOT NULL,
    audit_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    config JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error TEXT
);

-- Agent 执行记录表
CREATE TABLE IF NOT EXISTS agent_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_id VARCHAR(255) REFERENCES audit_sessions(id) ON DELETE CASCADE,
    agent_name VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL,
    input JSONB,
    output JSONB,
    thinking_chain TEXT,
    started_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP,
    duration_ms INTEGER
);

-- 漏洞发现表
CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_id VARCHAR(255) REFERENCES audit_sessions(id) ON DELETE CASCADE,
    agent_found VARCHAR(100),
    rule_id VARCHAR(255),
    vulnerability_type VARCHAR(100),
    severity VARCHAR(20),
    confidence FLOAT,
    title TEXT,
    description TEXT,
    file_path VARCHAR(1000),
    line_number INTEGER,
    code_snippet TEXT,
    remediation TEXT,
    references JSONB,
    verified BOOLEAN DEFAULT FALSE,
    is_false_positive BOOLEAN DEFAULT FALSE,
    verification_evidence JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

-- RAG 查询日志表（可选）
CREATE TABLE IF NOT EXISTS rag_queries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_id VARCHAR(255) REFERENCES audit_sessions(id) ON DELETE CASCADE,
    finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
    query_text TEXT NOT NULL,
    results JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

-- 创建索引
CREATE INDEX IF NOT EXISTS idx_audit_sessions_project ON audit_sessions(project_id);
CREATE INDEX IF NOT EXISTS idx_audit_sessions_status ON audit_sessions(status);
CREATE INDEX IF NOT EXISTS idx_agent_executions_audit ON agent_executions(audit_id);
CREATE INDEX IF NOT EXISTS idx_findings_audit ON findings(audit_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_verified ON findings(verified);
CREATE INDEX IF NOT EXISTS idx_rag_queries_audit ON rag_queries(audit_id);

-- 授予权限
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO audit_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO audit_user;
