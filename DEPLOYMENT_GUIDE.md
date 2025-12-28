# CTX-Audit 部署指南

> **版本**: 1.0.0
> **日期**: 2025-12-27
> **适用版本**: Multi-Agent 架构

---

## 📋 目录

1. [部署架构概述](#1-部署架构概述)
2. [本地开发部署](#2-本地开发部署)
3. [生产环境部署](#3-生产环境部署)
4. [环境变量配置](#4-环境变量配置)
5. [数据库初始化](#5-数据库初始化)
6. [服务启动顺序](#6-服务启动顺序)
7. [常见问题排查](#7-常见问题排查)
8. [性能优化建议](#8-性能优化建议)

---

## 1. 部署架构概述

### 1.1 服务依赖关系

```
┌─────────────────────────────────────────────────────────────────┐
│                        服务依赖图                                 │
└─────────────────────────────────────────────────────────────────┘

                    ┌──────────┐
                    │  前端 Web │  (端口 3000)
                    └─────┬────┘
                          │
          ┌───────────────┴───────────────┐
                          │
          ┌───────────────┴───────────────┐
          │                               │
          ▼                               ▼
┌─────────────────┐           ┌────────────────────┐
│  Rust 后端       │           │  Agent 服务         │  (端口 8001)
│  (端口 8000)     │◄──────────│  (FastAPI)          │
└────────┬─────────┘           └─────────┬──────────┘
         │                               │
         │                               │
         ▼                               ▼
┌─────────────────┐           ┌────────────────────┐
│  SQLite         │           │  PostgreSQL         │
│  (项目数据)      │           │  (Agent 状态)       │
└─────────────────┘           └────────────────────┘
                                         │
                               ┌─────────┴─────────┐
                               │                   │
                               ▼                   ▼
                    ┌─────────────────┐  ┌─────────────────┐
                    │  ChromaDB       │  │  Redis          │
                    │  (向量库)        │  │  (消息队列)      │
                    │  端口 8002       │  │  端口 6379       │
                    └─────────────────┘  └─────────────────┘
```

### 1.2 端口分配

| 服务 | 端口 | 说明 |
|------|------|------|
| 前端 Web | 3000 | React 静态文件（生产通过 Rust 后端服务） |
| Rust 后端 | 8000 | Axum API 服务器 |
| Agent 服务 | 8001 | FastAPI Agent 服务器 |
| ChromaDB | 8002 | 向量数据库 |
| PostgreSQL | 5432 | Agent 状态存储 |
| Redis | 6379 | 消息队列和缓存 |

---

## 2. 本地开发部署

### 2.1 前置要求

```bash
# 检查已安装的版本
node --version    # >= 20.x
npm --version     # >= 10.x
rustc --version   # >= 1.75.x
docker --version  # >= 24.x
python --version  # >= 3.11.x
```

### 2.2 快速启动（推荐）

**一键启动所有服务**：

```bash
# 1. 克隆项目
git clone <repo-url>
cd CTX-Audit

# 2. 配置环境变量
cp .env.example .env
# 编辑 .env 文件，填入必要的配置（见第 4 节）

# 3. 启动所有服务
docker-compose up -d

# 4. 查看日志
docker-compose logs -f

# 5. 访问应用
open http://localhost:3000
```

### 2.3 分步启动（开发调试）

#### Step 1: 启动基础服务（Docker）

```bash
# 启动 PostgreSQL + ChromaDB + Redis
docker-compose up -d postgres chromadb redis

# 等待服务就绪
docker-compose logs -f postgres
# 看到类似 "database system is ready to accept connections" 即可
```

#### Step 2: 启动 Rust 后端

```bash
# 新终端窗口
cd web-backend

# 开发模式运行
cargo run

# 或使用 watch 自动重载
cargo install cargo-watch
cargo watch -x run

# 后端启动成功后会看到：
# "DeepAudit Web server listening on 0.0.0.0:8000"
```

#### Step 3: 启动 Agent 服务

```bash
# 新终端窗口
cd agent-service

# 创建虚拟环境
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 安装依赖
pip install -r requirements.txt

# 配置环境变量
cp .env.example .env
# 编辑 .env（参考第 4 节）

# 启动服务
uvicorn app.main:app --reload --port 8001

# Agent 服务启动成功后会看到：
# "Uvicorn running on http://0.0.0.0:8001"
```

#### Step 4: 启动前端

```bash
# 新终端窗口
# 返回项目根目录
cd ..

# 安装依赖（首次）
npm install

# 启动开发服务器
npm run dev

# 前端启动成功后访问：
# http://localhost:5173
```

### 2.4 开发环境目录结构

```
CTX-Audit/
├── .env                          # 环境变量配置
├── docker-compose.yml            # Docker 编排
├── docker-compose.dev.yml        # 开发环境编排
│
├── src/                          # 前端（npm run dev）
│   └── ...
│
├── web-backend/                  # Rust 后端（cargo run）
│   ├── src/
│   └── Cargo.toml
│
├── agent-service/                # Agent 服务（uvicorn）
│   ├── app/
│   ├── requirements.txt
│   └── .env
│
└── data/                         # 本地数据目录
    ├── deepaudit.db              # SQLite 数据库
    └── uploads/                  # 上传文件
```

---

## 3. 生产环境部署

### 3.1 生产环境 Docker Compose

**文件**: `docker-compose.prod.yml`

生产环境使用 Nginx 作为反向代理，统一处理前端静态文件和后端 API 请求：

```yaml
# 见 docker-compose.prod.yml 文件
# 主要服务：
# - nginx: 反向代理，端口 80/443
# - backend: Rust 后端服务
# - agent-service: Python Agent 服务
# - postgres: PostgreSQL 数据库
# - chromadb: 向量数据库
# - redis: 消息队列
```

**目录结构**：
```
ctx-audit/
├── docker-compose.prod.yml      # 生产环境编排
├── docker/
│   └── nginx/
│       ├── nginx.conf           # Nginx 配置
│       └── ssl/                 # SSL 证书目录
├── web-backend/
│   ├── Dockerfile               # 生产环境 Dockerfile
│   └── Dockerfile.dev           # 开发环境 Dockerfile
├── agent-service/
│   └── Dockerfile               # Agent 服务 Dockerfile
└── dist/                        # 前端构建产物
```

### 3.2 生产部署步骤

```bash
# 1. 克隆项目到服务器
git clone <repo-url> /opt/ctx-audit
cd /opt/ctx-audit

# 2. 配置生产环境变量
cp .env.example .env.prod
vim .env.prod

# 必须配置的变量：
# - POSTGRES_PASSWORD=强密码
# - ANTHROPIC_API_KEY=sk-ant-xxx
# - LLM_MODEL=claude-3-5-sonnet-20241022

# 3. 构建前端静态文件
npm install
npm run build

# 4. 构建后端和 Agent 服务镜像
docker-compose -f docker-compose.prod.yml build

# 5. 启动服务
docker-compose -f docker-compose.prod.yml up -d

# 6. 检查服务状态
docker-compose -f docker-compose.prod.yml ps

# 7. 查看日志
docker-compose -f docker-compose.prod.yml logs -f

# 8. 访问应用
open http://your-server-ip
# 生产环境通过 Nginx 端口 80 访问
```

### 3.3 Nginx 反向代理

**文件**: `docker/nginx/nginx.conf`

Nginx 配置已包含在生产环境的 Docker Compose 中。主要功能：

```nginx
# 配置概要：
# - 前端静态文件服务：/
# - Rust 后端 API 代理：/api/
# - Agent 服务 API 代理：/agent/
# - SSE 流式响应支持（禁用缓冲）
# - Gzip 压缩
# - 静态资源缓存
```

**SSL 配置**（生产环境推荐）：

```bash
# 1. 创建 SSL 证书目录
mkdir -p docker/nginx/ssl

# 2. 使用 Let's Encrypt 获取证书
sudo certbot certonly --standalone -d audit.yourdomain.com

# 3. 复制证书到项目
sudo cp /etc/letsencrypt/live/audit.yourdomain.com/fullchain.pem docker/nginx/ssl/
sudo cp /etc/letsencrypt/live/audit.yourdomain.com/privkey.pem docker/nginx/ssl/

# 4. 更新 nginx.conf 添加 HTTPS 配置
```

---

## 4. 环境变量配置

### 4.1 环境变量文件

**文件**: `.env`

```bash
# ============ 基础配置 ============
# 环境：development | production
NODE_ENV=production

# 前端 API 地址
VITE_API_BASE_URL=http://localhost:8000
VITE_AGENT_API_BASE_URL=http://localhost:8001

# ============ Rust 后端配置 ============
RUST_LOG=info
DATABASE_URL=sqlite:./data/deepaudit.db
AGENT_SERVICE_URL=http://agent-service:8001

# ============ PostgreSQL 配置 ============
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_DB=audit_db
POSTGRES_USER=audit_user
POSTGRES_PASSWORD=your_strong_password_here
DATABASE_URL=postgresql://audit_user:your_strong_password_here@postgres:5432/audit_db

# ============ ChromaDB 配置 ============
CHROMADB_HOST=chromadb
CHROMADB_PORT=8000

# ============ Redis 配置 ============
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=redis_password
REDIS_URL=redis://:redis_password@redis:6379/0

# ============ LLM 配置 ============
# LLM 提供商：anthropic | openai | litellm
LLM_PROVIDER=anthropic
LLM_MODEL=claude-3-5-sonnet-20241022

# Anthropic Claude
ANTHROPIC_API_KEY=sk-ant-your-key-here

# OpenAI（可选）
# OPENAI_API_KEY=sk-your-key-here

# 通过 LiteLLM（可选，支持多模型）
# LLM_PROVIDER=litellm
# LLM_MODEL=anthropic/claude-3-5-sonnet
# LITELLM_API_KEY=your-key
# LITELLM_BASE_URL=http://localhost:4000

# ============ Agent 配置 ============
RAG_ENABLED=true
EMBEDDING_MODEL=text-embedding-3-small
CHUNK_SIZE=500
CHUNK_OVERLAP=50
TOP_K_RETRIEVAL=5

MAX_CONCURRENT_AGENTS=3
AGENT_TIMEOUT=300
ENABLE_VERIFICATION=false

# ============ 其他配置 ============
# Sentry 错误监控（可选）
# SENTRY_DSN=https://xxx@sentry.io/xxx

# 遥测（默认关闭）
TELEMETRY_ENABLED=false
```

### 4.2 敏感信息保护

```bash
# 生产环境推荐使用 Docker Secrets 或环境变量文件

# 方式 1: 使用单独的 .env 文件（不提交到 Git）
echo ".env.prod" >> .gitignore

# 方式 2: 使用 Docker Secrets
docker secret create postgres_password - < password.txt

# 在 docker-compose.yml 中引用：
# POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password
```

---

## 5. 数据库初始化

### 5.1 PostgreSQL 初始化脚本

**文件**: `docker/postgres/init.sql`

```sql
-- CTX-Audit Agent 数据库初始化脚本

-- 启用 pgvector 扩展（用于向量相似度搜索）
CREATE EXTENSION IF NOT EXISTS vector;

-- 审计会话表
CREATE TABLE IF NOT EXISTS audit_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
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
    audit_id UUID REFERENCES audit_sessions(id) ON DELETE CASCADE,
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
    audit_id UUID REFERENCES audit_sessions(id) ON DELETE CASCADE,
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

-- RAG 查询日志表
CREATE TABLE IF NOT EXISTS rag_queries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_id UUID REFERENCES audit_sessions(id) ON DELETE CASCADE,
    finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
    query_text TEXT NOT NULL,
    embedding VECTOR(1536),
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

-- 授予权限
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO audit_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO audit_user;
```

### 5.2 ChromaDB 初始化

**在 Agent 服务启动时自动创建集合**：

```python
# agent-service/app/init_db.py

import chromadb
from chromadb.config import Settings

def init_chroma():
    client = chromadb.HttpClient(
        host=os.getenv("CHROMADB_HOST", "localhost"),
        port=int(os.getenv("CHROMADB_PORT", "8000"))
    )

    # 代码片段集合
    client.get_or_create_collection(
        name="code_chunks",
        metadata={"hnsw:space": "cosine"}
    )

    # 漏洞知识库集合
    client.get_or_create_collection(
        name="vulnerability_kb"
    )

    # 历史审计结果集合
    client.get_or_create_collection(
        name="historical_findings"
    )

    print("ChromaDB collections initialized")
```

---

## 6. 服务启动顺序

### 6.1 依赖关系

```
启动顺序：
1. PostgreSQL（数据库基础）
2. ChromaDB（向量库）
3. Redis（消息队列）
4. Rust 后端（依赖 SQLite，可独立启动）
5. Agent 服务（依赖 PostgreSQL + ChromaDB + Redis + Rust 后端）
6. 前端（依赖 Rust 后端）
```

### 6.2 健康检查端点

每个服务都应提供健康检查端点：

```bash
# Rust 后端
curl http://localhost:8000/health
# {"status":"ok","version":"1.0.0"}

# Agent 服务
curl http://localhost:8001/health
# {"status":"healthy","services":{"postgres":"up","chromadb":"up","redis":"up"}}

# PostgreSQL
docker exec ctx-audit-postgres pg_isready -U audit_user
# /var/run/postgresql:5432 - accepting connections

# ChromaDB
curl http://localhost:8002/api/v1/heartbeat
# OK

# Redis
docker exec ctx-audit-redis redis-cli ping
# PONG
```

### 6.3 优雅关闭

```bash
# 停止所有服务
docker-compose down

# 停止并删除数据卷（⚠️ 会清空数据）
docker-compose down -v

# 仅重启某个服务
docker-compose restart agent-service

# 查看服务日志
docker-compose logs -f agent-service
docker-compose logs --tail=100 web
```

---

## 7. 常见问题排查

### 7.1 服务无法启动

**问题**: `agent-service` 无法连接到 PostgreSQL

**排查**:
```bash
# 1. 检查 PostgreSQL 是否运行
docker-compose ps postgres

# 2. 检查 PostgreSQL 日志
docker-compose logs postgres

# 3. 测试连接
docker-compose exec agent-service python -c "
import asyncpg
await asyncpg.connect('postgresql://audit_user:password@postgres:5432/audit_db')
"
```

**解决**:
- 确保 `depends_on` 和 `healthcheck` 配置正确
- 检查数据库连接字符串
- 确认数据库密码正确

### 7.2 LLM API 调用失败

**问题**: Agent 服务报错 `Anthropic API Error`

**排查**:
```bash
# 1. 检查 API Key 是否配置
docker-compose exec agent-service env | grep ANTHROPIC

# 2. 测试 API 连接
docker-compose exec agent-service python -c "
import anthropic
client = anthropic.Anthropic(api_key='your-key')
print(client.messages.list())
"
```

**解决**:
- 验证 API Key 有效性
- 检查网络是否可以访问 API 端点
- 考虑使用 API 中转服务

### 7.3 SSE 连接断开

**问题**: 前端审计流日志中断

**排查**:
```bash
# 1. 检查 Agent 服务日志
docker-compose logs -f agent-service | grep -i "sse\|stream"

# 2. 测试 SSE 端点
curl -N http://localhost:8001/api/audit/test-audit-id/stream
```

**解决**:
- 检查 Nginx 反向代理配置（禁用缓冲）
- 确认 `proxy_buffering off;` 已配置
- 增加超时时间

### 7.4 ChromaDB 连接超时

**问题**: RAG 检索超时

**排查**:
```bash
# 检查 ChromaDB 状态
curl http://localhost:8002/api/v1/heartbeat

# 查看集合信息
curl http://localhost:8002/api/v1/collections
```

**解决**:
- 增加 ChromaDB 内存限制
- 检查向量索引是否正确构建

---

## 8. 性能优化建议

### 8.1 资源限制

```yaml
# docker-compose.yml

services:
  agent-service:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
        reservations:
          cpus: '1.0'
          memory: 2G
```

### 8.2 数据库优化

```sql
-- PostgreSQL 连接池配置
ALTER SYSTEM SET max_connections = 100;
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';

-- 重启使配置生效
```

### 8.3 并发控制

```bash
# .env 配置
MAX_CONCURRENT_AGENTS=3         # 同时运行的 Agent 数量
AGENT_TIMEOUT=300               # Agent 超时时间（秒）
RAG_TOP_K=5                     # RAG 检索结果数量
```

### 8.4 缓存策略

```python
# Redis 缓存配置
CACHE_TTL = {
    "ast_context": 3600,        # AST 上下文缓存 1 小时
    "rag_results": 1800,        # RAG 结果缓存 30 分钟
    "scan_results": 600,        # 扫描结果缓存 10 分钟
}
```

---

## 9. 监控和日志

### 9.1 日志配置

```python
# agent-service/app/logging_config.py

import logging
from loguru import logger

# 配置日志
logger.add(
    "logs/agent_{time}.log",
    rotation="500 MB",
    retention="10 days",
    level="INFO"
)
```

### 9.2 监控指标

推荐监控以下指标：

| 指标 | 说明 | 告警阈值 |
|------|------|----------|
| Agent 执行时间 | 单个 Agent 平均执行时间 | > 60s |
| LLM API 调用延迟 | LLM 响应时间 | > 10s |
| 误报率 | 验证后确认的漏洞比例 | > 30% |
| 内存使用 | Agent 服务内存 | > 80% |
| SSE 连接数 | 活跃审计流数量 | > 100 |

---

## 10. 快速参考

### 10.1 常用命令

```bash
# 构建和启动
docker-compose up -d --build

# 查看日志
docker-compose logs -f [service-name]

# 重启服务
docker-compose restart [service-name]

# 进入容器
docker-compose exec agent-service bash

# 清理和重建
docker-compose down -v
docker-compose up -d --build

# 数据库备份
docker-compose exec postgres pg_dump -U audit_user audit_db > backup.sql

# 数据库恢复
docker-compose exec -T postgres psql -U audit_user audit_db < backup.sql
```

### 10.2 端口速查

| 服务 | 内部端口 | 外部端口 |
|------|----------|----------|
| Web | 8000 | 3000 |
| Rust API | 8000 | 8000 |
| Agent API | 8001 | 8001 |
| ChromaDB | 8000 | 8002 |
| PostgreSQL | 5432 | 5432 |
| Redis | 6379 | 6379 |

---

## 附录 A: Dockerfile 示例

### Agent 服务 Dockerfile

**文件**: `agent-service/Dockerfile`

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件
COPY requirements.txt .

# 安装 Python 依赖
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用代码
COPY app ./app
COPY prompts ./prompts

# 暴露端口
EXPOSE 8001

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8001/health || exit 1

# 启动命令
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
```

---

**有问题随时问我！**
