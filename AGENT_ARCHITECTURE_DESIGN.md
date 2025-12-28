# CTX-Audit Multi-Agent 架构设计文档

> **版本**: 1.0.0
> **日期**: 2025-12-27
> **状态**: 设计阶段

---

## 📋 目录

1. [概述](#1-概述)
2. [整体架构](#2-整体架构)
3. [Multi-Agent 系统设计](#3-multi-agent-系统设计)
4. [API 接口定义](#4-api-接口定义)
5. [数据流设计](#5-数据流设计)
6. [数据库 Schema](#6-数据库-schema)
7. [RAG 知识库设计](#7-rag-知识库设计)
8. [部署方案](#8-部署方案)
9. [安全考虑](#9-安全考虑)
10. [实施路线图](#10-实施路线图)

---

## 1. 概述

### 1.1 设计目标

CTX-Audit Multi-Agent 系统旨在通过引入智能 Agent 协作机制，解决传统静态分析工具的三大痛点：

| 痛点 | 解决方案 |
|------|----------|
| **误报率高** - 缺乏语义理解 | 通过 LLM 上下文分析 + RAG 知识增强，智能验证规则扫描结果 |
| **业务逻辑盲点** - 无法理解跨文件调用 | Multi-Agent 协作分析调用链、权限校验等复杂业务逻辑 |
| **缺乏验证手段** - 无法确认漏洞真实性 | 通过 Agent 生成 PoC 并在沙箱环境中验证（后期实现） |

### 1.2 设计原则

1. **保留现有优势** - Rust 高性能扫描引擎 + Tree-sitter AST 继续作为基础
2. **渐进式增强** - 在现有架构上添加 Agent 层，而非重写
3. **松耦合** - Rust 后端与 Python Agent 服务通过 HTTP 通信
4. **可扩展** - 支持动态添加新 Agent 和功能
5. **可观测** - 完整的审计流日志和 Agent 思考链可视化

### 1.3 技术选型

| 组件 | 技术选型 | 理由 |
|------|----------|------|
| **Agent 框架** | LangGraph | 成熟的 Agent 编排框架，支持复杂工作流 |
| **Web 服务** | FastAPI | 高性能异步框架，自动生成 OpenAPI 文档 |
| **LLM 接口** | LiteLLM | 统一接口，支持 100+ LLM 提供商 |
| **向量数据库** | ChromaDB | 轻量级、易部署、支持 Docker |
| **状态管理** | PostgreSQL | 事务支持、Agent 状态持久化 |
| **消息队列** | Redis | Agent 间异步通信、任务队列 |

---

## 2. 整体架构

### 2.1 系统架构图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              React 前端 (Vite + TS)                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│  │ 仪表盘   │  │ 项目管理  │  │ 扫描器   │  │ 审计流   │  │ 报告     │      │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘      │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    │                               │
                    ▼                               ▼
┌──────────────────────────────────┐  ┌──────────────────────────────────────┐
│   Rust 后端 (Axum)                │  │   Agent 服务 (FastAPI)               │
│   ────────────────────            │  │   ────────────────────────            │
│                                   │  │                                      │
│  ┌────────────────────────────┐  │  │  ┌────────────────────────────────┐  │
│  │ API Gateway                │  │  │  │ API Gateway                    │  │
│  │ • /api/ast/*               │  │  │  │ • /api/agent/*                 │  │
│  │ • /api/project/*           │  │  │  │ • /api/audit/*                 │  │
│  │ • /api/scanner/*           │◄─┼──┼──┤ • /ws/audit_stream (SSE)      │  │
│  └────────────────────────────┘  │  │  └────────────────────────────────┘  │
│                │                  │  │                │                     │
│  ┌─────────────▼──────────────┐  │  │  ┌─────────────▼────────────────┐   │
│  │ Core Engine                │  │  │  │ Multi-Agent System           │   │
│  │ ────────────────            │  │  │  │ ────────────────             │   │
│  │ • AST Parser (Tree-sitter) │  │  │  │                              │   │
│  │ • Rule Engine              │  │  │  │  ┌─────────────────────────┐ │   │
│  │ • Scanner (并发)            │  │  │  │  │ Orchestrator Agent      │ │   │
│  │ • Index Cache              │  │─┼──┼──┤ (任务编排、决策)         │ │   │
│  └─────────────┬──────────────┘  │  │  │  └─────────────────────────┘ │   │
│                │                  │  │  │                              │   │
│  ┌─────────────▼──────────────┐  │  │  │  ┌─────────────────────────┐ │   │
│  │ Storage                    │  │  │  │  │ Recon Agent             │ │   │
│  │ ────────────               │  │  │  │  │ (信息收集、攻击面识别)    │ │   │
│  │ • SQLite (项目数据)         │  │  │  │  └─────────────────────────┘ │   │
│  │ • File Cache               │  │  │  │                              │   │
│  └─────────────────────────────┘  │  │  │  ┌─────────────────────────┐ │   │
│                                   │  │  │  │ Analysis Agent          │ │   │
│                                   │  │  │  │ (漏洞挖掘、RAG 分析)     │ │   │
│                                   │  │  │  └─────────────────────────┘ │   │
│                                   │  │  │                              │   │
│                                   │  │  │  ┌─────────────────────────┐ │   │
│                                   │  │  │  │ Verification Agent      │ │   │
│                                   │  │  │  │ (PoC 验证、误报过滤)     │ │   │
│                                   │  │  │  └─────────────────────────┘ │   │
│                                   │  │  └─────────────┬────────────────┘   │
│                                   │  │                │                     │
│                                   │  │  ┌─────────────▼────────────────┐   │
│                                   │  │  │ RAG Engine                     │   │
│                                   │  │  │ • ChromaDB 向量存储           │   │
│                                   │  │  │ • Code Chunk Embedding        │   │
│                                   │  │  │ • CWE/CVE 知识库              │   │
│                                   │  │  └─────────────┬────────────────┘   │
│                                   │  │                │                     │
│                                   │  │  ┌─────────────▼────────────────┐   │
│                                   │  │  │ LLM Gateway (LiteLLM)          │   │
│                                   │  │  │ • OpenAI / Claude / Gemini    │   │
│                                   │  │  │ • 通义千问 / 智谱 / DeepSeek  │   │
│                                   │  │  │ • Ollama (本地模型)           │   │
│                                   │  │  └───────────────────────────────┘   │
│                                   │  └──────────────────────────────────────┘
│                                   │
└───────────────────────────────────┘

                    ┌───────────────┐  ┌───────────────┐  ┌───────────────┐
                    │  PostgreSQL   │  │  ChromaDB     │  │  Redis        │
                    │  (Agent 状态) │  │  (向量库)     │  │  (消息队列)   │
                    └───────────────┘  └───────────────┘  └───────────────┘
```

### 2.2 目录结构

```
CTX-Audit/
├── src/                          # React 前端
│   ├── components/
│   │   ├── audit/                # Agent 审计相关组件
│   │   │   ├── AuditFlow.tsx     # 审计流可视化
│   │   │   ├── AgentLog.tsx      # Agent 思考链日志
│   │   │   └── FindingCard.tsx   # 漏洞卡片（带 AI 评分）
│   │   └── ...
│   ├── pages/
│   │   └── AgentAudit.tsx        # Agent 审计页面
│   └── shared/
│       ├── api/
│       │   └── services/
│       │       └── agentService.ts  # Agent API 客户端
│       └── types/
│           └── agent.ts           # Agent 相关类型定义
│
├── web-backend/                  # Rust 后端（保留）
│   └── src/
│       ├── api/
│       │   ├── mod.rs
│       │   ├── ast.rs
│       │   ├── project.rs
│       │   ├── scanner.rs
│       │   └── agent.rs          # 新增：Agent 代理接口
│       └── main.rs
│
├── agent-service/                # 新增：Python Agent 服务
│   ├── app/
│   │   ├── main.py               # FastAPI 应用入口
│   │   ├── config.py             # 配置管理
│   │   │
│   │   ├── api/                  # API 路由
│   │   │   ├── __init__.py
│   │   │   ├── audit.py          # Agent 审计 API
│   │   │   └── ws.py             # WebSocket/SSE 端点
│   │   │
│   │   ├── agents/               # Multi-Agent 核心逻辑
│   │   │   ├── __init__.py
│   │   │   ├── base.py           # Agent 基类
│   │   │   ├── orchestrator.py   # Orchestrator Agent
│   │   │   ├── recon.py          # Recon Agent
│   │   │   ├── analysis.py       # Analysis Agent
│   │   │   └── verification.py   # Verification Agent
│   │   │
│   │   ├── core/                 # 核心模块
│   │   │   ├── __init__.py
│   │   │   ├── llm.py            # LLM 客户端 (LiteLLM)
│   │   │   ├── rag.py            # RAG 引擎
│   │   │   ├── graph.py          # LangGraph 工作流
│   │   │   ├── state.py          # Agent 状态管理
│   │   │   └── tools.py          # Agent 工具集合
│   │   │
│   │   ├── models/               # 数据模型
│   │   │   ├── __init__.py
│   │   │   ├── audit.py          # 审计相关模型
│   │   │   └── agent.py          # Agent 相关模型
│   │   │
│   │   └── services/             # 服务层
│   │       ├── __init__.py
│   │       ├── rust_client.py    # Rust 后端客户端
│   │       ├── vector_store.py   # 向量数据库服务
│   │       └── queue.py          # 消息队列服务
│   │
│   ├── prompts/                  # 提示词模板
│   │   ├── orchestrator.yaml
│   │   ├── recon.yaml
│   │   ├── analysis.yaml
│   │   └── verification.yaml
│   │
│   ├── tests/                    # 测试
│   │   ├── test_agents.py
│   │   └── test_rag.py
│   │
│   ├── requirements.txt          # Python 依赖
│   ├── pyproject.toml           # 项目配置
│   ├── Dockerfile               # Docker 镜像
│   └── .env.example             # 环境变量示例
│
├── core/                        # Rust 核心库（保留）
│   └── ...
│
├── docker/                      # Docker 配置
│   ├── agent-service/
│   │   └── Dockerfile
│   ├── postgres/
│   │   └── init.sql
│   └── chromadb/
│       └── Dockerfile
│
├── docker-compose.yml           # Docker 编排（更新）
├── docker-compose.dev.yml       # 开发环境编排
└── AGENT_ARCHITECTURE_DESIGN.md # 本文档
```

---

## 3. Multi-Agent 系统设计

### 3.1 Agent 角色定义

#### 3.1.1 Orchestrator Agent（总指挥）

**职责**：
- 接收用户审计任务
- 分析项目类型和技术栈
- 制定审计策略和计划
- 协调子 Agent 的工作
- 汇总结果并生成最终报告

**输入**：
- 项目 ID 或代码路径
- 审计类型（全面审计 / 快速扫描 / 特定漏洞类型）
- 用户配置（模型选择、并发数等）

**输出**：
- 审计计划 JSON
- 子 Agent 任务分配
- 最终审计报告

**关键能力**：
```python
class OrchestratorAgent(BaseAgent):
    """
    总指挥 Agent - 负责任务编排和决策

    能力：
    1. 分析项目结构，识别技术栈
    2. 制定审计策略（漏洞优先级、扫描范围）
    3. 协调子 Agent 执行
    4. 处理子 Agent 的反馈和异常
    5. 生成最终报告
    """

    async def analyze_project(self, project_id: str) -> ProjectContext:
        """分析项目，提取上下文信息"""

    async def create_audit_plan(self, context: ProjectContext) -> AuditPlan:
        """创建审计计划"""

    async def coordinate_agents(self, plan: AuditPlan) -> AuditResult:
        """协调子 Agent 执行计划"""

    async def generate_report(self, results: List[AgentResult]) -> AuditReport:
        """生成最终报告"""
```

#### 3.1.2 Recon Agent（侦察兵）

**职责**：
- 快速扫描项目结构
- 识别框架、库、API
- 提取攻击面（Entry Points）
- 构建项目知识图谱

**输入**：
- 项目路径
- Orchestrator 的侦察指令

**输出**：
- 项目结构树
- 攻击面列表（URL 路由、API 端点、用户输入点等）
- 技术/框架依赖清单

**关键能力**：
```python
class ReconAgent(BaseAgent):
    """
    侦察 Agent - 负责信息收集

    能力：
    1. 扫描项目目录结构
    2. 识别编程语言和框架
    3. 提取 API 端点和路由
    4. 识别用户输入点（表单、API 参数等）
    5. 分析依赖库版本
    """

    async def scan_structure(self, path: str) -> ProjectStructure:
        """扫描项目结构"""

    async def identify_frameworks(self, structure: ProjectStructure) -> List[Framework]:
        """识别使用的框架"""

    async def extract_entry_points(self, code: str) -> List[EntryPoint]:
        """提取攻击面入口点"""

    async def analyze_dependencies(self) -> DependencyReport:
        """分析依赖库（已知漏洞检测）"""
```

#### 3.1.3 Analysis Agent（分析师）

**职责**：
- 结合 RAG 知识库深度审查代码
- 分析业务逻辑漏洞
- 跨文件调用链分析
- 利用 AST 理解代码语义

**输入**：
- Recon Agent 收集的信息
- Rust 后端的 AST 索引和规则扫描结果
- RAG 检索的相关代码片段

**输出**：
- 潜在漏洞列表（带置信度）
- 每个漏洞的详细分析
- 代码上下文和修复建议

**关键能力**：
```python
class AnalysisAgent(BaseAgent):
    """
    分析 Agent - 负责漏洞挖掘

    能力：
    1. 深度代码分析（结合 AST）
    2. 业务逻辑漏洞检测
    3. 跨文件调用链分析
    4. RAG 辅助分析
    5. 降低规则扫描的误报率
    """

    async def analyze_finding(self, finding: RuleFinding) -> AnalyzedFinding:
        """
        分析规则扫描发现

        使用 LLM + RAG 判断：
        - 是否为真实漏洞（降低误报）
        - 漏洞严重程度
        - 利用条件
        """

    async def trace_data_flow(self, entry_point: str) -> DataFlowTrace:
        """
        追踪数据流
        从入口点到敏感操作（SQL、命令执行等）
        """

    async def check_auth_logic(self, route: str) -> AuthAnalysis:
        """
        分析认证/授权逻辑
        检查权限绕过、身份验证缺陷
        """

    async def search_similar_vulnerabilities(
        self, code_pattern: str
    ) -> List[CVEEntry]:
        """
        使用 RAG 搜索相似漏洞模式
        """
```

#### 3.1.4 Verification Agent（验证者）

**职责**：
- 验证 Analysis Agent 发现的漏洞
- 生成 PoC 脚本
- 在沙箱环境中执行（后期实现）
- 过滤误报

**输入**：
- Analysis Agent 的漏洞列表

**输出**：
- 验证后的漏洞列表（剔除误报）
- PoC 脚本（可执行）
- 验证证据（截图、响应等）

**关键能力**：
```python
class VerificationAgent(BaseAgent):
    """
    验证 Agent - 负责 PoC 验证

    能力：
    1. 生成 PoC 脚本
    2. 沙箱环境执行
    3. 误报过滤
    4. 生成验证证据
    """

    async def generate_poc(self, vulnerability: Vulnerability) -> PoCScript:
        """生成验证脚本"""

    async def execute_poc(self, poc: PoCScript) -> VerificationResult:
        """在沙箱中执行 PoC"""

    async def filter_false_positives(
        self, findings: List[Vulnerability]
    ) -> List[Vulnerability]:
        """使用 LLM 过滤误报"""
```

### 3.2 Agent 协作流程

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          Agent 协作流程                                  │
└─────────────────────────────────────────────────────────────────────────┘

   用户                    Orchestrator            Recon                   Analysis
    │                           │                      │                        │
    │  1. 提交审计任务             │                      │                        │
    ├──────────────────────────►│                      │                        │
    │                           │                      │                        │
    │                           │  2. 下达侦察指令        │                        │
    │                           ├─────────────────────►│                        │
    │                           │                      │                        │
    │                           │                      │  3. 扫描项目结构          │
    │                           │                      │  • 识别框架              │
    │                           │                      │  • 提取攻击面            │
    │                           │                      │                        │
    │                           │  4. 返回侦察结果       │                        │
    │                           │◄─────────────────────┤                        │
    │                           │                      │                        │
    │                           │  5. 制定审计计划       │                        │
    │                           │  • 确定扫描范围        │                        │
    │                           │  • 分配优先级          │                        │
    │                           │                      │                        │
    │                           │  6. 调用 Rust 扫描     │                        │
    │                           ├──────────────────────────────────────────────►│
    │                           │                      │                        │
    │                           │                      │                        │  7. 运行规则扫描
    │                           │                      │                        │  • AST 查询
    │                           │                      │                        │  • 正则匹配
    │                           │                      │                        │
    │                           │  8. 扫描结果          │                        │
    │                           │◄──────────────────────────────────────────────┤
    │                           │                      │                        │
    │                           │  9. 分配分析任务       │                        │
    │                           ├──────────────────────────────────────────────►│
    │                           │                      │                        │
    │                           │                      │                        │  10. 深度分析
    │                           │                      │                        │  • RAG 检索
    │                           │                      │                        │  • 数据流追踪
    │                           │                      │                        │  • 业务逻辑检查
    │                           │                      │                        │
    │                           │  11. 返回分析结果      │                        │
    │                           │◄──────────────────────────────────────────────┤
    │                           │                      │                        │
    │  审计流日志 (SSE)           │                      │                        │
    │◄───────────────────────────┤──────────────────────┤────────────────────────┤
    │  • Agent 思考链             │                      │                        │
    │  • 进度更新                 │                      │                        │
    │                           │                      │                        │
    │                           │  12. 调用验证 Agent    │                        │
    │                           ├──────────────────────────────────────────────►│
    │                           │                      │                        │
    │                           │                      │                        │  13. 验证漏洞
    │                           │                      │                        │  • 生成 PoC
    │                           │                      │                        │  • 沙箱执行
    │                           │                      │                        │
    │                           │  14. 验证结果          │                        │
    │                           │◄──────────────────────────────────────────────┤
    │                           │                      │                        │
    │                           │  15. 生成最终报告      │                        │
    │                           │  • 剔除误报           │                        │
    │                           │  • 风险评分           │                        │
    │                           │                      │                        │
    │  16. 返回报告               │                      │                        │
    │◄───────────────────────────┤                      │                        │
    │                           │                      │                        │
```

### 3.3 LangGraph 工作流定义

```python
from langgraph.graph import StateGraph, END
from typing import TypedDict, List, Annotated
import operator

class AuditState(TypedDict):
    """审计状态定义"""
    project_id: str
    audit_type: str
    recon_result: dict
    scan_results: Annotated[List[dict], operator.add]
    analysis_results: Annotated[List[dict], operator.add]
    verification_results: List[dict]
    final_report: dict
    errors: List[str]

def create_audit_graph():
    """创建审计工作流图"""
    workflow = StateGraph(AuditState)

    # 添加节点
    workflow.add_node("orchestrator", orchestrator_node)
    workflow.add_node("recon", recon_node)
    workflow.add_node("rust_scanner", rust_scanner_node)
    workflow.add_node("analysis", analysis_node)
    workflow.add_node("verification", verification_node)
    workflow.add_node("report_generator", report_generator_node)

    # 定义边
    workflow.set_entry_point("orchestrator")

    workflow.add_conditional_edges(
        "orchestrator",
        should_recon,
        {
            "recon": "recon",
            "scan": "rust_scanner",
        }
    )

    workflow.add_edge("recon", "rust_scanner")
    workflow.add_edge("rust_scanner", "analysis")

    workflow.add_conditional_edges(
        "analysis",
        should_verify,
        {
            "verify": "verification",
            "skip": "report_generator",
        }
    )

    workflow.add_edge("verification", "report_generator")
    workflow.add_edge("report_generator", END)

    return workflow.compile()
```

---

## 4. API 接口定义

### 4.1 Agent 服务 API（FastAPI）

#### 4.1.1 启动审计

```http
POST /api/audit/start
Content-Type: application/json

{
  "project_id": "proj_123",
  "audit_type": "full",           # full | quick | targeted
  "target_types": [               # 可选，指定漏洞类型
    "sql_injection",
    "xss",
    "auth_bypass"
  ],
  "config": {
    "llm_model": "claude-3-5-sonnet",
    "max_concurrent": 3,
    "enable_rag": true,
    "enable_verification": true
  }
}

Response:
{
  "audit_id": "audit_abc123",
  "status": "started",
  "estimated_time": 300
}
```

#### 4.1.2 获取审计状态

```http
GET /api/audit/{audit_id}/status

Response:
{
  "audit_id": "audit_abc123",
  "status": "running",             # pending | running | completed | failed
  "progress": {
    "current_stage": "analysis",
    "completed_steps": 5,
    "total_steps": 8,
    "percentage": 62.5
  },
  "agent_status": {
    "orchestrator": "idle",
    "recon": "completed",
    "analysis": "running",
    "verification": "pending"
  },
  "stats": {
    "files_scanned": 234,
    "findings_detected": 15,
    "verified_vulnerabilities": 3
  }
}
```

#### 4.1.3 订阅审计流（SSE）

```http
GET /api/audit/{audit_id}/stream

Response: Server-Sent Events 流

data: {"type": "agent_thinking", "agent": "analysis", "content": "分析 user_login 函数..."}
data: {"type": "agent_thinking", "agent": "analysis", "content": "发现可能的 SQL 注入，追踪数据流..."}
data: {"type": "finding", "data": {"id": "find_1", "type": "sql_injection", "severity": "high", "file": "src/auth.rs:45"}}
data: {"type": "rag_retrieval", "query": "SQL injection authentication bypass", "results": 3}
data: {"type": "progress", "stage": "analysis", "percentage": 45}
data: {"type": "agent_thinking", "agent": "verification", "content": "生成 PoC 脚本..."}
data: {"type": "verification", "finding_id": "find_1", "result": "confirmed", "poc": "..."}
data: {"type": "complete", "audit_id": "audit_abc123"}
```

#### 4.1.4 获取审计结果

```http
GET /api/audit/{audit_id}/result

Response:
{
  "audit_id": "audit_abc123",
  "status": "completed",
  "summary": {
    "total_files": 234,
    "scan_duration": 285,
    "raw_findings": 15,
    "verified_vulnerabilities": 8,
    "false_positives_filtered": 7
  },
  "vulnerabilities": [
    {
      "id": "vuln_1",
      "type": "sql_injection",
      "severity": "critical",
      "confidence": 0.95,
      "title": "用户登录函数存在 SQL 注入漏洞",
      "description": "...",
      "file": "src/auth.rs",
      "line": 45,
      "code_snippet": "SELECT * FROM users WHERE username = '${user_input}'",
      "remediation": "使用参数化查询...",
      "references": [
        {"type": "cwe", "id": "CWE-89", "url": "..."},
        {"type": "owasp", "id": "A03:2021", "url": "..."}
      ],
      "verification": {
        "status": "confirmed",
        "poc_script": "...",
        "evidence": "..."
      }
    }
  ],
  "agent_logs": [
    {
      "agent": "analysis",
      "timestamp": "2025-12-27T10:30:00Z",
      "thinking": "发现 user_login 函数直接拼接用户输入到 SQL 查询中..."
    }
  ]
}
```

### 4.2 Rust 后端新增 API

#### 4.2.1 AST 上下文获取（供 Agent 使用）

```http
POST /api/ast/context
Content-Type: application/json

{
  "file_path": "src/auth.rs",
  "line_range": [40, 50],
  "include_callers": true,
  "include_callees": true
}

Response:
{
  "file": "src/auth.rs",
  "ast": {...},
  "context": {
    "function": "user_login",
    "callers": [
      {"file": "src/routes.rs", "line": 123, "function": "login_route"}
    ],
    "callees": [
      {"file": "src/db.rs", "line": 67, "function": "execute_query"}
    ],
    "data_sources": ["request.body.username"],
    "sensitive_operations": ["SQL query", "file write"]
  }
}
```

#### 4.2.2 批量代码查询

```http
POST /api/ast/batch_query
Content-Type: application/json

{
  "queries": [
    {
      "type": "function_call",
      "pattern": "execute_sql",
      "language": "rust"
    },
    {
      "type": "assignment",
      "pattern": "user_input.*=.*request",
      "language": "rust"
    }
  ]
}

Response:
{
  "results": [
    {
      "query": {...},
      "matches": [
        {"file": "src/auth.rs", "line": 45, "code": "..."},
        {"file": "src/admin.rs", "line": 78, "code": "..."}
      ]
    }
  ]
}
```

---

## 5. 数据流设计

### 5.1 审计数据流

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           审计数据流                                         │
└─────────────────────────────────────────────────────────────────────────────┘

1. 用户提交审计任务
   │
   ├──> POST /api/audit/start
   │
   ▼

2. Orchestrator 创建审计会话
   │
   ├──> 生成 audit_id
   ├──> 初始化 AuditState（存入 PostgreSQL）
   ├──> 推送初始事件到 Redis
   │
   ▼

3. Recon Agent 执行
   │
   ├──> 调用 Rust 后端：GET /api/project/{id}
   ├──> 调用 Rust 后端：POST /api/scanner/list_files
   ├──> 分析项目结构（LLM）
   ├──> 存储结果到 PostgreSQL
   │
   ▼

4. Rust 规则扫描
   │
   ├──> Orchestrator 调用 Rust 后端：POST /api/scanner/scan
   ├──> Rust 返回规则扫描结果
   ├──> 结果存入 PostgreSQL
   │
   ▼

5. Analysis Agent 执行
   │
   ├──> 从 PostgreSQL 获取扫描结果
   ├──> 对每个 finding：
   │     ├──> 调用 Rust 获取 AST 上下文
   │     ├──> RAG 检索相似漏洞
   │     ├──> LLM 深度分析
   │     └── 存储分析结果
   │
   ▼

6. Verification Agent 执行
   │
   ├──> 获取 Analysis Agent 的结果
   ├──> 生成 PoC（LLM）
   ├──> 在沙箱执行（Docker）
   ├──> 过滤误报
   │
   ▼

7. 生成报告
   │
   ├──> 汇总所有 Agent 结果
   ├──> 计算风险评分
   ├──> 生成报告（Markdown/JSON）
   │
   ▼

8. 返回给用户
   │
   └──> GET /api/audit/{id}/result
```

### 5.2 事件流（SSE）

```
Event Stream (GET /api/audit/{id}/stream)
│
├──> [orchestrator] 开始审计任务
├──> [recon] 正在扫描项目结构...
├──> [recon] 发现框架: Express.js, PostgreSQL
├──> [recon] 提取攻击面: 23 个 API 端点
├──> [recon] 侦察完成，发现 3 个用户输入点
├──> [scanner] 开始规则扫描...
├──> [scanner] 扫描完成，发现 15 个潜在问题
├──> [analysis] 分析 finding_1...
│     └──> [rag] 检索到 3 个相似漏洞
│     └──> [analysis] 确认为 SQL 注入，置信度 0.92
├──> [analysis] 分析 finding_2...
│     └──> [analysis] 判定为误报（已验证）
├──> ...
├──> [verification] 验证 vuln_1...
│     └──> [verification] 生成 PoC
│     └──> [verification] 执行成功，漏洞确认
├──> [report] 生成报告
└──> [complete] 审计完成
```

---

## 6. 数据库 Schema

### 6.1 PostgreSQL（Agent 状态管理）

```sql
-- 审计会话表
CREATE TABLE audit_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id VARCHAR(255) NOT NULL,
    audit_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,        -- pending, running, completed, failed
    config JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error TEXT
);

-- Agent 执行记录表
CREATE TABLE agent_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_id UUID REFERENCES audit_sessions(id),
    agent_name VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL,
    input JSONB,
    output JSONB,
    thinking_chain TEXT,                -- Agent 思考链（长文本）
    started_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP,
    duration_ms INTEGER
);

-- 漏洞发现表
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_id UUID REFERENCES audit_sessions(id),
    agent_found VARCHAR(100),           -- 哪个 Agent 发现的
    rule_id VARCHAR(255),               -- 规则 ID（来自扫描器）
    vulnerability_type VARCHAR(100),
    severity VARCHAR(20),               -- critical, high, medium, low, info
    confidence FLOAT,                   -- 0.0 - 1.0
    title TEXT,
    description TEXT,
    file_path VARCHAR(1000),
    line_number INTEGER,
    code_snippet TEXT,
    remediation TEXT,
    references JSONB,                   -- [{type, id, url}]
    verified BOOLEAN DEFAULT FALSE,
    is_false_positive BOOLEAN DEFAULT FALSE,
    verification_evidence JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

-- RAG 查询日志表
CREATE TABLE rag_queries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_id UUID REFERENCES audit_sessions(id),
    finding_id UUID REFERENCES findings(id),
    query_text TEXT NOT NULL,
    embedding VECTOR(1536),             -- pgvector
    results JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

-- 创建索引
CREATE INDEX idx_audit_sessions_project ON audit_sessions(project_id);
CREATE INDEX idx_audit_sessions_status ON audit_sessions(status);
CREATE INDEX idx_agent_executions_audit ON agent_executions(audit_id);
CREATE INDEX idx_findings_audit ON findings(audit_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_verified ON findings(verified);
```

### 6.2 ChromaDB（向量存储）

```python
# ChromaDB Collection 设计

import chromadb

client = chromadb.HttpClient(host="chromadb", port=8000)

# 代码片段集合
code_chunks_collection = client.get_or_create_collection(
    name="code_chunks",
    metadata={"hnsw:space": "cosine"}
)

# 文档结构：
# {
#     "id": "chunk_proj123_src_auth_rs_45_67",
#     "document": "函数 user_login 接收用户名和密码...",
#     "metadata": {
#         "project_id": "proj123",
#         "file": "src/auth.rs",
#         "start_line": 45,
#         "end_line": 67,
#         "language": "rust",
#         "functions": ["user_login"],
#         "features": ["sql_query", "user_input"]
#     },
#     "embedding": [0.1, 0.2, ...]  # OpenAI text-embedding-3-small
# }

# 漏洞知识库集合
vulnerability_kb_collection = client.get_or_create_collection(
    name="vulnerability_kb"
)

# 文档结构：
# {
#     "id": "cwe_89_sql_injection",
#     "document": "CWE-89: SQL 注入漏洞...",
#     "metadata": {
#         "cwe_id": "CWE-89",
#         "owasp": "A03:2021",
#         "severity": "high",
#         "languages": ["php", "java", "python", "rust"],
#         "patterns": ["execute_sql", "query.*user_input"]
#     },
#     "embedding": [...]
# }

# 历史分析结果集合（用于学习）
historical_findings_collection = client.get_or_create_collection(
    name="historical_findings"
)

# 文档结构：
# {
#     "id": "finding_audit456_vuln1",
#     "document": "用户登录函数 SQL 注入漏洞...",
#     "metadata": {
#         "audit_id": "audit456",
#         "type": "sql_injection",
#         "was_true_positive": true,
#         "verified": true
#     },
#     "embedding": [...]
# }
```

---

## 7. RAG 知识库设计

### 7.1 RAG 流程

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           RAG 检索增强生成                                    │
└─────────────────────────────────────────────────────────────────────────────┘

用户查询 / 需分析的代码
        │
        ▼
┌───────────────┐
│ 查询扩展       │
│ • 同义词扩展   │
│ • 上下文补充   │
└───────┬───────┘
        │
        ▼
┌───────────────┐       ┌───────────────┐       ┌───────────────┐
│ 向量检索       │       │ 关键词检索     │       │ 混合检索      │
│ (ChromaDB)    │       │ (代码索引)     │       │ (两者结合)    │
└───────┬───────┘       └───────┬───────┘       └───────┬───────┘
        │                       │                       │
        └───────────────────────┴───────────────────────┘
                                │
                                ▼
                        ┌───────────────┐
                        │ 结果重排序     │
                        │ • Rerank      │
                        │ • 去重        │
                        └───────┬───────┘
                                │
                                ▼
                        ┌───────────────┐
                        │ 上下文构建     │
                        │ • Top-K       │
                        │ • 拼接 Prompt  │
                        └───────┬───────┘
                                │
                                ▼
                        ┌───────────────┐
                        │ LLM 生成       │
                        │ • 携带上下文   │
                        │ • 生成分析     │
                        └───────────────┘
```

### 7.2 知识库来源

| 知识库类型 | 数据来源 | 用途 |
|-----------|---------|------|
| **代码知识库** | 项目代码切片（按函数/类分块） | 语义代码搜索、相似模式识别 |
| **CWE/CVE 库** | MITRE CWE、NVD CVE | 漏洞类型匹配、参考信息 |
| **OWASP 知识库** | OWASP Top 10、ASVS | 安全标准对齐 |
| **历史审计结果** | 过往审计的漏洞记录 | 误报学习、模式匹配 |
| **安全最佳实践** | 安全编码指南、文档 | 修复建议生成 |

### 7.3 RAG Prompt 模板

```yaml
# prompts/analysis_rag.yaml

system_prompt: |
  你是一个资深的安全审计专家。你的任务是分析代码中的安全漏洞。

  参考信息：
  {% for doc in context %}
  - [{{ doc.metadata.type }}] {{ doc.title }}
    {{ doc.content }}
  {% endfor %}

  请基于上述参考信息，分析以下代码：

user_prompt: |
  文件: {{ file_path }}
  代码:
  ```{{ language }}
  {{ code_snippet }}
  ```

  规则扫描结果: {{ rule_result }}

  请分析：
  1. 这是否为真实的安全漏洞？（考虑上下文）
  2. 漏洞类型和严重程度
  3. 利用条件和影响
  4. 修复建议
```

---

## 8. 部署方案

### 8.1 Docker Compose 编排

```yaml
# docker-compose.yml（更新版）

version: '3.8'

services:
  # ============ 前端 ============
  web:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "3000:8000"
    environment:
      - VITE_API_BASE_URL=http://localhost:8000
      - VITE_AGENT_API_BASE_URL=http://localhost:8001
    depends_on:
      - backend
      - agent-service

  # ============ Rust 后端 ============
  backend:
    build:
      context: ./web-backend
      dockerfile: Dockerfile
    ports:
      - "8000:8000"
    volumes:
      - ./data:/app/data
    environment:
      - RUST_LOG=info
      - DATABASE_URL=sqlite:./data/deepaudit.db
      - AGENT_SERVICE_URL=http://agent-service:8001
    restart: unless-stopped

  # ============ Agent 服务 ============
  agent-service:
    build:
      context: ./agent-service
      dockerfile: Dockerfile
    ports:
      - "8001:8001"
    environment:
      # 后端服务
      - RUST_BACKEND_URL=http://backend:8000

      # 数据库
      - DATABASE_URL=postgresql://audit_user:audit_pass@postgres:5432/audit_db

      # 向量数据库
      - CHROMADB_HOST=chromadb
      - CHROMADB_PORT=8000

      # Redis
      - REDIS_URL=redis://redis:6379/0

      # LLM 配置
      - LLM_PROVIDER=litellm
      - LLM_MODEL=claude-3-5-sonnet
      - LLM_API_KEY=${ANTHROPIC_API_KEY}
      - LLM_BASE_URL=https://api.anthropic.com

      # 其他配置
      - RAG_ENABLED=true
      - MAX_CONCURRENT_AGENTS=3
    depends_on:
      - postgres
      - chromadb
      - redis
    restart: unless-stopped
    volumes:
      - ./agent-service/logs:/app/logs

  # ============ PostgreSQL ============
  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=audit_db
      - POSTGRES_USER=audit_user
      - POSTGRES_PASSWORD=audit_pass
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./docker/postgres/init.sql:/docker-entrypoint-initdb.d/init.sql
    ports:
      - "5432:5432"
    restart: unless-stopped

  # ============ ChromaDB ============
  chromadb:
    image: chromadb/chroma:latest
    environment:
      - CHROMA_SERVER_HOST=0.0.0.0
      - CHROMA_SERVER_PORT=8000
    volumes:
      - chromadb_data:/chroma/chroma
    ports:
      - "8002:8000"
    restart: unless-stopped

  # ============ Redis ============
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    restart: unless-stopped

volumes:
  postgres_data:
  chromadb_data:
  redis_data:
```

### 8.2 开发环境配置

```yaml
# docker-compose.dev.yml

version: '3.8'

services:
  backend-dev:
    build:
      context: ./web-backend
      dockerfile: Dockerfile.dev
    volumes:
      - ./web-backend/src:/app/src
    # ...

  agent-dev:
    build:
      context: ./agent-service
      dockerfile: Dockerfile.dev
    volumes:
      - ./agent-service/app:/app/app
      - ./agent-service/prompts:/app/prompts
    environment:
      - DEBUG=true
      - LOG_LEVEL=debug
    # ...
```

---

## 9. 安全考虑

### 9.1 LLM API 安全

| 风险 | 缓解措施 |
|------|----------|
| **代码泄露** | 支持本地 LLM（Ollama），敏感代码不外传 |
| **API Key 泄露** | 密钥加密存储，定期轮换 |
| **注入攻击** | Prompt 注入防护，输出验证 |

### 9.2 沙箱隔离（后期实现）

```python
# 沙箱配置
SANDBOX_CONFIG = {
    "docker_image": "deepaudit-sandbox:latest",
    "network": "none",           # 无网络访问
    "memory_limit": "512m",
    "cpu_limit": "1.0",
    "timeout": 30,               # 30 秒超时
    "read_only": True,           # 只读文件系统
}
```

### 9.3 访问控制

- Agent 服务仅内网访问
- API 认证（JWT 或 API Key）
- 审计日志记录所有操作

---

## 10. 实施路线图

### Phase 1: 基础框架（1-2 周）

- [ ] 创建 `agent-service` 目录结构
- [ ] 搭建 FastAPI 基础服务
- [ ] 实现与 Rust 后端的 HTTP 通信
- [ ] 配置 PostgreSQL + ChromaDB
- [ ] 编写 Docker 编排文件

### Phase 2: Agent 实现（2-3 周）

- [ ] 实现 BaseAgent 基类
- [ ] 实现 Orchestrator Agent
- [ ] 实现 Recon Agent
- [ ] 实现 Analysis Agent（核心）
- [ ] 集成 RAG 功能
- [ ] 配置 LiteLLM

### Phase 3: 前端集成（1-2 周）

- [ ] 创建 Agent 审计页面
- [ ] 实现审计流可视化（SSE）
- [ ] 实现漏洞详情展示
- [ ] 实现 Agent 思考链日志

### Phase 4: 验证和优化（1-2 周）

- [ ] 端到端测试
- [ ] 性能优化
- [ ] 误报率测试
- [ ] 文档完善

### Phase 5: 高级功能（后期）

- [ ] Verification Agent + 沙箱
- [ ] 增量审计（PR 集成）
- [ ] 自动修复（Auto-Fix）
- [ ] 自定义 RAG 知识库

---

## 附录

### A. 环境变量配置

```bash
# .env.example

# ============ Agent 服务 ============
AGENT_PORT=8001
LOG_LEVEL=info

# ============ Rust 后端 ============
RUST_BACKEND_URL=http://localhost:8000

# ============ 数据库 ============
DATABASE_URL=postgresql://audit_user:audit_pass@localhost:5432/audit_db

# ============ 向量数据库 ============
CHROMADB_HOST=localhost
CHROMADB_PORT=8002

# ============ Redis ============
REDIS_URL=redis://localhost:6379/0

# ============ LLM 配置 ============
# 方式1: 直接配置
LLM_PROVIDER=anthropic
LLM_MODEL=claude-3-5-sonnet-20241022
ANTHROPIC_API_KEY=sk-ant-xxx

# 方式2: 通过 LiteLLM
LLM_PROVIDER=litellm
LLM_MODEL=anthropic/claude-3-5-sonnet
LITELLM_API_KEY=sk-xxx
LITELLM_BASE_URL=http://localhost:4000

# ============ RAG 配置 ============
RAG_ENABLED=true
EMBEDDING_MODEL=text-embedding-3-small
CHUNK_SIZE=500
CHUNK_OVERLAP=50
TOP_K_RETRIEVAL=5

# ============ Agent 配置 ============
MAX_CONCURRENT_AGENTS=3
AGENT_TIMEOUT=300
ENABLE_VERIFICATION=false

# ============ 其他 ============
SENTRY_DSN=
TELEMETRY_ENABLED=false
```

### B. Python 依赖

```txt
# agent-service/requirements.txt

# Web 框架
fastapi==0.115.0
uvicorn[standard]==0.32.0
pydantic==2.9.2
pydantic-settings==2.6.0

# Agent 框架
langgraph==0.2.45
langchain==0.3.7
langchain-anthropic==0.2.1
langchain-community==0.3.5

# LLM
litellm==1.52.13
anthropic==0.40.0

# 数据库
asyncpg==0.29.0
sqlalchemy==2.0.35
alembic==1.14.0
psycopg2-binary==2.9.9

# 向量数据库
chromadb==0.5.23
sentence-transformers==3.3.1

# 缓存/队列
redis==5.2.0
hiredis==3.1.0

# 工具
httpx==0.27.2
aiofiles==24.1.0
python-multipart==0.0.12
python-dotenv==1.0.1

# 日志/监控
loguru==0.7.2
sentry-sdk==2.18.0

# 测试
pytest==8.3.3
pytest-asyncio==0.24.0
pytest-mock==3.14.0
```

### C. API 类型定义（TypeScript）

```typescript
// src/shared/types/agent.ts

export interface AuditStartRequest {
  project_id: string;
  audit_type: 'full' | 'quick' | 'targeted';
  target_types?: VulnerabilityType[];
  config?: AuditConfig;
}

export interface AuditConfig {
  llm_model?: string;
  max_concurrent?: number;
  enable_rag?: boolean;
  enable_verification?: boolean;
}

export interface AuditStatusResponse {
  audit_id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  progress: {
    current_stage: string;
    completed_steps: number;
    total_steps: number;
    percentage: number;
  };
  agent_status: Record<string, 'idle' | 'running' | 'completed' | 'failed'>;
  stats: {
    files_scanned: number;
    findings_detected: number;
    verified_vulnerabilities: number;
  };
}

export interface Vulnerability {
  id: string;
  type: VulnerabilityType;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: number;
  title: string;
  description: string;
  file: string;
  line: number;
  code_snippet: string;
  remediation: string;
  references: Reference[];
  verification?: VerificationInfo;
}

export type VulnerabilityType =
  | 'sql_injection'
  | 'xss'
  | 'command_injection'
  | 'path_traversal'
  | 'ssrf'
  | 'xxe'
  | 'insecure_deserialization'
  | 'hardcoded_secret'
  | 'weak_crypto'
  | 'authentication_bypass'
  | 'authorization_bypass'
  | 'idor';

export interface AuditStreamEvent =
  | { type: 'agent_thinking'; agent: string; content: string }
  | { type: 'finding'; data: Vulnerability }
  | { type: 'rag_retrieval'; query: string; results: number }
  | { type: 'progress'; stage: string; percentage: number }
  | { type: 'verification'; finding_id: string; result: 'confirmed' | 'false_positive'; poc?: string }
  | { type: 'complete'; audit_id: string };
```

---

## 更新日志

| 版本 | 日期 | 更改内容 |
|------|------|----------|
| 1.0.0 | 2025-12-27 | 初始版本 |

---

**文档维护**: CTX-Audit Team
**最后更新**: 2025-12-27
