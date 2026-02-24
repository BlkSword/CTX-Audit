# CTX-Audit 多 Agent 系统升级方案

## 概述

基于 Claude Code Agent Teams 框架的精华，升级当前的 Boss-Worker 系统。

**核心改进**:
1. ✅ 重命名为 Coordinator-Specialist (协调器-专家) 架构
2. ✅ 共享任务列表 + 自我认领机制
3. ✅ Peer-to-Peer 消息系统 (Mailbox)
4. ✅ 任务依赖管理
5. ✅ 委派模式 (Delegation Mode)
6. ✅ 文件锁定机制
7. ✅ 架构选择器 (支持 Boss-Worker 和 Coordinator-Specialist)

## 进度

### ✅ 阶段 1: 核心基础设施 (已完成)
- [x] 实现 SharedTaskList
- [x] 实现 Mailbox
- [x] 实现 TaskDependencyGraph

### ✅ 阶段 2: 组件重构 (已完成)
- [x] BossAgent → Coordinator (保留 legacy)
- [x] WorkerAgent → Specialist (保留 legacy)
- [x] 添加 Architecture 枚举用于架构选择
- [x] 实现 UnifiedMultiAgentSystem 统一接口

### 🔄 阶段 3: 新功能 (进行中)
- [x] 委派模式基础框架
- [x] Peer-to-Peer 消息基础框架
- [ ] 任务依赖管理完善
- [ ] 发现质疑与验证机制

### ⏳ 阶段 4: 测试与优化 (待进行)
- [ ] 集成测试
- [ ] 性能优化
- [ ] 文档更新

## 使用方式

### 使用新的 Coordinator-Specialist 架构

```rust
use ctx_audit_agent_engine::multi_agent::{
    system::{create_multi_agent_system, MultiAgentConfig, Architecture},
    coordinator::AuditTeamConfig,
};

// 方式 1: 使用统一接口
let config = MultiAgentConfig::standard()
    .with_coordinator_specialist(); // 启用新架构

let mut system = create_multi_agent_system(llm, tools, config).await?;
system.start(project_path).await?;
let report = system.audit(project_path, audit_state).await?;

// 方式 2: 直接使用 Coordinator-Specialist
let config = AuditTeamConfig::standard();
let mut system = AuditTeamSystem::new(config);
system.start().await?;
let report = system.orchestrate_audit(project_path).await?;
```

### 保持使用 Boss-Worker 架构 (默认)

```rust
// 默认使用 Boss-Worker
let config = MultiAgentConfig::standard();
let mut system = MultiAgentSystem::new(llm, tools, config).await?;
```

## 新架构

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AuditTeamSystem (审计团队系统)                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐      ┌──────────────────┐      ┌────────────────────┐   │
│  │ Coordinator │◄─────┤ SharedTaskList  │◄─────┤ TaskDependencyGraph │   │
│  │  协调器      │      │  共享任务列表    │      │   任务依赖图        │   │
│  └──────┬───────┘      └──────────────────┘      └────────────────────┘   │
│         │                                                                   │
│         │                    Mailbox (消息系统)                            │
│         │                                                                   │
│    ┌────┴─────────────────────────────────────────────────────────────┐   │
│    │                                                                  │   │
│    ▼                                                                  ▼   │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐               │
│  │ SQL          │    │ XSS          │    │ Auth         │  ...          │
│  │ Specialist   │    │ Specialist   │    │ Specialist   │               │
│  └──────┬───────┘    └──────────────┘    └──────────────┘               │
│         │                                                                  │
│         └──────────── Peer-to-Peer Messages ──────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 核心组件

### 1. SharedTaskList (共享任务列表)

**核心特性**:
- 任务状态: Pending → InProgress → Completed → Failed
- 自我认领机制 (Self-claim)
- 任务优先级队列
- 文件锁定防冲突

```rust
pub struct SharedTaskList {
    /// 任务列表 (使用 RwLock 实现并发安全)
    tasks: Arc<RwLock<HashMap<TaskId, AuditTask>>>,

    /// 待处理任务队列 (按优先级排序)
    pending_queue: Arc<Mutex<BinaryHeap<TaskPriorityEntry>>>,

    /// 文件锁 (防止冲突)
    file_locks: Arc<RwLock<HashMap<String, TaskId>>>,

    /// 任务依赖图
    dependency_graph: TaskDependencyGraph,
}
```

### 2. Mailbox (消息系统)

**核心特性**:
- Peer-to-Peer 直接消息
- Broadcast 广播消息
- 自动消息传递
- 消息优先级

```rust
pub struct Mailbox {
    /// 各 Specialist 的消息队列
    queues: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,

    /// 消息总线 (广播)
    broadcast_tx: broadcast::Sender<Message>,
}
```

### 3. TaskDependencyGraph (任务依赖图)

```rust
pub struct TaskDependencyGraph {
    /// 依赖关系: task_id -> 依赖的任务列表
    dependencies: HashMap<String, Vec<String>>,

    /// 被依赖关系: task_id -> 依赖此任务的任务列表
    dependents: HashMap<String, Vec<String>>,

    /// 阻塞状态
    blocked_tasks: HashSet<String>,
}
```

### 4. Coordinator (协调器)

**核心职责**:
- 任务分解与依赖管理
- 监控任务进度
- 处理协助请求
- 结果综合

### 5. Specialist (专家)

**核心职责**:
- 自我认领任务
- Peer-to-Peer 通信
- 发现质疑机制
- 工作记忆

## 迁移路径

### 阶段 1: 核心基础设施 ✅
1. ✅ 实现 SharedTaskList
2. ✅ 实现 Mailbox
3. ✅ 实现 TaskDependencyGraph

### 阶段 2: 组件重构 ✅
1. ✅ BossAgent → Coordinator
2. ✅ WorkerAgent → Specialist
3. ✅ 保留 ResultAggregator 和 CrossValidator

### 阶段 3: 新功能 🔄
1. ✅ 委派模式
2. ✅ Peer-to-Peer 消息
3. ⏳ 任务依赖管理

### 阶段 4: 测试与优化 ⏳
1. ⏳ 单元测试
2. ⏳ 集成测试
3. ⏳ 性能优化

## 向后兼容

保留原有 API，通过配置控制:

```rust
pub enum Architecture {
    BossWorker,                // 默认
    CoordinatorSpecialist,    // 新架构
}

pub struct MultiAgentConfig {
    pub architecture: Architecture,
    // ... 其他字段
}
```

## 配置文件变更

```toml
[audit_team]
# 选择架构: "boss_worker" 或 "coordinator_specialist"
architecture = "coordinator_specialist"

# 启用委派模式
delegation_mode = true

# 协调器配置
[audit_team.coordinator]
max_parallel_tasks = 5
monitoring_interval_ms = 100

# 专家配置
[audit_team.specialists]
sql_experts = 1
xss_experts = 1
auth_experts = 1
business_logic_experts = 1
general_analysts = 1

# 任务配置
[audit_team.tasks]
default_timeout_secs = 300
max_retries = 2

# 消息配置
[audit_team.messaging]
message_queue_size = 1000
broadcast_queue_size = 100

# 文件锁配置
[audit_team.file_locks]
enabled = true
lock_timeout_secs = 600
```

