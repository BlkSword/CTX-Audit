# CTX-Audit Agent 系统重构计划

## 📊 现状分析

### 当前项目 (CTX-Audit) vs DeepAudit-3.0.0 对比

| 维度 | CTX-Audit (当前) | DeepAudit-3.0.0 | 差距 |
|------|------------------|-----------------|------|
| **LLM 模式** | OpenAI Tool Calling | ReAct 文本模式 | ⚠️ 不兼容 |
| **Agent 框架** | ToolCallLoop | LangGraph + ReAct | ⚠️ 架构差异大 |
| **事件系统** | event_bus_v2 (简单) | EventManager + SSE | ⚠️ 缺少流式推送 |
| **前端同步** | 轮询 API | SSE 实时推送 | ⚠️ 实时性差 |
| **状态管理** | 分散在多处 | 统一在 AgentTask 模型 | ⚠️ 不一致 |
| **工具系统** | MCP 工具 | 自定义工具 + AgentTool | ⚠️ 已适配 |
| **Agent 树** | agent_registry | agent_registry + TaskHandoff | ⚠️ 缺少交接协议 |
| **进度跟踪** | 简单计数 | 详细统计 (tokens, iterations, files) | ⚠️ 信息不足 |
| **错误处理** | 基础异常捕获 | 详细错误事件 + 重试 | ⚠️ 不够健壮 |

---

## 🔴 核心问题

### 1. LLM 模式不兼容

**当前问题**：
- 使用 OpenAI Function Calling 格式：`{"type": "function", "function": {...}}`
- LLM 返回 `tool_calls` 数组
- 需要解析 JSON 格式的工具调用

**DeepAudit 方式**：
- 使用 ReAct 文本模式：
  ```
  Thought: 我需要分析这个文件
  Action: read_file
  Action Input: {"file_path": "src/main.py"}
  ```
- LLM 返回纯文本
- 用正则表达式解析

### 2. 前端状态同步延迟

**当前问题**：
- 前端定时轮询 `/api/audit/{id}/status`
- 最快每 5 秒更新一次
- 容易产生大量重复请求

**DeepAudit 方式**：
- SSE (Server-Sent Events) 实时推送
- 事件类型：`llm_thought`, `tool_call`, `finding_new` 等
- 断线自动重连
- 支持 `after_sequence` 增量同步

### 3. 缺少 Agent 间协作机制

**当前问题**：
- Orchestrator 直接调度子 Agent
- 没有结构化的上下文传递
- 子 Agent 重复工作

**DeepAudit 方式**：
- TaskHandoff 协议
- 结构化的工作摘要传递
- 建议的下一步行动
- 优先级区域标记

### 4. 进度统计不完整

**当前问题**：
- 只有基本的 `findings_count`
- 没有 token 使用统计
- 没有迭代次数统计
- 没有工具调用次数统计

**DeepAudit 方式**：
```python
{
    "total_iterations": 15,
    "tool_calls_count": 42,
    "tokens_used": 12580,
    "total_files": 120,
    "analyzed_files": 45,
    "findings_count": 8,
    "verified_count": 5,
}
```

---

## 📋 详细重构计划

### 阶段一：核心架构重构 (2-3天)

#### 1.1 实现统一的 AgentEvent 系统

**目标**：替换现有的 event_bus_v2，使用与 DeepAudit 兼容的事件系统

**任务**：
- [ ] 创建 `app/services/event_manager.py`
  - `EventManager` 类：事件队列管理
  - `AgentEventEmitter` 类：事件发射器
  - 事件类型：`llm_thought`, `tool_call`, `tool_result`, `finding_new`, `finding_verified`

- [ ] 创建 `app/services/streaming.py`
  - `StreamHandler` 类：处理 LangGraph 事件
  - `StreamEventType` 枚举：定义所有流式事件类型
  - SSE 格式转换器

- [ ] 更新 `app/api/audit.py`
  - 添加 `GET /api/audit/{audit_id}/stream` 端点
  - 返回 `text/event-stream` 格式
  - 支持 `after_sequence` 参数

**验收标准**：
- 事件能正确存储到数据库
- SSE 端点能推送实时事件
- 前端能接收并解析事件

#### 1.2 重构 Orchestrator 为 ReAct 模式

**目标**：放弃 Tool Calling，使用 ReAct 文本模式

**任务**：
- [ ] 创建 `app/core/react_agent.py`
  ```python
  class ReActAgent:
      def _parse_response(self, response: str) -> AgentStep:
          # 解析 Thought, Action, Action Input
          pass

      def _build_prompt(self, context: Dict) -> str:
          # 构建 ReAct 格式 prompt
          pass
  ```

- [ ] 更新 `app/agents/orchestrator.py`
  - 继承 `ReActAgent`
  - 使用 ReAct prompt 模板
  - 正则解析 LLM 输出

- [ ] 更新 `app/agents/analysis.py`
  - 移除 `ToolCallLoop`
  - 使用 `ReActAgent` 基类
  - 简化工具调用逻辑

**验收标准**：
- Orchestrator 能正确解析 ReAct 格式
- 子 Agent 能响应 ReAct 指令
- 工具调用不再依赖 Function Calling

#### 1.3 实现 TaskHandoff 协议

**目标**：Agent 之间结构化传递上下文

**任务**：
- [ ] 创建 `app/core/task_handoff.py`
  ```python
  @dataclass
  class TaskHandoff:
      from_agent: str
      to_agent: str
      summary: str
      work_completed: List[str]
      key_findings: List[Dict]
      insights: List[str]
      suggested_actions: List[Dict]
      priority_areas: List[str]

      def to_prompt_context(self) -> str:
          # 转换为 LLM 可读格式
          pass
  ```

- [ ] 更新 `app/agents/base.py`
  - 添加 `create_handoff()` 方法
  - 添加 `receive_handoff()` 方法

- [ ] 更新 Orchestrator
  - 接收子 Agent 的 handoff
  - 传递给下一个子 Agent

**验收标准**：
- Agent 能生成结构化的 handoff
- 下一个 Agent 能正确解析 handoff
- 减少重复工作

---

### 阶段二：前端状态同步重构 (1-2天)

#### 2.1 实现前端 SSE 客户端

**目标**：替换轮询，使用 SSE 实时接收事件

**任务**：
- [ ] 创建 `src/shared/api/agentStream.ts`
  ```typescript
  export class AgentStreamHandler {
    connect(): void
    disconnect(): void
    private parseSSE(buffer: string)
    private handleEvent(event: StreamEventData)
  }
  ```

- [ ] 创建 `src/hooks/useAgentStream.ts`
  ```typescript
  export function useAgentStream(auditId: string) {
    return {
      events, thinking, toolCalls,
      findings, progress, isComplete
    }
  }
  ```

- [ ] 更新 `src/pages/AgentAudit/EnhancedAuditPage.tsx`
  - 移除定时轮询
  - 使用 `useAgentStream` hook
  - 监听 `status` 事件更新状态

**验收标准**：
- 前端能实时接收后端事件
- 断线自动重连
- 减少 API 调用

#### 2.2 重构状态管理

**目标**：统一使用流式事件更新状态

**任务**：
- [ ] 更新 `src/pages/AgentAudit/useAgentAuditState.ts`
  - 添加 `handleStreamEvent()` 方法
  - 处理所有事件类型
  - 自动更新统计信息

- [ ] 添加状态计算
  ```typescript
  const tokenCount = events.reduce(...)
  const toolCallCount = events.filter(...)
  ```

**验收标准**：
- 状态完全由事件驱动
- 不需要手动轮询
- 统计信息准确

---

### 阶段三：统计和监控增强 (1天)

#### 3.1 完善统计信息

**任务**：
- [ ] 更新 `app/services/database.py`
  - 添加 `tokens_used` 字段
  - 添加 `iterations` 字段
  - 添加 `tool_calls_count` 字段

- [ ] 更新 Orchestrator
  - 每次迭代更新统计
  - 每次 LLM 调用记录 tokens
  - 每次工具调用计数

- [ ] 更新 API 响应
  ```python
  class AuditTaskResponse(BaseModel):
      total_iterations: int
      tool_calls_count: int
      tokens_used: int
      analyzed_files: int
      findings_count: int
  ```

**验收标准**：
- 统计信息准确
- 前端能显示详细统计

#### 3.2 添加错误追踪

**任务**：
- [ ] 添加 `error` 事件
- [ ] 记录错误堆栈
- [ ] 前端显示错误详情

**验收标准**：
- 所有错误被捕获
- 错误信息清晰
- 方便调试

---

### 阶段四：测试和优化 (1天)

#### 4.1 端到端测试

**任务**：
- [ ] 测试完整审计流程
- [ ] 测试 SSE 连接稳定性
- [ ] 测试断线重连
- [ ] 测试取消功能

#### 4.2 性能优化

**任务**：
- [ ] 减少不必要的数据库查询
- [ ] 优化事件队列
- [ ] 批量更新统计信息

---

## 🎯 优先级排序

### P0 (必须做)
1. ✅ 工具系统修复 (已完成)
2. 🔴 ReAct 模式重构
3. 🔴 SSE 事件推送
4. 🔴 前端 SSE 客户端

### P1 (重要)
5. 🟡 TaskHandoff 协议
6. 🟡 统计信息完善
7. 🟡 错误处理增强

### P2 (可选)
8. 🟢 Agent 树可视化
9. 🟢 进度预测
10. 🟢 报告生成

---

## 📁 文件清单

### 需要创建的文件

```
agent-service/app/services/
├── event_manager.py          # 事件管理器
├── streaming/
│   ├── __init__.py
│   ├── stream_handler.py     # SSE 处理器
│   └── stream_types.py       # 事件类型定义
└── react_agent.py            # ReAct Agent 基类

agent-service/app/core/
└── task_handoff.py           # TaskHandoff 协议

src/shared/api/
└── agentStream.ts            # SSE 客户端

src/hooks/
└── useAgentStream.ts         # React Hook
```

### 需要修改的文件

```
agent-service/app/agents/
├── orchestrator.py           # 重构为 ReAct
├── analysis.py               # 使用 ReAct
└── base.py                   # 添加 handoff 支持

agent-service/app/api/
└── audit.py                  # 添加 SSE 端点

src/pages/AgentAudit/
├── EnhancedAuditPage.tsx     # 使用 SSE
└── useAgentAuditState.ts     # 事件驱动状态
```

---

## 🚀 实施步骤

### 第 1 步：ReAct 模式重构 (后端)
1. 创建 `ReActAgent` 基类
2. 更新 Orchestrator 使用 ReAct
3. 更新子 Agent
4. 测试工具调用

### 第 2 步：SSE 事件推送 (后端)
1. 创建 `EventManager`
2. 添加 SSE 端点
3. 在 Agent 中发射事件
4. 测试事件推送

### 第 3 步：SSE 客户端 (前端)
1. 创建 `AgentStreamHandler`
2. 创建 `useAgentStream` hook
3. 集成到审计页面
4. 测试实时更新

### 第 4 步：TaskHandoff (后端)
1. 创建 `TaskHandoff` 类
2. 更新 Agent 基类
3. 实现交接逻辑
4. 测试协作效果

### 第 5 步：统计和优化
1. 完善统计字段
2. 添加错误追踪
3. 性能优化
4. 端到端测试

---

## ⚠️ 风险和注意事项

1. **ReAct 模式稳定性**：正则解析可能失败，需要添加容错
2. **SSE 连接管理**：需要处理断线、超时、重连
3. **向后兼容**：确保旧 API 仍然可用
4. **性能影响**：大量事件可能影响性能
5. **测试覆盖**：需要全面的测试

---

## 📊 预期效果

完成后：
- ✅ 实时显示 LLM 思考过程
- ✅ 工具调用实时可视化
- ✅ 减少 90% 的 API 轮询
- ✅ 统计信息完整准确
- ✅ Agent 协作更高效
- ✅ 错误信息更清晰
