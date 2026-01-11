# 前端审计页面修复方案

## 问题分析

### 1. 消息更新和持久化问题

#### 1.1 事件类型映射不一致

**问题**：后端和前端的事件类型映射可能不一致，导致部分事件丢失或显示不正确。

**后端事件类型**（来自 audit.py 和 event_manager.py）：
- `status` - 状态变更
- `thinking` - LLM 思考
- `tool_call` - 工具调用开始
- `tool_result` - 工具调用结果
- `finding` - 发现漏洞
- `progress` - 进度更新
- `error` - 错误

**前端日志类型**（来自 types.ts）：
- `thinking` - 思考
- `tool` - 工具调用
- `observation` - 观察结果
- `finding` - 发现
- `progress` - 进度
- `phase` - 阶段变更
- `complete` - 完成
- `info` - 信息
- `error` - 错误

#### 1.2 日志持久化问题

**问题**：
- 日志只存储在内存中，页面刷新后丢失
- 没有使用 localStorage 进行持久化

### 2. 审计报告生成功能问题

#### 2.1 后端 API 端点

**文件**：`agent-service/app/api/audit.py`

**端点**：`GET /{audit_id}/report?format={markdown|json|html}`

**实现状态**：✅ 已完整实现

#### 2.2 前端调用

**文件**：`src/pages/AgentAudit/components/ReportExportDialog.tsx`

**问题**：
- API 基础 URL 可能配置不正确
- 错误处理可能不够友好

### 3. 前端展示效果问题

#### 3.1 与 DeepAudit-3.0.0 的差距

**DeepAudit-3.0.0 的优秀特性**：
1. 打字机效果（thinking_token 事件）
2. 更流畅的动画过渡
3. 更好的视觉反馈
4. 事件节流优化
5. 更丰富的统计面板

**当前项目缺失**：
1. 打字机效果
2. 流畅的动画
3. 事件节流
4. 更好的统计可视化

## 修复方案

### 修复 1：统一事件类型映射

**文件**：`src/pages/AgentAudit/api.ts`

**修改内容**：
- 完善 `eventToLogItem` 函数的事件类型映射
- 确保所有后端事件都能正确转换

### 修复 2：实现日志持久化

**文件**：`src/pages/AgentAudit/useAgentAuditState.ts`

**修改内容**：
- 添加 localStorage 持久化
- 页面刷新后恢复日志

### 修复 3：修复报告导出功能

**文件**：`src/pages/AgentAudit/components/ReportExportDialog.tsx`

**修改内容**：
- 确保正确的 API 调用
- 改进错误处理

### 修复 4：增强前端视觉效果

**文件**：`src/components/audit/ChatLogPanel.tsx`

**修改内容**：
- 添加打字机效果
- 改进动画
- 添加事件节流

## 优先级

1. **高优先级**（立即修复）：
   - ✅ 统一事件类型映射
   - ✅ 修复报告导出功能

2. **中优先级**（下个版本）：
   - ⏳ 实现日志持久化
   - ⏳ 增强视觉效果

3. **低优先级**（优化）：
   - ⏳ 添加打字机效果
   - ⏳ 改进统计可视化
