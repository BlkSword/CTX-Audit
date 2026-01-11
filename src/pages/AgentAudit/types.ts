/**
 * Agent 审计页面类型定义
 * 参考 DeepAudit-3.0.0 实现
 */

// ==================== 任务相关 ====================

export interface AgentTask {
  id: string
  project_id: string
  audit_type: 'quick' | 'full' | 'targeted'
  status: TaskStatus
  current_phase?: string
  progress_percentage: number
  total_files: number
  indexed_files: number
  analyzed_files: number
  findings_count: number
  created_at: string
  updated_at: string
  started_at?: string
  completed_at?: string
  error?: string
}

export type TaskStatus =
  | 'pending'
  | 'running'
  | 'paused'
  | 'completed'
  | 'failed'
  | 'cancelled'

// ==================== 发现相关 ====================

export interface AgentFinding {
  id: string
  task_id: string
  vulnerability_type: string
  severity: FindingSeverity
  title: string
  description: string
  file_path?: string
  line_start?: number
  line_end?: number
  code_snippet?: string
  recommendation?: string
  references?: string[]
  status: FindingStatus
  is_verified: boolean
  confidence?: number
  created_at: string
}

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type FindingStatus = 'new' | 'investigating' | 'confirmed' | 'false_positive' | 'fixed'

// ==================== 事件相关 ====================

export interface AgentEvent {
  id: string
  task_id: string
  event_type: EventType
  sequence: number
  timestamp: string
  agent_type: AgentType
  message?: string
  tool_name?: string
  tool_input?: Record<string, unknown>
  tool_output?: unknown
  tool_duration_ms?: number
  thought?: string
  accumulated_thought?: string
  finding?: Partial<AgentFinding>
  progress?: {
    current?: number
    total?: number
    message?: string
    percentage?: number
  }
  metadata?: Record<string, unknown>
  // 后端事件数据
  data?: Record<string, unknown>
}

export type EventType =
  // 任务事件
  | 'task_start'
  | 'task_complete'
  | 'task_error'
  | 'task_cancel'
  | 'status'  // 后端状态更新事件
  // LLM 相关（新增）
  | 'llm_start'
  | 'llm_thought'
  | 'llm_decision'
  | 'llm_action'
  | 'llm_complete'
  // 阶段事件
  | 'phase_start'
  | 'phase_end'
  | 'phase_complete'
  // Agent 思考
  | 'thinking'
  | 'thinking_start'
  | 'thinking_token'
  | 'thinking_end'
  | 'planning'
  | 'decision'
  // 工具调用
  | 'tool_call_start'
  | 'tool_call'
  | 'tool_result'
  | 'tool_call_end'
  | 'tool_error'
  // 发现
  | 'finding'
  | 'finding_new'
  | 'finding_update'
  | 'finding_verified'
  | 'finding_false_positive'
  // 进度
  | 'progress'
  | 'info'
  | 'warning'
  | 'error'
  // Agent
  | 'agent_start'
  | 'agent_complete'
  | 'heartbeat'
  | 'connected'

export type AgentType = 'ORCHESTRATOR' | 'RECON' | 'ANALYSIS' | 'VERIFICATION' | 'SYSTEM'

// ==================== Agent 树相关 ====================

export interface AgentTreeNode {
  agent_id: string
  agent_type: AgentType
  agent_name: string
  status: AgentNodeStatus
  task?: string
  children?: AgentTreeNode[]
  parent_id?: string
  created_at: string
  updated_at: string
}

export type AgentNodeStatus =
  | 'created'
  | 'running'
  | 'waiting'
  | 'completed'
  | 'failed'
  | 'stopped'
  | 'idle'

export interface AgentTreeResponse {
  roots: AgentTreeNode[]
  total_count: number
  running_count: number
  completed_count: number
}

// ==================== 日志相关 ====================

export interface LogItem {
  id: string
  type: LogType
  agent_type: AgentType
  timestamp: number
  content: string
  data?: Record<string, unknown>
  expanded?: boolean
  sequence?: number
  // 日志特有字段
  title?: string
  progressKey?: string
  isComplete?: boolean
  accumulatedContent?: string
  toolName?: string
  toolInput?: Record<string, unknown>
  toolOutput?: unknown
  finding?: Partial<AgentFinding>
}

export type LogType =
  | 'thinking'
  | 'tool'
  | 'observation'
  | 'finding'
  | 'dispatch'
  | 'phase'
  | 'info'
  | 'error'
  | 'progress'
  | 'complete'

// ==================== 连接状态 ====================

export type ConnectionStatus =
  | 'disconnected'
  | 'connecting'
  | 'connected'
  | 'reconnecting'
  | 'failed'

// ==================== UI 状态 ====================

export interface AgentAuditUIState {
  isAutoScroll: boolean
  showAllLogs: boolean
  selectedAgentId: string | null
  expandedLogIds: Set<string>
  isLoading: boolean
  error: string | null
  connectionStatus: ConnectionStatus
  historicalEventsLoaded: boolean
  afterSequence: number
}

// ==================== 统计相关 ====================

export interface AuditStats {
  total_events: number
  by_type: Record<string, number>
  latest_sequence: number
}

// ==================== API 请求/响应 ====================

export interface GetEventsParams {
  after_sequence?: number
  limit?: number
  event_types?: string
}

export interface GetEventsResponse {
  audit_id: string
  count: number
  events: AgentEvent[]
}

export interface CreateAuditRequest {
  project_id: string
  audit_type: 'quick' | 'full' | 'targeted'
  target_types?: string[]
  config?: Record<string, unknown>
}

export interface CreateAuditResponse {
  audit_id: string
  status: string
  estimated_time: number
}
