/**
 * Agent 审计 API 层
 *
 * 使用 Tauri invoke 调用 Rust 后端（替代 Python Agent 服务）
 */

import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import type { UnlistenFn } from '@tauri-apps/api/event'

// 从 types.ts 导入类型定义
import type {
  AgentTask,
  AgentFinding,
  AgentEvent,
  AgentTreeResponse,
  LogItem,
  ConnectionStatus,
  GetEventsParams,
  AuditStats,
  CreateAuditRequest as TypesCreateAuditRequest,
  CreateAuditResponse as TypesCreateAuditResponse,
} from './types'

// 导出类型
export type {
  AgentTask,
  AgentFinding,
  AgentEvent,
  AgentTreeResponse,
  LogItem,
  ConnectionStatus,
  AuditStats,
  GetEventsParams,
}

// 扩展 CreateAuditRequest 以支持 Rust 后端
export interface CreateAuditRequest {
  project_id: string
  audit_type: 'full' | 'quick' | 'incremental' | 'custom'
  config?: {
    enabled_agents?: string[]
    max_concurrent_files?: number
    enable_verification?: boolean
    enable_external_tools?: boolean
    include_patterns?: string[]
    exclude_patterns?: string[]
  }
}

export interface CreateAuditResponse {
  audit_id: string
  status: string
}

export interface AuditStatusResponse {
  audit_id: string
  status: string
  progress: {
    current_stage: string
    percentage: number
    total_files: number
    indexed_files: number
    analyzed_files: number
    findings_detected: number
  }
  stats: {
    total_tokens: number
    tool_calls: number
    llm_calls: number
    duration_seconds: number
  }
}

export interface GetEventsResponse {
  events: AgentEvent[]
}

// ==================== API 函数 ====================

/**
 * 创建审计任务
 */
export async function createAuditTask(request: CreateAuditRequest): Promise<CreateAuditResponse> {
  return await invoke('start_audit', {
    projectId: request.project_id,
    auditType: request.audit_type,
    config: request.config || {}
  })
}

/**
 * 获取审计任务状态
 */
export async function getAuditTask(auditId: string): Promise<AgentTask> {
  const response = await invoke<AuditStatusResponse>('get_audit_status', { auditId })

  return {
    id: response.audit_id,
    project_id: '',
    audit_type: response.status as AgentTask['audit_type'], // 简化，实际需要从数据库获取
    status: response.status as AgentTask['status'],
    current_phase: response.progress.current_stage || response.status,
    progress_percentage: response.progress.percentage,
    total_files: response.progress.total_files || 0,
    indexed_files: response.progress.indexed_files || 0,
    analyzed_files: response.progress.analyzed_files || 0,
    findings_count: response.progress.findings_detected || 0,
    created_at: '',
    updated_at: ''
  }
}

/**
 * 暂停审计任务
 */
export async function pauseAuditTask(auditId: string): Promise<void> {
  return await invoke('pause_audit', { auditId })
}

/**
 * 取消审计任务
 */
export async function cancelAuditTask(auditId: string): Promise<void> {
  return await invoke('cancel_audit', { auditId })
}

/**
 * 获取审计发现列表
 */
export async function getAuditFindings(auditId: string): Promise<AgentFinding[]> {
  return await invoke('get_audit_result', { auditId })
}

/**
 * 获取 Agent 树
 */
export async function getAuditAgentTree(auditId: string): Promise<AgentTreeResponse> {
  try {
    const result = await invoke<{ nodes: any[]; edges: any[] }>('get_agent_tree', { auditId })
    // 转换为 AgentTreeResponse 格式
    return {
      roots: result.nodes || [],
      total_count: result.nodes?.length || 0,
      running_count: 0,
      completed_count: 0
    } as AgentTreeResponse
  } catch (error) {
    // 如果失败，返回空树
    return {
      roots: [],
      total_count: 0,
      running_count: 0,
      completed_count: 0
    } as AgentTreeResponse
  }
}

/**
 * 获取审计事件列表
 */
export async function getAuditEvents(
  auditId: string,
  params: GetEventsParams = {}
): Promise<AgentEvent[]> {
  return await invoke('get_audit_events', {
    auditId,
    afterSequence: params.after_sequence,
    limit: params.limit
  })
}

/**
 * 获取审计事件统计
 */
export async function getAuditEventsStats(auditId: string): Promise<AuditStats> {
  try {
    const events = await getAuditEvents(auditId)
    const stats = {
      total_events: events.length,
      by_type: {} as Record<string, number>,
      latest_sequence: 0
    } as unknown as AuditStats

    return stats
  } catch {
    return {
      total_events: 0,
      by_type: {},
      latest_sequence: 0
    } as unknown as AuditStats
  }
}

// ==================== 事件流处理 ====================

/**
 * 订阅审计事件流
 *
 * 使用 Tauri Events 替代 SSE
 */
export async function subscribeAuditEvents(
  auditId: string,
  onEvent: (event: AgentEvent) => void,
  onComplete?: () => void,
  _onError?: (error: Error) => void
): Promise<UnlistenFn> {
  // 监听 audit-event 事件
  const unlisten = await listen<any>('audit-event', (event) => {
    const payload = event.payload as any
    if (payload.audit_id === auditId) {
      onEvent(payload as AgentEvent)

      // 检查是否完成
      const eventType = payload.event_type || ''
      const isComplete = eventType === 'complete' ||
                       eventType === 'agent_completed' ||
                       eventType === 'task_complete'

      if (isComplete) {
        onComplete?.()
      }
    }
  })

  return unlisten
}

/**
 * 创建 SSE 连接 URL（兼容旧接口，现在返回空字符串）
 */
export function createSSEUrl(_auditId: string, _afterSequence = 0): string {
  // 不再使用 SSE，返回空字符串
  return ''
}

/**
 * 解析 SSE 事件（兼容旧接口，现在返回 null）
 */
export function parseSSEEvent(_line: string): { eventType: string; data: any } | null {
  // 不再使用 SSE
  return null
}

// ==================== 转换函数 ====================

/**
 * 转换后端事件到前端事件格式（兼容旧接口）
 */
export function transformBackendEvent(backendEvent: any): AgentEvent {
  // 直接返回事件，因为 Rust 后端已经返回正确的格式
  return backendEvent as AgentEvent
}

/**
 * 转换事件到日志项
 */

// 用于生成唯一 ID 的计数器
let logIdCounter = 0

export function eventToLogItem(event: AgentEvent): LogItem | null {
  // 过滤掉不相关的事件
  const ignoredEventTypes = ['heartbeat', 'connected', 'sse_connected']
  const eventType = event.event_type || ''
  if (ignoredEventTypes.includes(eventType)) {
    return null
  }

  // 过滤掉没有内容的事件
  const hasContent =
    event.message ||
    event.thought ||
    event.accumulated_thought ||
    event.finding?.title ||
    event.data?.message ||
    event.metadata?.message

  if (!hasContent && !['status', 'task_complete', 'task_end', 'phase_start', 'phase_complete', 'complete'].includes(eventType)) {
    return null
  }

  // 后端使用的事件类型到前端日志类型的映射
  const logTypeMap: Record<string, LogItem['type']> = {
    // 思考事件
    thinking: 'thinking',
    llm_thought: 'thinking',
    thought: 'thinking',

    // 工具调用
    tool_call: 'tool',
    tool_result: 'observation',
    tool_error: 'error',

    // 发现
    finding: 'finding',
    vulnerability: 'finding',

    // 阶段/进度
    phase_start: 'phase',
    phase_complete: 'complete',
    progress: 'progress',

    // 状态事件
    status: 'info',
    cancelled: 'info',
    paused: 'info',

    // 任务事件
    task_start: 'info',
    task_complete: 'complete',
    task_error: 'error',

    // Agent 事件
    agent_start: 'info',
    agent_complete: 'complete',
    agent_started: 'info',
    agent_completed: 'complete',

    // 通用事件
    info: 'info',
    warning: 'info',
    error: 'error',
    debug: 'info',
  }

  const logType = logTypeMap[eventType] || 'info'

  const content: string =
    event.message ??
    event.thought ??
    event.accumulated_thought ??
    event.finding?.title ??
    event.data?.message as string ??
    event.metadata?.message as string ??
    ''

  // 确保有唯一的 ID
  const logId = event.id ? `log_${event.id}` : `log_${eventType}_${event.sequence}_${++logIdCounter}`

  // 构建日志项
  const logItem: LogItem = {
    id: logId,
    type: logType,
    agent_type: event.agent_type || 'SYSTEM',
    timestamp: new Date(event.timestamp).getTime(),
    content,
    sequence: event.sequence,
    data: event.data || event.metadata || {},
    // 特殊字段
    toolName: event.tool_name,
    toolInput: event.tool_input,
    toolOutput: event.tool_output,
    finding: event.finding,
  }

  return logItem
}

// ==================== 健康检查 ====================

/**
 * 检查 Rust 后端健康状态
 * 现在总是返回成功，因为 Rust 后端是嵌入式运行的
 */
export async function healthCheck(): Promise<{ status: string } | null> {
  // Rust 后端总是可用的
  return { status: 'ok' }
}

// ==================== 类型重新导出 ====================

