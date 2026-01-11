/**
 * Agent 审计 API 层
 * 参考 DeepAudit-3.0.0 实现
 */

import type {
  AgentTask,
  AgentFinding,
  AgentEvent,
  AgentTreeResponse,
  GetEventsParams,
  GetEventsResponse,
  CreateAuditRequest,
  CreateAuditResponse,
  AuditStats,
  LogItem,
} from './types'

const API_BASE_URL = import.meta.env.VITE_AGENT_SERVICE_URL || 'http://localhost:8001'

// ==================== 辅助函数 ====================

async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${API_BASE_URL}${endpoint}`

  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  })

  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: response.statusText }))
    throw new Error(error.detail || error.message || 'API request failed')
  }

  return response.json()
}

// ==================== 任务相关 ====================

/**
 * 获取审计任务详情
 */
export async function getAuditTask(auditId: string): Promise<AgentTask> {
  const data = await apiRequest<{ audit_id: string; status: string; progress?: any }>(
    `/api/audit/${auditId}/status`
  )

  // 转换后端格式到前端格式
  return {
    id: data.audit_id,
    project_id: '',
    audit_type: 'full',
    status: data.status as AgentTask['status'],
    current_phase: data.progress?.current_stage,
    progress_percentage: data.progress?.percentage || 0,
    total_files: data.progress?.total_files || 0,
    indexed_files: data.progress?.indexed_files || 0,
    analyzed_files: data.progress?.analyzed_files || 0,
    findings_count: data.progress?.findings_detected || 0,
    created_at: '',
    updated_at: '',
  }
}

/**
 * 创建审计任务
 */
export async function createAuditTask(request: CreateAuditRequest): Promise<CreateAuditResponse> {
  return apiRequest<CreateAuditResponse>('/api/audit/start', {
    method: 'POST',
    body: JSON.stringify(request),
  })
}

/**
 * 暂停审计任务
 */
export async function pauseAuditTask(auditId: string): Promise<{ success: boolean; message: string }> {
  return apiRequest(`/api/audit/${auditId}/pause`, {
    method: 'POST',
  })
}

/**
 * 取消审计任务
 */
export async function cancelAuditTask(auditId: string): Promise<{ success: boolean; message: string }> {
  return apiRequest(`/api/audit/${auditId}/cancel`, {
    method: 'POST',
  })
}

// ==================== 数据获取 ====================

/**
 * 获取审计发现列表
 */
export async function getAuditFindings(auditId: string): Promise<AgentFinding[]> {
  const data = await apiRequest<{
    audit_id: string
    status: string
    summary: { total_vulnerabilities: number }
    vulnerabilities: any[]
  }>(`/api/audit/${auditId}/result`)

  return data.vulnerabilities.map((v, index) => ({
    id: v.id || `finding_${auditId}_${index}`,
    task_id: auditId,
    vulnerability_type: v.vulnerability_type,
    severity: v.severity,
    title: v.title,
    description: v.description,
    file_path: v.file_path,
    line_start: v.line_number,
    line_end: v.line_number,
    code_snippet: v.code_snippet,
    recommendation: v.remediation,
    references: [],
    status: 'new' as const,
    is_verified: v.verified || false,
    confidence: v.confidence,
    created_at: v.created_at,
  }))
}

/**
 * 获取 Agent 树
 */
export async function getAuditAgentTree(auditId: string): Promise<AgentTreeResponse> {
  try {
    // 使用 audit_id 参数过滤特定审计的 Agent 树
    const url = `${API_BASE_URL}/api/agents/tree?audit_id=${encodeURIComponent(auditId)}`
    const response = await fetch(url, {
      headers: { 'Content-Type': 'application/json' },
    })

    if (!response.ok) {
      // 如果 404，返回空树（可能还没有 Agent 运行）
      if (response.status === 404) {
        return { roots: [], total_count: 0, running_count: 0, completed_count: 0 }
      }
      throw new Error(`Failed to fetch agent tree: ${response.statusText}`)
    }

    const data = await response.json()

    // 处理不同的响应格式
    if (data.tree) {
      return data.tree
    } else if (data.data?.tree) {
      return data.data.tree
    } else if (Array.isArray(data)) {
      return { roots: data, total_count: data.length, running_count: 0, completed_count: 0 }
    } else if (data.roots) {
      return data
    }

    return { roots: [], total_count: 0, running_count: 0, completed_count: 0 }
  } catch (error) {
    console.warn('[API] Failed to fetch agent tree:', error)
    // 返回空树而不是抛出错误
    return { roots: [], total_count: 0, running_count: 0, completed_count: 0 }
  }
}

/**
 * 获取审计事件列表（历史）
 */
export async function getAuditEvents(
  auditId: string,
  params: GetEventsParams = {}
): Promise<AgentEvent[]> {
  const searchParams = new URLSearchParams()
  if (params.after_sequence) searchParams.append('after_sequence', String(params.after_sequence))
  if (params.limit) searchParams.append('limit', String(params.limit))
  if (params.event_types) searchParams.append('event_types', params.event_types)

  const queryString = searchParams.toString()
  const url = `/api/audit/${auditId}/events${queryString ? `?${queryString}` : ''}`

  const data = await apiRequest<GetEventsResponse>(url)
  return data.events
}

/**
 * 获取审计事件统计
 */
export async function getAuditEventsStats(auditId: string): Promise<AuditStats> {
  return apiRequest<AuditStats>(`/api/audit/${auditId}/events/stats`)
}

// ==================== SSE 流处理 ====================

/**
 * 创建 SSE 连接 URL
 */
export function createSSEUrl(auditId: string, afterSequence = 0): string {
  const params = new URLSearchParams()
  if (afterSequence > 0) {
    params.append('after_sequence', String(afterSequence))
  }
  const queryString = params.toString()
  return `${API_BASE_URL}/api/audit/${auditId}/stream${queryString ? `?${queryString}` : ''}`
}

/**
 * 解析 SSE 事件
 */
export function parseSSEEvent(line: string): { eventType: string; data: any } | null {
  if (line.startsWith('event:')) {
    const eventType = line.slice(6).trim()
    return { eventType, data: null }
  }
  if (line.startsWith('data:')) {
    const dataStr = line.slice(5).trim()
    try {
      const data = JSON.parse(dataStr)
      return { eventType: '', data }
    } catch {
      return { eventType: '', data: dataStr }
    }
  }
  return null
}

/**
 * 转换后端事件到前端事件格式
 */
export function transformBackendEvent(backendEvent: any): AgentEvent {
  // 同时支持根级别和 data 字段的数据
  const data = backendEvent.data || backendEvent

  return {
    id: backendEvent.id || backendEvent.event_id || '',
    task_id: backendEvent.audit_id || backendEvent.task_id || '',
    event_type: backendEvent.event_type || backendEvent.type || 'info',
    sequence: backendEvent.sequence || 0,
    timestamp: backendEvent.timestamp || new Date().toISOString(),
    agent_type: (backendEvent.agent_type || 'system').toUpperCase(),
    message: backendEvent.message,
    tool_name: backendEvent.tool_name || data?.tool_name,
    tool_input: backendEvent.tool_input || data?.tool_input || data?.parameters,
    tool_output: backendEvent.tool_output || data?.tool_output || data?.result,
    tool_duration_ms: backendEvent.tool_duration_ms || data?.tool_duration_ms,
    thought: backendEvent.thought || data?.thought,
    accumulated_thought: backendEvent.accumulated_thought || data?.accumulated,
    finding: backendEvent.finding || data?.finding,
    progress: backendEvent.progress || data?.progress,
    status: backendEvent.status || data?.status,
    metadata: data,
  }
}

/**
 * 转换后端事件到日志项
 */

// 用于生成唯一 ID 的计数器
let logIdCounter = 0

export function eventToLogItem(event: AgentEvent): LogItem | null {
  // 过滤掉不相关的事件
  const ignoredEventTypes = ['heartbeat', 'connected', 'sse_connected']
  if (ignoredEventTypes.includes(event.event_type)) {
    return null
  }

  // 过滤掉没有内容的事件
  const hasContent =
    event.message ||
    event.thought ||
    event.accumulated_thought ||
    event.finding?.title ||
    event.progress?.message ||
    event.data?.message ||
    event.metadata?.message

  if (!hasContent && !['status', 'task_complete', 'task_end', 'phase_start', 'phase_complete', 'complete'].includes(event.event_type)) {
    return null
  }

  // 后端使用的事件类型到前端日志类型的映射（增强版）
  const logTypeMap: Record<string, LogItem['type']> = {
    // 思考事件
    thinking: 'thinking',
    thinking_start: 'thinking',
    thinking_token: 'thinking',
    thinking_end: 'thinking',
    llm_thought: 'thinking',    // LLM 思考内容
    llm_decision: 'thinking',   // LLM 决策
    llm_action: 'tool',         // LLM 动作
    thought: 'thinking',        // 通用思考

    // 工具调用
    tool_call_start: 'tool',
    tool_call: 'tool',
    tool_result: 'observation',
    tool_call_end: 'observation',
    tool_output: 'observation',
    tool_error: 'error',

    // 发现（增强）
    finding: 'finding',
    finding_new: 'finding',
    finding_update: 'finding',
    finding_verified: 'finding',
    finding_false_positive: 'finding',
    vulnerability: 'finding',   // 漏洞

    // 阶段/进度（增强）
    phase_start: 'phase',
    phase_end: 'phase',
    phase_complete: 'complete',
    phase_change: 'phase',
    progress: 'progress',
    analysis_progress: 'progress',  // 后端 analysis.py 使用

    // 状态事件 - 后端 audit.py 使用
    status: 'info',  // 状态变更
    cancelled: 'info',  // 任务取消
    paused: 'info',  // 任务暂停

    // 任务事件（增强）
    task_start: 'info',
    task_complete: 'complete',
    task_end: 'complete',
    task_error: 'error',
    task_cancel: 'info',
    task_failed: 'error',

    // Agent 事件（增强）
    agent_start: 'info',
    agent_complete: 'complete',
    agent_dispatch: 'info',
    node_start: 'info',
    node_complete: 'complete',

    // 验证事件
    verification_start: 'info',
    verification_complete: 'complete',
    poc_generated: 'finding',

    // 通用事件
    info: 'info',
    warning: 'info',
    error: 'error',
    debug: 'info',

    // SSE 特殊事件 (已过滤)
    connected: 'info',  // SSE 连接成功
    heartbeat: 'info',  // 心跳
    sse_connected: 'info',
  }

  const logType = logTypeMap[event.event_type] || 'info'

  const content =
    event.message ||
    event.thought ||
    event.accumulated_thought ||
    (event.finding?.title) ||
    (event.progress?.message) ||
    (event.metadata?.message) ||
    ''

  // 确保有唯一的 ID：使用 event.id，如果为空则生成一个唯一的组合 ID
  const logId = event.id || `log_${event.event_type}_${event.sequence}_${++logIdCounter}`

  // 构建日志项
  const logItem: LogItem = {
    id: logId,
    type: logType,
    agent_type: event.agent_type || 'SYSTEM',
    timestamp: new Date(event.timestamp).getTime(),
    content,
    sequence: event.sequence,
    data: event.metadata || event.data || {},
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
 * 检查 Agent 服务健康状态
 */
export async function healthCheck(): Promise<{ status: string } | null> {
  try {
    const response = await fetch(`${API_BASE_URL}/health`, {
      headers: { 'Content-Type': 'application/json' },
    })

    if (!response.ok) {
      return null
    }

    return await response.json()
  } catch {
    return null
  }
}
