/**
 * Agent API Client
 *
 * 用于与 Agent 服务通信，包括审计任务、LLM 配置、提示词模板等
 */

import type { AgentNode } from '@/shared/types'
import type {
  AuditStartRequest,
  AuditStartResponse,
  AuditStatusResponse,
  AuditResult,
  LLMConfig,
  PromptTemplate,
  AgentEvent,
  AgentEventType,
} from '@/shared/types'

export interface AgentAPIConfig {
  baseURL: string
  timeout?: number
}

export class AgentAPIClient {
  private config: AgentAPIConfig
  private eventSource: EventSource | null = null
  private sseEventHandlers: Map<AgentEventType, Set<(event: AgentEvent) => void>> = new Map()
  private sseMessageHandlers: Set<(event: AgentEvent) => void> = new Set()

  get baseURL() {
    return this.config.baseURL
  }

  constructor(config?: Partial<AgentAPIConfig>) {
    this.config = {
      baseURL: config?.baseURL || import.meta.env.VITE_AGENT_API_BASE_URL || 'http://localhost:8001',
      timeout: config?.timeout || 60000,
    }
  }

  private async request<T>(
    method: string,
    path: string,
    data?: unknown
  ): Promise<T> {
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout)

    try {
      const response = await fetch(`${this.config.baseURL}${path}`, {
        method,
        headers: {
          'Content-Type': 'application/json',
        },
        body: data ? JSON.stringify(data) : undefined,
        signal: controller.signal,
      })

      clearTimeout(timeoutId)

      if (!response.ok) {
        const errorText = await response.text()
        throw new Error(`${method} ${path} failed (${response.status}): ${errorText}`)
      }

      return response.json()
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error('Agent API request timeout')
      }
      throw error
    }
  }

  async get<T>(path: string): Promise<T> {
    return this.request<T>('GET', path)
  }

  async post<T>(path: string, data?: unknown): Promise<T> {
    return this.request<T>('POST', path, data)
  }

  async put<T>(path: string, data?: unknown): Promise<T> {
    return this.request<T>('PUT', path, data)
  }

  async delete<T>(path: string): Promise<T> {
    return this.request<T>('DELETE', path)
  }

  // ==================== 审计任务相关 ====================

  /**
   * 启动审计任务
   */
  async startAudit(request: AuditStartRequest): Promise<AuditStartResponse> {
    return this.post<AuditStartResponse>('/api/audit/start', request)
  }

  /**
   * 获取审计状态
   */
  async getAuditStatus(auditId: string): Promise<AuditStatusResponse> {
    return this.get<AuditStatusResponse>(`/api/audit/${auditId}/status`)
  }

  /**
   * 获取审计结果
   */
  async getAuditResult(auditId: string): Promise<AuditResult> {
    return this.get<AuditResult>(`/api/audit/${auditId}/result`)
  }

  /**
   * 暂停审计
   */
  async pauseAudit(auditId: string): Promise<{ success: boolean }> {
    return this.post<{ success: boolean }>(`/api/audit/${auditId}/pause`)
  }

  /**
   * 恢复审计
   */
  async resumeAudit(auditId: string): Promise<{ success: boolean }> {
    return this.post<{ success: boolean }>(`/api/audit/${auditId}/resume`)
  }

  /**
   * 取消审计
   */
  async cancelAudit(auditId: string): Promise<{ success: boolean }> {
    return this.post<{ success: boolean }>(`/api/audit/${auditId}/cancel`)
  }

  /**
   * 获取审计列表
   */
  async listAudits(projectId?: string): Promise<AuditStatusResponse[]> {
    const params = projectId ? `?project_id=${projectId}` : ''
    return this.get<AuditStatusResponse[]>(`/api/audit${params}`)
  }

  // ==================== SSE 事件流 ====================

  /**
   * 获取审计历史事件
   */
  async getAuditEvents(
    auditId: string,
    afterSequence = 0,
    limit = 100,
    eventTypes?: string
  ): Promise<{ audit_id: string; count: number; events: AgentEvent[] }> {
    const params = new URLSearchParams()
    if (afterSequence > 0) params.append('after_sequence', String(afterSequence))
    if (limit > 0) params.append('limit', String(limit))
    if (eventTypes) params.append('event_types', eventTypes)

    const url = `/api/audit/${auditId}/events${params.toString() ? '?' + params.toString() : ''}`
    return this.get<{ audit_id: string; count: number; events: any[] }>(url)
  }

  /**
   * 获取审计事件统计
   */
  async getAuditEventsStats(auditId: string): Promise<{
    audit_id: string
    latest_sequence: number
    statistics: { total_events: number; by_type: Record<string, number> }
  }> {
    return this.get(`/api/audit/${auditId}/events/stats`)
  }

  /**
   * 连接到审计事件流（使用 SSE）
   */
  connectAuditStream(auditId: string, afterSequence = 0): void {
    // 先关闭之前的连接
    this.disconnectAuditStream()

    // 构建 URL，支持 after_sequence 参数
    const params = new URLSearchParams()
    if (afterSequence > 0) {
      params.append('after_sequence', String(afterSequence))
    }

    const queryString = params.toString()
    const eventSourceUrl = `${this.config.baseURL}/api/audit/${auditId}/stream${queryString ? '?' + queryString : ''}`

    console.log(`[SSE] 连接到: ${eventSourceUrl}`)

    this.eventSource = new EventSource(eventSourceUrl)

    this.eventSource.onopen = () => {
      console.log('SSE connected to audit stream')
    }

    // 处理通用消息（兼容旧代码）
    this.eventSource.addEventListener('message', (event) => {
      try {
        const parsed = JSON.parse(event.data)
        // 映射后端事件格式到前端
        const agentEvent: AgentEvent = {
          ...parsed,
          type: parsed.event_type || parsed.type,
          agent_type: (parsed.agent_type || '').toUpperCase(),
          timestamp: parsed.timestamp ? new Date(parsed.timestamp).getTime() / 1000 : Date.now() / 1000,
        }
        this.emitEvent(agentEvent)
      } catch (error) {
        console.error('Failed to parse SSE message:', error)
      }
    })

    // 处理特定事件类型
    const eventTypes: AgentEventType[] = [
      'thinking',
      'action',
      'observation',
      'finding',
      'decision',
      'error',
      'complete',
      'progress',
      'agent_start',
      'agent_complete',
      'tool_call',
      'rag_retrieval',
      'status',
      'connected',
    ]

    eventTypes.forEach(eventType => {
      this.eventSource!.addEventListener(eventType, (event) => {
        try {
          const parsed = JSON.parse((event as MessageEvent).data)
          // 映射后端事件格式到前端
          const agentEvent: AgentEvent = {
            ...parsed,
            type: parsed.event_type || parsed.type,
            agent_type: (parsed.agent_type || '').toUpperCase(),
            timestamp: parsed.timestamp ? new Date(parsed.timestamp).getTime() / 1000 : Date.now() / 1000,
          }
          this.emitEvent(agentEvent)
        } catch (parseError) {
          console.error(`Failed to parse SSE ${eventType} event:`, parseError)
        }
      })
    })

    this.eventSource.onerror = (error) => {
      console.error('SSE connection error:', error)
      // EventSource 会自动重连，但遇到某些错误需要手动处理
    }
  }

  /**
   * 断开审计事件流
   */
  disconnectAuditStream(): void {
    if (this.eventSource) {
      this.eventSource.close()
      this.eventSource = null
      console.log('SSE connection closed')
    }
  }

  /**
   * 注册事件处理器（兼容旧代码）
   */
  onEvent(eventType: AgentEventType, handler: (event: AgentEvent) => void): () => void {
    if (!this.sseEventHandlers.has(eventType)) {
      this.sseEventHandlers.set(eventType, new Set())
    }
    this.sseEventHandlers.get(eventType)!.add(handler)

    // 返回取消订阅函数
    return () => {
      this.sseEventHandlers.get(eventType)?.delete(handler)
    }
  }

  /**
   * 触发事件
   */
  private emitEvent(event: AgentEvent): void {
    const handlers = this.sseEventHandlers.get(event.type)
    if (handlers) {
      handlers.forEach(handler => handler(event))
    }
    // 同时触发所有消息处理器（兼容）
    this.sseMessageHandlers.forEach(handler => handler(event))
  }

  // ==================== LLM 配置相关 ====================

  /**
   * 获取 LLM 配置列表
   */
  async getLLMConfigs(): Promise<LLMConfig[]> {
    const response = await this.get<{ configs: LLMConfig[] }>('/api/settings/llm/configs')
    return response.configs
  }

  /**
   * 创建 LLM 配置
   */
  async createLLMConfig(config: Omit<LLMConfig, 'id'>): Promise<LLMConfig> {
    // 驼峰命名转下划线命名
    const snakeCaseConfig: Record<string, unknown> = {}
    for (const [key, value] of Object.entries(config)) {
      const snakeKey = key
        .replace(/([a-z])([A-Z])/g, '$1_$2')
        .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
        .toLowerCase()
      snakeCaseConfig[snakeKey] = value
    }
    const response = await this.post<{ id: string; status: string }>('/api/settings/llm/configs', snakeCaseConfig)
    return { ...config, id: response.id }
  }

  /**
   * 更新 LLM 配置
   */
  async updateLLMConfig(id: string, config: Partial<LLMConfig>): Promise<LLMConfig> {
    // 驼峰命名转下划线命名
    const snakeCaseConfig: Record<string, unknown> = {}
    for (const [key, value] of Object.entries(config)) {
      const snakeKey = key
        .replace(/([a-z])([A-Z])/g, '$1_$2')
        .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
        .toLowerCase()
      snakeCaseConfig[snakeKey] = value
    }
    await this.put<{ id: string; status: string }>(`/api/settings/llm/configs/${id}`, snakeCaseConfig)
    return { ...config, id } as LLMConfig
  }

  /**
   * 删除 LLM 配置
   */
  async deleteLLMConfig(id: string): Promise<{ success: boolean }> {
    await this.delete<{ status: string }>(`/api/settings/llm/configs/${id}`)
    return { success: true }
  }

  /**
   * 设置默认 LLM 配置
   */
  async setDefaultLLMConfig(id: string): Promise<LLMConfig> {
    await this.post<{ status: string }>(`/api/settings/llm/configs/${id}/default`)
    // 重新获取配置列表
    const configs = await this.getLLMConfigs()
    return configs.find(c => c.id === id) || { id, provider: '', model: '', apiKey: '', enabled: false, isDefault: false }
  }

  /**
   * 测试 LLM 配置
   */
  async testLLMConfig(id: string): Promise<{ success: boolean; error?: string }> {
    const response = await this.post<{ success: boolean; message?: string }>(`/api/settings/llm/configs/${id}/test`, {})
    return {
      success: response.success,
      error: response.success ? undefined : response.message,
    }
  }

  // ==================== 提示词模板相关 ====================

  /**
   * 获取提示词模板列表
   */
  async getPromptTemplates(category?: string): Promise<PromptTemplate[]> {
    const params = category ? `?category=${category}` : ''
    return this.get<PromptTemplate[]>(`/api/prompts/templates${params}`)
  }

  /**
   * 获取提示词模板详情
   */
  async getPromptTemplate(id: string): Promise<PromptTemplate> {
    return this.get<PromptTemplate>(`/api/prompts/templates/${id}`)
  }

  /**
   * 创建提示词模板
   */
  async createPromptTemplate(template: Omit<PromptTemplate, 'id' | 'createdAt' | 'updatedAt'>): Promise<PromptTemplate> {
    return this.post<PromptTemplate>('/api/prompts/templates', template)
  }

  /**
   * 更新提示词模板
   */
  async updatePromptTemplate(id: string, template: Partial<PromptTemplate>): Promise<PromptTemplate> {
    return this.put<PromptTemplate>(`/api/prompts/templates/${id}`, template)
  }

  /**
   * 删除提示词模板
   */
  async deletePromptTemplate(id: string): Promise<{ success: boolean }> {
    return this.delete<{ success: boolean }>(`/api/prompts/templates/${id}`)
  }

  /**
   * 渲染提示词模板
   */
  async renderPromptTemplate(id: string, variables: Record<string, unknown>): Promise<{
    success: boolean
    rendered?: string
    error?: string
  }> {
    return this.post<{
      success: boolean
      rendered?: string
      error?: string
    }>(`/api/prompts/${id}/render`, { variables })
  }

  /**
   * 测试提示词模板
   */
  async testPromptTemplate(id: string, variables: Record<string, unknown>): Promise<{
    success: boolean
    result?: unknown
    error?: string
    executionTime?: number
  }> {
    return this.post<{
      success: boolean
      result?: unknown
      error?: string
      executionTime?: number
    }>(`/api/prompts/${id}/test`, { variables })
  }

  // ==================== 健康检查 ====================

  /**
   * Agent 服务健康检查
   */
  async healthCheck(): Promise<{ status: string; version?: string }> {
    return this.get<{ status: string; version?: string }>('/health')
  }

  /**
   * 获取 Agent 服务统计
   */
  async getStats(): Promise<{
    total_audits: number
    running_audits: number
    completed_audits: number
    total_findings: number
  }> {
    return this.get<{
      total_audits: number
      running_audits: number
      completed_audits: number
      total_findings: number
    }>('/api/stats')
  }
}

// 单例实例
let agentClientInstance: AgentAPIClient | null = null

export function getAgentClient(config?: Partial<AgentAPIConfig>): AgentAPIClient {
  if (!agentClientInstance) {
    agentClientInstance = new AgentAPIClient(config)
  }
  return agentClientInstance
}

export const agentApi = getAgentClient()

// 便捷函数
export async function startAudit(projectId: string, auditType: string = 'quick', config?: any) {
  return agentApi.startAudit({
    project_id: projectId,
    audit_type: auditType as any,
    config,
  })
}

export async function getAuditStatus(auditId: string) {
  return agentApi.getAuditStatus(auditId)
}

export async function getAuditResult(auditId: string) {
  return agentApi.getAuditResult(auditId)
}

export async function healthCheck() {
  return agentApi.healthCheck()
}

// ==================== Agent 管理相关 ====================

/**
 * 获取 Agent 树结构
 */
async function getAgentTree(rootId?: string): Promise<AgentNode | {}> {
  const params = rootId ? `?root_id=${rootId}` : ''
  return agentApi.get<AgentNode | {}>(`/api/agents/tree${params}`)
}

/**
 * 列出所有 Agent
 */
async function listAgents(agentType?: string, status?: string): Promise<AgentNode[]> {
  const params = new URLSearchParams()
  if (agentType) params.append('agent_type', agentType)
  if (status) params.append('status', status)
  const queryString = params.toString()
  return agentApi.get<AgentNode[]>(`/api/agents/list${queryString ? '?' + queryString : ''}`)
}

/**
 * 获取单个 Agent 详情
 */
async function getAgentInfo(agentId: string): Promise<AgentNode> {
  return agentApi.get<AgentNode>(`/api/agents/${agentId}`)
}

/**
 * 创建新 Agent
 */
async function createAgent(agentType: string, task: string, parentId?: string, config?: Record<string, unknown>): Promise<{ agent_id: string; status: string }> {
  return agentApi.post<{ agent_id: string; status: string }>('/api/agents/create', {
    agent_type: agentType,
    task,
    parent_id: parentId,
    config,
  })
}

/**
 * 停止 Agent
 */
async function stopAgent(agentId: string, stopChildren = true): Promise<{ status: string; agent_id: string }> {
  return agentApi.post<{ status: string; agent_id: string }>(`/api/agents/${agentId}/stop?stop_children=${stopChildren}`)
}

/**
 * 获取 Agent 统计信息
 */
async function getAgentStatistics(): Promise<{
  total: number
  running: number
  completed: number
  stopped: number
  error: number
  by_type: Record<string, number>
}> {
  return agentApi.get<{
    total: number
    running: number
    completed: number
    stopped: number
    error: number
    by_type: Record<string, number>
  }>('/api/agents/statistics/overview')
}

/**
 * 获取消息历史
 */
async function getMessageHistory(agentId?: string, limit = 100): Promise<Array<{
  message_id: string
  sender: string
  recipient: string
  message_type: string
  content: string
  priority: string
  data: Record<string, unknown>
  timestamp: string
}>> {
  const params = new URLSearchParams()
  if (agentId) params.append('agent_id', agentId)
  params.append('limit', limit.toString())
  return agentApi.get<Array<{
    message_id: string
    sender: string
    recipient: string
    message_type: string
    content: string
    priority: string
    data: Record<string, unknown>
    timestamp: string
  }>>(`/api/agents/message/history?${params}`)
}

// 导出 Agent API 方法
export const agentTreeApi = {
  getAgentTree,
  listAgents,
  getAgentInfo,
  createAgent,
  stopAgent,
  getAgentStatistics,
  getMessageHistory,
}
