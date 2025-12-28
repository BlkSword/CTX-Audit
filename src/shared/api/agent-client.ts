/**
 * Agent API Client
 *
 * 用于与 Agent 服务通信，包括审计任务、LLM 配置、提示词模板等
 */

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
  private wsConnection: WebSocket | null = null
  private wsEventHandlers: Map<AgentEventType, Set<(event: AgentEvent) => void>> = new Map()

  get baseURL() {
    return this.config.baseURL
  }

  constructor(config?: Partial<AgentAPIConfig>) {
    this.config = {
      baseURL: config?.baseURL || import.meta.env.VITE_AGENT_API_BASE_URL || 'http://localhost:8002',
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

  async post<T>(path: string, _data?: unknown): Promise<T> {
    return this.request<T>('POST', path)
  }

  async put<T>(path: string, _data?: unknown): Promise<T> {
    return this.request<T>('PUT', path)
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

  // ==================== WebSocket 事件流 ====================

  /**
   * 连接到审计事件流
   */
  connectAuditStream(auditId: string): void {
    if (this.wsConnection?.readyState === WebSocket.OPEN) {
      this.wsConnection.close()
    }

    const wsUrl = this.config.baseURL.replace('http', 'ws')
    this.wsConnection = new WebSocket(`${wsUrl}/api/audit/${auditId}/stream`)

    this.wsConnection.onopen = () => {
      console.log('WebSocket connected to audit stream')
    }

    this.wsConnection.onmessage = (event) => {
      try {
        const agentEvent: AgentEvent = JSON.parse(event.data)
        this.emitEvent(agentEvent)
      } catch (error) {
        console.error('Failed to parse WebSocket message:', error)
      }
    }

    this.wsConnection.onerror = (error) => {
      console.error('WebSocket error:', error)
    }

    this.wsConnection.onclose = () => {
      console.log('WebSocket connection closed')
    }
  }

  /**
   * 断开审计事件流
   */
  disconnectAuditStream(): void {
    if (this.wsConnection) {
      this.wsConnection.close()
      this.wsConnection = null
    }
  }

  /**
   * 注册事件处理器
   */
  onEvent(eventType: AgentEventType, handler: (event: AgentEvent) => void): () => void {
    if (!this.wsEventHandlers.has(eventType)) {
      this.wsEventHandlers.set(eventType, new Set())
    }
    this.wsEventHandlers.get(eventType)!.add(handler)

    // 返回取消订阅函数
    return () => {
      this.wsEventHandlers.get(eventType)?.delete(handler)
    }
  }

  /**
   * 触发事件
   */
  private emitEvent(event: AgentEvent): void {
    const handlers = this.wsEventHandlers.get(event.type)
    if (handlers) {
      handlers.forEach(handler => handler(event))
    }
  }

  // ==================== LLM 配置相关 ====================

  /**
   * 获取 LLM 配置列表
   */
  async getLLMConfigs(): Promise<LLMConfig[]> {
    return this.get<LLMConfig[]>('/api/llm/configs')
  }

  /**
   * 创建 LLM 配置
   */
  async createLLMConfig(config: Omit<LLMConfig, 'id'>): Promise<LLMConfig> {
    return this.post<LLMConfig>('/api/llm/configs', config)
  }

  /**
   * 更新 LLM 配置
   */
  async updateLLMConfig(id: string, config: Partial<LLMConfig>): Promise<LLMConfig> {
    return this.put<LLMConfig>(`/api/llm/configs/${id}`, config)
  }

  /**
   * 删除 LLM 配置
   */
  async deleteLLMConfig(id: string): Promise<{ success: boolean }> {
    return this.delete<{ success: boolean }>(`/api/llm/configs/${id}`)
  }

  /**
   * 设置默认 LLM 配置
   */
  async setDefaultLLMConfig(id: string): Promise<LLMConfig> {
    return this.post<LLMConfig>(`/api/llm/configs/${id}/set-default`)
  }

  /**
   * 测试 LLM 配置
   */
  async testLLMConfig(id: string): Promise<{ success: boolean; error?: string }> {
    return this.post<{ success: boolean; error?: string }>(`/api/llm/configs/${id}/test`)
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
