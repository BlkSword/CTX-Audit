/**
 * Agent API 客户端（简化版）
 *
 * 注意：这是一个简化的客户端，仅用于满足编译需求
 * 实际功能应使用 @/pages/AgentAudit/api.ts 中的 API
 */

import type {
  PromptTemplate,
  LLMConfig,
  AgentNode,
} from '@/shared/types'

// Agent API
export const agentApi = {
  async startAudit(_params: { project_id: string; audit_type: string; config?: any }) {
    return { audit_id: 'audit_' + Date.now(), status: 'pending' as const }
  },
  async pauseAudit(_auditId: string) {
    return { success: true }
  },
  async resumeAudit(_auditId: string) {
    return { success: true }
  },
  async cancelAudit(_auditId: string) {
    return { success: true }
  },
  async getAuditStatus(_auditId: string) {
    return {
      status: 'pending' as const,
      progress: { current_stage: '', completed_steps: 0, total_steps: 0, percentage: 0 },
      agent_status: { orchestrator: 'idle', recon: 'idle', analysis: 'idle', verification: 'idle' },
      stats: { files_scanned: 0, findings_detected: 0, verified_vulnerabilities: 0 },
    }
  },
  async getAuditResult(_auditId: string) {
    return {
      summary: { total_vulnerabilities: 0 },
      vulnerabilities: [],
    }
  },
  async listAudits(_projectId?: string) {
    return []
  },
  async getAuditEvents(_auditId: string, _offset?: number, _limit?: number) {
    return { events: [], count: 0 }
  },
  async getAuditEventsStats(_auditId: string) {
    return { latest_sequence: 0, total_events: 0 }
  },
  connectAuditStream(_auditId: string, _sequence?: number) {
    // SSE 连接
  },
  disconnectAuditStream() {
    // 断开连接
  },
  onEvent(_eventType: string, _handler: (event: any) => void) {
    // 事件监听
  },
  async healthCheck() {
    return { status: 'healthy' as const }
  },
  async getLLMConfigs(): Promise<LLMConfig[]> {
    return []
  },
  async createLLMConfig(_config: Omit<LLMConfig, 'id'>): Promise<LLMConfig> {
    return {} as LLMConfig
  },
  async updateLLMConfig(_id: string, _config: Partial<LLMConfig>): Promise<LLMConfig> {
    return {} as LLMConfig
  },
  async deleteLLMConfig(_id: string) {
    return
  },
  async setDefaultLLMConfig(_id: string): Promise<LLMConfig> {
    return {} as LLMConfig
  },
  async testLLMConfig(_id: string) {
    return { success: true }
  },
  async getPromptTemplates(_category?: string): Promise<PromptTemplate[]> {
    return []
  },
  async createPromptTemplate(_template: Omit<PromptTemplate, 'id' | 'createdAt' | 'updatedAt'>): Promise<PromptTemplate> {
    return {} as PromptTemplate
  },
  async updatePromptTemplate(_id: string, _template: Partial<PromptTemplate>): Promise<PromptTemplate> {
    return {} as PromptTemplate
  },
  async deletePromptTemplate(_id: string) {
    return
  },
}

// Agent Tree API
export const agentTreeApi = {
  async getAgentTree(_rootId?: string): Promise<AgentNode | {}> {
    return {}
  },
  async stopAgent(_agentId: string, _stopChildren?: boolean) {
    return
  },
  async getAgentStatistics() {
    return { total: 0, running: 0, completed: 0, stopped: 0, error: 0, by_type: {} }
  },
  async createAgent(_agentType: string, _task: string, _parentId?: string, _config?: any) {
    return { agent_id: 'agent_' + Date.now() }
  },
  async getAgentInfo(_agentId: string): Promise<AgentNode> {
    return {} as AgentNode
  },
}
