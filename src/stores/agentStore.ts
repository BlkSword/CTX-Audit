/**
 * Agent 审计状态管理
 * 基于 Zustand
 */

import { create } from 'zustand'
import { devtools } from 'zustand/middleware'
import type {
  AuditStatus,
  AuditStatusResponse,
  AuditProgress,
  AgentStatusMap,
  AuditStats,
  AgentEvent,
  AgentEventType,
  LLMConfig,
  PromptTemplate,
} from '@/shared/types'
import { agentApi, agentTreeApi } from '@/shared/api/agent-client'
import type { AgentNode } from '@/shared/types'

interface AgentState {
  // 当前审计任务
  currentAuditId: string | null
  auditStatus: AuditStatus
  auditProgress: AuditProgress
  agentStatus: AgentStatusMap
  auditStats: AuditStats
  auditError: string | null

  // 审计历史
  auditHistory: AuditStatusResponse[]

  // 实时事件
  events: AgentEvent[]
  isConnected: boolean

  // LLM 配置
  llmConfigs: LLMConfig[]
  defaultLLMConfig: LLMConfig | null

  // 提示词模板
  promptTemplates: PromptTemplate[]

  // Agent 树相关
  agentTree: AgentNode | null
  agentTreeLoading: boolean
  agentTreeError: string | null
  agentStatistics: {
    total: number
    running: number
    completed: number
    stopped: number
    error: number
    by_type: Record<string, number>
  } | null

  // 操作方法
  startAudit: (projectId: string, auditType: 'quick' | 'full' | 'targeted', config?: any) => Promise<string>
  pauseAudit: () => Promise<void>
  resumeAudit: () => Promise<void>
  cancelAudit: () => Promise<void>
  getAuditStatus: (auditId: string) => Promise<void>
  getAuditResult: (auditId: string) => Promise<void>
  loadAuditHistory: (projectId?: string) => Promise<void>
  connectStream: (auditId: string) => void
  disconnectStream: () => void
  addEvent: (event: AgentEvent) => void
  clearEvents: () => void

  // 连接检查
  checkConnection: () => Promise<boolean>

  // LLM 配置操作
  loadLLMConfigs: () => Promise<void>
  createLLMConfig: (config: Omit<LLMConfig, 'id'>) => Promise<void>
  updateLLMConfig: (id: string, config: Partial<LLMConfig>) => Promise<void>
  deleteLLMConfig: (id: string) => Promise<void>
  setDefaultLLMConfig: (id: string) => Promise<void>
  testLLMConfig: (id: string) => Promise<{ success: boolean; error?: string }>

  // 提示词模板操作
  loadPromptTemplates: (category?: string) => Promise<void>
  createPromptTemplate: (template: Omit<PromptTemplate, 'id' | 'createdAt' | 'updatedAt'>) => Promise<void>
  updatePromptTemplate: (id: string, template: Partial<PromptTemplate>) => Promise<void>
  deletePromptTemplate: (id: string) => Promise<void>

  // Agent 树操作
  loadAgentTree: (rootId?: string) => Promise<void>
  refreshAgentTree: () => Promise<void>
  stopAgent: (agentId: string, stopChildren?: boolean) => Promise<void>
  loadAgentStatistics: () => Promise<void>
  createAgent: (agentType: string, task: string, parentId?: string, config?: any) => Promise<string>
  getAgentInfo: (agentId: string) => Promise<AgentNode>

  // 清理
  clearError: () => void
  reset: () => void
}

const initialState = {
  currentAuditId: null,
  auditStatus: 'pending' as AuditStatus,
  auditProgress: {
    current_stage: '',
    completed_steps: 0,
    total_steps: 0,
    percentage: 0,
  },
  agentStatus: {
    orchestrator: 'idle' as const,
    recon: 'idle' as const,
    analysis: 'idle' as const,
    verification: 'idle' as const,
  },
  auditStats: {
    files_scanned: 0,
    findings_detected: 0,
    verified_vulnerabilities: 0,
  },
  auditError: null,
  auditHistory: [],
  events: [],
  isConnected: false,
  llmConfigs: [],
  defaultLLMConfig: null,
  promptTemplates: [],
  agentTree: null,
  agentTreeLoading: false,
  agentTreeError: null,
  agentStatistics: null,
}

export const useAgentStore = create<AgentState>()(
  devtools(
    (set, get) => ({
      ...initialState,

      // 启动审计
      startAudit: async (projectId, auditType, config) => {
        set({ auditError: null, auditStatus: 'pending' })
        try {
          const response = await agentApi.startAudit({
            project_id: projectId,
            audit_type: auditType,
            config,
          })
          set({
            currentAuditId: response.audit_id,
            auditStatus: response.status,
          })

          // 连接 WebSocket 流
          get().connectStream(response.audit_id)

          // 开始轮询状态
          get().getAuditStatus(response.audit_id)

          return response.audit_id
        } catch (error) {
          const message = error instanceof Error ? error.message : '启动审计失败'
          set({ auditError: message })
          throw error
        }
      },

      // 暂停审计
      pauseAudit: async () => {
        const { currentAuditId } = get()
        if (!currentAuditId) return

        try {
          await agentApi.pauseAudit(currentAuditId)
          set({ auditStatus: 'paused' })
        } catch (error) {
          const message = error instanceof Error ? error.message : '暂停审计失败'
          set({ auditError: message })
        }
      },

      // 恢复审计
      resumeAudit: async () => {
        const { currentAuditId } = get()
        if (!currentAuditId) return

        try {
          await agentApi.resumeAudit(currentAuditId)
          set({ auditStatus: 'running' })
          get().getAuditStatus(currentAuditId)
        } catch (error) {
          const message = error instanceof Error ? error.message : '恢复审计失败'
          set({ auditError: message })
        }
      },

      // 取消审计
      cancelAudit: async () => {
        const { currentAuditId } = get()
        if (!currentAuditId) return

        try {
          await agentApi.cancelAudit(currentAuditId)
          set({
            auditStatus: 'failed',
            auditError: '审计已取消',
          })
          get().disconnectStream()
        } catch (error) {
          const message = error instanceof Error ? error.message : '取消审计失败'
          set({ auditError: message })
        }
      },

      // 获取审计状态
      getAuditStatus: async (auditId) => {
        try {
          const status = await agentApi.getAuditStatus(auditId)
          set({
            auditStatus: status.status,
            auditProgress: status.progress,
            agentStatus: status.agent_status,
            auditStats: status.stats,
          })

          // 如果审计还在运行，继续轮询
          if (status.status === 'running') {
            setTimeout(() => get().getAuditStatus(auditId), 2000)
          } else if (status.status === 'completed' || status.status === 'failed') {
            get().disconnectStream()
          }
        } catch (error) {
          console.error('获取审计状态失败:', error)
        }
      },

      // 获取审计结果
      getAuditResult: async (auditId) => {
        try {
          const result = await agentApi.getAuditResult(auditId)
          // 更新统计数据
          set({
            auditStats: {
              files_scanned: result.summary.total_vulnerabilities,
              findings_detected: result.summary.total_vulnerabilities,
              verified_vulnerabilities: result.vulnerabilities.filter(v => v.verified).length,
            },
          })
          return result
        } catch (error) {
          console.error('获取审计结果失败:', error)
          throw error
        }
      },

      // 加载审计历史
      loadAuditHistory: async (projectId) => {
        try {
          const history = await agentApi.listAudits(projectId)
          set({ auditHistory: history })
        } catch (error) {
          console.error('加载审计历史失败:', error)
        }
      },

      // 连接 WebSocket 流
      connectStream: (auditId) => {
        try {
          agentApi.connectAuditStream(auditId)
          set({ isConnected: true })

          // 注册事件监听器
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
          ]

          eventTypes.forEach(eventType => {
            agentApi.onEvent(eventType, (event) => {
              get().addEvent(event)
            })
          })
        } catch (error) {
          console.error('连接审计流失败:', error)
        }
      },

      // 断开 WebSocket 流
      disconnectStream: () => {
        agentApi.disconnectAuditStream()
        set({ isConnected: false })
      },

      // 检查服务连接
      checkConnection: async () => {
        try {
          const response = await agentApi.healthCheck()
          const isHealthy = response && response.status === 'healthy'
          set({ isConnected: isHealthy })
          return isHealthy
        } catch (error) {
          console.error('连接检查失败:', error)
          set({ isConnected: false })
          return false
        }
      },

      // 添加事件
      addEvent: (event) => {
        set((state) => {
          const MAX_EVENTS = 1000
          // 将后端事件格式转换为前端格式
          const normalizedEvent: AgentEvent = {
            id: event.event_id || event.id,
            audit_id: event.audit_id,
            type: event.event_type as AgentEventType || event.type,
            agent_type: (event.agent_type?.toLowerCase() + '_' || '') as AgentType,
            timestamp: Date.now() / 1000, // 后端发送 ISO 字符串，转换为时间戳
            data: event.data || (event as any).data,
          }
          const events = [...state.events, normalizedEvent]
          if (events.length > MAX_EVENTS) {
            return { events: events.slice(events.length - MAX_EVENTS) }
          }
          return { events }
        })
      },

      // 清空事件
      clearEvents: () => {
        set({ events: [] })
      },

      // 加载 LLM 配置
      loadLLMConfigs: async () => {
        try {
          const configs = await agentApi.getLLMConfigs()
          const defaultConfig = configs.find(c => c.isDefault) || null
          set({
            llmConfigs: configs,
            defaultLLMConfig: defaultConfig,
          })
        } catch (error) {
          console.error('加载 LLM 配置失败:', error)
        }
      },

      // 创建 LLM 配置
      createLLMConfig: async (config) => {
        try {
          const newConfig = await agentApi.createLLMConfig(config)
          set((state) => ({
            llmConfigs: [...state.llmConfigs, newConfig],
          }))
        } catch (error) {
          const message = error instanceof Error ? error.message : '创建 LLM 配置失败'
          set({ auditError: message })
          throw error
        }
      },

      // 更新 LLM 配置
      updateLLMConfig: async (id, config) => {
        try {
          const updatedConfig = await agentApi.updateLLMConfig(id, config)
          set((state) => ({
            llmConfigs: state.llmConfigs.map(c =>
              c.id === id ? updatedConfig : c
            ),
            defaultLLMConfig: state.defaultLLMConfig?.id === id ? updatedConfig : state.defaultLLMConfig,
          }))
        } catch (error) {
          const message = error instanceof Error ? error.message : '更新 LLM 配置失败'
          set({ auditError: message })
          throw error
        }
      },

      // 删除 LLM 配置
      deleteLLMConfig: async (id) => {
        try {
          await agentApi.deleteLLMConfig(id)
          set((state) => ({
            llmConfigs: state.llmConfigs.filter(c => c.id !== id),
            defaultLLMConfig: state.defaultLLMConfig?.id === id ? null : state.defaultLLMConfig,
          }))
        } catch (error) {
          const message = error instanceof Error ? error.message : '删除 LLM 配置失败'
          set({ auditError: message })
          throw error
        }
      },

      // 设置默认 LLM 配置
      setDefaultLLMConfig: async (id) => {
        try {
          const updatedConfig = await agentApi.setDefaultLLMConfig(id)
          set((state) => ({
            llmConfigs: state.llmConfigs.map(c =>
              c.id === id ? { ...c, isDefault: true } : { ...c, isDefault: false }
            ),
            defaultLLMConfig: updatedConfig,
          }))
        } catch (error) {
          const message = error instanceof Error ? error.message : '设置默认 LLM 配置失败'
          set({ auditError: message })
          throw error
        }
      },

      // 测试 LLM 配置
      testLLMConfig: async (id) => {
        try {
          return await agentApi.testLLMConfig(id)
        } catch (error) {
          const message = error instanceof Error ? error.message : '测试 LLM 配置失败'
          return { success: false, error: message }
        }
      },

      // 加载提示词模板
      loadPromptTemplates: async (category) => {
        try {
          const templates = await agentApi.getPromptTemplates(category)
          set({ promptTemplates: templates })
        } catch (error) {
          console.error('加载提示词模板失败:', error)
        }
      },

      // 创建提示词模板
      createPromptTemplate: async (template) => {
        try {
          const newTemplate = await agentApi.createPromptTemplate(template)
          set((state) => ({
            promptTemplates: [...state.promptTemplates, newTemplate],
          }))
        } catch (error) {
          const message = error instanceof Error ? error.message : '创建提示词模板失败'
          set({ auditError: message })
          throw error
        }
      },

      // 更新提示词模板
      updatePromptTemplate: async (id, template) => {
        try {
          const updatedTemplate = await agentApi.updatePromptTemplate(id, template)
          set((state) => ({
            promptTemplates: state.promptTemplates.map(t =>
              t.id === id ? updatedTemplate : t
            ),
          }))
        } catch (error) {
          const message = error instanceof Error ? error.message : '更新提示词模板失败'
          set({ auditError: message })
          throw error
        }
      },

      // 删除提示词模板
      deletePromptTemplate: async (id) => {
        try {
          await agentApi.deletePromptTemplate(id)
          set((state) => ({
            promptTemplates: state.promptTemplates.filter(t => t.id !== id),
          }))
        } catch (error) {
          const message = error instanceof Error ? error.message : '删除提示词模板失败'
          set({ auditError: message })
          throw error
        }
      },

      // 加载 Agent 树
      loadAgentTree: async (rootId) => {
        set({ agentTreeLoading: true, agentTreeError: null })
        try {
          const tree = await agentTreeApi.getAgentTree(rootId)
          if (tree && Object.keys(tree).length > 0) {
            set({ agentTree: tree as AgentNode, agentTreeLoading: false })
          } else {
            set({ agentTree: null, agentTreeLoading: false })
          }
        } catch (error) {
          const message = error instanceof Error ? error.message : '加载 Agent 树失败'
          set({ agentTreeError: message, agentTreeLoading: false })
        }
      },

      // 刷新 Agent 树
      refreshAgentTree: async () => {
        await get().loadAgentTree()
      },

      // 停止 Agent
      stopAgent: async (agentId, stopChildren = true) => {
        try {
          await agentTreeApi.stopAgent(agentId, stopChildren)
          // 刷新树
          await get().loadAgentTree()
        } catch (error) {
          const message = error instanceof Error ? error.message : '停止 Agent 失败'
          set({ auditError: message })
          throw error
        }
      },

      // 加载 Agent 统计
      loadAgentStatistics: async () => {
        try {
          const stats = await agentTreeApi.getAgentStatistics()
          set({ agentStatistics: stats })
        } catch (error) {
          console.error('加载 Agent 统计失败:', error)
        }
      },

      // 创建 Agent
      createAgent: async (agentType, task, parentId, config) => {
        try {
          const result = await agentTreeApi.createAgent(agentType, task, parentId, config)
          // 刷新树
          await get().loadAgentTree()
          return result.agent_id
        } catch (error) {
          const message = error instanceof Error ? error.message : '创建 Agent 失败'
          set({ auditError: message })
          throw error
        }
      },

      // 获取 Agent 详情
      getAgentInfo: async (agentId) => {
        return await agentTreeApi.getAgentInfo(agentId)
      },

      // 清理错误
      clearError: () => {
        set({ auditError: null })
      },

      // 重置状态
      reset: () => {
        set({
          ...initialState,
          llmConfigs: get().llmConfigs,
          defaultLLMConfig: get().defaultLLMConfig,
          promptTemplates: get().promptTemplates,
          agentTree: get().agentTree,
          agentStatistics: get().agentStatistics,
        })
      },
    }),
    { name: 'agent-store' }
  )
)
