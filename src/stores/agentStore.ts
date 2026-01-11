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
  AgentStatus,
  AuditStats,
  AgentEvent,
  AgentEventType,
  AgentType,
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

  // 是否使用从 Agent 树提取的状态（而非后端 API 返回的假数据）
  useTreeAgentStatus: boolean

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
  connectStream: (auditId: string) => Promise<void>
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
  updateAgentStatusFromTree: (tree: AgentNode) => void
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
  useTreeAgentStatus: true,
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
          await get().connectStream(response.audit_id)

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

          // 如果启用从树提取状态，不覆盖 agentStatus
          if (get().useTreeAgentStatus) {
            set({
              auditStatus: status.status,
              auditProgress: status.progress,
              // agentStatus 由 loadAgentTree 通过 updateAgentStatusFromTree 更新
              auditStats: status.stats,
            })
          } else {
            set({
              auditStatus: status.status,
              auditProgress: status.progress,
              agentStatus: status.agent_status,
              auditStats: status.stats,
            })
          }

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
      connectStream: async (auditId) => {
        try {
          // 1. 先加载历史事件
          try {
            console.log(`[AgentStore] 加载历史事件: ${auditId}`)
            const history = await agentApi.getAuditEvents(auditId, 0, 1000)

            console.log(`[AgentStore] 加载了 ${history.count} 个历史事件`)

            // 批量添加历史事件
            history.events.forEach(event => {
              get().addEvent(event)
            })
          } catch (error) {
            console.warn('[AgentStore] 加载历史事件失败:', error)
          }

          // 2. 获取最新序列号
          let latestSequence = 0
          try {
            const stats = await agentApi.getAuditEventsStats(auditId)
            latestSequence = stats.latest_sequence
            console.log(`[AgentStore] 最新序列号: ${latestSequence}`)
          } catch (error) {
            console.warn('[AgentStore] 获取统计信息失败:', error)
          }

          // 3. 连接 SSE 流（从最新序列号开始）
          console.log(`[AgentStore] 连接 SSE，从序列号 ${latestSequence} 开始`)
          agentApi.connectAuditStream(auditId, latestSequence)
          set({ isConnected: true })

          // 4. 注册事件监听器
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
      // event: any - 后端发送的事件格式与前端 AgentEvent 类型不同
      addEvent: (event: any) => {
        console.log('[AgentStore] 收到事件:', event)
        set((state) => {
          const MAX_EVENTS = 1000

          // 处理后端事件格式到前端格式的转换
          // 后端格式: { event_id, event_type, agent_type, timestamp, data, message }
          // 前端格式: { id, type, agent_type, timestamp, data }
          const normalizedEvent: AgentEvent = {
            id: event.event_id || event.id || `evt_${Date.now()}_${Math.random()}`,
            audit_id: event.audit_id || state.currentAuditId || '',
            // 后端使用 event_type，前端使用 type
            type: (event.event_type || event.type) as AgentEventType,
            // 后端发送小写的 agent_type，需要转换为大写
            agent_type: (event.agent_type?.toUpperCase?.() || event.agent_type || 'ORCHESTRATOR') as AgentType,
            // 后端发送 ISO 字符串或时间戳，统一转换为时间戳（秒）
            timestamp: typeof event.timestamp === 'string'
              ? new Date(event.timestamp).getTime() / 1000
              : event.timestamp || Date.now() / 1000,
            // 保留原始 data，如果没有则从 event 其他字段构建
            data: event.data || {
              message: event.message,
              thought: event.thought,
              action: event.action,
              observation: event.observation,
              finding: event.finding,
              error: event.error,
              progress: event.progress,
            },
          }
          console.log('[AgentStore] 规范化后的事件:', normalizedEvent)

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
            set({
              agentTree: tree as AgentNode,
              agentTreeLoading: false
            })
            // 如果启用，从树中提取 Agent 状态
            if (get().useTreeAgentStatus) {
              get().updateAgentStatusFromTree(tree as AgentNode)
            }
          } else {
            set({ agentTree: null, agentTreeLoading: false })
          }
        } catch (error) {
          const message = error instanceof Error ? error.message : '加载 Agent 树失败'
          set({ agentTreeError: message, agentTreeLoading: false })
        }
      },

      // 从 Agent 树更新 Agent 状态
      updateAgentStatusFromTree: (tree: AgentNode) => {
        const extractStatusFromTree = (node: AgentNode): AgentStatusMap => {
          const statusMap: AgentStatusMap = {
            orchestrator: 'idle',
            recon: 'idle',
            analysis: 'idle',
            verification: 'idle',
          }

          const processNode = (n: AgentNode) => {
            const agentType = n.agent_type.toLowerCase() as keyof AgentStatusMap
            // @ts-ignore - statusMap will be properly typed after all assignments
            const currentStatus = statusMap[agentType] as string
            const newStatus = n.status as string

            // 如果已有 running 状态，保持不变
            if (currentStatus === 'running') return

            // 如果新状态是 running，更新
            if (newStatus === 'running') {
              statusMap[agentType] = 'running'
            }
            // 如果新状态是 completed，且当前不是 running，更新
            else if (newStatus === 'completed' && currentStatus !== 'running') {
              statusMap[agentType] = 'completed'
            }
            // 如果新状态是 error，映射为 failed
            else if (newStatus === 'error' && currentStatus !== 'running' && currentStatus !== 'completed') {
              statusMap[agentType] = 'failed'
            }
            // 如果新状态是 stopped，映射为 stopped
            else if (newStatus === 'stopped' && currentStatus === 'idle') {
              statusMap[agentType] = 'stopped'
            }
            // 如果当前是 idle，更新为任何非 idle 状态（需要映射）
            else if (currentStatus === 'idle' && newStatus !== 'idle') {
              statusMap[agentType] = (newStatus === 'error' ? 'failed' : newStatus) as AgentStatus
            }

            // 递归处理子节点
            if (n.children) {
              n.children.forEach(processNode)
            }
          }

          processNode(node)
          return statusMap
        }

        const newStatus = extractStatusFromTree(tree)
        set({ agentStatus: newStatus })
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
