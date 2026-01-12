/**
 * 新版 Agent 审计主页面
 *
 * 基于参考设计的重新实现：
 * - 左侧 60% 活动日志区域
 * - 右侧 40% 状态面板（Agent Tree + 状态卡片）
 * - 新的 Header 组件
 * - 新的配色方案
 *
 * 颜色方案：
 * - 背景黑色: #121212
 * - 边框深灰: #333333
 * - 文本白色: #FFFFFF
 * - 文本灰色: #888888
 * - 运行绿色: #10B981
 * - 橙色: #F97316
 * - 紫色: #8B5CF6
 * - 红色: #EF4444
 */

import { useEffect, useRef, useCallback, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { Play, Pause, Square, Loader2 } from 'lucide-react'
import { useProjectStore } from '@/stores/projectStore'
import { useToast } from '@/hooks/use-toast'
import { cn } from '@/lib/utils'
import { confirmDialog } from '@/components/ui/confirm-dialog'

// 新组件
import { AuditHeader } from '@/components/audit/AuditHeader'
import { ActivityLogPanel } from '@/components/audit/ActivityLogPanel'
import { StatusCards } from '@/components/audit/StatusCards'
import { AgentTreePanelNew } from '@/components/audit/AgentTreePanelNew'

// 原有组件
import { ReportExportDialog } from './components/ReportExportDialog'
import { useAgentAuditState } from './useAgentAuditState'
import {
  getAuditTask,
  getAuditFindings,
  getAuditAgentTree,
  getAuditEvents,
  createAuditTask,
  pauseAuditTask,
  cancelAuditTask,
  eventToLogItem,
  healthCheck,
} from './api'
import { useResilientStream } from './useResilientStream'
import type { AgentEvent, AgentFinding } from './types'

const HISTORY_EVENT_LIMIT = 500

export function EnhancedAuditPageNew() {
  const { auditId } = useParams<{ auditId?: string }>()
  const navigate = useNavigate()
  const { currentProject } = useProjectStore()
  const toast = useToast()

  // 状态管理
  const {
    state,
    filteredLogs,
    tokenCount,
    toolCallCount,
    setTask,
    setFindings,
    addFinding,
    setAgentTree,
    addLog,
    selectAgent,
    toggleLogExpanded,
    setLoading,
    setError,
    setConnectionStatus,
    setHistoricalEventsLoaded,
    setAfterSequence,
    reset,
  } = useAgentAuditState()

  // UI 状态
  const [auditType, setAuditType] = useState<'quick' | 'full'>('full')
  const [isServiceHealthy, setIsServiceHealthy] = useState(false)
  const [isCheckingHealth, setIsCheckingHealth] = useState(true)
  const [exportDialogOpen, setExportDialogOpen] = useState(false)

  // Refs
  const previousAuditIdRef = useRef<string | null>(null)
  const hasLoadedHistoricalEventsRef = useRef(false)
  const lastEventSequenceRef = useRef(0)
  const pollIntervalRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const lastPolledStatusRef = useRef<string | null>(null)

  // ==================== 健康检查 ====================
  useEffect(() => {
    let mounted = true

    const checkHealth = async () => {
      setIsCheckingHealth(true)
      try {
        const result = await healthCheck()
        if (mounted) {
          setIsServiceHealthy(!!result)
        }
      } catch {
        if (mounted) {
          setIsServiceHealthy(false)
        }
      } finally {
        if (mounted) {
          setIsCheckingHealth(false)
        }
      }
    }

    checkHealth()
    const intervalId = setInterval(checkHealth, 10000)

    return () => {
      mounted = false
      clearInterval(intervalId)
    }
  }, [])

  // ==================== auditId 变化处理 ====================
  useEffect(() => {
    if (auditId !== previousAuditIdRef.current) {
      console.log('[AgentAudit] auditId changed:', auditId)
      reset()
      previousAuditIdRef.current = auditId || null
      hasLoadedHistoricalEventsRef.current = false
      lastEventSequenceRef.current = 0
      setAfterSequence(0)
      setHistoricalEventsLoaded(false)

      if (pollIntervalRef.current) {
        clearTimeout(pollIntervalRef.current)
        pollIntervalRef.current = null
      }
    }
  }, [auditId, reset, setAfterSequence, setHistoricalEventsLoaded])

  // ==================== 加载历史事件 ====================
  const loadHistoricalEvents = useCallback(async () => {
    if (!auditId) return 0

    if (hasLoadedHistoricalEventsRef.current) {
      return 0
    }
    hasLoadedHistoricalEventsRef.current = true

    try {
      const events = await getAuditEvents(auditId, { limit: HISTORY_EVENT_LIMIT })
      events.sort((a, b) => a.sequence - b.sequence)

      let processedCount = 0
      events.forEach((event: AgentEvent) => {
        if (event.sequence > lastEventSequenceRef.current) {
          lastEventSequenceRef.current = event.sequence
        }

        const logItem = eventToLogItem(event)
        addLog(logItem)
        processedCount++
      })

      setAfterSequence(lastEventSequenceRef.current)
      return events.length
    } catch (err) {
      console.error('[AgentAudit] Failed to load historical events:', err)
      return 0
    }
  }, [auditId, addLog, setAfterSequence])

  // ==================== 加载任务数据 ====================
  const loadTask = useCallback(async () => {
    if (!auditId) return

    try {
      setLoading(true)
      const task = await getAuditTask(auditId)
      setTask(task)
      setError(null)
    } catch (err) {
      const message = err instanceof Error ? err.message : '加载任务失败'
      setError(message)
    } finally {
      setLoading(false)
    }
  }, [auditId, setTask, setLoading, setError])

  // ==================== 加载发现列表 ====================
  const loadFindings = useCallback(async () => {
    if (!auditId) return

    try {
      const findings = await getAuditFindings(auditId)
      setFindings(findings)
    } catch (err) {
      console.error('[AgentAudit] Failed to load findings:', err)
    }
  }, [auditId, setFindings])

  // ==================== 加载 Agent 树 ====================
  const loadAgentTree = useCallback(async () => {
    if (!auditId) return

    try {
      const tree = await getAuditAgentTree(auditId)
      setAgentTree(tree)
    } catch (err) {
      console.error('[AgentAudit] Failed to load agent tree:', err)
    }
  }, [auditId, setAgentTree])

  // ==================== 初始数据加载 ====================
  useEffect(() => {
    if (!auditId) return

    const loadAllData = async () => {
      try {
        await Promise.all([loadTask(), loadFindings(), loadAgentTree()])
        await loadHistoricalEvents()
        setHistoricalEventsLoaded(true)
      } catch (err) {
        console.error('[AgentAudit] Failed to load initial data:', err)
      } finally {
        setLoading(false)
      }
    }

    loadAllData()
  }, [auditId, loadTask, loadFindings, loadAgentTree, loadHistoricalEvents, setLoading, setHistoricalEventsLoaded])

  // ==================== SSE 事件处理 ====================
  const handleStreamEvent = useCallback((event: AgentEvent) => {
    if (event.sequence > lastEventSequenceRef.current) {
      lastEventSequenceRef.current = event.sequence
    }

    const logItem = eventToLogItem(event)

    if (logItem) {
      addLog(logItem)
    }

    switch (event.event_type) {
      case 'finding':
      case 'finding_new':
      case 'finding_update':
        if (event.finding) {
          const finding: AgentFinding = {
            id: event.finding.id || `finding_${event.id}`,
            task_id: event.task_id,
            vulnerability_type: event.finding.vulnerability_type || 'unknown',
            severity: event.finding.severity || 'info',
            title: event.finding.title || '发现漏洞',
            description: event.finding.description || '',
            status: event.finding.status || 'new',
            is_verified: event.finding.is_verified || false,
            created_at: event.finding.created_at || new Date().toISOString(),
            file_path: event.finding.file_path,
            line_start: event.finding.line_start,
            line_end: event.finding.line_end,
            code_snippet: event.finding.code_snippet,
            recommendation: event.finding.recommendation,
            references: event.finding.references,
            confidence: event.finding.confidence,
          }
          addFinding(finding)
        }
        break

      case 'progress':
        if (event.progress !== undefined || event.data?.progress !== undefined) {
          const progressObj = event.progress ?? (event.data?.progress as any) ?? {}
          const progressValue = progressObj?.percentage ?? progressObj?.current ?? 0
          if (state.task) {
            setTask({
              ...state.task,
              progress_percentage: Math.round(progressValue)
            })
          }
        }
        break

      case 'status':
        const status = event.data?.status as string | undefined
        if (status === 'completed' || status === 'failed' || status === 'cancelled') {
          setTimeout(() => {
            loadTask()
            loadFindings()
            loadAgentTree()
          }, 100)

          if (status === 'completed' && state.task) {
            setTask({
              ...state.task,
              status: status as any,
              progress_percentage: 100
            })
          }
        } else {
          if (state.task && status) {
            setTask({
              ...state.task,
              status: status as any
            })
          }
        }
        if (status === 'failed' || status === 'error') {
          setError(event.data?.message as string || event.message || '任务执行失败')
        }
        break

      case 'task_complete':
      case 'task_end' as any:
        loadTask()
        loadFindings()
        loadAgentTree()
        break

      case 'error':
      case 'task_error':
        setError(event.data?.message as string || event.message || '任务执行失败')
        loadTask()
        break
    }
  }, [addLog, addFinding, loadTask, loadFindings, loadAgentTree, setError, setTask, state.task])

  // ==================== Resilient Stream ====================
  const { isConnecting } = useResilientStream(auditId || null, state.afterSequence, {
    enabled: state.historicalEventsLoaded && (
      !state.task ||
      state.task.status === 'running' ||
      state.task.status === 'pending'
    ),
    onEvent: handleStreamEvent,
    onConnectionChange: setConnectionStatus,
    onError: (err) => {
      setError(err.message)
    },
  })

  // ==================== 轮询任务状态 ====================
  useEffect(() => {
    if (!auditId || !state.task) return

    const isRunning = state.task.status === 'running' || state.task.status === 'pending'

    if (!isRunning) {
      if (pollIntervalRef.current) {
        clearTimeout(pollIntervalRef.current)
        pollIntervalRef.current = null
      }
      return
    }

    const pollInterval = 5000

    const poll = async () => {
      try {
        const currentStatus = state.task?.status
        const updatedTask = await getAuditTask(auditId)

        if (updatedTask.status !== currentStatus) {
          setTask(updatedTask)

          if (updatedTask.status === 'completed' || updatedTask.status === 'failed') {
            loadFindings()
            loadAgentTree()
          }
        }
      } catch (err) {
        console.error('[AgentAudit] Poll status failed:', err)
      }
    }

    poll()
    pollIntervalRef.current = setInterval(poll, pollInterval)

    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current)
        pollIntervalRef.current = null
      }
    }
  }, [auditId, state.task?.status, setTask, loadFindings, loadAgentTree])

  // ==================== 操作处理 ====================
  const handleStartAudit = async () => {
    if (!currentProject) {
      toast.error('请先打开一个项目')
      return
    }

    if (!isServiceHealthy) {
      toast.error('Agent 服务未连接，请检查服务状态')
      return
    }

    setLoading(true)
    toast.info('正在启动审计...')

    try {
      const result = await createAuditTask({
        project_id: currentProject.uuid,
        audit_type: auditType,
        config: undefined,
      })

      toast.success(`审计任务已启动: ${result.audit_id}`)
      navigate(`/project/${currentProject.id}/agent/${result.audit_id}`, { replace: true })
    } catch (err) {
      const message = err instanceof Error ? err.message : '启动审计失败'
      toast.error(message)
    } finally {
      setLoading(false)
    }
  }

  const handlePauseAudit = async () => {
    if (!auditId) return

    try {
      await pauseAuditTask(auditId)
      toast.success('审计已暂停')
      await loadTask()
    } catch (err) {
      toast.error('暂停审计失败')
    }
  }

  const handleCancelAudit = async () => {
    if (!auditId) return

    const confirmed = await confirmDialog({
      title: '终止审计任务',
      description: '确定要终止此审计任务吗？',
      confirmText: '终止',
      cancelText: '取消',
      type: 'warning',
    })
    if (!confirmed) return

    try {
      await cancelAuditTask(auditId)
      toast.success('审计已终止')
      await loadTask()
    } catch (err) {
      toast.error('终止审计失败')
    }
  }

  // 计算状态卡片数据
  const securityScore = state.findings.length > 0
    ? Math.max(0, 100 - state.findings.length * 5)
    : 100

  // ==================== 渲染 ====================
  return (
    <div className="flex flex-col h-full bg-[#121212]">
      {/* Header */}
      <AuditHeader
        taskName={auditId ? `Agent审计-${auditId.slice(-6)}` : undefined}
        status={state.task?.status}
        progress={state.task?.progress_percentage}
        isLoading={state.isLoading}
        isServiceHealthy={isServiceHealthy}
        logCount={filteredLogs.length}
        onStart={handleStartAudit}
        onCancel={handleCancelAudit}
        onExport={() => setExportDialogOpen(true)}
        onNewAudit={handleStartAudit}
      />

      {/* 主内容区 */}
      <div className="flex-1 flex overflow-hidden min-h-0">
        {/* 左侧：活动日志区域 (60%) */}
        <div className="w-[60%] border-r border-[#333333]">
          <ActivityLogPanel
            logs={filteredLogs}
            autoScroll={state.isAutoScroll}
            onToggleAutoScroll={() => {
              // 实现自动滚动切换
            }}
            isLoading={state.isLoading}
          />
        </div>

        {/* 右侧：状态面板 (40%) */}
        <div className="w-[40%] flex flex-col bg-[#121212]">
          {/* Agent Tree */}
          <div className="flex-1 flex flex-col border-b border-[#333333]">
            {/* Tab 栏 */}
            <div className="flex items-center justify-between px-4 py-2 border-b border-[#333333]">
              <div className="flex items-center gap-2">
                <div className="w-4 h-4 flex items-center justify-center">
                  {/* 文件夹图标 */}
                  <svg className="w-4 h-4 text-[#8B5CF6]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
                  </svg>
                </div>
                <h3 className="text-sm font-bold text-[#8B5CF6]">AGENT TREE</h3>
              </div>
              {isConnecting && (
                <Loader2 className="w-4 h-4 animate-spin text-[#888888]" />
              )}
            </div>

            {/* Agent Tree 内容 */}
            <div className="flex-1 overflow-hidden">
              <AgentTreePanelNew
                treeData={state.agentTree}
                loading={state.isLoading}
                selectedAgentId={state.selectedAgentId}
                onSelectAgent={selectAgent}
              />
            </div>
          </div>

          {/* 状态卡片 */}
          <div className="shrink-0">
            <StatusCards
              progress={state.task?.progress_percentage || 0}
              scannedFiles={state.task?.analyzed_files || 0}
              totalFiles={state.task?.total_files || 0}
              iterations={0}
              toolCalls={toolCallCount}
              tokens={tokenCount}
              findings={state.findings.length}
              securityScore={securityScore}
              isLoading={false}
            />
          </div>
        </div>
      </div>

      {/* 报告导出对话框 */}
      {auditId && (
        <ReportExportDialog
          open={exportDialogOpen}
          onOpenChange={setExportDialogOpen}
          auditId={auditId}
          findings={state.findings}
        />
      )}
    </div>
  )
}

export default function EnhancedAuditPageNewWrapper() {
  return (
    <div className="h-screen w-screen bg-[#121212] text-white overflow-hidden">
      <EnhancedAuditPageNew />
    </div>
  )
}
