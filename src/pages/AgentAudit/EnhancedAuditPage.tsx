/**
 * 增强版 Agent 审计主页面
 *
 * 特性：
 * - 标签页切换（日志/结果）
 * - 审计状态指示器
 * - 优化的布局和交互
 * - 报告导出功能
 */

import { useEffect, useRef, useCallback, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { Play, Pause, Square, Zap, Sparkles, Loader2, Maximize2, Minimize2, FileText, Activity, Download, BarChart3 } from 'lucide-react'
import { useProjectStore } from '@/stores/projectStore'
import { useToast } from '@/hooks/use-toast'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { cn } from '@/lib/utils'

// 报告导出对话框
import { ReportExportDialog } from './components/ReportExportDialog'

// 状态管理
import { useAgentAuditState } from './useAgentAuditState'

// API
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

// Hook
import { useResilientStream } from './useResilientStream'

// 组件
import { ChatLogPanel } from '@/components/audit/ChatLogPanel'
import { FindingsPanel } from '@/components/audit/FindingsPanel'
import { AuditStatusIndicator, AuditStatusBadge } from '@/components/audit/AuditStatusIndicator'
import { AgentTreePanel } from './AgentTreePanel'
import { StatsPanel } from './StatsPanel'
import { AgentDetailPanel } from './AgentDetailPanel'
import { AuditFooter } from '@/components/audit/AuditFooter'
import { TerminalLogPanel } from '@/components/audit/TerminalLogPanel'
import { VizPanel } from './VizPanel'

// 类型
import type { AgentEvent, AgentFinding } from './types'

const HISTORY_EVENT_LIMIT = 500

export function EnhancedAuditPageContent() {
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
  const _selectedLLMConfig = useState<string>('default')[0]
  const [isFullscreen, setIsFullscreen] = useState(false)
  const [isServiceHealthy, setIsServiceHealthy] = useState(false)
  const [isCheckingHealth, setIsCheckingHealth] = useState(true)
  const [activeTab, setActiveTab] = useState<'logs' | 'findings' | 'viz'>('logs')
  const [logViewStyle, setLogViewStyle] = useState<'chat' | 'terminal'>('chat')

  // 报告导出对话框状态
  const [exportDialogOpen, setExportDialogOpen] = useState(false)

  // Refs
  const previousAuditIdRef = useRef<string | null>(null)
  const hasLoadedHistoricalEventsRef = useRef(false)
  const lastEventSequenceRef = useRef(0)
  const pollIntervalRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const lastPolledStatusRef = useRef<string | null>(null)

  // ==================== 初始化和清理 ====================

  // 健康检查
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

  useEffect(() => {
    return () => {
      if (pollIntervalRef.current) {
        clearTimeout(pollIntervalRef.current)
      }
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

      // 如果任务完成，自动切换到结果标签页
      if (task.status === 'completed' || task.status === 'failed') {
        setActiveTab('findings')
      }
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

    // 只添加有效的日志项（过滤掉 heartbeat、connected 等）
    if (logItem) {
      addLog(logItem)
    }

    // 切换到日志标签页（只在有新日志时）
    if (logItem && activeTab !== 'logs') {
      setActiveTab('logs')
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

      case 'phase_start':
      case 'phase_end':
      case 'phase_complete':
        // 更新当前阶段
        if ((event as any).phase || (event.data as any)?.phase || event.metadata?.phase) {
          if (state.task) {
            setTask({
              ...state.task,
              current_phase: (event as any).phase || (event.data as any)?.phase || event.metadata?.phase as string
            })
          }
        }
        break

      case 'progress':
        // 更新进度
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
        // 后端发送 status 事件，包含 status 字段
        const status = event.data?.status as string | undefined
        if (status === 'completed' || status === 'failed' || status === 'cancelled') {
          // 任务完成/失败/取消，刷新任务状态和发现列表
          // 使用 setTimeout 确保事件处理完成后再刷新
          setTimeout(() => {
            loadTask()
            loadFindings()
            loadAgentTree()
          }, 100)

          // 更新进度到 100%（完成时）
          if (status === 'completed' && state.task) {
            setTask({
              ...state.task,
              status: status as any,
              progress_percentage: 100
            })
          }

          // 切换到结果标签页
          setActiveTab('findings')
        } else {
          // 其他状态变更，也更新任务状态
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
        // 任务完成事件，刷新所有数据
        loadTask()
        loadFindings()
        loadAgentTree()
        setActiveTab('findings')
        break

      case 'error':
      case 'task_error':
        setError(event.data?.message as string || event.message || '任务执行失败')
        loadTask()
        break
    }
  }, [addLog, addFinding, loadTask, loadFindings, loadAgentTree, setError, activeTab, setTask])

  // ==================== Resilient Stream ====================

  const {
    isConnecting,
    connectionStatus,
  } = useResilientStream(auditId || null, state.afterSequence, {
    // 保持流连接，即使任务完成也继续连接一小段时间以接收最后的事件
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

  // 当任务运行时，定期轮询状态以确保同步
  useEffect(() => {
    if (!auditId || !state.task) return

    const isRunning = state.task.status === 'running' || state.task.status === 'pending'

    if (!isRunning) {
      // 清除轮询
      if (pollIntervalRef.current) {
        clearTimeout(pollIntervalRef.current)
        pollIntervalRef.current = null
      }
      return
    }

    // 轮询间隔：5秒
    const pollInterval = 5000

    const poll = async () => {
      try {
        const currentStatus = state.task?.status
        const updatedTask = await getAuditTask(auditId)

        // 只在状态改变时更新
        if (updatedTask.status !== currentStatus) {
          setTask(updatedTask)

          // 如果任务完成，加载完整数据
          if (updatedTask.status === 'completed' || updatedTask.status === 'failed') {
            loadFindings()
            loadAgentTree()
            setActiveTab('findings')
          }
        }
      } catch (err) {
        console.error('[AgentAudit] Poll status failed:', err)
      }
    }

    // 立即轮询一次
    poll()

    // 设置定期轮询
    pollIntervalRef.current = setInterval(poll, pollInterval)

    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current)
        pollIntervalRef.current = null
      }
    }
  }, [auditId, state.task?.status, setTask, loadFindings, loadAgentTree, setActiveTab])

  useEffect(() => {
    setConnectionStatus(connectionStatus)
  }, [connectionStatus, setConnectionStatus])

  // ==================== 定时轮询 ====================
// 仅在任务完成/失败/取消后轮询一次，避免重复请求
  useEffect(() => {
    // 只有当任务已结束且不是加载状态时才轮询
    const shouldPoll = auditId &&
      state.task?.status &&
      ['completed', 'failed', 'cancelled'].includes(state.task.status) &&
      !state.isLoading

    if (!shouldPoll) {
      if (pollIntervalRef.current) {
        clearTimeout(pollIntervalRef.current)
        pollIntervalRef.current = null
      }
      // 重置轮询状态标记
      if (state.task?.status === 'running') {
        lastPolledStatusRef.current = null
      }
      return
    }

    // 防止重复轮询 - 检查是否已经轮询过这个任务状态
    if (lastPolledStatusRef.current === (state.task?.status || null)) {
      return
    }
    lastPolledStatusRef.current = state.task?.status || null

    // 只轮询一次，不使用 setTimeout 重复轮询
    const pollOnce = async () => {
      try {
        // 并行请求但只执行一次
        await Promise.all([
          getAuditTask(auditId).then(setTask),
          getAuditFindings(auditId).then(setFindings),
          getAuditAgentTree(auditId).then(setAgentTree),
        ])
      } catch (err) {
        console.error('[AgentAudit] Poll error:', err)
      }
    }

    pollOnce()

    return () => {
      if (pollIntervalRef.current) {
        clearTimeout(pollIntervalRef.current)
        pollIntervalRef.current = null
      }
    }
  }, [auditId, state.task?.status, state.isLoading, setTask, setFindings, setAgentTree])

  // ==================== 启动审计 ====================

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
        config: _selectedLLMConfig !== 'default' ? { llm_config_id: _selectedLLMConfig } : undefined,
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

  // ==================== 暂停/取消 ====================

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

    if (!confirm('确定要终止此审计任务吗？')) return

    try {
      await cancelAuditTask(auditId)
      toast.success('审计已终止')
      await loadTask()
    } catch (err) {
      toast.error('终止审计失败')
    }
  }

  // ==================== 渲染 ====================

  return (
    <div className={cn(
      "flex flex-col h-full bg-slate-950",
      isFullscreen && "fixed inset-0 z-50"
    )}>
      {/* 顶部控制栏 */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800 bg-slate-900/50 backdrop-blur-sm shrink-0">
        <div className="flex items-center gap-4">
          {/* 审计模式选择 */}
          <div className="flex items-center gap-2">
            <label className="text-xs font-semibold text-slate-400">审计模式</label>
            <div className="flex rounded-lg bg-slate-900/50 p-1 border border-slate-800">
              <button
                onClick={() => setAuditType('quick')}
                className={cn(
                  "px-3 py-1.5 rounded-md text-xs font-medium transition-all flex items-center gap-1.5",
                  auditType === 'quick'
                    ? "bg-amber-500/20 text-amber-300"
                    : "text-slate-500 hover:text-slate-300"
                )}
              >
                <Zap className="w-3.5 h-3.5" />
                快速扫描
              </button>
              <button
                onClick={() => setAuditType('full')}
                className={cn(
                  "px-3 py-1.5 rounded-md text-xs font-medium transition-all flex items-center gap-1.5",
                  auditType === 'full'
                    ? "bg-violet-500/20 text-violet-300"
                    : "text-slate-500 hover:text-slate-300"
                )}
              >
                <Sparkles className="w-3.5 h-3.5" />
                深度审计
              </button>
            </div>
          </div>

          {/* 连接状态 */}
          <div className={cn(
            "flex items-center gap-2 px-3 py-1.5 rounded-full border transition-all",
            isServiceHealthy ? "bg-emerald-950/30 border-emerald-800/50" : "bg-rose-950/30 border-rose-800/50"
          )}>
            <div className={cn(
              "w-2 h-2 rounded-full transition-colors",
              isCheckingHealth ? "bg-amber-400 animate-pulse" : isServiceHealthy ? "bg-emerald-400 animate-pulse" : "bg-rose-400"
            )} />
            <span className={cn(
              "text-xs font-medium",
              isCheckingHealth ? "text-amber-400" : isServiceHealthy ? "text-emerald-400" : "text-rose-400"
            )}>
              {isCheckingHealth ? '检查中...' : isServiceHealthy ? '服务正常' : '服务离线'}
            </span>
          </div>

          {/* 审计状态徽章 */}
          {state.task && <AuditStatusBadge status={state.task.status} progress={state.task.progress_percentage} />}
        </div>

        {/* 右侧操作 */}
        <div className="flex items-center gap-2">
          {/* 导出报告按钮 */}
          {(state.task || state.findings.length > 0) && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => setExportDialogOpen(true)}
              disabled={!auditId}
              className="h-8 bg-slate-800 border-slate-700 text-slate-300 hover:text-slate-100"
            >
              <Download className="w-3.5 h-3.5 mr-1.5" />
              导出报告
            </Button>
          )}

          {/* 控制按钮 */}
          {state.task?.status === 'running' ? (
            <>
              <Button variant="outline" size="sm" onClick={handlePauseAudit} className="h-8 bg-slate-800 border-slate-700">
                <Pause className="w-3.5 h-3.5 mr-1.5" /> 暂停
              </Button>
              <Button variant="destructive" size="sm" onClick={handleCancelAudit} className="h-8">
                <Square className="w-3.5 h-3.5 mr-1.5" /> 终止
              </Button>
            </>
          ) : (
            <Button size="sm" onClick={handleStartAudit} disabled={!isServiceHealthy} className="h-8">
              <Play className="w-3.5 h-3.5 mr-1.5" /> 开始审计
            </Button>
          )}

          {/* 全屏切换 */}
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8 text-slate-400 hover:text-slate-200"
            onClick={() => setIsFullscreen(!isFullscreen)}
          >
            {isFullscreen ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
          </Button>
        </div>
      </div>

      {/* 主内容区 */}
      <div className="flex-1 flex overflow-hidden min-h-0">
        {/* 左侧：主面板 (70%) */}
        <div className="w-[70%] flex flex-col border-r border-slate-800 min-w-0">
          {/* 标签页切换 */}
          <Tabs value={activeTab} onValueChange={(v: any) => setActiveTab(v)} className="flex-1 flex flex-col">
            <div className="px-4 pt-3 shrink-0">
              <TabsList className="w-full bg-slate-900/50 border border-slate-800 rounded-lg p-1">
                <TabsTrigger value="logs" className="flex items-center gap-2 data-[state=active]:bg-slate-800">
                  <Activity className="w-4 h-4" />
                  <span>活动日志</span>
                  {state.logs.length > 0 && (
                    <Badge variant="secondary" className="ml-1 text-xs bg-slate-700 text-slate-400">
                      {state.logs.length}
                    </Badge>
                  )}
                </TabsTrigger>
                <TabsTrigger value="findings" className="flex items-center gap-2 data-[state=active]:bg-slate-800">
                  <FileText className="w-4 h-4" />
                  <span>审计结果</span>
                  {state.findings.length > 0 && (
                    <Badge variant="secondary" className="ml-1 text-xs bg-rose-900/50 text-rose-400">
                      {state.findings.length}
                    </Badge>
                  )}
                </TabsTrigger>
                <TabsTrigger value="viz" className="flex items-center gap-2 data-[state=active]:bg-slate-800">
                  <BarChart3 className="w-4 h-4" />
                  <span>数据统计</span>
                </TabsTrigger>
              </TabsList>
            </div>

            {/* 标签页内容 */}
            <div className="flex-1 min-h-0 overflow-hidden">
              <TabsContent value="logs" className="h-full m-0 p-0 overflow-hidden">
                {/* 日志视图切换按钮 */}
                <div className="absolute top-24 right-4 z-10 flex items-center gap-1 bg-slate-900/80 border border-slate-700 rounded-lg p-1">
                  <Button
                    variant={logViewStyle === 'chat' ? 'default' : 'ghost'}
                    size="sm"
                    onClick={() => setLogViewStyle('chat')}
                    className={cn(
                      "h-7 px-2 text-xs",
                      logViewStyle === 'chat' ? "bg-slate-700 text-white" : "text-slate-400"
                    )}
                  >
                    💬 聊天式
                  </Button>
                  <Button
                    variant={logViewStyle === 'terminal' ? 'default' : 'ghost'}
                    size="sm"
                    onClick={() => setLogViewStyle('terminal')}
                    className={cn(
                      "h-7 px-2 text-xs",
                      logViewStyle === 'terminal' ? "bg-slate-700 text-white" : "text-slate-400"
                    )}
                  >
                    ⌨️ 终端式
                  </Button>
                </div>

                {/* 根据视图风格显示不同的日志面板 */}
                {logViewStyle === 'terminal' ? (
                  <TerminalLogPanel
                    logs={filteredLogs}
                    autoScroll={state.isAutoScroll}
                    expandedLogIds={state.expandedLogIds}
                    onToggleExpand={toggleLogExpanded}
                  />
                ) : (
                  <ChatLogPanel
                    logs={filteredLogs}
                    autoScroll={state.isAutoScroll}
                    expandedLogIds={state.expandedLogIds}
                    onToggleExpand={toggleLogExpanded}
                  />
                )}
              </TabsContent>

              <TabsContent value="findings" className="h-full m-0 p-0 overflow-hidden">
                <div className="h-full flex flex-col">
                  {/* 工具栏 */}
                  <div className="px-4 py-2 border-b border-slate-800 bg-slate-900/50 flex items-center justify-between shrink-0">
                    <div className="text-sm text-slate-400">
                      发现 {state.findings.length} 个漏洞
                    </div>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setExportDialogOpen(true)}
                      disabled={state.findings.length === 0}
                      className="h-8 bg-slate-800 border-slate-700"
                    >
                      <Download className="w-3.5 h-3.5 mr-1.5" />
                      导出报告
                    </Button>
                  </div>

                  {/* 发现列表 */}
                  <div className="flex-1 min-h-0 overflow-hidden">
                    <FindingsPanel
                      findings={state.findings}
                      loading={state.isLoading}
                      onRefresh={loadFindings}
                    />
                  </div>
                </div>
              </TabsContent>

              {/* 可视化标签页 */}
              <TabsContent value="viz" className="h-full m-0 p-0 overflow-auto">
                <div className="h-full p-6 overflow-auto">
                  <VizPanel
                    findings={state.findings}
                    task={state.task}
                    tokenCount={tokenCount}
                    toolCallCount={toolCallCount}
                  />
                </div>
              </TabsContent>
            </div>
          </Tabs>
        </div>

        {/* 右侧：状态 + Agent 树 + 详情/统计 (30%) */}
        <div className="w-[30%] flex flex-col bg-slate-900/20 min-w-0">
          {/* 审计状态指示器 */}
          {state.task && (
            <div className="p-4 border-b border-slate-800 shrink-0">
              <AuditStatusIndicator
                status={state.task.status}
                progress={state.task.progress_percentage}
                currentPhase={state.task.current_phase}
                error={state.error}
              />
            </div>
          )}

          {/* Agent 树 */}
          <div className={cn(
            "flex flex-col border-b border-slate-800 bg-slate-900/20",
            state.selectedAgentId ? "h-[40%]" : "flex-1"
          )}>
            <div className="px-4 py-3 border-b border-slate-800 bg-slate-900/50 flex items-center justify-between shrink-0">
              <h3 className="text-sm font-semibold text-slate-200">Agent Tree</h3>
              {isConnecting && <Loader2 className="w-4 h-4 animate-spin text-slate-500" />}
            </div>
            <div className="flex-1 overflow-hidden">
              <AgentTreePanel
                treeData={state.agentTree}
                loading={state.isLoading}
                selectedAgentId={state.selectedAgentId}
                onSelectAgent={selectAgent}
              />
            </div>
          </div>

          {/* Agent 详情 或 统计面板 */}
          {state.selectedAgentId ? (
            <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
              <div className="px-4 py-3 border-b border-slate-800 bg-slate-900/50 flex items-center justify-between shrink-0">
                <h3 className="text-sm font-semibold text-slate-200">Agent 详情</h3>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => selectAgent(null)}
                  className="h-6 text-xs text-slate-400 hover:text-slate-200"
                >
                  关闭
                </Button>
              </div>
              <div className="flex-1 overflow-hidden">
                <AgentDetailPanel
                  agent={state.agentTree?.roots
                    .flatMap(root => [root, ...(root.children || [])])
                    .find(a => a.agent_id === state.selectedAgentId) || null}
                  logs={filteredLogs}
                  findings={state.findings}
                />
              </div>
            </div>
          ) : (
            <div className="shrink-0">
              <StatsPanel
                findings={state.findings}
                task={state.task}
                tokenCount={tokenCount}
                toolCallCount={toolCallCount}
              />
            </div>
          )}
        </div>
      </div>

      {/* 底部状态栏 */}
      <AuditFooter
        task={state.task}
        tokenCount={tokenCount}
        toolCallCount={toolCallCount}
        connectionStatus={state.connectionStatus}
        findingsCount={state.findings.length}
      />

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

// 导出默认组件
export default function EnhancedAuditPage() {
  return (
    <div className="h-screen w-screen bg-background text-foreground overflow-hidden">
      <EnhancedAuditPageContent />
    </div>
  )
}
