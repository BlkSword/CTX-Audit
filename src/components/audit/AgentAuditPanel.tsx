/**
 * Agent 审计面板 - 创新设计版
 *
 * 特性：
 * - 流光卡片效果
 * - 时间轴布局
 * - 智能折叠卡片
 * - 实时脉动动画
 * - 玻璃态设计
 */

import React, { useEffect, useRef, useState } from 'react'
import {
  Play,
  Pause,
  Square,
  Brain,
  ChevronDown,
  ChevronRight,
  FileSearch,
  Shield,
  Bug,
  Network,
  Activity,
  Zap,
  Clock,
  AlertCircle,
  CheckCircle2,
  Loader2,
} from 'lucide-react'
import { useAgentStore } from '@/stores/agentStore'
import { useUIStore } from '@/stores/uiStore'
import { useProjectStore } from '@/stores/projectStore'
import { useToast } from '@/hooks/use-toast'
import { useToastStore } from '@/stores/toastStore'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { AgentTreeVisualization } from './AgentTreeVisualization'
import type { AgentEvent, AgentType } from '@/shared/types'
import { cn } from '@/lib/utils'

// ==================== 样式常量 ====================

const AGENT_CONFIG: Record<AgentType, {
  icon: React.ComponentType<{ className?: string }>
  name: string
  color: string
  gradient: string
  bgGradient: string
}> = {
  ORCHESTRATOR: {
    icon: Brain,
    name: '编排者',
    color: 'text-violet-500',
    gradient: 'from-violet-500 to-purple-600',
    bgGradient: 'bg-gradient-to-br from-violet-500/10 to-purple-600/10',
  },
  RECON: {
    icon: FileSearch,
    name: '侦察者',
    color: 'text-blue-500',
    gradient: 'from-blue-500 to-cyan-600',
    bgGradient: 'bg-gradient-to-br from-blue-500/10 to-cyan-600/10',
  },
  ANALYSIS: {
    icon: Bug,
    name: '分析者',
    color: 'text-orange-500',
    gradient: 'from-orange-500 to-amber-600',
    bgGradient: 'bg-gradient-to-br from-orange-500/10 to-amber-600/10',
  },
  VERIFICATION: {
    icon: Shield,
    name: '验证者',
    color: 'text-emerald-500',
    gradient: 'from-emerald-500 to-green-600',
    bgGradient: 'bg-gradient-to-br from-emerald-500/10 to-green-600/10',
  },
}

const EVENT_TYPE_CONFIG: Record<string, {
  icon: React.ComponentType<{ className?: string }>
  color: string
  bgGradient: string
  borderGradient: string
}> = {
  thinking: {
    icon: Brain,
    color: 'text-violet-500',
    bgGradient: 'bg-gradient-to-br from-violet-50 to-purple-50 dark:from-violet-950/30 dark:to-purple-950/30',
    borderGradient: 'border-violet-200 dark:border-violet-800',
  },
  tool_call: {
    icon: Zap,
    color: 'text-blue-500',
    bgGradient: 'bg-gradient-to-br from-blue-50 to-cyan-50 dark:from-blue-950/30 dark:to-cyan-950/30',
    borderGradient: 'border-blue-200 dark:border-blue-800',
  },
  observation: {
    icon: Activity,
    color: 'text-emerald-500',
    bgGradient: 'bg-gradient-to-br from-emerald-50 to-green-50 dark:from-emerald-950/30 dark:to-green-950/30',
    borderGradient: 'border-emerald-200 dark:border-emerald-800',
  },
  finding: {
    icon: AlertCircle,
    color: 'text-red-500',
    bgGradient: 'bg-gradient-to-br from-red-50 to-orange-50 dark:from-red-950/30 dark:to-orange-950/30',
    borderGradient: 'border-red-200 dark:border-red-800',
  },
  decision: {
    icon: CheckCircle2,
    color: 'text-amber-500',
    bgGradient: 'bg-gradient-to-br from-amber-50 to-yellow-50 dark:from-amber-950/30 dark:to-yellow-950/30',
    borderGradient: 'border-amber-200 dark:border-amber-800',
  },
  progress: {
    icon: Clock,
    color: 'text-cyan-500',
    bgGradient: 'bg-gradient-to-br from-cyan-50 to-blue-50 dark:from-cyan-950/30 dark:to-blue-950/30',
    borderGradient: 'border-cyan-200 dark:border-cyan-800',
  },
  error: {
    icon: AlertCircle,
    color: 'text-rose-500',
    bgGradient: 'bg-gradient-to-br from-rose-50 to-red-50 dark:from-rose-950/30 dark:to-red-950/30',
    borderGradient: 'border-rose-200 dark:border-rose-800',
  },
  complete: {
    icon: CheckCircle2,
    color: 'text-green-500',
    bgGradient: 'bg-gradient-to-br from-green-50 to-emerald-50 dark:from-green-950/30 dark:to-emerald-950/30',
    borderGradient: 'border-green-200 dark:border-green-800',
  },
}

// ==================== 时间轴事件卡片 ====================

interface TimelineEventProps {
  event: AgentEvent
  isExpanded: boolean
  onToggle: () => void
  index: number
  total: number
}

function TimelineEvent({ event, isExpanded, onToggle, index, total }: TimelineEventProps) {
  const agentConfig = AGENT_CONFIG[event.agent_type]
  const eventConfig = EVENT_TYPE_CONFIG[event.type] || EVENT_TYPE_CONFIG.thinking
  const EventIcon = eventConfig.icon
  const AgentIcon = agentConfig.icon

  // 格式化事件内容
  const formatEventContent = () => {
    const data = event.data as any
    switch (event.type) {
      case 'thinking':
        return data.thought || data.reasoning
      case 'tool_call':
      case 'action':
        return data.tool_name || data.action
      case 'observation':
        return data.observation || data.summary || '执行完成'
      case 'finding':
        return `${data.finding?.title || '发现漏洞'} [${data.finding?.severity?.toUpperCase() || 'UNKNOWN'}]`
      case 'decision':
        return data.decision || '做出决策'
      case 'progress':
        return data.message || data.stage
      case 'error':
        return data.error || '发生错误'
      case 'complete':
        return data.summary || '任务完成'
      default:
        return JSON.stringify(data).slice(0, 100)
    }
  }

  // 获取详细信息
  const getDetails = () => {
    const data = event.data as any
    switch (event.type) {
      case 'thinking':
        return (
          <div className="mt-3 space-y-2">
            {data.reasoning && (
              <div className="p-3 bg-violet-50 dark:bg-violet-950/20 rounded-lg border border-violet-200 dark:border-violet-800">
                <p className="text-xs font-medium text-violet-700 dark:text-violet-300 mb-1">💭 推理过程</p>
                <p className="text-xs text-muted-foreground">{data.reasoning}</p>
              </div>
            )}
            {data.context && (
              <details className="group">
                <summary className="cursor-pointer text-xs text-muted-foreground hover:text-foreground flex items-center gap-1">
                  <ChevronRight className="w-3 h-3 transition-transform group-open:rotate-90" />
                  查看上下文
                </summary>
                <pre className="mt-2 p-3 bg-muted rounded-lg text-xs overflow-x-auto no-scrollbar">
                  {JSON.stringify(data.context, null, 2)}
                </pre>
              </details>
            )}
          </div>
        )
      case 'tool_call':
      case 'action':
        return (
          <div className="mt-3 space-y-2">
            {data.tool_name && (
              <div className="flex items-center gap-2 p-2 bg-blue-50 dark:bg-blue-950/20 rounded-lg">
                <Zap className="w-4 h-4 text-blue-500" />
                <span className="text-xs font-medium text-blue-700 dark:text-blue-300">
                  {data.tool_name}
                </span>
              </div>
            )}
            {data.parameters && (
              <details className="group">
                <summary className="cursor-pointer text-xs text-muted-foreground hover:text-foreground flex items-center gap-1">
                  <ChevronRight className="w-3 h-3 transition-transform group-open:rotate-90" />
                  调用参数
                </summary>
                <pre className="mt-2 p-3 bg-muted rounded-lg text-xs overflow-x-auto no-scrollbar">
                  {JSON.stringify(data.parameters, null, 2)}
                </pre>
              </details>
            )}
          </div>
        )
      case 'observation':
        return data.result && (
          <details className="mt-3 group">
            <summary className="cursor-pointer text-xs text-muted-foreground hover:text-foreground flex items-center gap-1">
              <ChevronRight className="w-3 h-3 transition-transform group-open:rotate-90" />
              查看结果
            </summary>
            <pre className="mt-2 p-3 bg-emerald-50 dark:bg-emerald-950/20 rounded-lg text-xs overflow-x-auto max-h-48 no-scrollbar border border-emerald-200 dark:border-emerald-800">
              {JSON.stringify(data.result, null, 2)}
            </pre>
          </details>
        )
      case 'finding':
        const finding = data.finding
        return (
          <div className="mt-3 p-3 bg-red-50 dark:bg-red-950/20 rounded-lg border border-red-200 dark:border-red-800 space-y-2">
            <div className="flex items-start justify-between">
              <div className="flex-1 min-w-0">
                <p className="text-xs font-medium text-red-700 dark:text-red-300 mb-1">🔴 漏洞发现</p>
                <p className="text-sm font-semibold">{finding?.title}</p>
              </div>
              <Badge className="shrink-0 ml-2" variant="destructive">
                {finding?.severity?.toUpperCase()}
              </Badge>
            </div>
            <p className="text-xs text-muted-foreground">{finding?.description}</p>
            <p className="text-xs font-mono text-muted-foreground">
              📄 {finding?.file_path}:{finding?.line_number}
            </p>
            {finding?.code_snippet && (
              <pre className="mt-2 p-2 bg-red-100 dark:bg-red-900/30 rounded text-xs overflow-x-auto no-scrollbar">
                <code>{finding.code_snippet}</code>
              </pre>
            )}
          </div>
        )
      case 'decision':
        return (
          <div className="mt-3 p-3 bg-amber-50 dark:bg-amber-950/20 rounded-lg border border-amber-200 dark:border-amber-800 space-y-1">
            {data.reasoning && (
              <p className="text-xs"><strong>理由:</strong> {data.reasoning}</p>
            )}
            {data.next_agent && (
              <p className="text-xs">
                <strong>下一个:</strong> {AGENT_CONFIG[data.next_agent as AgentType]?.name}
              </p>
            )}
            {data.next_action && (
              <p className="text-xs"><strong>动作:</strong> {data.next_action}</p>
            )}
          </div>
        )
      case 'error':
        return (
          <div className="mt-3 p-3 bg-rose-50 dark:bg-rose-950/20 rounded-lg border border-rose-200 dark:border-rose-800">
            <p className="text-xs text-rose-700 dark:text-rose-300">{data.error}</p>
          </div>
        )
      default:
        return null
    }
  }

  const isFirst = index === 0
  const isLast = index === total - 1

  return (
    <div className="relative pl-8">
      {/* 时间轴线 */}
      {!isLast && (
        <div className="absolute left-3 top-8 w-0.5 h-full bg-gradient-to-b from-violet-200 via-violet-100 to-transparent dark:from-violet-800 dark:via-violet-900" />
      )}

      {/* 时间轴节点 */}
      <div className={cn(
        "absolute left-0 top-4 w-6 h-6 rounded-full flex items-center justify-center",
        "bg-gradient-to-br shadow-lg",
        agentConfig.gradient
      )}>
        <AgentIcon className="w-3.5 h-3.5 text-white" />
      </div>

      {/* 事件卡片 */}
      <div
        className={cn(
          "relative group mb-4 rounded-xl border transition-all duration-300",
          eventConfig.borderGradient,
          eventConfig.bgGradient,
          "hover:shadow-lg hover:scale-[1.01] cursor-pointer",
          isExpanded && "shadow-md"
        )}
        onClick={onToggle}
      >
        {/* 流光效果 */}
        <div className="absolute inset-0 rounded-xl overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent -translate-x-full group-hover:animate-[shimmer_2s_infinite]" />
        </div>

        {/* 卡片内容 */}
        <div className="relative p-4">
          {/* 头部 */}
          <div className="flex items-start gap-3">
            {/* 图标 */}
            <div className={cn(
              "p-2 rounded-lg bg-gradient-to-br shadow-sm",
              agentConfig.gradient
            )}>
              <EventIcon className="w-4 h-4 text-white" />
            </div>

            {/* 内容 */}
            <div className="flex-1 min-w-0">
              {/* 标签行 */}
              <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                <Badge variant="outline" className={cn(
                  "text-[9px] h-5 px-1.5 font-medium",
                  eventConfig.color,
                  eventConfig.borderGradient
                )}>
                  {event.type}
                </Badge>
                <Badge variant="outline" className={cn(
                  "text-[9px] h-5 px-1.5 font-medium",
                  agentConfig.color,
                  "border-current"
                )}>
                  {agentConfig.name}
                </Badge>
                <span className="text-[10px] text-muted-foreground font-mono">
                  {new Date(event.timestamp).toLocaleTimeString()}
                </span>
              </div>

              {/* 标题 */}
              <p className="text-sm font-medium text-foreground">
                {formatEventContent()}
              </p>
            </div>

            {/* 展开按钮 */}
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7 shrink-0 opacity-50 group-hover:opacity-100 transition-opacity"
            >
              {isExpanded ? (
                <ChevronDown className="w-4 h-4" />
              ) : (
                <ChevronRight className="w-4 h-4" />
              )}
            </Button>
          </div>

          {/* 展开内容 */}
          {isExpanded && getDetails()}
        </div>
      </div>
    </div>
  )
}

// ==================== Agent 状态卡片 ====================

interface AgentStatusCardProps {
  type: AgentType
  status: string
}

function AgentStatusCard({ type, status }: AgentStatusCardProps) {
  const config = AGENT_CONFIG[type]
  const Icon = config.icon

  const isRunning = status === 'running'
  const isCompleted = status === 'completed'

  return (
    <div className={cn(
      "relative overflow-hidden rounded-xl border transition-all duration-300",
      config.bgGradient,
      isRunning ? "border-current shadow-lg shadow-current/20" : "border-border/50",
      isCompleted && "opacity-60"
    )}>
      {/* 运行时的流光边框 */}
      {isRunning && (
        <>
          <div className="absolute inset-0 rounded-xl bg-gradient-to-r from-transparent via-current/10 to-transparent -translate-x-full animate-[shimmer_3s_infinite]" />
          <div className="absolute inset-0 rounded-xl bg-gradient-to-r from-transparent via-current/5 to-transparent translate-x-full animate-[shimmer-reverse_3s_infinite]" />
        </>
      )}

      <div className="relative p-3">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <div className={cn(
              "p-1.5 rounded-lg bg-gradient-to-br",
              config.gradient
            )}>
              <Icon className={cn(
                "w-4 h-4 text-white",
                isRunning && "animate-pulse"
              )} />
            </div>
            <span className="text-sm font-medium">{config.name}</span>
          </div>

          <div className="flex items-center gap-1.5">
            {isRunning && (
              <div className="flex gap-0.5">
                <span className="w-1 h-1 rounded-full bg-current animate-pulse" />
                <span className="w-1 h-1 rounded-full bg-current animate-pulse delay-75" />
                <span className="w-1 h-1 rounded-full bg-current animate-pulse delay-150" />
              </div>
            )}
            {isCompleted && (
              <CheckCircle2 className="w-4 h-4 text-green-500" />
            )}
          </div>
        </div>

        <div className="flex items-center justify-between">
          <Badge
            variant={isRunning ? "default" : "outline"}
            className={cn(
              "text-[9px] h-5 px-1.5 font-medium",
              isRunning && config.gradient
            )}
          >
            {status || 'idle'}
          </Badge>

          {isRunning && (
            <div className="h-1 flex-1 mx-3 rounded-full bg-current/20 overflow-hidden">
              <div className="h-full rounded-full bg-current animate-[progress_2s_ease-in-out_infinite]" />
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ==================== 主面板 ====================

export function AgentAuditPanel() {
  const { currentProject } = useProjectStore()
  const { addLog } = useUIStore()
  const toast = useToast()
  const { removeToast } = useToastStore()

  const {
    auditStatus,
    auditProgress,
    agentStatus,
    auditError,
    events,
    llmConfigs,
    isConnected,
    agentTree,
    agentTreeLoading,
    agentTreeError,
    startAudit,
    pauseAudit,
    cancelAudit,
    loadAgentTree,
    refreshAgentTree,
    stopAgent,
  } = useAgentStore()

  const [auditType, setAuditType] = useState<'quick' | 'full'>('quick')
  const [selectedLLMConfig, setSelectedLLMConfig] = useState<string>('default')
  const [expandedEvents, setExpandedEvents] = useState<Set<string>>(new Set())
  const [activeTab, setActiveTab] = useState<'events' | 'tree'>('events')
  const [autoScroll, setAutoScroll] = useState(true)

  const eventsEndRef = useRef<HTMLDivElement>(null)
  const eventsContainerRef = useRef<HTMLDivElement>(null)

  // 初始化
  useEffect(() => {
    useAgentStore.getState().loadLLMConfigs()
    useAgentStore.getState().checkConnection()

    const interval = setInterval(() => {
      useAgentStore.getState().checkConnection()
    }, 10000)

    return () => clearInterval(interval)
  }, [])

  // 加载 Agent 树
  useEffect(() => {
    if (auditStatus === 'running' && activeTab === 'tree') {
      loadAgentTree()
    }
  }, [auditStatus, activeTab, loadAgentTree])

  // 定时刷新
  useEffect(() => {
    if (auditStatus === 'running' && activeTab === 'tree') {
      const interval = setInterval(() => loadAgentTree(), 5000)
      return () => clearInterval(interval)
    }
  }, [auditStatus, activeTab, loadAgentTree])

  // 自动滚动
  useEffect(() => {
    if (autoScroll && eventsEndRef.current) {
      eventsEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [events, autoScroll])

  // 切换展开状态
  const toggleEventExpanded = (eventId: string) => {
    setExpandedEvents(prev => {
      const newSet = new Set(prev)
      if (newSet.has(eventId)) {
        newSet.delete(eventId)
      } else {
        newSet.add(eventId)
      }
      return newSet
    })
  }

  // 启动审计
  const handleStartAudit = async () => {
    if (!currentProject) {
      toast.warning('请先打开一个项目')
      return
    }

    if (!isConnected) {
      toast.error('Agent 服务未连接，请先启动服务')
      return
    }

    const loadingToast = toast.loading(`正在启动${auditType === 'quick' ? '快速' : '完整'}审计...`)

    try {
      let config: any = undefined
      if (selectedLLMConfig && selectedLLMConfig !== 'default') {
        config = { llm_config_id: selectedLLMConfig }
      }

      const auditId = await startAudit(
        currentProject.id.toString(),
        auditType,
        config
      )
      toast.success(`审计任务已启动: ${auditId}`)
    } catch (err) {
      const message = err instanceof Error ? err.message : '未知错误'
      toast.error(`启动审计失败: ${message}`)
    } finally {
      removeToast(loadingToast)
    }
  }

  // 暂停/终止审计
  const handlePauseAudit = async () => {
    try {
      await pauseAudit()
      toast.info('审计已暂停')
    } catch (err) {
      toast.error(`暂停失败: ${err}`)
    }
  }

  const handleCancelAudit = async () => {
    try {
      await cancelAudit()
      toast.warning('审计已终止')
    } catch (err) {
      toast.error(`终止失败: ${err}`)
    }
  }

  return (
    <div className="flex flex-col h-full bg-gradient-to-br from-background via-background to-muted/20">
      {/* 顶部控制栏 */}
      <div className="flex items-center justify-between p-4 border-b bg-background/50 backdrop-blur-sm">
        <div className="flex items-center gap-6">
          {/* 审计类型选择 */}
          <div className="flex items-center gap-2">
            <label className="text-xs font-medium text-muted-foreground">审计模式</label>
            <Select value={auditType} onValueChange={(v: any) => setAuditType(v)}>
              <SelectTrigger className="w-32 h-8">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="quick">⚡ 快速扫描</SelectItem>
                <SelectItem value="full">🔍 深度审计</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* LLM 配置选择 */}
          <div className="flex items-center gap-2">
            <label className="text-xs font-medium text-muted-foreground">AI 模型</label>
            <Select value={selectedLLMConfig} onValueChange={setSelectedLLMConfig}>
              <SelectTrigger className="w-48 h-8">
                <SelectValue placeholder="选择配置" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="default">🤖 默认配置</SelectItem>
                {llmConfigs?.map((config: any) => (
                  <SelectItem key={config.id} value={config.id}>
                    {config.provider} - {config.model}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* 连接状态 */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-background border">
            <div className={cn(
              "w-2 h-2 rounded-full transition-colors",
              isConnected ? "bg-green-500" : "bg-red-500"
            )} />
            <span className="text-xs text-muted-foreground">
              {isConnected ? '已连接' : '未连接'}
            </span>
          </div>
        </div>

        {/* 控制按钮 */}
        <div className="flex items-center gap-2">
          {auditStatus === 'running' ? (
            <>
              <Button variant="outline" size="sm" onClick={handlePauseAudit} className="h-8">
                <Pause className="w-3.5 h-3.5 mr-1" /> 暂停
              </Button>
              <Button variant="destructive" size="sm" onClick={handleCancelAudit} className="h-8">
                <Square className="w-3.5 h-3.5 mr-1" /> 终止
              </Button>
            </>
          ) : (
            <Button size="sm" onClick={handleStartAudit} disabled={!isConnected} className="h-8">
              <Play className="w-3.5 h-3.5 mr-1" /> 开始审计
            </Button>
          )}
        </div>
      </div>

      {/* 主内容区 */}
      <div className="flex-1 min-h-0 flex overflow-hidden">
        {/* 左侧：事件流 (70%) */}
        <div className="flex-[7] flex flex-col min-w-0 border-r">
          {/* Tab 标题栏 */}
          <div className="flex items-center justify-between px-4 py-2 border-b bg-background/50 backdrop-blur-sm">
            <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as 'events' | 'tree')} className="flex-1">
              <TabsList className="h-8 bg-muted/50">
                <TabsTrigger value="events" className="gap-1.5 data-[state=active]:bg-background">
                  <Activity className="w-3.5 h-3.5" />
                  事件流
                  {events.length > 0 && (
                    <Badge variant="secondary" className="h-4 px-1 text-[9px]">
                      {events.length}
                    </Badge>
                  )}
                </TabsTrigger>
                <TabsTrigger value="tree" className="gap-1.5 data-[state=active]:bg-background">
                  <Network className="w-3.5 h-3.5" />
                  Agent 树
                </TabsTrigger>
              </TabsList>

              {/* Tab 内容 - 移到 Tabs 内部 */}
              <TabsContent value="events" className="mt-0 flex-1 m-0 p-0 min-h-0 data-[state=active]:flex data-[state=active]:flex-col">
                <ScrollArea ref={eventsContainerRef} className="h-full">
                  <div className="p-6">
                    {events.length === 0 ? (
                      <div className="flex flex-col items-center justify-center h-full min-h-[300px] text-muted-foreground">
                        <div className="relative">
                          <div className="absolute inset-0 bg-gradient-to-r from-violet-500/20 to-purple-500/20 blur-3xl rounded-full" />
                          <Brain className="relative w-16 h-16 mb-4 opacity-30" />
                        </div>
                        <p className="text-sm font-medium">准备就绪</p>
                        <p className="text-xs mt-1">点击"开始审计"启动 Agent 系统</p>
                      </div>
                    ) : (
                      <div className="space-y-0">
                        {events.map((event, index) => (
                          <TimelineEvent
                            key={event.id}
                            event={event}
                            isExpanded={expandedEvents.has(event.id)}
                            onToggle={() => toggleEventExpanded(event.id)}
                            index={index}
                            total={events.length}
                          />
                        ))}
                        <div ref={eventsEndRef} />
                      </div>
                    )}
                  </div>
                </ScrollArea>
              </TabsContent>

              <TabsContent value="tree" className="mt-0 flex-1 m-0 p-0 min-h-0 data-[state=active]:flex data-[state=active]:flex-col">
                <AgentTreeVisualization
                  treeData={agentTree}
                  loading={agentTreeLoading}
                  error={agentTreeError}
                  onStopAgent={stopAgent}
                  onRefresh={refreshAgentTree}
                />
              </TabsContent>
            </Tabs>

            <div className="flex items-center gap-2">
              {/* 进度显示 */}
              {auditProgress && (
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <div className="w-24 h-1.5 rounded-full bg-muted overflow-hidden">
                    <div
                      className="h-full bg-gradient-to-r from-violet-500 to-purple-600 transition-all duration-500"
                      style={{ width: `${auditProgress.percentage}%` }}
                    />
                  </div>
                  <span className="font-mono">{auditProgress.percentage}%</span>
                </div>
              )}

              {/* 自动滚动开关 */}
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setAutoScroll(!autoScroll)}
                className={cn(
                  "h-7 px-2 text-xs",
                  autoScroll && "bg-primary/10 text-primary"
                )}
              >
                {autoScroll ? '📍 跟随' : '📍 固定'}
              </Button>
            </div>
          </div>
        </div>

        {/* 右侧：Agent 状态 (30%) */}
        <div className="flex-[3] flex flex-col bg-muted/10">
          {/* 标题 */}
          <div className="px-4 py-2 border-b bg-background/50 backdrop-blur-sm">
            <h3 className="text-sm font-medium">Agent 状态</h3>
          </div>

          {/* Agent 卡片列表 */}
          <ScrollArea className="flex-1">
            <div className="p-4 space-y-3">
              {(Object.keys(AGENT_CONFIG) as AgentType[]).map((type) => (
                <AgentStatusCard
                  key={type}
                  type={type}
                  status={agentStatus[type] || 'idle'}
                />
              ))}

              {/* 错误显示 */}
              {auditError && (
                <div className="mt-4 p-3 bg-red-50 dark:bg-red-950/20 rounded-xl border border-red-200 dark:border-red-800">
                  <div className="flex items-start gap-2">
                    <AlertCircle className="w-4 h-4 text-red-500 shrink-0 mt-0.5" />
                    <div>
                      <p className="text-xs font-medium text-red-700 dark:text-red-300">错误</p>
                      <p className="text-xs text-red-600 dark:text-red-400 mt-1">{auditError}</p>
                    </div>
                  </div>
                </div>
              )}

              {/* 统计信息 */}
              {events.length > 0 && (
                <div className="mt-4 p-3 bg-gradient-to-br from-violet-50 to-purple-50 dark:from-violet-950/20 dark:to-purple-950/20 rounded-xl border border-violet-200 dark:border-violet-800">
                  <p className="text-xs font-medium text-violet-700 dark:text-violet-300 mb-2">📊 审计统计</p>
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div className="p-2 bg-background/50 rounded-lg">
                      <p className="text-muted-foreground">总事件</p>
                      <p className="text-lg font-bold text-foreground">{events.length}</p>
                    </div>
                    <div className="p-2 bg-background/50 rounded-lg">
                      <p className="text-muted-foreground">进度</p>
                      <p className="text-lg font-bold text-foreground">{auditProgress?.percentage || 0}%</p>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </ScrollArea>
        </div>
      </div>
    </div>
  )
}
