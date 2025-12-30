/**
 * Agent 审计面板 - 精美版
 *
 * 特性：
 * - 动态节点树展示
 * - 流光动画效果
 * - 时间轴布局
 * - 实时脉动动画
 * - 玻璃态设计
 * - 渐变色彩系统
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
  Sparkles,
  TrendingUp,
  Radio,
  Cpu,
  Database,
  Info,
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
  glowColor: string
}> = {
  ORCHESTRATOR: {
    icon: Brain,
    name: '编排者',
    color: 'text-violet-500',
    gradient: 'from-violet-500 to-purple-600',
    bgGradient: 'bg-gradient-to-br from-violet-500/10 to-purple-600/10',
    glowColor: 'shadow-violet-500/50',
  },
  RECON: {
    icon: FileSearch,
    name: '侦察者',
    color: 'text-blue-500',
    gradient: 'from-blue-500 to-cyan-600',
    bgGradient: 'bg-gradient-to-br from-blue-500/10 to-cyan-600/10',
    glowColor: 'shadow-blue-500/50',
  },
  ANALYSIS: {
    icon: Bug,
    name: '分析者',
    color: 'text-orange-500',
    gradient: 'from-orange-500 to-amber-600',
    bgGradient: 'bg-gradient-to-br from-orange-500/10 to-amber-600/10',
    glowColor: 'shadow-orange-500/50',
  },
  VERIFICATION: {
    icon: Shield,
    name: '验证者',
    color: 'text-emerald-500',
    gradient: 'from-emerald-500 to-green-600',
    bgGradient: 'bg-gradient-to-br from-emerald-500/10 to-green-600/10',
    glowColor: 'shadow-emerald-500/50',
  },
}

const EVENT_TYPE_CONFIG: Record<string, {
  icon: React.ComponentType<{ className?: string }>
  color: string
  bgGradient: string
  borderGradient: string
  glowColor: string
}> = {
  thinking: {
    icon: Brain,
    color: 'text-violet-500',
    bgGradient: 'bg-gradient-to-br from-violet-50 to-purple-50 dark:from-violet-950/30 dark:to-purple-950/30',
    borderGradient: 'border-violet-200 dark:border-violet-800',
    glowColor: 'shadow-violet-500/20',
  },
  tool_call: {
    icon: Zap,
    color: 'text-blue-500',
    bgGradient: 'bg-gradient-to-br from-blue-50 to-cyan-50 dark:from-blue-950/30 dark:to-cyan-950/30',
    borderGradient: 'border-blue-200 dark:border-blue-800',
    glowColor: 'shadow-blue-500/20',
  },
  observation: {
    icon: Activity,
    color: 'text-emerald-500',
    bgGradient: 'bg-gradient-to-br from-emerald-50 to-green-50 dark:from-emerald-950/30 dark:to-green-950/30',
    borderGradient: 'border-emerald-200 dark:border-emerald-800',
    glowColor: 'shadow-emerald-500/20',
  },
  finding: {
    icon: AlertCircle,
    color: 'text-red-500',
    bgGradient: 'bg-gradient-to-br from-red-50 to-orange-50 dark:from-red-950/30 dark:to-orange-950/30',
    borderGradient: 'border-red-200 dark:border-red-800',
    glowColor: 'shadow-red-500/20',
  },
  decision: {
    icon: CheckCircle2,
    color: 'text-amber-500',
    bgGradient: 'bg-gradient-to-br from-amber-50 to-yellow-50 dark:from-amber-950/30 dark:to-yellow-950/30',
    borderGradient: 'border-amber-200 dark:border-amber-800',
    glowColor: 'shadow-amber-500/20',
  },
  progress: {
    icon: Clock,
    color: 'text-cyan-500',
    bgGradient: 'bg-gradient-to-br from-cyan-50 to-blue-50 dark:from-cyan-950/30 dark:to-blue-950/30',
    borderGradient: 'border-cyan-200 dark:border-cyan-800',
    glowColor: 'shadow-cyan-500/20',
  },
  error: {
    icon: AlertCircle,
    color: 'text-rose-500',
    bgGradient: 'bg-gradient-to-br from-rose-50 to-red-50 dark:from-rose-950/30 dark:to-red-950/30',
    borderGradient: 'border-rose-200 dark:border-rose-800',
    glowColor: 'shadow-rose-500/20',
  },
  complete: {
    icon: CheckCircle2,
    color: 'text-green-500',
    bgGradient: 'bg-gradient-to-br from-green-50 to-emerald-50 dark:from-green-950/30 dark:to-emerald-950/30',
    borderGradient: 'border-green-200 dark:border-green-800',
    glowColor: 'shadow-green-500/20',
  },
  status: {
    icon: Info,
    color: 'text-blue-500',
    bgGradient: 'bg-gradient-to-br from-blue-50 to-indigo-50 dark:from-blue-950/30 dark:to-indigo-950/30',
    borderGradient: 'border-blue-200 dark:border-blue-800',
    glowColor: 'shadow-blue-500/20',
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
  // 调试：检查事件数据
  if (!event.type) {
    console.warn('[TimelineEvent] 事件缺少 type 字段:', event)
  }
  if (!event.agent_type) {
    console.warn('[TimelineEvent] 事件缺少 agent_type 字段:', event)
  }

  const agentConfig = AGENT_CONFIG[event.agent_type] || AGENT_CONFIG.ORCHESTRATOR
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
                <p className="text-xs font-medium text-violet-700 dark:text-violet-300 mb-1 flex items-center gap-1">
                  <Brain className="w-3 h-3" />
                  推理过程
                </p>
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
                <p className="text-xs font-medium text-red-700 dark:text-red-300 mb-1 flex items-center gap-1">
                  <Shield className="w-3 h-3" />
                  漏洞发现
                </p>
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
        "absolute left-0 top-4 w-7 h-7 rounded-full flex items-center justify-center transition-all duration-300",
        "bg-gradient-to-br shadow-lg hover:scale-110",
        agentConfig.gradient,
        agentConfig.glowColor
      )}>
        <AgentIcon className="w-4 h-4 text-white" />
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
              "p-2.5 rounded-xl bg-gradient-to-br shadow-sm transition-all",
              agentConfig.gradient,
              "hover:scale-110"
            )}>
              <EventIcon className="w-4 h-4 text-white" />
            </div>

            {/* 内容 */}
            <div className="flex-1 min-w-0">
              {/* 标签行 */}
              <div className="flex items-center gap-2 mb-2 flex-wrap">
                <Badge variant="outline" className={cn(
                  "text-[9px] h-5 px-2 font-medium",
                  eventConfig.color,
                  eventConfig.borderGradient
                )}>
                  {event.type}
                </Badge>
                <Badge variant="outline" className={cn(
                  "text-[9px] h-5 px-2 font-medium",
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
      isRunning ? "border-current shadow-lg" : "border-border/50",
      isCompleted && "opacity-60",
      "hover:shadow-md hover:scale-[1.02]"
    )}>
      {/* 运行时的流光边框 */}
      {isRunning && (
        <>
          <div className="absolute inset-0 rounded-xl bg-gradient-to-r from-transparent via-current/10 to-transparent -translate-x-full animate-[shimmer_3s_infinite]" />
          <div className="absolute inset-0 rounded-xl bg-gradient-to-r from-transparent via-current/5 to-transparent translate-x-full animate-[shimmer-reverse_3s_infinite]" />
        </>
      )}

      <div className="relative p-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-3">
            <div className={cn(
              "p-2 rounded-xl bg-gradient-to-br shadow-sm transition-all",
              config.gradient,
              isRunning && "animate-pulse"
            )}>
              <Icon className={cn(
                "w-5 h-5 text-white"
              )} />
            </div>
            <span className="text-sm font-semibold">{config.name}</span>
          </div>

          <div className="flex items-center gap-2">
            {isRunning && (
              <div className="flex gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" />
                <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse delay-75" />
                <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse delay-150" />
              </div>
            )}
            {isCompleted && (
              <CheckCircle2 className="w-5 h-5 text-emerald-500" />
            )}
          </div>
        </div>

        <div className="flex items-center justify-between">
          <Badge
            variant={isRunning ? "default" : "outline"}
            className={cn(
              "text-[10px] h-6 px-2 font-medium",
              isRunning && config.gradient
            )}
          >
            {status || 'idle'}
          </Badge>

          {isRunning && (
            <div className="h-1.5 flex-1 mx-3 rounded-full bg-current/20 overflow-hidden">
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

  // 加载 Agent 树（用于更新 Agent 状态）
  // 无论在哪个标签页，只要审计运行就加载树
  useEffect(() => {
    if (auditStatus === 'running') {
      loadAgentTree()
    }
  }, [auditStatus, loadAgentTree])

  // 定时刷新 Agent 树
  useEffect(() => {
    if (auditStatus === 'running') {
      const interval = setInterval(() => loadAgentTree(), 3000)
      return () => clearInterval(interval)
    }
  }, [auditStatus, loadAgentTree])

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
        currentProject.uuid,
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
      <div className="flex items-center justify-between p-4 border-b bg-background/80 backdrop-blur-sm">
        <div className="flex items-center gap-6">
          {/* 审计类型选择 */}
          <div className="flex items-center gap-2">
            <label className="text-xs font-semibold text-muted-foreground">审计模式</label>
            <Select value={auditType} onValueChange={(v: any) => setAuditType(v)}>
              <SelectTrigger className="w-36 h-9">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="quick">
                  <div className="flex items-center gap-2">
                    <Zap className="w-4 h-4 text-amber-500" />
                    <span>快速扫描</span>
                  </div>
                </SelectItem>
                <SelectItem value="full">
                  <div className="flex items-center gap-2">
                    <Sparkles className="w-4 h-4 text-violet-500" />
                    <span>深度审计</span>
                  </div>
                </SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* LLM 配置选择 */}
          <div className="flex items-center gap-2">
            <label className="text-xs font-semibold text-muted-foreground">AI 模型</label>
            <Select value={selectedLLMConfig} onValueChange={setSelectedLLMConfig}>
              <SelectTrigger className="w-48 h-9">
                <SelectValue placeholder="选择配置" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="default">
                  <div className="flex items-center gap-2">
                    <Cpu className="w-4 h-4 text-primary" />
                    <span>默认配置</span>
                  </div>
                </SelectItem>
                {llmConfigs?.map((config: any) => (
                  <SelectItem key={config.id} value={config.id}>
                    <div className="flex items-center gap-2">
                      <Radio className="w-4 h-4 text-primary" />
                      <span>{config.provider} - {config.model}</span>
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* 连接状态 */}
          <div className={cn(
            "flex items-center gap-2 px-4 py-2 rounded-full border transition-all",
            isConnected
              ? "bg-emerald-500/10 border-emerald-500/30"
              : "bg-rose-500/10 border-rose-500/30"
          )}>
            <div className={cn(
              "w-2 h-2 rounded-full transition-colors",
              isConnected ? "bg-emerald-500 animate-pulse" : "bg-rose-500"
            )} />
            <span className={cn(
              "text-xs font-medium",
              isConnected ? "text-emerald-600 dark:text-emerald-400" : "text-rose-600 dark:text-rose-400"
            )}>
              {isConnected ? '已连接' : '未连接'}
            </span>
          </div>
        </div>

        {/* 控制按钮 */}
        <div className="flex items-center gap-2">
          {auditStatus === 'running' ? (
            <>
              <Button variant="outline" size="sm" onClick={handlePauseAudit} className="h-9">
                <Pause className="w-4 h-4 mr-2" /> 暂停
              </Button>
              <Button variant="destructive" size="sm" onClick={handleCancelAudit} className="h-9">
                <Square className="w-4 h-4 mr-2" /> 终止
              </Button>
            </>
          ) : (
            <Button size="sm" onClick={handleStartAudit} disabled={!isConnected} className="h-9">
              <Play className="w-4 h-4 mr-2" /> 开始审计
            </Button>
          )}
        </div>
      </div>

      {/* 主内容区 */}
      <div className="flex-1 min-h-0 flex overflow-hidden">
        {/* 左侧：事件流 (65%) */}
        <div className="flex-[65] flex flex-col min-w-0 border-r">
          {/* Tab 标题栏 */}
          <div className="flex items-center justify-between px-4 py-3 border-b bg-background/80 backdrop-blur-sm">
            <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as 'events' | 'tree')} className="flex-1">
              <TabsList className="h-9 bg-muted/50">
                <TabsTrigger value="events" className="gap-2 data-[state=active]:bg-background">
                  <Activity className="w-4 h-4" />
                  事件流
                  {events.length > 0 && (
                    <Badge variant="secondary" className="h-5 px-1.5 text-[9px]">
                      {events.length}
                    </Badge>
                  )}
                </TabsTrigger>
                <TabsTrigger value="tree" className="gap-2 data-[state=active]:bg-background">
                  <Network className="w-4 h-4" />
                  Agent 树
                </TabsTrigger>
              </TabsList>

              {/* Tab 内容 */}
              <TabsContent value="events" className="mt-0 flex-1 m-0 p-0 min-h-0 data-[state=active]:flex data-[state=active]:flex-col">
                <ScrollArea ref={eventsContainerRef} className="h-full">
                  <div className="p-6">
                    {events.length === 0 ? (
                      <div className="flex flex-col items-center justify-center h-full min-h-[400px] text-muted-foreground">
                        <div className="relative mb-6">
                          <div className="absolute inset-0 bg-gradient-to-r from-violet-500/30 to-purple-500/30 blur-3xl rounded-full" />
                          <Brain className="relative w-20 h-20 opacity-20" />
                        </div>
                        <div className="text-center">
                          <Sparkles className="w-8 h-8 mx-auto mb-3 text-primary/50" />
                          <p className="text-sm font-semibold mb-1">准备就绪</p>
                          <p className="text-xs">点击"开始审计"启动 AI Agent 系统</p>
                        </div>
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

            <div className="flex items-center gap-3 ml-4">
              {/* 进度显示 */}
              {auditProgress && (
                <div className="flex items-center gap-2">
                  <div className="w-28 h-2 rounded-full bg-muted overflow-hidden">
                    <div
                      className="h-full bg-gradient-to-r from-violet-500 to-purple-600 transition-all duration-500"
                      style={{ width: `${auditProgress.percentage}%` }}
                    />
                  </div>
                  <span className="text-xs font-mono font-semibold text-primary">{auditProgress.percentage}%</span>
                </div>
              )}

              {/* 自动滚动开关 */}
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setAutoScroll(!autoScroll)}
                className={cn(
                  "h-8 px-3 text-xs",
                  autoScroll && "bg-primary/10 text-primary"
                )}
              >
                {autoScroll ? <Activity className="w-3.5 h-3.5 mr-1" /> : <Clock className="w-3.5 h-3.5 mr-1" />}
                {autoScroll ? '跟随' : '固定'}
              </Button>
            </div>
          </div>
        </div>

        {/* 右侧：日志面板 (35%) */}
        <div className="flex-[35] flex flex-col bg-muted/5">
          {/* 标题 */}
          <div className="px-5 py-3 border-b bg-background/80 backdrop-blur-sm">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="p-1.5 rounded-lg bg-gradient-to-br from-blue-20 to-blue-10">
                  <Radio className="w-4 h-4 text-blue-500" />
                </div>
                <h3 className="text-sm font-semibold">运行日志</h3>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant={auditStatus === 'running' ? 'default' : 'secondary'} className="text-xs">
                  {events.length} 条
                </Badge>
              </div>
            </div>
          </div>

          {/* 日志列表 */}
          <ScrollArea className="flex-1">
            <div className="p-3 space-y-1">
              {events.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
                  <Activity className="w-12 h-12 mb-3 opacity-20" />
                  <p className="text-xs">暂无日志</p>
                </div>
              ) : (
                events.slice().reverse().map((event, index) => (
                  <div
                    key={event.id}
                    className={cn(
                      "text-xs p-2 rounded font-mono border-l-2 transition-all",
                      {
                        'border-blue-500 bg-blue-50/50 dark:bg-blue-950/20': event.type === 'thinking',
                        'border-emerald-500 bg-emerald-50/50 dark:bg-emerald-950/20': event.type === 'observation',
                        'border-amber-500 bg-amber-50/50 dark:bg-amber-950/20': event.type === 'tool_call' || event.type === 'action',
                        'border-red-500 bg-red-50/50 dark:bg-red-950/20': event.type === 'error' || event.type === 'finding',
                        'border-violet-500 bg-violet-50/50 dark:bg-violet-950/20': event.type === 'status',
                      }
                    )}
                  >
                    <div className="flex items-start gap-2">
                      <span className="text-[10px] text-muted-foreground shrink-0">
                        {new Date(event.timestamp * 1000).toLocaleTimeString('zh-CN', { hour12: false })}
                      </span>
                      <span className="text-muted-foreground shrink-0">
                        [{event.agent_type}]
                      </span>
                      <span className="flex-1 break-words">
                        {event.message || event.data?.message || JSON.stringify(event.data).substring(0, 100)}
                      </span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </ScrollArea>
        </div>
      </div>
    </div>
  )
}
