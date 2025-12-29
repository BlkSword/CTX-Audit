/**
 * Agent 审计面板组件
 *
 * 显示 AI Agent 审计过程，包括实时事件流、思考过程、工具调用等
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

// Agent 图标映射
const AGENT_ICONS: Record<AgentType, React.ComponentType<{ className?: string }>> = {
  ORCHESTRATOR: Brain,
  RECON: FileSearch,
  ANALYSIS: Bug,
  VERIFICATION: Shield,
}

// Agent 颜色映射
const AGENT_COLORS: Record<AgentType, string> = {
  ORCHESTRATOR: 'text-purple-500 bg-purple-500/10',
  RECON: 'text-blue-500 bg-blue-500/10',
  ANALYSIS: 'text-orange-500 bg-orange-500/10',
  VERIFICATION: 'text-green-500 bg-green-500/10',
}

// Agent 名称映射
const AGENT_NAMES: Record<AgentType, string> = {
  ORCHESTRATOR: '编排者',
  RECON: '侦察者',
  ANALYSIS: '分析者',
  VERIFICATION: '验证者',
}

// 单个事件组件
interface EventItemProps {
  event: AgentEvent
  isExpanded: boolean
  onToggle: () => void
}

function EventItem({ event, isExpanded, onToggle }: EventItemProps) {
  const AgentIcon = AGENT_ICONS[event.agent_type]
  const agentColorClass = AGENT_COLORS[event.agent_type]

  // 格式化事件数据
  const formatEventData = () => {
    switch (event.type) {
      case 'thinking':
        return (event.data as any).thought
      case 'action':
      case 'tool_call':
        return `${(event.data as any).tool_name || (event.data as any).action}`
      case 'observation':
        return (event.data as any).observation || (event.data as any).summary
      case 'finding':
        return `${(event.data as any).finding.title} [${(event.data as any).finding.severity.toUpperCase()}]`
      case 'decision':
        return (event.data as any).decision
      case 'error':
        return (event.data as any).error
      case 'complete':
        return (event.data as any).summary
      case 'progress':
        return (event.data as any).message || (event.data as any).stage
      case 'agent_start':
        return `Agent ${AGENT_NAMES[event.agent_type]} 开始`
      case 'agent_complete':
        return `Agent ${AGENT_NAMES[event.agent_type]} 完成`
      case 'rag_retrieval':
        return `RAG 检索: ${(event.data as any).query}`
      default:
        return JSON.stringify(event.data)
    }
  }

  // 获取详细信息
  const getDetails = () => {
    const data = event.data as any
    switch (event.type) {
      case 'thinking':
        return data.reasoning && (
          <div className="mt-2 text-xs text-muted-foreground">
            <p>推理: {data.reasoning}</p>
            {data.context && (
              <details className="mt-1">
                <summary className="cursor-pointer hover:text-foreground">上下文</summary>
                <pre className="mt-1 p-2 bg-muted rounded text-xs overflow-x-auto">
                  {JSON.stringify(data.context, null, 2)}
                </pre>
              </details>
            )}
          </div>
        )
      case 'action':
      case 'tool_call':
        return (
          <div className="mt-2 text-xs space-y-1">
            {data.tool_name && <p><strong>工具:</strong> {data.tool_name}</p>}
            {data.parameters && (
              <details>
                <summary className="cursor-pointer hover:text-foreground">参数</summary>
                <pre className="mt-1 p-2 bg-muted rounded text-xs overflow-x-auto">
                  {JSON.stringify(data.parameters, null, 2)}
                </pre>
              </details>
            )}
          </div>
        )
      case 'observation':
        return data.result && (
          <div className="mt-2">
            <details>
              <summary className="cursor-pointer text-xs hover:text-foreground">结果</summary>
              <pre className="mt-1 p-2 bg-muted rounded text-xs overflow-x-auto max-h-40">
                {JSON.stringify(data.result, null, 2)}
              </pre>
            </details>
          </div>
        )
      case 'finding':
        const finding = data.finding
        return (
          <div className="mt-2 text-xs space-y-1">
            <p><strong>文件:</strong> {finding.file_path}:{finding.line_number}</p>
            <p><strong>描述:</strong> {finding.description}</p>
            {finding.code_snippet && (
              <pre className="mt-1 p-2 bg-red-500/10 border border-red-500/20 rounded text-xs overflow-x-auto">
                <code>{finding.code_snippet}</code>
              </pre>
            )}
            <p><strong>置信度:</strong> {data.confidence}</p>
          </div>
        )
      case 'decision':
        return (
          <div className="mt-2 text-xs space-y-1">
            {data.reasoning && <p><strong>理由:</strong> {data.reasoning}</p>}
            {data.next_agent && <p><strong>下一个 Agent:</strong> {AGENT_NAMES[data.next_agent as AgentType]}</p>}
            {data.next_action && <p><strong>下一步:</strong> {data.next_action}</p>}
          </div>
        )
      case 'rag_retrieval':
        return (
          <div className="mt-2 text-xs space-y-1">
            <p><strong>查询:</strong> {data.query}</p>
            <p><strong>检索到 {data.context_count} 条相关内容</strong></p>
            {data.relevant_info && data.relevant_info.length > 0 && (
              <details>
                <summary className="cursor-pointer hover:text-foreground">相关内容</summary>
                <ul className="mt-1 space-y-1">
                  {data.relevant_info.map((info: string, i: number) => (
                    <li key={i} className="p-2 bg-muted rounded">{info}</li>
                  ))}
                </ul>
              </details>
            )}
          </div>
        )
      default:
        return null
    }
  }

  return (
    <div className="border-b border-border/40 last:border-b-0">
      <div
        className="flex items-start gap-2 p-3 hover:bg-muted/30 cursor-pointer transition-colors"
        onClick={onToggle}
      >
        <div className={`p-1 rounded ${agentColorClass} mt-0.5`}>
          <AgentIcon className="w-3.5 h-3.5" />
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] text-muted-foreground font-mono">
              {new Date(event.timestamp).toLocaleTimeString()}
            </span>
            <Badge variant="outline" className="text-[9px] h-4 px-1">
              {event.type}
            </Badge>
          </div>
          <p className="text-xs">{formatEventData()}</p>
        </div>

        <Button
          variant="ghost"
          size="icon"
          className="h-6 w-6 flex-shrink-0"
        >
          {isExpanded ? (
            <ChevronDown className="w-4 h-4" />
          ) : (
            <ChevronRight className="w-4 h-4" />
          )}
        </Button>
      </div>

      {isExpanded && (
        <div className="px-3 pb-3 ml-7 border-l-2 border-border/40 pl-3">
          {getDetails()}
        </div>
      )}
    </div>
  )
}

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

  const eventsEndRef = useRef<HTMLDivElement>(null)

  // 加载 LLM 配置
  useEffect(() => {
    useAgentStore.getState().loadLLMConfigs()
  }, [])

  // 当审计运行时，加载 Agent 树
  useEffect(() => {
    if (auditStatus === 'running' && activeTab === 'tree') {
      loadAgentTree()
    }
  }, [auditStatus, activeTab, loadAgentTree])

  // 定时刷新 Agent 树
  useEffect(() => {
    if (auditStatus === 'running' && activeTab === 'tree') {
      const interval = setInterval(() => {
        loadAgentTree()
      }, 5000) // 每 5 秒刷新一次
      return () => clearInterval(interval)
    }
  }, [auditStatus, activeTab, loadAgentTree])

  // 自动滚动事件列表
  useEffect(() => {
    eventsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [events])

  // 切换事件展开状态
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

  // 处理启动审计
  const handleStartAudit = async () => {
    if (!currentProject) {
      toast.warning('请先打开一个项目')
      addLog('请先打开一个项目', 'system')
      return
    }

    if (!isConnected) {
      toast.error('Agent 服务未连接，请先启动服务')
      return
    }

    const loadingToast = toast.loading(`正在启动${auditType === 'quick' ? '快速' : '完整'}审计...`)

    try {
      addLog(`开始 ${auditType === 'quick' ? '快速' : '完整'} 审计...`, 'system')
      const auditId = await startAudit(
        currentProject.id.toString(),
        auditType,
        { llm_config: selectedLLMConfig === 'default' ? '' : selectedLLMConfig }
      )
      toast.success(`审计任务已启动: ${auditId}`)
      addLog(`审计任务已创建: ${auditId}`, 'system')
    } catch (err) {
      const message = err instanceof Error ? err.message : '未知错误'
      toast.error(`启动审计失败: ${message}`)
      addLog(`启动审计失败: ${err}`, 'system')
    } finally {
      removeToast(loadingToast)
    }
  }

  // 处理暂停审计
  const handlePauseAudit = async () => {
    try {
      await pauseAudit()
      toast.info('审计已暂停')
    } catch (err) {
      const message = err instanceof Error ? err.message : '未知错误'
      toast.error(`暂停失败: ${message}`)
    }
  }

  // 处理终止审计
  const handleCancelAudit = async () => {
    try {
      await cancelAudit()
      toast.warning('审计已终止')
    } catch (err) {
      const message = err instanceof Error ? err.message : '未知错误'
      toast.error(`终止失败: ${message}`)
    }
  }

  return (
    <div className="flex flex-col h-full">
      {/* 顶部控制栏 */}
      <div className="flex items-center justify-between p-4 border-b">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium">审计模式:</span>
            <Select value={auditType} onValueChange={(v: any) => setAuditType(v)}>
              <SelectTrigger className="w-[120px]">
                <SelectValue placeholder="选择模式" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="quick">快速扫描</SelectItem>
                <SelectItem value="full">深度审计</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-sm font-medium">模型配置:</span>
            <Select value={selectedLLMConfig} onValueChange={setSelectedLLMConfig}>
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="选择 LLM 配置" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="default">默认配置</SelectItem>
                {llmConfigs?.map((config: any) => (
                  <SelectItem key={config.id} value={config.id}>
                    {config.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {auditStatus === 'running' ? (
            <>
              <Button variant="outline" size="sm" onClick={handlePauseAudit}>
                <Pause className="w-4 h-4 mr-1" /> 暂停
              </Button>
              <Button variant="destructive" size="sm" onClick={handleCancelAudit}>
                <Square className="w-4 h-4 mr-1" /> 终止
              </Button>
            </>
          ) : (
            <Button size="sm" onClick={handleStartAudit} disabled={!isConnected}>
              <Play className="w-4 h-4 mr-1" /> 开始审计
            </Button>
          )}
        </div>
      </div>

      {/* 审计流内容区域 */}
      <div className="flex-1 min-h-0 flex">
        {/* 主内容区：使用 Tab 切换事件流和 Agent 树 */}
        <div className="flex-1 flex flex-col min-w-0">
          <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as 'events' | 'tree')} className="flex flex-col h-full">
            <div className="flex items-center justify-between border-b px-4">
              <TabsList className="h-9">
                <TabsTrigger value="events" className="gap-2">
                  <Brain className="w-4 h-4" />
                  审计事件流
                  {events.length > 0 && (
                    <Badge variant="secondary" className="ml-1 h-5 px-1.5 text-[10px]">
                      {events.length}
                    </Badge>
                  )}
                </TabsTrigger>
                <TabsTrigger value="tree" className="gap-2">
                  <Network className="w-4 h-4" />
                  Agent 执行树
                  {auditStatus === 'running' && (
                    <span className="flex h-2 w-2 relative">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
                    </span>
                  )}
                </TabsTrigger>
              </TabsList>

              {auditProgress && (
                <span className="text-xs text-muted-foreground">
                  {auditProgress.percentage}% - {auditProgress.current_stage}
                </span>
              )}
            </div>

            {/* 事件流 Tab */}
            <TabsContent value="events" className="flex-1 m-0 p-0 min-h-0">
              <ScrollArea className="h-full">
                <div className="p-0">
                  {events.length === 0 ? (
                    <div className="flex flex-col items-center justify-center h-64 text-muted-foreground">
                      <Brain className="w-12 h-12 mb-4 opacity-20" />
                      <p>准备就绪，点击开始审计启动 Agent 系统</p>
                    </div>
                  ) : (
                    events.map(event => (
                      <EventItem
                        key={event.id}
                        event={event}
                        isExpanded={expandedEvents.has(event.id)}
                        onToggle={() => toggleEventExpanded(event.id)}
                      />
                    ))
                  )}
                  <div ref={eventsEndRef} />
                </div>
              </ScrollArea>
            </TabsContent>

            {/* Agent 树 Tab */}
            <TabsContent value="tree" className="flex-1 m-0 p-0 min-h-0">
              <AgentTreeVisualization
                treeData={agentTree}
                loading={agentTreeLoading}
                error={agentTreeError}
                onStopAgent={stopAgent}
                onRefresh={refreshAgentTree}
              />
            </TabsContent>
          </Tabs>
        </div>

        {/* 右侧：Agent 状态监控 (窄栏) */}
        <div className="w-56 bg-muted/10 flex flex-col min-w-0 border-l">
          <div className="p-2 bg-muted/30 text-xs font-medium border-b">
            Agent 状态监控
          </div>
          <ScrollArea className="flex-1">
            <div className="p-3 space-y-3">
              {Object.entries(AGENT_NAMES).map(([type, name]) => (
                <div key={type} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    {React.createElement(AGENT_ICONS[type as AgentType], {
                      className: `w-4 h-4 ${agentStatus[type] === 'running' ? 'animate-pulse text-primary' : 'text-muted-foreground'}`
                    })}
                    <span className="text-xs">{name}</span>
                  </div>
                  <Badge
                    variant={agentStatus[type] === 'running' ? 'default' : 'outline'}
                    className="text-[9px] h-4 px-1"
                  >
                    {agentStatus[type] || 'idle'}
                  </Badge>
                </div>
              ))}

              {auditError && (
                <div className="mt-4 p-2 bg-red-500/10 border border-red-500/20 rounded text-xs text-red-500">
                  <p className="font-bold mb-1">错误</p>
                  {auditError}
                </div>
              )}
            </div>
          </ScrollArea>
        </div>
      </div>
    </div>
  )
}
