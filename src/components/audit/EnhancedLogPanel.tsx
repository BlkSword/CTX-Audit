/**
 * 增强版 Agent 审计日志面板
 *
 * 特性：
 * - 更现代化的视觉设计
 * - 更好的日志类型区分
 * - 流畅的动画效果
 * - 智能滚动控制
 */

import { useEffect, useRef, useState } from 'react'
import { Terminal, X, Trash2, Minus, ChevronDown, ChevronRight, Filter, Clock, Cpu, Activity, Pause } from 'lucide-react'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import type { LogItem, AgentFinding } from '@/shared/types'

export interface EnhancedLogPanelProps {
  logs: LogItem[]
  autoScroll?: boolean
  expandedLogIds?: Set<string>
  onToggleExpand?: (id: string) => void
  active?: boolean
  onToggle?: () => void
  onClear?: () => void
  onMinimize?: () => void
  filterTypes?: string[]
  onFilterChange?: (types: string[]) => void
}

// 日志类型配置 - 更精致的配色
const LOG_TYPE_CONFIG: Record<string, {
  icon: string
  label: string
  bgGradient: string
  borderGradient: string
  textColor: string
  iconBg: string
}> = {
  thinking: {
    icon: '🧠',
    label: '思考',
    bgGradient: 'from-violet-950/40 to-purple-950/20',
    borderGradient: 'border-l-violet-500',
    textColor: 'text-violet-200',
    iconBg: 'bg-violet-500/20',
  },
  tool: {
    icon: '🔧',
    label: '工具',
    bgGradient: 'from-amber-950/40 to-orange-950/20',
    borderGradient: 'border-l-amber-500',
    textColor: 'text-amber-200',
    iconBg: 'bg-amber-500/20',
  },
  observation: {
    icon: '👁️',
    label: '观察',
    bgGradient: 'from-emerald-950/40 to-teal-950/20',
    borderGradient: 'border-l-emerald-500',
    textColor: 'text-emerald-200',
    iconBg: 'bg-emerald-500/20',
  },
  finding: {
    icon: '🐛',
    label: '漏洞',
    bgGradient: 'from-rose-950/40 to-red-950/20',
    borderGradient: 'border-l-rose-500',
    textColor: 'text-rose-200',
    iconBg: 'bg-rose-500/20',
  },
  phase: {
    icon: '📋',
    label: '阶段',
    bgGradient: 'from-blue-950/40 to-indigo-950/20',
    borderGradient: 'border-l-blue-500',
    textColor: 'text-blue-200',
    iconBg: 'bg-blue-500/20',
  },
  dispatch: {
    icon: '🚀',
    label: '调度',
    bgGradient: 'from-cyan-950/40 to-sky-950/20',
    borderGradient: 'border-l-cyan-500',
    textColor: 'text-cyan-200',
    iconBg: 'bg-cyan-500/20',
  },
  info: {
    icon: 'ℹ️',
    label: '信息',
    bgGradient: 'from-slate-950/40 to-gray-950/20',
    borderGradient: 'border-l-slate-500',
    textColor: 'text-slate-300',
    iconBg: 'bg-slate-500/20',
  },
  system: {
    icon: '⚙️',
    label: '系统',
    bgGradient: 'from-slate-900/60 to-gray-900/30',
    borderGradient: 'border-l-slate-600',
    textColor: 'text-slate-400',
    iconBg: 'bg-slate-600/20',
  },
  error: {
    icon: '❌',
    label: '错误',
    bgGradient: 'from-red-950/60 to-red-900/30',
    borderGradient: 'border-l-red-500',
    textColor: 'text-red-200',
    iconBg: 'bg-red-500/20',
  },
  progress: {
    icon: '📊',
    label: '进度',
    bgGradient: 'from-teal-950/40 to-cyan-950/20',
    borderGradient: 'border-l-teal-500',
    textColor: 'text-teal-200',
    iconBg: 'bg-teal-500/20',
  },
  complete: {
    icon: '✅',
    label: '完成',
    bgGradient: 'from-green-950/40 to-emerald-950/20',
    borderGradient: 'border-l-green-500',
    textColor: 'text-green-200',
    iconBg: 'bg-green-500/20',
  },
}

// Agent 类型配置
const AGENT_CONFIG: Record<string, { icon: string; color: string; bg: string }> = {
  ORCHESTRATOR: { icon: '🎯', color: 'text-purple-400', bg: 'bg-purple-500/20' },
  RECON: { icon: '🔍', color: 'text-blue-400', bg: 'bg-blue-500/20' },
  ANALYSIS: { icon: '🔬', color: 'text-amber-400', bg: 'bg-amber-500/20' },
  VERIFICATION: { icon: '✅', color: 'text-green-400', bg: 'bg-green-500/20' },
  SYSTEM: { icon: '⚙️', color: 'text-slate-400', bg: 'bg-slate-500/20' },
}

export function EnhancedLogPanel({
  logs,
  autoScroll = true,
  expandedLogIds = new Set(),
  onToggleExpand = () => { },
  active = true,
  onToggle,
  onClear,
  onMinimize,
  filterTypes = [],
  onFilterChange
}: EnhancedLogPanelProps) {
  const logEndRef = useRef<HTMLDivElement>(null)
  const [showFilter, setShowFilter] = useState(false)
  const [isPaused, setIsPaused] = useState(false)

  // 自动滚动
  useEffect(() => {
    if (active && autoScroll && !isPaused && logEndRef.current) {
      logEndRef.current.scrollIntoView({ behavior: 'smooth', block: 'end' })
    }
  }, [logs, autoScroll, active, isPaused])

  // 格式化时间
  const formatTime = (timestamp: number) => {
    const date = new Date(timestamp)
    return date.toLocaleTimeString('zh-CN', {
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  }

  // 获取日志内容
  const getLogContent = (log: LogItem) => {
    const data = log.data || {} as Record<string, unknown>

    switch (log.type) {
      case 'thinking':
        return (
          <div className="space-y-2">
            <div className={LOG_TYPE_CONFIG.thinking.textColor + ' leading-relaxed'}>{log.content}</div>
            {(data as { reasoning?: string }).reasoning && (
              <div className="mt-2 p-3 rounded-lg bg-black/20 border border-white/5">
                <div className="text-xs text-slate-500 mb-1 flex items-center gap-1">
                  <Cpu className="w-3 h-3" />
                  推理过程
                </div>
                <div className="text-sm text-slate-300 leading-relaxed">{(data as { reasoning?: string }).reasoning}</div>
              </div>
            )}
          </div>
        )

      case 'tool':
        return (
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span className="text-emerald-400 font-mono">$</span>
              <span className="font-semibold text-slate-200">
                {log.toolName || (data as { tool_name?: string }).tool_name || (data as { action?: string }).action}
              </span>
            </div>
            {log.content && (
              <div className="text-sm text-slate-400 mt-1 pl-4 border-l-2 border-slate-700">
                {log.content}
              </div>
            )}
          </div>
        )

      case 'observation':
        return (
          <div className={LOG_TYPE_CONFIG.observation.textColor + ' leading-relaxed'}>
            {log.content || (data as { observation?: string }).observation || (data as { summary?: string }).summary || '执行完成'}
          </div>
        )

      case 'finding':
        const finding = log.finding || (data as { finding?: Partial<AgentFinding> }).finding
        return (
          <div className="space-y-3">
            <div className="flex items-start justify-between gap-3">
              <div className={LOG_TYPE_CONFIG.finding.textColor + ' font-semibold text-lg'}>
                {finding?.title || log.content || '发现漏洞'}
              </div>
              {finding?.severity && (
                <Badge className={cn(
                  "shrink-0 text-xs font-semibold",
                  finding.severity === 'critical' && "bg-rose-600 text-white",
                  finding.severity === 'high' && "bg-orange-600 text-white",
                  finding.severity === 'medium' && "bg-amber-600 text-white",
                  finding.severity === 'low' && "bg-blue-600 text-white",
                  finding.severity === 'info' && "bg-slate-600 text-white"
                )}>
                  {finding.severity.toUpperCase()}
                </Badge>
              )}
            </div>
            {finding?.description && (
              <div className="p-3 rounded-lg bg-rose-950/30 border border-rose-900/50">
                <p className="text-sm text-rose-200/90 leading-relaxed">{finding.description}</p>
              </div>
            )}
            {finding?.file_path && (
              <div className="flex items-center gap-2 text-xs text-slate-500">
                <span className="font-mono">{finding.file_path}</span>
                {finding.line_start && (
                  <span>:{finding.line_start}{finding.line_end && `-${finding.line_end}`}</span>
                )}
              </div>
            )}
          </div>
        )

      case 'error':
        return (
          <div className="p-3 rounded-lg bg-red-950/40 border border-red-900/50">
            <div className="flex items-start gap-2">
              <span className="text-lg">⚠️</span>
              <div className="flex-1">
                <div className="font-semibold text-red-200 mb-1">
                  {log.content || (data as { error?: string }).error || (data as { message?: string }).message || '发生错误'}
                </div>
                {(data as { details?: string }).details && (
                  <div className="text-sm text-red-300/70 mt-1 font-mono text-xs">
                    {(data as { details?: string }).details}
                  </div>
                )}
              </div>
            </div>
          </div>
        )

      case 'complete':
        return (
          <div className="flex items-center gap-3 p-3 rounded-lg bg-emerald-950/30 border border-emerald-900/50">
            <div className="w-8 h-8 rounded-full bg-emerald-500/20 flex items-center justify-center">
              <span className="text-lg">✓</span>
            </div>
            <div className="flex-1">
              <div className="font-semibold text-emerald-200">
                {log.content || (data as { message?: string }).message || '任务完成'}
              </div>
            </div>
          </div>
        )

      default:
        return <div className="text-slate-300">{log.content || JSON.stringify(data).substring(0, 200)}</div>
    }
  }

  // 检查是否有可展开的详情
  const hasDetails = (log: LogItem) => {
    return !!(
      log.data?.parameters ||
      log.data?.result ||
      log.data?.reasoning ||
      log.data?.input ||
      log.toolOutput ||
      log.finding?.description
    )
  }

  // 过滤日志
  const filteredLogs = filterTypes.length > 0
    ? logs.filter(log => filterTypes.includes(log.type))
    : logs

  // 统计日志类型
  const logTypeCounts = logs.reduce((acc, log) => {
    acc[log.type] = (acc[log.type] || 0) + 1
    return acc
  }, {} as Record<string, number>)

  return (
    <div className="h-full bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 relative flex flex-col border border-slate-700/50 rounded-lg overflow-hidden">
      {/* Header - 增强版控制栏 */}
      <div className="h-10 px-3 flex items-center justify-between bg-slate-900/90 backdrop-blur-xl border-b border-slate-700/50 shrink-0 select-none rounded-t-lg">
        <div className="flex items-center gap-2">
          {/* 统计徽章 */}
          <div className="flex items-center gap-1.5">
            {Object.entries(logTypeCounts).slice(0, 3).map(([type, count]) => {
              const config = LOG_TYPE_CONFIG[type]
              if (!config) return null
              return (
                <Badge key={type} variant="outline" className={cn(
                  "text-[10px] px-1.5 py-0 h-5 font-normal border-0",
                  config.iconBg,
                  config.textColor
                )}>
                  {config.icon} {count}
                </Badge>
              )
            })}
            {logs.length > 0 && (
              <Badge variant="secondary" className="text-[10px] h-5 px-1.5 font-normal bg-slate-800 text-slate-400">
                {logs.length} 总计
              </Badge>
            )}
          </div>
        </div>

        <div className="flex items-center gap-1.5">
          {/* 暂停滚动按钮 */}
          <Button
            variant="ghost"
            size="icon"
            className={cn(
              "h-7 w-7 transition-all",
              isPaused ? "bg-amber-500/20 text-amber-400" : "text-slate-500 hover:text-slate-300"
            )}
            onClick={() => setIsPaused(!isPaused)}
            title={isPaused ? "恢复滚动" : "暂停滚动"}
          >
            {isPaused ? <Pause className="w-3.5 h-3.5" /> : <Activity className="w-3.5 h-3.5" />}
          </Button>

          {/* 过滤按钮 */}
          <Button
            variant="ghost"
            size="icon"
            className={cn(
              "h-7 w-7 transition-all",
              showFilter ? "bg-violet-500/20 text-violet-400" : "text-slate-500 hover:text-slate-300"
            )}
            onClick={() => setShowFilter(!showFilter)}
            title="过滤日志"
          >
            <Filter className="w-3.5 h-3.5" />
          </Button>

          {onClear && logs.length > 0 && (
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7 text-slate-500 hover:text-red-400 transition-colors"
              onClick={onClear}
              title="清空日志"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </Button>
          )}

          {onMinimize && (
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7 text-slate-500 hover:text-slate-300 transition-colors"
              onClick={onMinimize}
              title="最小化"
            >
              <Minus className="w-3.5 h-3.5" />
            </Button>
          )}

          {onToggle && (
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7 text-slate-500 hover:text-slate-300 transition-colors"
              onClick={onToggle}
              title="关闭面板"
            >
              <X className="w-3.5 h-3.5" />
            </Button>
          )}
        </div>
      </div>

      {/* 过滤栏 */}
      {showFilter && (
        <div className="px-4 py-2 bg-slate-900/60 border-b border-slate-800/50 shrink-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs text-slate-500 font-medium">过滤:</span>
            {Object.entries(LOG_TYPE_CONFIG).map(([type, config]) => {
              const isActive = filterTypes.includes(type)
              const count = logTypeCounts[type] || 0
              return (
                <button
                  key={type}
                  onClick={() => {
                    const newTypes = isActive
                      ? filterTypes.filter(t => t !== type)
                      : [...filterTypes, type]
                    onFilterChange?.(newTypes)
                  }}
                  className={cn(
                    "px-2 py-1 rounded-md text-xs font-medium transition-all flex items-center gap-1.5",
                    isActive
                      ? config.iconBg + ' ' + config.textColor + ' shadow-sm'
                      : "bg-slate-800/50 text-slate-500 hover:bg-slate-800"
                  )}
                  disabled={count === 0}
                >
                  <span>{config.icon}</span>
                  <span>{config.label}</span>
                  <span className={cn(
                    "px-1.5 py-0.5 rounded-full text-[10px]",
                    isActive ? config.iconBg : "bg-slate-700"
                  )}>{count}</span>
                </button>
              )
            })}
          </div>
        </div>
      )}

      {/* Logs Content - 固定对话框 */}
      <div className="flex-1 min-h-0 m-2 flex flex-col overflow-hidden">
        {/* 固定高度的日志容器 */}
        <div className="flex-1 min-h-0 bg-slate-950/80 border border-slate-700/50 rounded-lg overflow-hidden shadow-inner">
          <ScrollArea className="h-full">
            <div className="px-4 py-3">
          {filteredLogs.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-64 text-slate-600">
              <Terminal className="w-12 h-12 mb-3 opacity-50" />
              <p className="text-sm">
                {logs.length === 0 ? "等待操作..." : "没有符合条件的日志"}
              </p>
            </div>
          ) : (
            <div className="space-y-1">
              {filteredLogs.map((log) => {
                const config = LOG_TYPE_CONFIG[log.type] || LOG_TYPE_CONFIG.info
                const agentConfig = AGENT_CONFIG[log.agent_type]
                const isExpanded = expandedLogIds.has(log.id)

                return (
                  <div
                    key={log.id}
                    className={cn(
                      "group relative flex gap-3 py-3 px-4 rounded-xl border-l-4 transition-all duration-200 hover:shadow-lg hover:shadow-black/20",
                      "bg-gradient-to-r " + config.bgGradient,
                      config.borderGradient
                    )}
                  >
                    {/* 时间戳 */}
                    <div className="flex flex-col items-center gap-1 shrink-0">
                      <div className={cn(
                        "w-8 h-8 rounded-lg flex items-center justify-center text-sm transition-all",
                        config.iconBg
                      )}>
                        {config.icon}
                      </div>
                      <span className="text-[10px] text-slate-600 font-mono">
                        {formatTime(log.timestamp)}
                      </span>
                    </div>

                    {/* Agent 标识 */}
                    {agentConfig && (
                      <div className={cn(
                        "absolute top-3 right-3 px-2 py-0.5 rounded-md text-[10px] font-semibold uppercase tracking-wider",
                        agentConfig.bg,
                        agentConfig.color
                      )}>
                        {agentConfig.icon} {log.agent_type}
                      </div>
                    )}

                    {/* 日志内容 */}
                    <div className="flex-1 min-w-0 pr-16">
                      {/* 类型标签 */}
                      <div className="mb-2">
                        <span className={cn(
                          "inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[10px] font-semibold uppercase tracking-wider",
                          config.iconBg,
                          config.textColor
                        )}>
                          {config.label}
                        </span>
                      </div>

                      {/* 内容 */}
                      <div className="text-sm leading-relaxed">
                        {getLogContent(log)}
                      </div>

                      {/* 展开的详情 */}
                      {isExpanded && (
                        <div className="mt-3 space-y-2">
                          {'parameters' in (log.data || {}) && (
                            <details className="group/details" open>
                              <summary className="flex items-center gap-2 text-xs text-slate-500 cursor-pointer hover:text-slate-300 transition-colors">
                                <ChevronDown className="w-3 h-3" />
                                参数
                              </summary>
                              <pre className="mt-2 text-xs bg-black/40 p-3 rounded-lg overflow-x-auto max-h-48 overflow-y-auto border border-white/5">
                                {String(JSON.stringify((log.data as { parameters: unknown }).parameters, null, 2))}
                              </pre>
                            </details>
                          )}
                          {log.toolOutput != null && log.type === 'tool' && (
                            <details className="group/details" open>
                              <summary className="flex items-center gap-2 text-xs text-slate-500 cursor-pointer hover:text-slate-300 transition-colors">
                                <ChevronDown className="w-3 h-3" />
                                执行结果
                              </summary>
                              <pre className="mt-2 text-xs bg-emerald-950/30 p-3 rounded-lg overflow-x-auto max-h-48 overflow-y-auto border border-emerald-900/30 text-emerald-200/90">
                                {String(typeof log.toolOutput === 'string' ? log.toolOutput : JSON.stringify(log.toolOutput, null, 2))}
                              </pre>
                            </details>
                          )}
                          {'result' in (log.data || {}) && log.type === 'observation' && (
                            <details className="group/details">
                              <summary className="flex items-center gap-2 text-xs text-slate-500 cursor-pointer hover:text-slate-300 transition-colors">
                                <ChevronRight className="w-3 h-3" />
                                结果
                              </summary>
                              <pre className="mt-2 text-xs bg-black/40 p-3 rounded-lg overflow-x-auto max-h-48 overflow-y-auto border border-white/5">
                                {String(JSON.stringify((log.data as { result: unknown }).result, null, 2))}
                              </pre>
                            </details>
                          )}
                        </div>
                      )}
                    </div>

                    {/* 展开/收起按钮 */}
                    {hasDetails(log) && (
                      <button
                        onClick={() => onToggleExpand(log.id)}
                        className="absolute bottom-3 right-3 p-1.5 hover:bg-white/10 rounded-lg transition-all"
                        title={isExpanded ? '收起' : '展开'}
                      >
                        {isExpanded ? (
                          <ChevronDown className="w-4 h-4 text-slate-500" />
                        ) : (
                          <ChevronRight className="w-4 h-4 text-slate-500" />
                        )}
                      </button>
                    )}
                  </div>
                )
              })}
            </div>
          )}
          <div ref={logEndRef} />
            </div>
          </ScrollArea>
        </div>
      </div>

      {/* 底部状态栏 */}
      <div className="h-8 px-4 flex items-center justify-between bg-slate-900/60 border-t border-slate-800/50 shrink-0">
        <div className="flex items-center gap-3 text-[10px] text-slate-500">
          <span className="flex items-center gap-1">
            <Clock className="w-3 h-3" />
            实时更新
          </span>
          <span>·</span>
          <span>{filteredLogs.length} / {logs.length} 条显示</span>
        </div>
        <div className="flex items-center gap-2">
          {isPaused && (
            <Badge variant="outline" className="text-[10px] h-5 px-2 border-amber-800 text-amber-500 bg-amber-950/30">
              已暂停
            </Badge>
          )}
          {filterTypes.length > 0 && (
            <Badge variant="outline" className="text-[10px] h-5 px-2 border-violet-800 text-violet-500 bg-violet-950/30">
              {filterTypes.length} 个过滤器
            </Badge>
          )}
        </div>
      </div>
    </div>
  )
}
