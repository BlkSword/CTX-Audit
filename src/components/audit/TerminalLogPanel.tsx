/**
 * 终端风格日志面板
 *
 * 采用 Terminal Retro 设计风格：
 * - 黑色背景 + 绿色文本
 * - 等宽字体
 * - 每条日志显示为终端行
 * - 支持展开/收起
 * - 显示行号
 * - 类型图标
 */

import { useEffect, useRef, useState, memo, useMemo, useCallback } from 'react'
import { ChevronDown, ChevronRight, Terminal, Trash2, Pause, Activity, Copy, Check } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import type { LogItem } from '@/shared/types'

export interface TerminalLogPanelProps {
  logs: LogItem[]
  autoScroll?: boolean
  expandedLogIds?: Set<string>
  onToggleExpand?: (id: string) => void
  onClear?: () => void
}

// 日志类型配置（终端风格）
const LOG_TYPE_CONFIG = {
  thinking: {
    icon: '🤔',
    color: 'text-violet-400',
    bg: 'bg-violet-950/20',
    prefix: '›',
    label: 'THINKING',
  },
  tool: {
    icon: '🔧',
    color: 'text-amber-400',
    bg: 'bg-amber-950/20',
    prefix: '→',
    label: 'TOOL',
  },
  observation: {
    icon: '👁️',
    color: 'text-emerald-400',
    bg: 'bg-emerald-950/20',
    prefix: '○',
    label: 'OBSERVE',
  },
  finding: {
    icon: '🐛',
    color: 'text-rose-400',
    bg: 'bg-rose-950/20',
    prefix: '⚠',
    label: 'FINDING',
  },
  error: {
    icon: '❌',
    color: 'text-red-400',
    bg: 'bg-red-950/20',
    prefix: '✖',
    label: 'ERROR',
  },
  info: {
    icon: 'ℹ️',
    color: 'text-blue-400',
    bg: 'bg-blue-950/20',
    prefix: '•',
    label: 'INFO',
  },
  complete: {
    icon: '✅',
    color: 'text-green-400',
    bg: 'bg-green-950/20',
    prefix: '✓',
    label: 'DONE',
  },
  system: {
    icon: '⚙️',
    color: 'text-slate-400',
    bg: 'bg-slate-950/20',
    prefix: '#',
    label: 'SYSTEM',
  },
  dispatch: {
    icon: '📤',
    color: 'text-cyan-400',
    bg: 'bg-cyan-950/20',
    prefix: '»',
    label: 'DISPATCH',
  },
  phase: {
    icon: '📋',
    color: 'text-indigo-400',
    bg: 'bg-indigo-950/20',
    prefix: '▸',
    label: 'PHASE',
  },
  progress: {
    icon: '📊',
    color: 'text-yellow-400',
    bg: 'bg-yellow-950/20',
    prefix: '≡',
    label: 'PROGRESS',
  },
}

// Agent 类型配置
const AGENT_CONFIG = {
  ORCHESTRATOR: { name: 'ORCHESTRATOR', color: 'text-violet-400', short: 'ORCH' },
  RECON: { name: 'RECON', color: 'text-blue-400', short: 'RECON' },
  ANALYSIS: { name: 'ANALYSIS', color: 'text-amber-400', short: 'ANAL' },
  VERIFICATION: { name: 'VERIFICATION', color: 'text-emerald-400', short: 'VERIFY' },
  SYSTEM: { name: 'SYSTEM', color: 'text-slate-400', short: 'SYS' },
}

function formatTime(timestamp: number): string {
  const date = new Date(timestamp)
  return date.toLocaleTimeString('zh-CN', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

// 单条终端日志组件
const TerminalLogEntry = memo(({
  log,
  index,
  isExpanded,
  onToggleExpand,
}: {
  log: LogItem
  index: number
  isExpanded: boolean
  onToggleExpand: (id: string) => void
}) => {
  const typeConfig = LOG_TYPE_CONFIG[log.type] || LOG_TYPE_CONFIG.info
  const agentConfig = AGENT_CONFIG[log.agent_type] || AGENT_CONFIG.SYSTEM
  const [copied, setCopied] = useState(false)

  const handleCopy = useCallback((content: string) => {
    navigator.clipboard.writeText(content)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }, [])

  const content = useMemo(
    () => log.content || (log.data as any)?.observation || (log.data as any)?.message || '',
    [log.content, log.data]
  )

  const hasDetails = Boolean(
    log.data && (
      (log.data as any)?.parameters ||
      (log.data as any)?.reasoning ||
      (log.data as any)?.finding ||
      (log.data as any)?.toolOutput
    )
  )

  return (
    <div className={cn(
      "group flex items-start gap-3 py-1.5 px-4 hover:bg-white/5 transition-colors",
      typeConfig.bg
    )}>
      {/* 行号 */}
      <span className="text-xs text-slate-700 font-mono tabular-nums select-none shrink-0 w-8 text-right">
        {index + 1}
      </span>

      {/* 展开/收起图标 */}
      {hasDetails && (
        <button
          onClick={() => onToggleExpand(log.id)}
          className="shrink-0 text-slate-600 hover:text-slate-400 transition-colors"
        >
          {isExpanded ? (
            <ChevronDown className="w-3.5 h-3.5" />
          ) : (
            <ChevronRight className="w-3.5 h-3.5" />
          )}
        </button>
      )}

      {/* 类型图标和前缀 */}
      <div className="flex items-center gap-2 shrink-0">
        <span className="text-sm">{typeConfig.icon}</span>
        <span className={cn("text-xs font-semibold", typeConfig.color)}>
          {typeConfig.prefix}
        </span>
      </div>

      {/* Agent 名称 */}
      <span className={cn("text-xs font-medium font-mono", agentConfig.color)}>
        [{agentConfig.short}]
      </span>

      {/* 时间戳 */}
      <span className="text-xs text-slate-600 font-mono shrink-0">
        {formatTime(log.timestamp)}
      </span>

      {/* 日志内容 */}
      <div className="flex-1 min-w-0">
        <span className={cn("text-sm font-mono leading-relaxed break-words", typeConfig.color)}>
          {content}
        </span>

        {/* 展开详情 */}
        {isExpanded && hasDetails && (
          <div className="mt-2 pl-4 border-l-2 border-white/10 space-y-2">
            {/* 推理过程 */}
            {(log.data as any)?.reasoning && (
              <div className="text-xs text-slate-400 font-mono whitespace-pre-wrap bg-black/30 p-2 rounded">
                {(log.data as any).reasoning}
              </div>
            )}

            {/* 参数详情 */}
            {(log.data as any)?.parameters && (
              <div className="text-xs text-slate-500 font-mono">
                <span className="text-slate-600">Parameters:</span>
                <pre className="mt-1 bg-black/30 p-2 rounded overflow-x-auto">
                  {JSON.stringify((log.data as any).parameters, null, 2)}
                </pre>
              </div>
            )}

            {/* 工具输出 */}
            {(log.data as any)?.toolOutput && (
              <div className="text-xs text-slate-400 font-mono">
                <span className="text-slate-600">Output:</span>
                <pre className="mt-1 bg-black/30 p-2 rounded overflow-x-auto">
                  {typeof (log.data as any).toolOutput === 'string'
                    ? (log.data as any).toolOutput
                    : JSON.stringify((log.data as any).toolOutput, null, 2)}
                </pre>
              </div>
            )}

            {/* 发现详情 */}
            {(log.data as any)?.finding && (
              <div className="p-2 bg-rose-950/20 border border-rose-500/30 rounded">
                <div className="text-xs font-semibold text-rose-400">
                  {(log.data as any).finding.title || '发现漏洞'}
                </div>
                <div className="text-xs text-slate-400 mt-1">
                  {(log.data as any).finding.description}
                </div>
                {(log.data as any).finding.file_path && (
                  <div className="text-xs text-slate-500 font-mono mt-1">
                    📁 {(log.data as any).finding.file_path}:{(log.data as any).finding.line_start}
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      {/* 复制按钮 */}
      <Button
        variant="ghost"
        size="sm"
        onClick={() => handleCopy(content)}
        className="h-6 w-6 p-0 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity"
      >
        {copied ? (
          <Check className="w-3 h-3 text-emerald-400" />
        ) : (
          <Copy className="w-3 h-3 text-slate-500" />
        )}
      </Button>
    </div>
  )
}, (prev, next) => {
  return (
    prev.log.id === next.log.id &&
    prev.log.content === next.log.content &&
    prev.isExpanded === next.isExpanded
  )
})

TerminalLogEntry.displayName = 'TerminalLogEntry'

export function TerminalLogPanel({
  logs,
  autoScroll = true,
  expandedLogIds = new Set(),
  onToggleExpand,
  onClear,
}: TerminalLogPanelProps) {
  const logContainerRef = useRef<HTMLDivElement>(null)
  const [isPaused, setIsPaused] = useState(false)

  const handleToggleExpand = useCallback((id: string) => {
    onToggleExpand?.(id)
  }, [onToggleExpand])

  const handleClear = useCallback(() => {
    if (confirm('确定要清空日志吗？')) {
      onClear?.()
    }
  }, [onClear])

  // 自动滚动
  useEffect(() => {
    if (autoScroll && !isPaused && logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight
    }
  }, [logs.length, autoScroll, isPaused])

  return (
    <div className="h-full flex flex-col bg-black">
      {/* 终端顶部栏 */}
      <div className="h-10 px-4 flex items-center justify-between bg-slate-900/90 border-b border-slate-700/50 shrink-0">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-emerald-400" />
          <span className="text-sm font-medium text-emerald-400 font-mono">Agent Audit Log</span>
          <span className="text-xs text-slate-600 font-mono">({logs.length} entries)</span>
        </div>
        <div className="flex items-center gap-1">
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
          {onClear && logs.length > 0 && (
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7 text-slate-500 hover:text-red-400"
              onClick={handleClear}
              title="清空日志"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </Button>
          )}
        </div>
      </div>

      {/* 终端内容区 */}
      <div
        ref={logContainerRef}
        className="flex-1 overflow-y-auto overflow-x-hidden font-mono text-sm"
        style={{
          maxHeight: 'calc(100vh - 200px)',
          scrollBehavior: 'smooth',
        }}
      >
        {logs.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-64 text-slate-700">
            <Terminal className="w-16 h-16 mb-4 opacity-20" />
            <p className="text-sm font-mono text-slate-600">Waiting for audit to start...</p>
          </div>
        ) : (
          <div className="py-2">
            {logs.map((log, index) => (
              <TerminalLogEntry
                key={log.id}
                log={log}
                index={index}
                isExpanded={expandedLogIds.has(log.id)}
                onToggleExpand={handleToggleExpand}
              />
            ))}
          </div>
        )}
      </div>

      {/* 终端底部状态 */}
      <div className="h-6 px-4 flex items-center justify-between bg-slate-900/60 border-t border-slate-700/50 shrink-0">
        <div className="flex items-center gap-2 text-[10px] text-slate-600 font-mono">
          <span className={cn(
            "flex items-center gap-1",
            !isPaused && "text-emerald-500"
          )}>
            <span className={cn(
              "w-1.5 h-1.5 rounded-full",
              !isPaused ? "bg-emerald-400 animate-pulse" : "bg-amber-400"
            )} />
            {!isPaused ? "LIVE" : "PAUSED"}
          </span>
          <span>·</span>
          <span>{logs.length} messages</span>
        </div>
        <div className="text-[10px] text-slate-700 font-mono">
          v1.0.0
        </div>
      </div>
    </div>
  )
}

export default memo(TerminalLogPanel, (prev, next) => {
  return (
    prev.logs.length === next.logs.length &&
    prev.autoScroll === next.autoScroll &&
    prev.expandedLogIds?.size === next.expandedLogIds?.size
  )
})
