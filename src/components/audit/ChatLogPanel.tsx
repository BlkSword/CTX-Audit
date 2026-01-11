/**
 * 对话式日志面板
 *
 * 采用聊天/对话式UI设计：
 * - 每条日志显示为消息气泡
 * - 左侧Agent头像，右侧消息内容
 * - 固定高度滚动容器
 * - 性能优化：使用 memo 防止不必要的重渲染
 */

import { useEffect, useRef, useState, memo, useMemo, useCallback } from 'react'
import { Maximize2, Trash2, Clock, Pause, Activity } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import type { LogItem } from '@/shared/types'

export interface ChatLogPanelProps {
  logs: LogItem[]
  autoScroll?: boolean
  expandedLogIds?: Set<string>
  onToggleExpand?: (id: string) => void
  onToggle?: () => void
  onClear?: () => void
}

// Agent 头像配置
const AGENT_AVATAR: Record<string, { emoji: string; name: string; color: string }> = {
  ORCHESTRATOR: { emoji: '🎯', name: '编排者', color: 'bg-purple-500/20 border-purple-500/30' },
  RECON: { emoji: '🔍', name: '侦察者', color: 'bg-blue-500/20 border-blue-500/30' },
  ANALYSIS: { emoji: '🔬', name: '分析者', color: 'bg-amber-500/20 border-amber-500/30' },
  VERIFICATION: { emoji: '✅', name: '验证者', color: 'bg-green-500/20 border-green-500/30' },
  SYSTEM: { emoji: '⚙️', name: '系统', color: 'bg-slate-500/20 border-slate-500/30' },
}

// 日志类型样式
const LOG_TYPE_STYLE: Record<string, { bg: string; border: string; text: string }> = {
  thinking: { bg: 'bg-violet-950/30', border: 'border-violet-500/30', text: 'text-violet-200' },
  tool: { bg: 'bg-amber-950/30', border: 'border-amber-500/30', text: 'text-amber-200' },
  observation: { bg: 'bg-emerald-950/30', border: 'border-emerald-500/30', text: 'text-emerald-200' },
  finding: { bg: 'bg-rose-950/30', border: 'border-rose-500/30', text: 'text-rose-200' },
  error: { bg: 'bg-red-950/50', border: 'border-red-500/50', text: 'text-red-200' },
  info: { bg: 'bg-slate-800/50', border: 'border-slate-600/30', text: 'text-slate-300' },
  complete: { bg: 'bg-green-950/30', border: 'border-green-500/30', text: 'text-green-200' },
  system: { bg: 'bg-slate-900/60', border: 'border-slate-700/50', text: 'text-slate-400' },
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

// 单条日志消息组件 - 使用 memo 优化性能
const LogMessageItem = memo(({
  log,
  isExpanded,
  onToggleExpand,
}: {
  log: LogItem
  isExpanded: boolean
  onToggleExpand: (id: string) => void
}) => {
  const avatar = useMemo(
    () => AGENT_AVATAR[log.agent_type] || AGENT_AVATAR.SYSTEM,
    [log.agent_type]
  )

  const style = useMemo(
    () => LOG_TYPE_STYLE[log.type] || LOG_TYPE_STYLE.info,
    [log.type]
  )

  const content = useMemo(
    () => log.content || (log.data as any)?.observation || (log.data as any)?.message || '',
    [log.content, log.data]
  )

  const handleToggle = useCallback(() => {
    onToggleExpand(log.id)
  }, [log.id, onToggleExpand])

  // 渲染日志内容
  const renderContent = useMemo(() => {
    // thinking 类型特殊处理
    if (log.type === 'thinking') {
      return (
        <div className={cn("p-3 rounded-lg border", style.bg, style.border)}>
          <div className={cn("text-sm leading-relaxed", style.text)}>
            {content}
          </div>
          {(log.data as any)?.reasoning && (
            <details className="mt-2" open={isExpanded}>
              <summary className="cursor-pointer text-xs text-slate-400 hover:text-slate-300 flex items-center gap-1">
                推理过程
              </summary>
              <pre className="mt-2 text-xs bg-black/20 p-2 rounded border border-white/5 overflow-x-auto">
                {(log.data as any).reasoning}
              </pre>
            </details>
          )}
        </div>
      )
    }

    // finding 类型特殊处理
    if (log.type === 'finding') {
      const finding = (log.data as any)?.finding
      if (finding) {
        return (
          <div className={cn("p-3 rounded-lg border space-y-2", style.bg, style.border)}>
            <div className={cn("font-semibold", style.text)}>
              🐛 {finding.title || '发现漏洞'}
            </div>
            <div className="text-sm text-slate-300">
              {finding.description}
            </div>
            {finding.file_path && (
              <div className="text-xs text-slate-400 font-mono">
                📁 {finding.file_path}:{finding.line_start || '?'}
              </div>
            )}
          </div>
        )
      }
    }

    // 默认渲染
    return (
      <div className={cn("p-3 rounded-lg border max-w-full", style.bg, style.border)}>
        <div className={cn("text-sm leading-relaxed break-words", style.text)}>
          {content}
        </div>
      </div>
    )
  }, [log.type, log.data, content, style, isExpanded])

  // 渲染参数详情
  const parametersDetail = useMemo(() => {
    if (log.data && (log.data as any)?.parameters) {
      return (
        <details className="mt-2" open={isExpanded}>
          <summary
            className="cursor-pointer text-xs text-slate-500 hover:text-slate-400"
            onClick={(e) => {
              e.preventDefault()
              handleToggle()
            }}
          >
            参数详情
          </summary>
          <pre className="mt-2 text-xs bg-black/30 p-2 rounded border border-slate-700 overflow-x-auto">
            {JSON.stringify((log.data as any).parameters, null, 2)}
          </pre>
        </details>
      )
    }
    return null
  }, [log.data, isExpanded, handleToggle])

  return (
    <div className="flex gap-3 group">
      {/* Agent 头像 */}
      <div className={cn(
        "w-10 h-10 shrink-0 rounded-full flex items-center justify-center text-lg border-2",
        avatar.color
      )}>
        {avatar.emoji}
      </div>

      {/* 消息内容 */}
      <div className="flex-1 min-w-0">
        {/* 头部：Agent名称 + 时间 */}
        <div className="flex items-center gap-2 mb-1">
          <span className="text-xs font-semibold text-slate-400">
            {avatar.name}
          </span>
          <span className="text-[10px] text-slate-600">
            {formatTime(log.timestamp)}
          </span>
        </div>

        {/* 消息气泡 */}
        {renderContent}

        {/* 展开详情 */}
        {parametersDetail}
      </div>
    </div>
  )
}, (prevProps, nextProps) => {
  // 自定义比较函数，避免不必要的重渲染
  return (
    prevProps.log.id === nextProps.log.id &&
    prevProps.log.content === nextProps.log.content &&
    prevProps.log.timestamp === nextProps.log.timestamp &&
    prevProps.isExpanded === nextProps.isExpanded
  )
})

LogMessageItem.displayName = 'LogMessageItem'

export function ChatLogPanel({
  logs,
  autoScroll = true,
  expandedLogIds = new Set(),
  onToggleExpand,
  onToggle,
  onClear,
}: ChatLogPanelProps) {
  const logContainerRef = useRef<HTMLDivElement>(null)
  const [isPaused, setIsPaused] = useState(false)

  // 使用 useCallback 优化事件处理函数
  const handleToggleExpand = useCallback((id: string) => {
    onToggleExpand?.(id)
  }, [onToggleExpand])

  const handleClear = useCallback(() => {
    if (confirm('确定要清空日志吗？')) {
      onClear?.()
    }
  }, [onClear])

  // 自动滚动到底部 - 只在日志数量变化时滚动
  useEffect(() => {
    if (autoScroll && !isPaused && logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight
    }
  }, [logs.length, autoScroll, isPaused]) // 只依赖 logs.length 而不是整个 logs

  return (
    <div className="h-full flex flex-col bg-slate-950">
      {/* 顶部栏 */}
      <div className="h-10 px-4 flex items-center justify-between bg-slate-900/90 border-b border-slate-700/50 shrink-0">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-slate-300">审计日志</span>
          <Badge variant="secondary" className="text-xs bg-slate-800 text-slate-400">
            {logs.length} 条
          </Badge>
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
          {onToggle && (
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7 text-slate-500 hover:text-slate-300"
              onClick={onToggle}
              title="关闭"
            >
              <Maximize2 className="w-3.5 h-3.5" />
            </Button>
          )}
        </div>
      </div>

      {/* 对话区域 - 固定高度滚动容器 */}
      <div
        ref={logContainerRef}
        className="flex-1 overflow-y-auto overflow-x-hidden px-4 py-4"
        style={{
          maxHeight: 'calc(100vh - 200px)', // 固定最大高度
          scrollBehavior: 'smooth'
        }}
      >
        <div className="space-y-4">
          {logs.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-64 text-slate-600">
              <div className="text-6xl mb-4 opacity-50">💬</div>
              <p className="text-sm">等待审计开始...</p>
            </div>
          ) : (
            logs.map((log) => (
              <LogMessageItem
                key={log.id}
                log={log}
                isExpanded={expandedLogIds.has(log.id)}
                onToggleExpand={handleToggleExpand}
              />
            ))
          )}
        </div>
      </div>

      {/* 底部状态栏 */}
      <div className="h-8 px-4 flex items-center justify-between bg-slate-900/60 border-t border-slate-700/50 shrink-0">
        <div className="flex items-center gap-3 text-[10px] text-slate-500">
          <span className="flex items-center gap-1">
            <Clock className="w-3 h-3" />
            实时更新
          </span>
          <span>·</span>
          <span>{logs.length} 条消息</span>
        </div>
        {isPaused && (
          <Badge variant="outline" className="text-[10px] h-5 px-2 border-amber-800 text-amber-500 bg-amber-950/30">
            已暂停
          </Badge>
        )}
      </div>
    </div>
  )
}

// 使用 memo 优化主组件，只在 props 真正变化时才重渲染
export default memo(ChatLogPanel, (prevProps, nextProps) => {
  const prevExpandedSize = prevProps.expandedLogIds?.size ?? 0
  const nextExpandedSize = nextProps.expandedLogIds?.size ?? 0

  return (
    prevProps.logs.length === nextProps.logs.length &&
    prevProps.logs[prevProps.logs.length - 1]?.id === nextProps.logs[nextProps.logs.length - 1]?.id &&
    prevProps.autoScroll === nextProps.autoScroll &&
    prevExpandedSize === nextExpandedSize
  )
})
