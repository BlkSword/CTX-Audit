/**
 * Activity Log Panel Component
 *
 * 新设计的活动日志面板，包含：
 * - 顶部Tab栏（ACTIVITY LOG标题 + LIVE徽章 + 条目计数 + AUTO-SCROLL按钮）
 * - 滚动日志区域
 *
 * 颜色方案：
 * - 标题白色: #FFFFFF
 * - LIVE绿色: #10B981
 * - 条目灰色: #888888
 * - AUTO-SCROLL橙色: #F97316
 * - 背景黑色: #121212
 * - 边框深灰: #333333
 */

import { useEffect, useRef, useCallback } from 'react'
import { ArrowDown, Activity } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import type { LogItem } from '@/shared/types'

export interface ActivityLogPanelProps {
  logs: LogItem[]
  autoScroll?: boolean
  onToggleAutoScroll?: () => void
  isLoading?: boolean
  // 自定义日志渲染器
  renderLogItem?: (log: LogItem) => React.ReactNode
}

export function ActivityLogPanel({
  logs,
  autoScroll = true,
  onToggleAutoScroll,
  isLoading = false,
  renderLogItem,
}: ActivityLogPanelProps) {
  const logContainerRef = useRef<HTMLDivElement>(null)

  // 自动滚动到底部
  useEffect(() => {
    if (autoScroll && logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight
    }
  }, [logs.length, autoScroll])

  // 格式化时间
  const formatTime = useCallback((timestamp: number) => {
    const date = new Date(timestamp)
    return date.toLocaleTimeString('zh-CN', {
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  }, [])

  // 默认日志渲染器
  const defaultRenderLogItem = useCallback((log: LogItem) => {
    // 获取日志类型样式
    const getLogTypeStyle = (type: string) => {
      const styles: Record<string, { bg: string; text: string; border: string }> = {
        info: { bg: 'bg-slate-800', text: 'text-slate-300', border: 'border-slate-700' },
        thinking: { bg: 'bg-violet-950/30', text: 'text-violet-300', border: 'border-violet-800' },
        tool: { bg: 'bg-amber-950/30', text: 'text-amber-300', border: 'border-amber-800' },
        observation: { bg: 'bg-emerald-950/30', text: 'text-emerald-300', border: 'border-emerald-800' },
        finding: { bg: 'bg-rose-950/30', text: 'text-rose-300', border: 'border-rose-800' },
        error: { bg: 'bg-red-950/30', text: 'text-red-300', border: 'border-red-800' },
        system: { bg: 'bg-slate-900', text: 'text-slate-400', border: 'border-slate-800' },
      }
      return styles[type] || styles.info
    }

    // 获取日志类型标签
    const getLogTypeLabel = (type: string) => {
      const labels: Record<string, string> = {
        info: 'INFO',
        thinking: 'THINKING',
        tool: 'TOOL',
        observation: 'OBSERVATION',
        finding: 'FINDING',
        error: 'ERROR',
        system: 'SYSTEM',
      }
      return labels[type] || 'INFO'
    }

    const style = getLogTypeStyle(log.type)
    const typeLabel = getLogTypeLabel(log.type)
    const content = log.content || (log.data as any)?.observation || (log.data as any)?.message || ''

    return (
      <div key={log.id} className="flex items-start gap-3 py-2 px-3 hover:bg-white/5 transition-colors">
        {/* 提示符 */}
        <span className="text-white font-mono text-sm mt-0.5">&gt;</span>

        {/* 日志类型徽章 */}
        <Badge className={cn("shrink-0 text-[10px] px-1.5 py-0 rounded border", style.bg, style.text, style.border)}>
          {typeLabel}
        </Badge>

        {/* 时间戳 */}
        <span className="text-xs text-white font-mono shrink-0 mt-0.5">
          {formatTime(log.timestamp)}
        </span>

        {/* 箭头 */}
        <Activity className="w-3 h-3 text-[#888888] shrink-0 mt-0.5" />

        {/* 日志内容 */}
        <div className={cn("text-sm text-white font-mono flex-1 break-all", style.text)}>
          {content}
        </div>
      </div>
    )
  }, [formatTime])

  return (
    <div className="flex flex-col h-full bg-[#121212]">
      {/* 顶部Tab栏 */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-[#333333] shrink-0">
        {/* 左侧：ACTIVITY LOG + LIVE徽章 + 条目计数 */}
        <div className="flex items-center gap-3">
          <h3 className="text-sm font-bold text-white">ACTIVITY LOG</h3>

          {/* LIVE徽章 - 绿色圆点 */}
          <Badge className="bg-emerald-500/20 text-emerald-400 border-emerald-500/30 px-2 py-0.5 rounded-full flex items-center gap-1.5">
            <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-[10px] font-semibold">LIVE</span>
          </Badge>

          {/* 条目计数 */}
          <Badge className="bg-slate-800 text-[#888888] border-slate-700 px-2 py-0.5 rounded text-xs font-medium">
            {logs.length} ENTRIES
          </Badge>
        </div>

        {/* 右侧：AUTO-SCROLL按钮 */}
        {onToggleAutoScroll && (
          <Button
            variant="ghost"
            size="sm"
            onClick={onToggleAutoScroll}
            className={cn(
              "h-7 px-3 rounded-full flex items-center gap-1.5 transition-all",
              autoScroll
                ? "bg-orange-500/10 text-orange-400 border border-orange-500/30 hover:bg-orange-500/20"
                : "bg-slate-800 text-[#888888] border border-slate-700 hover:bg-slate-700"
            )}
          >
            <ArrowDown className="w-3 h-3" />
            <span className="text-xs font-semibold">AUTO-SCROLL</span>
          </Button>
        )}
      </div>

      {/* 日志滚动区域 */}
      <div
        ref={logContainerRef}
        className="flex-1 overflow-y-auto px-2 py-2"
        style={{
          scrollBehavior: 'smooth',
        }}
      >
        {logs.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-[#888888]">
            {isLoading ? (
              <>
                <div className="w-8 h-8 border-2 border-[#333333] border-t-orange-400 rounded-full animate-spin mb-3" />
                <p className="text-sm">加载日志中...</p>
              </>
            ) : (
              <>
                <div className="text-4xl mb-3 opacity-50">📋</div>
                <p className="text-sm">等待活动日志...</p>
              </>
            )}
          </div>
        ) : (
          <div className="space-y-1">
            {logs.map((log, index) =>
              renderLogItem ? renderLogItem(log) : defaultRenderLogItem(log)
            )}
          </div>
        )}
      </div>
    </div>
  )
}
