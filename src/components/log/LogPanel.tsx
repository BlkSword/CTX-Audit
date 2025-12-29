import { useEffect, useRef, memo } from 'react'
import { Terminal, X, Trash2, Minus } from 'lucide-react'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'

export interface LogEntry {
  timestamp: string
  message: string
  source: 'rust' | 'python' | 'system'
}

interface LogPanelProps {
  logs: LogEntry[]
  active?: boolean
  onToggle?: () => void
  onClear?: () => void
  onMinimize?: () => void
}

const LogEntryItem = memo(({ entry }: { entry: LogEntry }) => {
  const getSourceColor = (source: LogEntry['source']) => {
    switch (source) {
      case 'rust': return 'text-orange-500'
      case 'python': return 'text-blue-500'
      case 'system': return 'text-green-500'
      default: return 'text-muted-foreground'
    }
  }

  const formatMessage = (message: string) => {
    const lines = message.split('\n')
    return lines.map((line, i) => {
      const trimmed = line.trim()
      if (trimmed.startsWith('- ')) {
        return (
          <div key={i} className="ml-4">
            <span className="text-muted-foreground">•</span>
            <span className="ml-2">{line.replace(/^- /, '')}</span>
          </div>
        )
      }
      return <div key={i}>{line}</div>
    })
  }

  return (
    <div className="mb-3 pb-3 border-b border-border/20 last:border-b-0 last:pb-0 last:mb-0 font-mono text-xs text-foreground">
      <span className={`${getSourceColor(entry.source)} mr-3 font-semibold`}>
        [{entry.source}]
      </span>
      <span className="text-muted-foreground mr-2">{entry.timestamp}</span>
      <span className="whitespace-pre-line">
        {formatMessage(entry.message)}
      </span>
    </div>
  )
})

LogEntryItem.displayName = 'LogEntryItem'

export const LogPanel = memo(({ logs, active = true, onToggle, onClear, onMinimize }: LogPanelProps) => {
  const logsEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (active && logs.length > 0) {
      logsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [logs, active])

  return (
    <div className="h-full bg-card relative flex flex-col">
      {/* Header - 控制栏 */}
      <div className="h-10 px-3 flex items-center justify-between bg-muted/20 border-b border-border/40 shrink-0 select-none">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-muted-foreground" />
          <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            终端 / 输出
          </span>
          {logs.length > 0 && (
            <Badge variant="secondary" className="text-[10px] h-5 px-1.5 font-normal">
              {logs.length} 条
            </Badge>
          )}
        </div>
        <div className="flex items-center gap-1">
          {onClear && logs.length > 0 && (
            <Button
              variant="ghost"
              size="icon"
              className="h-6 w-6"
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
              className="h-6 w-6"
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
              className="h-6 w-6"
              onClick={onToggle}
              title="关闭面板"
            >
              <X className="w-3.5 h-3.5" />
            </Button>
          )}
        </div>
      </div>

      {/* Logs Content */}
      <ScrollArea className="flex-1">
        <div className="px-3 py-2">
          {logs.length === 0 ? (
            <div className="flex items-center justify-center h-32 text-muted-foreground text-sm">
              等待操作...
            </div>
          ) : (
            logs.map((entry, idx) => (
              <LogEntryItem key={`${entry.timestamp}-${idx}`} entry={entry} />
            ))
          )}
          <div ref={logsEndRef} />
        </div>
      </ScrollArea>
    </div>
  )
})

LogPanel.displayName = 'LogPanel'
