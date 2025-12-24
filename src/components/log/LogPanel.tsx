import { useEffect, useRef, memo } from 'react'
import { Terminal } from 'lucide-react'
import { ScrollArea } from '@/components/ui/scroll-area'

export interface LogEntry {
  timestamp: string
  message: string
  source: 'rust' | 'python' | 'system'
}

interface LogPanelProps {
  logs: LogEntry[]
  active?: boolean
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

export const LogPanel = memo(({ logs, active = true }: LogPanelProps) => {
  const logsEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (active && logs.length > 0) {
      logsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [logs, active])

  return (
    <div className="h-full bg-background relative">
      <div className="flex items-center gap-2 mb-3 px-4 py-3 bg-muted/30 border-b border-border/40 text-sm text-muted-foreground">
        <Terminal className="w-4 h-4" />
        <span>输出</span>
      </div>
      <ScrollArea className="h-[calc(100%-48px)] px-4">
        <div className="py-1">
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
