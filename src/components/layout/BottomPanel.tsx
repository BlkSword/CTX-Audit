import { Terminal, AlertCircle, Bug, ScrollText, X, Maximize2 } from 'lucide-react'
import { useLayoutStore } from '@/stores/layoutStore'
import type { BottomPanelTab } from '@/stores/layoutStore'
import { cn } from '@/lib/utils'
import { ProblemsPanel } from '@/components/editor/ProblemsPanel'
import { useFindingMarkerStore } from '@/stores/findingMarkerStore'

const bottomPanelTabs: Array<{
  id: BottomPanelTab
  icon: typeof Terminal
  label: string
}> = [
  { id: 'output', icon: ScrollText, label: '输出' },
  { id: 'terminal', icon: Terminal, label: '终端' },
  { id: 'problems', icon: AlertCircle, label: '问题' },
  { id: 'debug-console', icon: Bug, label: '调试控制台' },
  { id: 'logs', icon: ScrollText, label: '日志' },
]

interface BottomPanelProps {
  className?: string
  children?: React.ReactNode
}

export function BottomPanel({ className, children }: BottomPanelProps) {
  const {
    bottomPanelVisible,
    activeBottomTab,
    setActiveBottomTab,
    toggleBottomPanel,
  } = useLayoutStore()

  if (!bottomPanelVisible) {
    return null
  }

  return (
    <div className={cn('bg-[#1e1e1e] border-t border-border/40 flex flex-col h-full', className)}>
      <div className="h-9 flex items-center justify-between px-2 bg-[#252526] border-b border-border/40 select-none">
        <div className="flex items-center gap-1">
          {bottomPanelTabs.map((tab) => {
            const Icon = tab.icon
            const isActive = activeBottomTab === tab.id

            return (
              <button
                key={tab.id}
                onClick={() => setActiveBottomTab(tab.id)}
                className={cn(
                  'flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-t transition-colors',
                  isActive
                    ? 'bg-[#1e1e1e] text-white'
                    : 'text-muted-foreground hover:text-white hover:bg-white/5'
                )}
              >
                <Icon className="w-3.5 h-3.5" />
                {tab.label}
              </button>
            )
          })}
        </div>

        <div className="flex items-center gap-1">
          <button
            className="p-1.5 text-muted-foreground hover:text-white hover:bg-white/5 rounded transition-colors"
            title="最大化面板"
          >
            <Maximize2 className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={toggleBottomPanel}
            className="p-1.5 text-muted-foreground hover:text-white hover:bg-white/5 rounded transition-colors"
            title="关闭面板"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-auto">
        {children || <BottomPanelContent />}
      </div>
    </div>
  )
}

function BottomPanelContent() {
  const { activeBottomTab } = useLayoutStore()

  switch (activeBottomTab) {
    case 'output':
      return <OutputContent />
    case 'terminal':
      return <TerminalContent />
    case 'problems':
      return <ProblemsContent />
    case 'debug-console':
      return <DebugConsoleContent />
    case 'logs':
      return <LogsContent />
    default:
      return <OutputContent />
  }
}

function OutputContent() {
  return (
    <div className="p-4 text-sm font-mono text-muted-foreground">
      <p>输出面板</p>
      <p className="mt-2 text-xs">显示应用程序的输出信息</p>
    </div>
  )
}

function TerminalContent() {
  return (
    <div className="p-4 text-sm font-mono text-muted-foreground">
      <p>终端</p>
      <p className="mt-2 text-xs">集成终端用于运行命令</p>
    </div>
  )
}

function ProblemsContent() {
  const { jumpToFinding } = useFindingMarkerStore()

  return (
    <ProblemsPanel onJumpToFinding={(findingId) => jumpToFinding('group-1', findingId)} />
  )
}

function DebugConsoleContent() {
  return (
    <div className="p-4 text-sm font-mono text-muted-foreground">
      <p>调试控制台</p>
      <p className="mt-2 text-xs">在调试会话中执行表达式</p>
    </div>
  )
}

function LogsContent() {
  return (
    <div className="p-4 text-sm font-mono text-muted-foreground">
      <p>日志面板</p>
      <p className="mt-2 text-xs">显示应用程序日志</p>
    </div>
  )
}
