/**
 * ProjectTabsBar - 多项目标签栏
 *
 * 显示所有打开的项目标签，类似 VSCode 的编辑器标签栏
 */

import { X, Loader2, ShieldAlert, Circle, AlertCircle, CheckCircle2, Pause } from 'lucide-react'
import { useMultiProjectStore } from '@/stores/multiProjectStore'
import type { ProjectAuditState } from '@/stores/multiProjectStore'
import { cn } from '@/lib/utils'

// 状态图标映射
const statusIcons = {
  idle: Circle,
  pending: Loader2,
  running: Loader2,
  paused: Pause,
  completed: CheckCircle2,
  failed: AlertCircle,
  cancelled: X,
}

// 状态颜色映射
const statusColors = {
  idle: 'text-muted-foreground',
  pending: 'text-blue-400',
  running: 'text-green-400',
  paused: 'text-yellow-400',
  completed: 'text-emerald-400',
  failed: 'text-red-400',
  cancelled: 'text-muted-foreground',
}

// 状态背景色映射
const statusBgColors = {
  idle: 'bg-muted/10',
  pending: 'bg-blue-500/10',
  running: 'bg-green-500/10',
  paused: 'bg-yellow-500/10',
  completed: 'bg-emerald-500/10',
  failed: 'bg-red-500/10',
  cancelled: 'bg-muted/10',
}

interface ProjectTabsBarProps {
  className?: string
}

export function ProjectTabsBar({ className }: ProjectTabsBarProps) {
  const { openProjects, activeProjectId, setActiveProject, closeProject } = useMultiProjectStore()
  const projects = openProjects

  if (projects.length === 0) {
    return null
  }

  return (
    <div className={cn(
      'h-9 flex items-center bg-[#252526] border-b border-border/40 overflow-x-auto',
      className
    )}>
      <div className="flex items-center gap-0.5 px-1">
        {projects.map((projectState: ProjectAuditState) => {
          const isActive = projectState.project.uuid === activeProjectId
          const auditStatus = projectState.auditStatus as keyof typeof statusIcons
          const StatusIcon = statusIcons[auditStatus]
          const statusColor = statusColors[auditStatus]
          const statusBgColor = statusBgColors[auditStatus]

          return (
            <div
              key={projectState.project.uuid}
              className={cn(
                'group relative flex items-center gap-2 px-3 h-8 min-w-[160px] max-w-[240px] rounded-t cursor-pointer border-b-2 transition-all select-none',
                isActive
                  ? 'bg-[#1e1e1e] border-primary'
                  : 'bg-transparent border-transparent hover:bg-white/5'
              )}
              onClick={() => setActiveProject(projectState.project.uuid)}
            >
              {/* 状态指示器 */}
              <div className={cn('flex items-center gap-1.5', statusColor)}>
                {projectState.auditStatus === 'running' ? (
                  <StatusIcon className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <StatusIcon className="w-3.5 h-3.5" />
                )}
              </div>

              {/* 项目名称 */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-1.5">
                  <ShieldAlert className="w-3 h-3 shrink-0 text-primary/70" />
                  <span className={cn(
                    'text-xs font-medium truncate',
                    isActive ? 'text-white' : 'text-muted-foreground group-hover:text-white'
                  )}>
                    {projectState.project.name}
                  </span>
                </div>
              </div>

              {/* 进度条（运行中时显示） */}
              {projectState.auditStatus === 'running' && (
                <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-muted">
                  <div
                    className="h-full bg-primary transition-all duration-300"
                    style={{ width: `${projectState.progress}%` }}
                  />
                </div>
              )}

              {/* 关闭按钮 */}
              <button
                onClick={(e) => {
                  e.stopPropagation()
                  closeProject(projectState.project.uuid)
                }}
                className={cn(
                  'opacity-0 group-hover:opacity-100 p-0.5 rounded transition-all',
                  'hover:bg-white/10',
                  isActive ? 'opacity-100' : ''
                )}
              >
                <X className="w-3 h-3 text-muted-foreground hover:text-white" />
              </button>

              {/* 状态标识（右侧小点） */}
              {projectState.auditStatus !== 'idle' && (
                <div className={cn(
                  'absolute right-1 top-1/2 -translate-y-1/2 w-1.5 h-1.5 rounded-full',
                  statusBgColor,
                  statusColor.replace('text-', 'bg-')
                )} />
              )}
            </div>
          )
        })}
      </div>

      {/* 右侧空白区域 */}
      <div className="flex-1" />

      {/* 并行项目计数 */}
      <div className="px-3 flex items-center gap-1.5 text-xs text-muted-foreground">
        <ShieldAlert className="w-3.5 h-3.5" />
        <span>{projects.length} 个项目</span>
      </div>
    </div>
  )
}
