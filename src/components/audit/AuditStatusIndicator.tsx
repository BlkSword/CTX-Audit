/**
 * 审计状态指示器组件
 *
 * 显示审计任务的当前状态、进度等信息
 */

import { useMemo } from 'react'
import {
  Loader2,
  CheckCircle,
  XCircle,
  Pause,
  Clock,
  Zap,
  AlertCircle,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

export interface AuditStatusIndicatorProps {
  status: 'pending' | 'running' | 'paused' | 'completed' | 'failed' | 'cancelled'
  progress?: number
  currentPhase?: string
  error?: string | null
  className?: string
  compact?: boolean
}

// 状态配置
const STATUS_CONFIG = {
  pending: {
    icon: Clock,
    label: '等待中',
    color: 'text-slate-400',
    bgGradient: 'from-slate-950/40 to-gray-950/20',
    border: 'border-slate-700',
    barColor: 'bg-slate-600',
    pulse: false
  },
  running: {
    icon: Loader2,
    label: '运行中',
    color: 'text-blue-400',
    bgGradient: 'from-blue-950/40 to-indigo-950/20',
    border: 'border-blue-700',
    barColor: 'bg-gradient-to-r from-blue-500 to-indigo-500',
    pulse: true
  },
  paused: {
    icon: Pause,
    label: '已暂停',
    color: 'text-amber-400',
    bgGradient: 'from-amber-950/40 to-yellow-950/20',
    border: 'border-amber-700',
    barColor: 'bg-amber-600',
    pulse: false
  },
  completed: {
    icon: CheckCircle,
    label: '已完成',
    color: 'text-emerald-400',
    bgGradient: 'from-emerald-950/40 to-green-950/20',
    border: 'border-emerald-700',
    barColor: 'bg-emerald-600',
    pulse: false
  },
  failed: {
    icon: XCircle,
    label: '失败',
    color: 'text-rose-400',
    bgGradient: 'from-rose-950/40 to-red-950/20',
    border: 'border-rose-700',
    barColor: 'bg-rose-600',
    pulse: false
  },
  cancelled: {
    icon: XCircle,
    label: '已终止',
    color: 'text-slate-400',
    bgGradient: 'from-slate-950/40 to-gray-950/20',
    border: 'border-slate-700',
    barColor: 'bg-slate-600',
    pulse: false
  },
}

export function AuditStatusIndicator({
  status,
  progress = 0,
  currentPhase,
  error,
  className,
  compact = false
}: AuditStatusIndicatorProps) {
  const config = STATUS_CONFIG[status]
  const StatusIcon = config.icon

  // 计算进度条颜色
  const progressColor = useMemo(() => {
    if (progress >= 100) return 'bg-emerald-500'
    if (progress >= 75) return 'bg-blue-500'
    if (progress >= 50) return 'bg-violet-500'
    if (progress >= 25) return 'bg-amber-500'
    return 'bg-slate-500'
  }, [progress])

  if (compact) {
    return (
      <div className={cn("flex items-center gap-2", className)}>
        <div className={cn(
          "w-5 h-5 rounded-full flex items-center justify-center",
          config.bgGradient,
          config.border,
          "border"
        )}>
          <StatusIcon className={cn(
            "w-3 h-3",
            config.pulse && "animate-spin",
            config.color
          )} />
        </div>
        <span className={cn("text-xs font-medium", config.color)}>
          {config.label}
        </span>
        {status === 'running' && progress > 0 && (
          <span className="text-xs text-slate-500 ml-auto">
            {progress}%
          </span>
        )}
      </div>
    )
  }

  return (
    <div className={cn(
      "rounded-xl border p-4 transition-all duration-200",
      "bg-gradient-to-br " + config.bgGradient,
      config.border,
      className
    )}>
      {/* 状态头部 */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          {/* 状态图标 */}
          <div className={cn(
            "w-10 h-10 rounded-lg flex items-center justify-center",
            config.bgGradient.replace('from-', 'bg-').replace('/40', '/30')
          )}>
            <StatusIcon className={cn(
              "w-5 h-5",
              config.pulse && "animate-spin",
              config.color
            )} />
          </div>

          {/* 状态文本 */}
          <div>
            <div className={cn("text-sm font-bold", config.color)}>
              {config.label}
            </div>
            {currentPhase && (
              <div className="text-[10px] text-slate-500 flex items-center gap-1">
                <Zap className="w-2.5 h-2.5" />
                {currentPhase}
              </div>
            )}
          </div>
        </div>

        {/* 进度百分比 */}
        {status === 'running' && progress > 0 && (
          <div className="text-right">
            <div className={cn("text-2xl font-bold", config.color)}>
              {progress}
              <span className="text-lg text-slate-500">%</span>
            </div>
          </div>
        )}
      </div>

      {/* 进度条 */}
      {(status === 'running' || status === 'completed') && (
        <div className="space-y-2">
          <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
            <div
              className={cn(
                "h-full rounded-full transition-all duration-500 ease-out",
                status === 'completed' ? config.barColor : progressColor
              )}
              style={{ width: `${Math.min(100, Math.max(0, progress))}%` }}
            />
          </div>

          {/* 进度阶段标记 */}
          <div className="flex justify-between text-[10px] text-slate-600">
            <span>0%</span>
            <span>25%</span>
            <span>50%</span>
            <span>75%</span>
            <span>100%</span>
          </div>
        </div>
      )}

      {/* 错误信息 */}
      {status === 'failed' && error && (
        <div className="mt-3 p-3 rounded-lg bg-rose-950/30 border border-rose-900/50">
          <div className="flex items-start gap-2">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            <div className="flex-1">
              <div className="text-xs font-semibold text-rose-300 mb-1">错误信息</div>
              <div className="text-xs text-rose-200/80">{error}</div>
            </div>
          </div>
        </div>
      )}

      {/* 完成信息 */}
      {status === 'completed' && (
        <div className="mt-3 flex items-center justify-center gap-2 p-3 rounded-lg bg-emerald-950/30 border border-emerald-900/50">
          <CheckCircle className="w-4 h-4 text-emerald-400" />
          <span className="text-sm text-emerald-200">审计任务已成功完成</span>
        </div>
      )}
    </div>
  )
}

/**
 * 小型状态徽章组件
 */
export function AuditStatusBadge({
  status,
  progress
}: {
  status: AuditStatusIndicatorProps['status']
  progress?: number
}) {
  const config = STATUS_CONFIG[status]
  const StatusIcon = config.icon

  return (
    <Badge variant="outline" className={cn(
      "text-xs border px-2 py-1",
      config.bgGradient,
      config.border,
      config.color
    )}>
      <StatusIcon className={cn(
        "w-3 h-3 mr-1",
        config.pulse && "animate-spin"
      )} />
      {config.label}
      {status === 'running' && progress !== undefined && (
        <span className="ml-1 opacity-70">{progress}%</span>
      )}
    </Badge>
  )
}

/**
 * 状态指示灯组件
 */
export function StatusIndicator({
  status,
  size = 'md'
}: {
  status: AuditStatusIndicatorProps['status']
  size?: 'sm' | 'md' | 'lg'
}) {
  const config = STATUS_CONFIG[status]

  const sizeClasses = {
    sm: 'w-2 h-2',
    md: 'w-3 h-3',
    lg: 'w-4 h-4'
  }

  return (
    <div className={cn(
      "rounded-full transition-all duration-300",
      sizeClasses[size],
      config.color.replace('text-', 'bg-'),
      config.pulse && "animate-pulse"
    )}>
      <div className={cn(
        "rounded-full animate-ping",
        sizeClasses[size],
        config.color.replace('text-', 'bg-').replace('400', '200'),
        "absolute"
      )} />
    </div>
  )
}
