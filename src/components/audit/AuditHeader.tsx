/**
 * Audit Header Component
 *
 * 新设计的审计页面头部，包含：
 * - 品牌标识 (AUDIT SECURITY AGENT)
 * - 任务控制栏 (TASK标签、任务名称、RUNNING状态、操作按钮)
 *
 * 颜色方案：
 * - 品牌橙色: #F97316
 * - 状态绿色: #10B981
 * - 停止红色: #EF4444
 * - 导出青色: #14B8A6
 * - 背景黑色: #121212
 * - 边框深灰: #333333
 */

import { Play, Square, Download, Star } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import { Loader2 } from 'lucide-react'

export interface AuditHeaderProps {
  // 任务名称
  taskName?: string
  // 任务状态
  status?: 'pending' | 'running' | 'paused' | 'completed' | 'failed' | 'cancelled'
  // 进度百分比
  progress?: number
  // 是否正在加载
  isLoading?: boolean
  // 是否服务健康
  isServiceHealthy?: boolean
  // 日志条目数
  logCount?: number
  // 开始审计回调
  onStart?: () => void
  // 取消审计回调
  onCancel?: () => void
  // 导出报告回调
  onExport?: () => void
  // 新建审计回调
  onNewAudit?: () => void
  // 是否隐藏品牌标识（用于全屏模式）
  hideBrand?: boolean
}

export function AuditHeader({
  taskName,
  status = 'pending',
  progress = 0,
  isLoading = false,
  isServiceHealthy = true,
  logCount = 0,
  onStart,
  onCancel,
  onExport,
  onNewAudit,
  hideBrand = false,
}: AuditHeaderProps) {
  const isRunning = status === 'running'
  const canStart = !status || status === 'pending' || status === 'completed' || status === 'failed' || status === 'cancelled'

  return (
    <div className="flex items-center justify-between px-4 py-3 border-b border-[#333333] bg-[#121212] shrink-0">
      {/* 左侧：品牌标识 + 任务控制栏 */}
      <div className="flex items-center gap-6">
        {/* 品牌标识 */}
        {!hideBrand && (
          <div className="flex items-baseline gap-1">
            <span className="text-sm font-bold text-[#F97316] tracking-tight">AUDIT</span>
            <span className="text-xs font-medium text-[#888888]">SECURITY AGENT</span>
          </div>
        )}

        {/* 分隔线 */}
        {!hideBrand && <div className="w-px h-6 bg-[#333333]" />}

        {/* TASK标签 */}
        <div className="flex items-center gap-3">
          <span className="text-xs font-semibold text-[#888888]">TASK</span>

          {/* 任务名称 */}
          {taskName && (
            <span className="text-sm font-medium text-white">{taskName}</span>
          )}

          {/* RUNNING状态徽章 */}
          {isRunning && (
            <Badge className="bg-emerald-500/20 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20 px-2 py-0.5 rounded-full flex items-center gap-1.5">
              <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-xs font-semibold">RUNNING</span>
            </Badge>
          )}

          {/* 其他状态徽章 */}
          {!isRunning && status && status !== 'pending' && (
            <Badge
              className={cn(
                "px-2 py-0.5 rounded-full",
                status === 'completed' && "bg-blue-500/20 text-blue-400 border-blue-500/30",
                status === 'failed' && "bg-red-500/20 text-red-400 border-red-500/30",
                status === 'cancelled' && "bg-slate-500/20 text-slate-400 border-slate-500/30",
                status === 'paused' && "bg-amber-500/20 text-amber-400 border-amber-500/30"
              )}
            >
              <span className="text-xs font-semibold uppercase">{status}</span>
            </Badge>
          )}

          {/* ABORT按钮 - 仅运行时显示 */}
          {isRunning && onCancel && (
            <Button
              variant="ghost"
              size="sm"
              onClick={onCancel}
              className="h-7 px-3 rounded-full bg-red-500/10 text-red-400 hover:bg-red-500/20 border border-red-500/30 flex items-center gap-1.5"
            >
              <Square className="w-3 h-3" />
              <span className="text-xs font-semibold">ABORT</span>
            </Button>
          )}

          {/* EXPORT按钮 */}
          {onExport && (
            <Button
              variant="ghost"
              size="sm"
              onClick={onExport}
              className="h-7 px-3 rounded-full bg-teal-500/10 text-teal-400 hover:bg-teal-500/20 border border-teal-500/30 flex items-center gap-1.5"
            >
              <Download className="w-3 h-3" />
              <span className="text-xs font-semibold">EXPORT</span>
            </Button>
          )}

          {/* NEW AUDIT按钮 */}
          {onNewAudit && !isRunning && (
            <Button
              variant="ghost"
              size="sm"
              onClick={onNewAudit}
              disabled={!isServiceHealthy || isLoading}
              className="h-7 px-3 rounded-full bg-orange-500/10 text-orange-400 hover:bg-orange-500/20 border border-orange-500/30 flex items-center gap-1.5 disabled:opacity-50"
            >
              <Star className="w-3 h-3" />
              <span className="text-xs font-semibold">NEW AUDIT</span>
            </Button>
          )}

          {/* 开始审计按钮 - 非运行状态显示 */}
          {canStart && onStart && !onNewAudit && (
            <Button
              variant="ghost"
              size="sm"
              onClick={onStart}
              disabled={!isServiceHealthy || isLoading}
              className="h-7 px-3 rounded-full bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 border border-emerald-500/30 flex items-center gap-1.5 disabled:opacity-50"
            >
              {isLoading ? (
                <Loader2 className="w-3 h-3 animate-spin" />
              ) : (
                <Play className="w-3 h-3" />
              )}
              <span className="text-xs font-semibold">{status === 'paused' ? 'RESUME' : 'START'}</span>
            </Button>
          )}
        </div>
      </div>

      {/* 右侧：可扩展区域 */}
      <div className="flex items-center gap-3">
        {/* 可以在这里添加更多控制按钮 */}
      </div>
    </div>
  )
}
