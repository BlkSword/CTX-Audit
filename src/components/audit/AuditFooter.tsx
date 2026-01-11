/**
 * 审计底部状态栏组件
 *
 * 显示详细的进度和统计信息：
 * - 可视化进度条
 * - 文件扫描统计
 * - 工具调用次数
 * - Token 使用量
 * - 实时连接状态
 * - Live 指示器
 */

import { useMemo } from 'react'
import {
  Activity,
  FileText,
  Wrench,
  Zap,
  Clock,
  CheckCircle2,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import type { AgentTask, ConnectionStatus } from '@/pages/AgentAudit/types'

interface AuditFooterProps {
  task: AgentTask | null
  tokenCount?: number
  toolCallCount?: number
  connectionStatus?: ConnectionStatus
  findingsCount?: number
}

export function AuditFooter({
  task,
  tokenCount = 0,
  toolCallCount = 0,
  connectionStatus = 'disconnected',
  findingsCount = 0,
}: AuditFooterProps) {
  // 计算进度百分比
  const progressPercentage = task?.progress_percentage ?? 0

  // 计算文件扫描统计
  const fileStats = useMemo(() => {
    if (!task) return null
    const total = task.total_files || 0
    const scanned = task.analyzed_files || task.indexed_files || 0
    const remaining = total - scanned
    return { total, scanned, remaining }
  }, [task])

  // 计算预估剩余时间
  const estimatedTime = useMemo(() => {
    if (!task || !task.started_at || progressPercentage >= 100) return null

    const elapsed = Date.now() - new Date(task.started_at).getTime()
    const remaining = (elapsed / progressPercentage) * (100 - progressPercentage)

    if (remaining < 60000) return `${Math.ceil(remaining / 1000)}秒`
    if (remaining < 3600000) return `${Math.ceil(remaining / 60000)}分钟`
    return `${Math.ceil(remaining / 3600000)}小时`
  }, [task, progressPercentage])

  // 格式化数字（添加千分位）
  const formatNumber = (num: number) => {
    if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`
    if (num >= 1000) return `${(num / 1000).toFixed(1)}K`
    return num.toString()
  }

  // 连接状态配置
  const connectionConfig = {
    connected: { label: 'LIVE', color: 'text-emerald-400', bg: 'bg-emerald-950/30', border: 'border-emerald-500/30', animate: 'animate-pulse' },
    connecting: { label: '连接中...', color: 'text-amber-400', bg: 'bg-amber-950/30', border: 'border-amber-500/30', animate: 'animate-pulse' },
    reconnecting: { label: '重连中...', color: 'text-amber-400', bg: 'bg-amber-950/30', border: 'border-amber-500/30', animate: 'animate-pulse' },
    disconnected: { label: '离线', color: 'text-slate-500', bg: 'bg-slate-950/30', border: 'border-slate-700/30', animate: '' },
    failed: { label: '连接失败', color: 'text-rose-400', bg: 'bg-rose-950/30', border: 'border-rose-500/30', animate: '' },
  }

  const statusConfig = connectionConfig[connectionStatus] || connectionConfig.disconnected

  return (
    <div className="h-12 bg-slate-900/90 border-t border-slate-800 flex items-center px-4 gap-6 shrink-0">
      {/* 左侧：进度条和文件统计 */}
      <div className="flex-1 flex items-center gap-4 min-w-0">
        {/* 进度条 */}
        <div className="flex items-center gap-3 flex-1 min-w-0">
          <div className="flex items-center gap-2 shrink-0">
            <Activity className={cn("w-4 h-4", statusConfig.color, statusConfig.animate)} />
            <span className="text-xs font-medium text-slate-400">进度</span>
          </div>

          {/* 进度条可视化 */}
          <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden min-w-[100px]">
            <div
              className={cn(
                "h-full transition-all duration-500 rounded-full",
                progressPercentage >= 100
                  ? "bg-emerald-500"
                  : progressPercentage >= 75
                    ? "bg-blue-500"
                    : progressPercentage >= 50
                      ? "bg-amber-500"
                      : "bg-violet-500"
              )}
              style={{ width: `${progressPercentage}%` }}
            />
          </div>

          {/* 百分比文字 */}
          <span className={cn(
            "text-sm font-semibold tabular-nums shrink-0",
            progressPercentage >= 100 ? "text-emerald-400" : "text-slate-300"
          )}>
            {progressPercentage}%
          </span>
        </div>

        {/* 文件统计 */}
        {fileStats && (
          <div className="flex items-center gap-3 px-3 py-1.5 rounded-lg bg-slate-800/50 border border-slate-700 shrink-0">
            <FileText className="w-3.5 h-3.5 text-slate-400" />
            <div className="flex items-center gap-1 text-xs">
              <span className="text-slate-400">文件:</span>
              <span className="font-medium text-blue-400 tabular-nums">{fileStats.scanned}</span>
              <span className="text-slate-600">/</span>
              <span className="text-slate-400 tabular-nums">{fileStats.total}</span>
            </div>
          </div>
        )}
      </div>

      {/* 中间：统计数据 */}
      <div className="flex items-center gap-4 shrink-0">
        {/* 漏洞发现 */}
        {task && (
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-3.5 h-3.5 text-rose-400" />
            <span className="text-xs text-slate-400">发现:</span>
            <span className="text-sm font-semibold text-rose-400 tabular-nums">{findingsCount}</span>
          </div>
        )}

        {/* 工具调用 */}
        <div className="flex items-center gap-2">
          <Wrench className="w-3.5 h-3.5 text-violet-400" />
          <span className="text-xs text-slate-400">工具:</span>
          <span className="text-sm font-semibold text-violet-400 tabular-nums">{formatNumber(toolCallCount)}</span>
        </div>

        {/* Token 使用 */}
        <div className="flex items-center gap-2">
          <Zap className="w-3.5 h-3.5 text-amber-400" />
          <span className="text-xs text-slate-400">Token:</span>
          <span className="text-sm font-semibold text-amber-400 tabular-nums">{formatNumber(tokenCount)}</span>
        </div>
      </div>

      {/* 右侧：时间和连接状态 */}
      <div className="flex items-center gap-4 shrink-0">
        {/* 预计剩余时间 */}
        {task?.status === 'running' && estimatedTime && (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800/50 border border-slate-700">
            <Clock className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-xs text-slate-400">剩余:</span>
            <span className="text-sm font-medium text-slate-300">{estimatedTime}</span>
          </div>
        )}

        {/* 实时连接状态 */}
        <div className={cn(
          "flex items-center gap-2 px-3 py-1.5 rounded-full border transition-all",
          statusConfig.bg,
          statusConfig.border
        )}>
          <div className={cn(
            "w-2 h-2 rounded-full transition-colors",
            statusConfig.color,
            statusConfig.animate
          )} />
          <span className={cn("text-xs font-semibold", statusConfig.color)}>
            {statusConfig.label}
          </span>
        </div>
      </div>
    </div>
  )
}
