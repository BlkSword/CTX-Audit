/**
 * 审计统计可视化面板
 *
 * 使用纯 CSS 实现的数据可视化：
 * - 漏洞严重程度分布（饼图）
 * - 漏洞类型统计
 * - Agent 执行统计
 * - 时间线视图
 */

import { useMemo } from 'react'
import {
  Bug,
  Shield,
  Activity,
  Clock,
  AlertTriangle,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import type { AgentFinding, AgentTask } from '@/pages/AgentAudit/types'

interface VizPanelProps {
  findings: AgentFinding[]
  task: AgentTask | null
  tokenCount?: number
  toolCallCount?: number
}

// 严重程度颜色配置
const SEVERITY_CONFIG = {
  critical: { color: 'bg-rose-500', text: 'text-rose-400', label: '严重' },
  high: { color: 'bg-orange-500', text: 'text-orange-400', label: '高危' },
  medium: { color: 'bg-amber-500', text: 'text-amber-400', label: '中危' },
  low: { color: 'bg-blue-500', text: 'text-blue-400', label: '低危' },
  info: { color: 'bg-slate-500', text: 'text-slate-400', label: '信息' },
}

// CSS 饼图组件
function PieChart({
  data,
  size = 120,
}: {
  data: { label: string; value: number; color: string }[]
  size?: number
}) {
  const total = data.reduce((sum, d) => sum + d.value, 0)
  let currentAngle = 0

  const slices = data.map((d) => {
    const percentage = total > 0 ? (d.value / total) * 100 : 0
    const angle = (percentage / 100) * 360
    const startAngle = currentAngle
    const endAngle = currentAngle + angle

    // 计算扇形路径
    const x1 = 50 + 50 * Math.cos((Math.PI / 180) * startAngle)
    const y1 = 50 + 50 * Math.sin((Math.PI / 180) * startAngle)
    const x2 = 50 + 50 * Math.cos((Math.PI / 180) * endAngle)
    const y2 = 50 + 50 * Math.sin((Math.PI / 180) * endAngle)

    const largeArcFlag = angle > 180 ? 1 : 0

    // 如果只有一个数据且占比 100%
    const path =
      percentage >= 100
        ? `M 50 50 m -50, 0 a 50,50 0 1,0 100,0 a 50,50 0 1,0 -100,0`
        : `M 50 50 L ${x1} ${y1} A 50 50 0 ${largeArcFlag} 1 ${x2} ${y2} Z`

    currentAngle += angle

    return { ...d, percentage, path }
  })

  return (
    <div className="flex items-center gap-6">
      {/* SVG 饼图 */}
      <svg
        width={size}
        height={size}
        viewBox="0 0 100 100"
        className="transform -rotate-90"
      >
        {slices.map((slice, index) => (
          <path
            key={index}
            d={slice.path}
            fill={slice.color}
            stroke="#1e293b"
            strokeWidth="0.5"
            className="transition-opacity hover:opacity-80"
          />
        ))}
        {/* 中心圆（环形图） */}
        <circle cx="50" cy="50" r="30" fill="#1e293b" />
      </svg>

      {/* 图例 */}
      <div className="space-y-2">
        {slices.map((slice, index) => (
          <div key={index} className="flex items-center gap-2">
            <div
              className="w-3 h-3 rounded-sm"
              style={{ backgroundColor: slice.color }}
            />
            <span className="text-xs text-slate-400">{slice.label}</span>
            <span className="text-xs font-semibold text-slate-300 tabular-nums">
              {slice.value} ({slice.percentage.toFixed(1)}%)
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

// 进度条组件
function ProgressBar({
  value,
  max,
  color,
  label,
}: {
  value: number
  max: number
  color: string
  label: string
}) {
  const percentage = max > 0 ? (value / max) * 100 : 0

  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-xs">
        <span className="text-slate-400">{label}</span>
        <span className="text-slate-300 tabular-nums">{value} / {max}</span>
      </div>
      <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
        <div
          className={cn("h-full transition-all duration-500 rounded-full", color)}
          style={{ width: `${percentage}%` }}
        />
      </div>
    </div>
  )
}

// 统计卡片
function StatCard({
  icon: Icon,
  label,
  value,
  color,
  bgColor,
}: {
  icon: React.ComponentType<{ className?: string }>
  label: string
  value: number | string
  color: string
  bgColor: string
}) {
  return (
    <div className="flex items-center gap-3 p-4 rounded-xl bg-slate-900/50 border border-slate-800">
      <div className={cn("p-3 rounded-lg", bgColor)}>
        <Icon className={cn("w-5 h-5", color)} />
      </div>
      <div>
        <div className="text-xs text-slate-500 uppercase tracking-wide">{label}</div>
        <div className={cn("text-xl font-bold tabular-nums", color)}>
          {value}
        </div>
      </div>
    </div>
  )
}

export function VizPanel({ findings, task, tokenCount = 0, toolCallCount = 0 }: VizPanelProps) {
  // 计算严重程度分布
  const severityDistribution = useMemo(() => {
    const distribution = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    }

    findings.forEach((f) => {
      const severity = f.severity as keyof typeof distribution
      if (severity in distribution) {
        distribution[severity]++
      }
    })

    return Object.entries(distribution)
      .filter(([_, count]) => count > 0)
      .map(([severity, count]) => ({
        label: SEVERITY_CONFIG[severity as keyof typeof SEVERITY_CONFIG].label,
        value: count,
        color: SEVERITY_CONFIG[severity as keyof typeof SEVERITY_CONFIG].color.replace('bg-', 'bg-'),
      }))
  }, [findings])

  // 计算漏洞类型分布
  const typeDistribution = useMemo(() => {
    const types: Record<string, number> = {}

    findings.forEach((f) => {
      const type = f.vulnerability_type || 'Unknown'
      types[type] = (types[type] || 0) + 1
    })

    return Object.entries(types)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([type, count]) => ({ type, count }))
  }, [findings])

  // 计算验证状态
  const verificationStats = useMemo(() => {
    const verified = findings.filter((f) => f.is_verified).length
    const unverified = findings.length - verified
    return { verified, unverified }
  }, [findings])

  // 计算进度
  const progressStats = useMemo(() => {
    if (!task) return null

    return {
      filesScanned: task.analyzed_files || task.indexed_files || 0,
      totalFiles: task.total_files || 0,
      progress: task.progress_percentage || 0,
    }
  }, [task])

  // 计算执行时间
  const executionTime = useMemo(() => {
    if (!task?.started_at) return null

    const start = new Date(task.started_at)
    const end = task.completed_at ? new Date(task.completed_at) : new Date()
    const duration = Math.floor((end.getTime() - start.getTime()) / 1000)

    if (duration < 60) return `${duration}秒`
    if (duration < 3600) return `${Math.floor(duration / 60)}分${duration % 60}秒`
    return `${Math.floor(duration / 3600)}小时${Math.floor((duration % 3600) / 60)}分钟`
  }, [task])

  return (
    <div className="space-y-6">
      {/* 概览统计卡片 */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard
          icon={Bug}
          label="漏洞发现"
          value={findings.length}
          color="text-rose-400"
          bgColor="bg-rose-950/20"
        />
        <StatCard
          icon={Shield}
          label="已验证"
          value={`${verificationStats.verified}/${findings.length}`}
          color="text-emerald-400"
          bgColor="bg-emerald-950/20"
        />
        <StatCard
          icon={Activity}
          label="工具调用"
          value={toolCallCount}
          color="text-violet-400"
          bgColor="bg-violet-950/20"
        />
        <StatCard
          icon={Clock}
          label="执行时间"
          value={executionTime || '-'}
          color="text-blue-400"
          bgColor="bg-blue-950/20"
        />
      </div>

      {/* 漏洞严重程度分布 */}
      <div className="p-5 rounded-xl bg-slate-900/50 border border-slate-800">
        <h3 className="text-sm font-semibold text-slate-300 mb-4 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-400" />
          漏洞严重程度分布
        </h3>
        {severityDistribution.length > 0 ? (
          <PieChart data={severityDistribution} size={140} />
        ) : (
          <div className="text-center text-slate-600 py-8">暂无漏洞数据</div>
        )}
      </div>

      {/* 进度统计 */}
      {progressStats && (
        <div className="p-5 rounded-xl bg-slate-900/50 border border-slate-800">
          <h3 className="text-sm font-semibold text-slate-300 mb-4 flex items-center gap-2">
            <Activity className="w-4 h-4 text-blue-400" />
            扫描进度
          </h3>
          <div className="space-y-3">
            <ProgressBar
              value={progressStats.filesScanned}
              max={progressStats.totalFiles}
              color="bg-blue-500"
              label="文件扫描"
            />
            <ProgressBar
              value={progressStats.progress}
              max={100}
              color="bg-emerald-500"
              label="总体进度"
            />
          </div>
        </div>
      )}

      {/* 漏洞类型 TOP 5 */}
      {typeDistribution.length > 0 && (
        <div className="p-5 rounded-xl bg-slate-900/50 border border-slate-800">
          <h3 className="text-sm font-semibold text-slate-300 mb-4 flex items-center gap-2">
            <Bug className="w-4 h-4 text-amber-400" />
            漏洞类型 TOP 5
          </h3>
          <div className="space-y-3">
            {typeDistribution.map(({ type, count }, index) => (
              <div key={type} className="flex items-center gap-3">
                <div className={cn(
                  "w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold",
                  index === 0 ? "bg-rose-500/20 text-rose-400" :
                  index === 1 ? "bg-orange-500/20 text-orange-400" :
                  index === 2 ? "bg-amber-500/20 text-amber-400" :
                  "bg-slate-700/50 text-slate-400"
                )}>
                  {index + 1}
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm text-slate-300">{type}</span>
                    <span className="text-xs font-semibold text-slate-400 tabular-nums">
                      {count}
                    </span>
                  </div>
                  <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className={cn(
                        "h-full rounded-full",
                        index === 0 ? "bg-rose-500" :
                        index === 1 ? "bg-orange-500" :
                        index === 2 ? "bg-amber-500" :
                        "bg-slate-600"
                      )}
                      style={{ width: `${(count / typeDistribution[0].count) * 100}%` }}
                    />
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Token 使用统计 */}
      <div className="p-5 rounded-xl bg-slate-900/50 border border-slate-800">
        <h3 className="text-sm font-semibold text-slate-300 mb-4 flex items-center gap-2">
          <Activity className="w-4 h-4 text-amber-400" />
          Token 使用统计
        </h3>
        <div className="text-center py-4">
          <div className="text-4xl font-bold text-amber-400 tabular-nums">
            {tokenCount.toLocaleString()}
          </div>
          <div className="text-xs text-slate-500 mt-1">总 Token 数</div>
        </div>
      </div>
    </div>
  )
}
