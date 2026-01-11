/**
 * 统计面板组件
 * 参考 DeepAudit-3.0.0 实现
 *
 * 特性：
 * - 漏洞严重程度分布
 * - 实时指标（Token、工具调用）
 * - 进度展示
 * - 动画效果
 */

import { useMemo } from 'react'
import { Shield, Bug, Zap, Brain, TrendingUp, AlertTriangle, CheckCircle } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { AgentFinding, AgentTask } from './types'

interface StatsPanelProps {
  findings: AgentFinding[]
  task: AgentTask | null
  tokenCount: number
  toolCallCount: number
}

export function StatsPanel({ findings, task, tokenCount, toolCallCount }: StatsPanelProps) {
  // 计算严重程度分布
  const severityStats = useMemo(() => {
    return {
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length,
      info: findings.filter(f => f.severity === 'info').length,
    }
  }, [findings])

  // 计算安全评分
  const securityScore = useMemo(() => {
    if (findings.length === 0) return 100
    const weights: Record<string, number> = { critical: -25, high: -10, medium: -3, low: -1, info: 0 }
    let score = 100
    findings.forEach(f => {
      score += weights[f.severity] || 0
    })
    return Math.max(0, Math.min(100, score))
  }, [findings])

  // 计算文件扫描进度
  const fileProgress = useMemo(() => {
    if (!task || task.total_files === 0) return 0
    return Math.round((task.analyzed_files / task.total_files) * 100)
  }, [task])

  return (
    <div className="space-y-4 p-4">
      {/* 安全评分 */}
      <div className="p-4 rounded-xl bg-gradient-to-br from-violet-950/50 to-purple-950/30 border border-violet-800/50">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-violet-400" />
            <span className="text-sm font-medium text-violet-100">安全评分</span>
          </div>
          <span className={cn(
            "text-2xl font-bold",
            securityScore >= 80 && "text-emerald-400",
            securityScore >= 60 && securityScore < 80 && "text-amber-400",
            securityScore < 60 && "text-rose-400"
          )}>
            {securityScore}
          </span>
        </div>
        {/* 进度条 */}
        <div className="relative h-2 bg-slate-800 rounded-full overflow-hidden">
          <div
            className={cn(
              "absolute left-0 top-0 h-full transition-all duration-500",
              securityScore >= 80 && "bg-gradient-to-r from-emerald-500 to-green-500",
              securityScore >= 60 && securityScore < 80 && "bg-gradient-to-r from-amber-500 to-yellow-500",
              securityScore < 60 && "bg-gradient-to-r from-rose-500 to-red-500"
            )}
            style={{ width: `${securityScore}%` }}
          />
        </div>
        <div className="flex justify-between mt-2 text-xs text-slate-400">
          <span>风险</span>
          <span>安全</span>
        </div>
      </div>

      {/* 漏洞统计 */}
      <div className="p-4 rounded-xl bg-slate-900/50 border border-slate-800">
        <div className="flex items-center gap-2 mb-3">
          <Bug className="w-4 h-4 text-amber-400" />
          <span className="text-sm font-medium">发现漏洞</span>
          <span className="ml-auto text-lg font-bold text-amber-400">{findings.length}</span>
        </div>
        <div className="space-y-2">
          {(['critical', 'high', 'medium', 'low'] as const).map(severity => {
            const count = severityStats[severity]
            if (count === 0) return null

            const maxCount = Math.max(...Object.values(severityStats))
            const percentage = maxCount > 0 ? (count / maxCount) * 100 : 0

            const config = {
              critical: { color: 'text-rose-400', bg: 'bg-rose-500' },
              high: { color: 'text-orange-400', bg: 'bg-orange-500' },
              medium: { color: 'text-amber-400', bg: 'bg-amber-500' },
              low: { color: 'text-blue-400', bg: 'bg-blue-500' },
            }[severity]

            return (
              <div key={severity} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="capitalize text-slate-400">{severity}</span>
                  <span className={cn("font-medium", config.color)}>{count}</span>
                </div>
                <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className={cn("h-full transition-all duration-300", config.bg)}
                    style={{ width: `${percentage}%` }}
                  />
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* 文件扫描进度 */}
      {task && task.total_files > 0 && (
        <div className="p-4 rounded-xl bg-slate-900/50 border border-slate-800">
          <div className="flex items-center gap-2 mb-3">
            <TrendingUp className="w-4 h-4 text-blue-400" />
            <span className="text-sm font-medium">扫描进度</span>
          </div>
          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span className="text-slate-400">已扫描</span>
              <span className="text-blue-400 font-medium">
                {task.analyzed_files} / {task.total_files}
              </span>
            </div>
            <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-blue-500 to-cyan-500 transition-all duration-500"
                style={{ width: `${fileProgress}%` }}
              />
            </div>
            <div className="text-right text-xs text-slate-500">{fileProgress}%</div>
          </div>
        </div>
      )}

      {/* 实时指标 */}
      <div className="grid grid-cols-2 gap-3">
        {/* Token 消耗 */}
        <div className="p-3 rounded-xl bg-slate-900/50 border border-slate-800">
          <div className="flex items-center gap-1.5 mb-2">
            <Zap className="w-3.5 h-3.5 text-yellow-400" />
            <span className="text-xs text-slate-400">Token</span>
          </div>
          <div className="text-lg font-bold text-yellow-400">
            {tokenCount.toLocaleString()}
          </div>
        </div>

        {/* 工具调用 */}
        <div className="p-3 rounded-xl bg-slate-900/50 border border-slate-800">
          <div className="flex items-center gap-1.5 mb-2">
            <Brain className="w-3.5 h-3.5 text-violet-400" />
            <span className="text-xs text-slate-400">工具</span>
          </div>
          <div className="text-lg font-bold text-violet-400">
            {toolCallCount}
          </div>
        </div>
      </div>

      {/* 风险提示 */}
      {severityStats.critical > 0 || severityStats.high > 0 ? (
        <div className="p-3 rounded-xl bg-rose-950/20 border border-rose-900/50">
          <div className="flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            <div className="text-sm text-rose-200">
              发现 {severityStats.critical} 个严重和 {severityStats.high} 个高危漏洞
            </div>
          </div>
        </div>
      ) : findings.length > 0 ? (
        <div className="p-3 rounded-xl bg-emerald-950/20 border border-emerald-900/50">
          <div className="flex items-start gap-2">
            <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            <div className="text-sm text-emerald-200">
              未发现严重安全问题
            </div>
          </div>
        </div>
      ) : null}
    </div>
  )
}
