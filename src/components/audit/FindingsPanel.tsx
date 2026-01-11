/**
 * 审计结果面板组件
 *
 * 展示审计发现的漏洞列表
 */

import { useState } from 'react'
import {
  AlertTriangle,
  CheckCircle,
  XCircle,
  Shield,
  FileText,
  MapPin,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Copy,
  Eye,
  EyeOff
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { cn } from '@/lib/utils'
import type { AgentFinding } from '@/shared/types'

export interface FindingsPanelProps {
  findings: AgentFinding[]
  loading?: boolean
  onRefresh?: () => void
}

// 严重程度配置
const SEVERITY_CONFIG = {
  critical: {
    icon: AlertTriangle,
    label: '严重',
    color: 'text-rose-400',
    bgGradient: 'from-rose-950/40 to-red-950/20',
    border: 'border-rose-800/50',
    badge: 'bg-rose-600 text-white',
    priority: 4
  },
  high: {
    icon: AlertTriangle,
    label: '高危',
    color: 'text-orange-400',
    bgGradient: 'from-orange-950/40 to-amber-950/20',
    border: 'border-orange-800/50',
    badge: 'bg-orange-600 text-white',
    priority: 3
  },
  medium: {
    icon: Shield,
    label: '中危',
    color: 'text-amber-400',
    bgGradient: 'from-amber-950/40 to-yellow-950/20',
    border: 'border-amber-800/50',
    badge: 'bg-amber-600 text-white',
    priority: 2
  },
  low: {
    icon: Shield,
    label: '低危',
    color: 'text-blue-400',
    bgGradient: 'from-blue-950/40 to-sky-950/20',
    border: 'border-blue-800/50',
    badge: 'bg-blue-600 text-white',
    priority: 1
  },
  info: {
    icon: FileText,
    label: '信息',
    color: 'text-slate-400',
    bgGradient: 'from-slate-950/40 to-gray-950/20',
    border: 'border-slate-800/50',
    badge: 'bg-slate-600 text-white',
    priority: 0
  },
}

// 状态配置
const STATUS_CONFIG = {
  new: { icon: AlertTriangle, label: '待确认', color: 'text-amber-400', bg: 'bg-amber-500/20' },
  investigating: { icon: Eye, label: '调查中', color: 'text-blue-400', bg: 'bg-blue-500/20' },
  confirmed: { icon: CheckCircle, label: '已确认', color: 'text-emerald-400', bg: 'bg-emerald-500/20' },
  false_positive: { icon: XCircle, label: '误报', color: 'text-rose-400', bg: 'bg-rose-500/20' },
  fixed: { icon: CheckCircle, label: '已修复', color: 'text-blue-400', bg: 'bg-blue-500/20' },
  ignored: { icon: EyeOff, label: '已忽略', color: 'text-slate-400', bg: 'bg-slate-500/20' },
}

export function FindingsPanel({ findings, loading, onRefresh }: FindingsPanelProps) {
  const [filterSeverity, setFilterSeverity] = useState<string[]>([])
  const _filterStatus = useState<string[]>([])[0]
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set())
  const [hiddenIds, setHiddenIds] = useState<Set<string>>(new Set())

  // 排序和过滤
  const processedFindings = findings
    .filter(f => {
      if (filterSeverity.length > 0 && !filterSeverity.includes(f.severity)) return false
      if (_filterStatus.length > 0 && !_filterStatus.includes(f.status)) return false
      if (hiddenIds.has(f.id)) return false
      return true
    })
    .sort((a, b) => {
      const severityA = SEVERITY_CONFIG[a.severity]?.priority || 0
      const severityB = SEVERITY_CONFIG[b.severity]?.priority || 0
      if (severityA !== severityB) return severityB - severityA
      return new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
    })

  // 统计
  const stats = {
    total: findings.length,
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
  }

  const toggleExpand = (id: string) => {
    setExpandedIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const toggleVisibility = (id: string) => {
    setHiddenIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  return (
    <div className="h-full flex flex-col bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      {/* Header */}
      <div className="px-4 py-3 bg-slate-900/80 backdrop-blur-xl border-b border-slate-800/50 shrink-0">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-rose-500/20">
              <AlertTriangle className="w-4 h-4 text-rose-400" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-200">审计结果</h3>
              <p className="text-[10px] text-slate-500 font-mono">VULNERABILITIES</p>
            </div>
          </div>

          {onRefresh && (
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7 text-slate-500 hover:text-slate-300"
              onClick={onRefresh}
              title="刷新"
            >
              <ExternalLink className="w-3.5 h-3.5" />
            </Button>
          )}
        </div>

        {/* 统计卡片 */}
        <div className="grid grid-cols-4 gap-2">
          <div className="p-2 rounded-lg bg-gradient-to-br from-rose-950/40 to-red-950/20 border border-rose-800/30 text-center">
            <div className="text-2xl font-bold text-rose-400">{stats.critical}</div>
            <div className="text-[10px] text-rose-300/70">严重</div>
          </div>
          <div className="p-2 rounded-lg bg-gradient-to-br from-orange-950/40 to-amber-950/20 border border-orange-800/30 text-center">
            <div className="text-2xl font-bold text-orange-400">{stats.high}</div>
            <div className="text-[10px] text-orange-300/70">高危</div>
          </div>
          <div className="p-2 rounded-lg bg-gradient-to-br from-amber-950/40 to-yellow-950/20 border border-amber-800/30 text-center">
            <div className="text-2xl font-bold text-amber-400">{stats.medium}</div>
            <div className="text-[10px] text-amber-300/70">中危</div>
          </div>
          <div className="p-2 rounded-lg bg-gradient-to-br from-blue-950/40 to-sky-950/20 border border-blue-800/30 text-center">
            <div className="text-2xl font-bold text-blue-400">{stats.low}</div>
            <div className="text-[10px] text-blue-300/70">低危</div>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="px-4 py-2 border-b border-slate-800/50 shrink-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs text-slate-500 font-medium">严重程度:</span>
          {Object.entries(SEVERITY_CONFIG).map(([severity, config]) => {
            const isActive = filterSeverity.includes(severity)
            const count = findings.filter(f => f.severity === severity).length
            const Icon = config.icon
            return (
              <button
                key={severity}
                onClick={() => {
                  setFilterSeverity(prev =>
                    prev.includes(severity)
                      ? prev.filter(s => s !== severity)
                      : [...prev, severity]
                  )
                }}
                disabled={count === 0}
                className={cn(
                  "px-2 py-1 rounded-md text-xs font-medium transition-all flex items-center gap-1.5",
                  isActive
                    ? config.badge + " shadow-sm"
                    : "bg-slate-800/50 text-slate-500 hover:bg-slate-800"
                )}
              >
                <Icon className="w-3 h-3" />
                <span>{config.label}</span>
                <span className={cn(
                  "px-1.5 py-0.5 rounded-full text-[10px]",
                  isActive ? "bg-white/20" : "bg-slate-700"
                )}>{count}</span>
              </button>
            )
          })}
        </div>
      </div>

      {/* Findings List */}
      <ScrollArea className="flex-1">
        <div className="px-4 py-3">
          {loading ? (
            <div className="flex items-center justify-center h-32 text-slate-500">
              <div className="text-center">
                <div className="w-8 h-8 border-2 border-violet-500 border-t-transparent rounded-full animate-spin mx-auto mb-2" />
                <p className="text-sm">加载中...</p>
              </div>
            </div>
          ) : processedFindings.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-32 text-slate-600">
              <Shield className="w-12 h-12 mb-3 opacity-50" />
              <p className="text-sm">
                {findings.length === 0 ? "暂无漏洞发现" : "没有符合条件的结果"}
              </p>
            </div>
          ) : (
            <div className="space-y-2">
              {processedFindings.map((finding) => {
                const severityConfig = SEVERITY_CONFIG[finding.severity] || SEVERITY_CONFIG.info
                const statusConfig = STATUS_CONFIG[finding.status]
                const StatusIcon = statusConfig?.icon
                const SeverityIcon = severityConfig.icon
                const isExpanded = expandedIds.has(finding.id)

                return (
                  <div
                    key={finding.id}
                    className={cn(
                      "group rounded-xl border transition-all duration-200 overflow-hidden",
                      "bg-gradient-to-r " + severityConfig.bgGradient,
                      severityConfig.border
                    )}
                  >
                    {/* Header */}
                    <div
                      className="p-3 cursor-pointer hover:bg-white/5 transition-colors"
                      onClick={() => toggleExpand(finding.id)}
                    >
                      <div className="flex items-start gap-3">
                        {/* 严重程度图标 */}
                        <div className={cn(
                          "w-10 h-10 rounded-lg flex items-center justify-center shrink-0",
                          severityConfig.bgGradient.replace('from-', 'bg-').replace('/40', '/30')
                        )}>
                          <SeverityIcon className={cn("w-5 h-5", severityConfig.color)} />
                        </div>

                        {/* 主要信息 */}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-start justify-between gap-2 mb-1">
                            <h4 className={cn(
                              "font-semibold leading-snug",
                              severityConfig.color
                            )}>
                              {finding.title}
                            </h4>
                            <div className="flex items-center gap-1.5 shrink-0">
                              {/* 严重程度标签 */}
                              <Badge className={cn("text-[10px] px-2 py-0", severityConfig.badge)}>
                                {severityConfig.label}
                              </Badge>

                              {/* 状态标签 */}
                              {statusConfig && (
                                <Badge variant="outline" className={cn(
                                  "text-[10px] px-2 py-0 border",
                                  statusConfig.bg,
                                  statusConfig.color,
                                  statusConfig.bg.replace('/20', '/10') + " " + statusConfig.color.replace('text-', 'border-')
                                )}>
                                  <StatusIcon className="w-2.5 h-2.5 mr-1" />
                                  {statusConfig.label}
                                </Badge>
                              )}

                              {/* 展开/收起 */}
                              <button className="p-1 hover:bg-white/10 rounded transition-colors">
                                {isExpanded ? (
                                  <ChevronDown className="w-4 h-4 text-slate-500" />
                                ) : (
                                  <ChevronRight className="w-4 h-4 text-slate-500" />
                                )}
                              </button>
                            </div>
                          </div>

                          {/* 文件位置 */}
                          {finding.file_path && (
                            <div className="flex items-center gap-2 text-xs text-slate-500 mt-1">
                              <MapPin className="w-3 h-3" />
                              <span className="font-mono">{finding.file_path}</span>
                              {finding.line_start && (
                                <span>:<span className="text-slate-400">{finding.line_start}</span>
                                  {finding.line_end && <span>-{finding.line_end}</span>}
                                </span>
                              )}
                            </div>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* 展开的详情 */}
                    {isExpanded && (
                      <div className="px-3 pb-3 pt-0 border-t border-white/5">
                        <div className="mt-3 space-y-3">
                          {/* 描述 */}
                          {finding.description && (
                            <div className="p-3 rounded-lg bg-black/20 border border-white/5">
                              <h5 className="text-xs font-semibold text-slate-400 mb-1">描述</h5>
                              <p className="text-sm text-slate-300 leading-relaxed">{finding.description}</p>
                            </div>
                          )}

                          {/* 代码片段 */}
                          {finding.code_snippet && (
                            <details className="group/details">
                              <summary className="flex items-center gap-2 text-xs text-slate-500 cursor-pointer hover:text-slate-300 transition-colors">
                                <Eye className="w-3 h-3" />
                                代码片段
                              </summary>
                              <pre className="mt-2 text-xs bg-slate-950 p-3 rounded-lg overflow-x-auto border border-slate-800 text-slate-300">
                                {finding.code_snippet}
                              </pre>
                            </details>
                          )}

                          {/* 修复建议 */}
                          {finding.recommendation && (
                            <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-900/30">
                              <h5 className="text-xs font-semibold text-emerald-400 mb-1">修复建议</h5>
                              <p className="text-sm text-emerald-200/90 leading-relaxed">{finding.recommendation}</p>
                            </div>
                          )}

                          {/* 元数据 */}
                          <div className="grid grid-cols-2 gap-2 text-xs">
                            {finding.vulnerability_type && (
                              <div className="flex items-center gap-2 text-slate-500">
                                <span className="font-medium">类型:</span>
                                <span className="font-mono">{finding.vulnerability_type}</span>
                              </div>
                            )}
                            {finding.confidence && (
                              <div className="flex items-center gap-2 text-slate-500">
                                <span className="font-medium">置信度:</span>
                                <span>{Math.round(finding.confidence * 100)}%</span>
                              </div>
                            )}
                            <div className="flex items-center gap-2 text-slate-500">
                              <span className="font-medium">发现时间:</span>
                              <span>{new Date(finding.created_at).toLocaleString('zh-CN')}</span>
                            </div>
                            {finding.is_verified !== undefined && (
                              <div className="flex items-center gap-2 text-slate-500">
                                <span className="font-medium">验证状态:</span>
                                <span className={finding.is_verified ? "text-emerald-400" : "text-amber-400"}>
                                  {finding.is_verified ? "已验证" : "未验证"}
                                </span>
                              </div>
                            )}
                          </div>

                          {/* 操作按钮 */}
                          <div className="flex items-center gap-2 pt-2">
                            <Button
                              variant="outline"
                              size="sm"
                              className="h-7 text-xs"
                              onClick={(e) => {
                                e.stopPropagation()
                                toggleVisibility(finding.id)
                              }}
                            >
                              <EyeOff className="w-3 h-3 mr-1" />
                              隐藏
                            </Button>
                            <Button
                              variant="outline"
                              size="sm"
                              className="h-7 text-xs"
                              onClick={(e) => {
                                e.stopPropagation()
                                navigator.clipboard.writeText(JSON.stringify(finding, null, 2))
                              }}
                            >
                              <Copy className="w-3 h-3 mr-1" />
                              复制
                            </Button>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </ScrollArea>

      {/* 底部状态 */}
      <div className="h-8 px-4 flex items-center justify-between bg-slate-900/60 border-t border-slate-800/50 shrink-0 text-[10px] text-slate-500">
        <span>显示 {processedFindings.length} / {findings.length} 个结果</span>
        <span>按严重程度排序</span>
      </div>
    </div>
  )
}
