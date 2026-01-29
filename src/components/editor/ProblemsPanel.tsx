/**
 * ProblemsPanel - 问题面板组件
 *
 * 显示当前文件/所有文件的漏洞列表，支持跳转和状态过滤
 */

import { useState, useMemo } from 'react'
import { useEditorStore } from '@/stores/editorStore'
import { useFindingMarkerStore } from '@/stores/findingMarkerStore'
import type { Vulnerability } from '@/shared/types/agent'
import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  CheckCircle,
  XCircle,
  EyeOff,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'

type FilterStatus = 'all' | 'new' | 'fixed' | 'false_positive' | 'ignored' | 'verified'
type FilterSeverity = 'all' | 'critical' | 'high' | 'medium' | 'low' | 'info'
type ViewScope = 'current' | 'all'

export interface ProblemsPanelProps {
  onJumpToFinding?: (findingId: string) => void
}

export function ProblemsPanel({ onJumpToFinding }: ProblemsPanelProps) {
  const { editorGroups, activeGroupId } = useEditorStore()
  const {
    getAllFindings,
    markAsFixed,
    markAsFalsePositive,
    markAsIgnored,
    markAsVerified,
  } = useFindingMarkerStore()

  const [filterStatus, setFilterStatus] = useState<FilterStatus>('all')
  const [filterSeverity, setFilterSeverity] = useState<FilterSeverity>('all')
  const [viewScope, setViewScope] = useState<ViewScope>('current')
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set())

  // 获取当前活动的文件
  const currentFile = useMemo(() => {
    const activeGroup = editorGroups.find((g) => g.id === activeGroupId)
    return activeGroup?.activeFile
  }, [editorGroups, activeGroupId])

  // 获取漏洞列表
  const findings = useMemo(() => {
    const allFindings = getAllFindings()

    // 按严重程度过滤
    let filtered =
      filterSeverity === 'all'
        ? allFindings
        : allFindings.filter((f) => f.severity === filterSeverity)

    // 按状态过滤
    if (filterStatus !== 'all') {
      filtered = filtered.filter((f) => f.status === filterStatus)
    }

    // 按视图范围过滤
    if (viewScope === 'current' && currentFile) {
      return filtered.filter((f) => f.file_path === currentFile.path)
    }

    return filtered
  }, [getAllFindings, filterSeverity, filterStatus, viewScope, currentFile])

  // 按文件分组
  const findingsByFile = useMemo(() => {
    const groups = new Map<string, Vulnerability[]>()
    findings.forEach((finding) => {
      const filePath = finding.file_path
      if (!groups.has(filePath)) {
        groups.set(filePath, [])
      }
      groups.get(filePath)!.push(finding)
    })
    return groups
  }, [findings])

  // 按严重程度分组统计
  const severityStats = useMemo(() => {
    const stats = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    }
    findings.forEach((f) => {
      stats[f.severity]++
    })
    return stats
  }, [findings])

  // 切换分组展开
  const toggleGroup = (filePath: string) => {
    setExpandedGroups((prev) => {
      const newSet = new Set(prev)
      if (newSet.has(filePath)) {
        newSet.delete(filePath)
      } else {
        newSet.add(filePath)
      }
      return newSet
    })
  }

  // 跳转到漏洞
  const handleJumpToFinding = (findingId: string) => {
    onJumpToFinding?.(findingId)
  }

  // 处理状态更新
  const handleStatusUpdate = async (
    findingId: string,
    status: 'fixed' | 'false_positive' | 'ignored' | 'verified'
  ) => {
    switch (status) {
      case 'fixed':
        await markAsFixed(findingId)
        break
      case 'false_positive':
        await markAsFalsePositive(findingId)
        break
      case 'ignored':
        await markAsIgnored(findingId)
        break
      case 'verified':
        await markAsVerified(findingId)
        break
    }
  }

  const severityOrder = ['critical', 'high', 'medium', 'low', 'info']

  return (
    <div className="flex flex-col h-full bg-[#1e1e1e]">
      {/* 工具栏 */}
      <div className="flex items-center gap-2 px-3 py-2 bg-[#252526] border-b border-border/40">
        {/* 视图范围 */}
        <div className="flex items-center gap-1">
          <Button
            variant={viewScope === 'current' ? 'secondary' : 'ghost'}
            size="sm"
            className="h-7 text-xs"
            onClick={() => setViewScope('current')}
          >
            当前文件
          </Button>
          <Button
            variant={viewScope === 'all' ? 'secondary' : 'ghost'}
            size="sm"
            className="h-7 text-xs"
            onClick={() => setViewScope('all')}
          >
            全部文件
          </Button>
        </div>

        {/* 统计 */}
        <div className="flex items-center gap-2 ml-auto text-xs">
          {severityOrder.map((severity) => {
            const count = severityStats[severity as keyof typeof severityStats]
            if (count === 0) return null
            return (
              <div
                key={severity}
                className={cn(
                  'flex items-center gap-1 px-2 py-0.5 rounded',
                  severity === 'critical' && 'bg-red-500/20 text-red-400',
                  severity === 'high' && 'bg-orange-500/20 text-orange-400',
                  severity === 'medium' && 'bg-yellow-500/20 text-yellow-400',
                  severity === 'low' && 'bg-blue-500/20 text-blue-400',
                  severity === 'info' && 'bg-gray-500/20 text-gray-400'
                )}
              >
                <AlertTriangle className="w-3 h-3" />
                <span>{count}</span>
              </div>
            )
          })}
        </div>
      </div>

      {/* 过滤器 */}
      <div className="flex items-center gap-2 px-3 py-1.5 bg-[#1e1e1e] border-b border-border/20">
        <select
          value={filterSeverity}
          onChange={(e) => setFilterSeverity(e.target.value as FilterSeverity)}
          className="bg-[#252526] text-xs text-white border border-border/40 rounded px-2 py-1 focus:outline-none focus:border-[#007acc]"
        >
          <option value="all">所有严重程度</option>
          <option value="critical">严重</option>
          <option value="high">高</option>
          <option value="medium">中</option>
          <option value="low">低</option>
          <option value="info">信息</option>
        </select>

        <select
          value={filterStatus}
          onChange={(e) => setFilterStatus(e.target.value as FilterStatus)}
          className="bg-[#252526] text-xs text-white border border-border/40 rounded px-2 py-1 focus:outline-none focus:border-[#007acc]"
        >
          <option value="all">所有状态</option>
          <option value="new">新发现</option>
          <option value="verified">已验证</option>
          <option value="fixed">已修复</option>
          <option value="false_positive">误报</option>
          <option value="ignored">已忽略</option>
        </select>
      </div>

      {/* 漏洞列表 */}
      <div className="flex-1 overflow-auto">
        {findingsByFile.size === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-muted-foreground">
            <CheckCircle className="w-12 h-12 mb-3 opacity-20" />
            <p className="text-sm">没有发现漏洞</p>
            <p className="text-xs opacity-60 mt-1">
              {filterSeverity !== 'all' || filterStatus !== 'all'
                ? '尝试调整过滤条件'
                : '代码安全，继续保持！'}
            </p>
          </div>
        ) : (
          <div className="divide-y divide-border/20">
            {Array.from(findingsByFile.entries()).map(([filePath, fileFindings]) => {
              const fileName = filePath.split('/').pop() || filePath
              const isExpanded = expandedGroups.has(filePath)

              // 按严重程度排序
              const sortedFindings = [...fileFindings].sort(
                (a, b) =>
                  severityOrder.indexOf(a.severity) -
                  severityOrder.indexOf(b.severity)
              )

              return (
                <div key={filePath}>
                  {/* 文件组头 */}
                  <button
                    onClick={() => toggleGroup(filePath)}
                    className="w-full flex items-center gap-2 px-3 py-2 hover:bg-[#252526] transition-colors"
                  >
                    {isExpanded ? (
                      <ChevronDown className="w-4 h-4 text-muted-foreground" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-muted-foreground" />
                    )}
                    <span className="text-sm text-white flex-1 text-left">
                      {fileName}
                    </span>
                    <span className="text-xs text-muted-foreground">
                      {fileFindings.length} 个问题
                    </span>
                  </button>

                  {/* 漏洞列表 */}
                  {isExpanded && (
                    <div className="pl-6 divide-y divide-border/10">
                      {sortedFindings.map((finding) => (
                        <FindingItem
                          key={finding.id}
                          finding={finding}
                          onJump={() => handleJumpToFinding(finding.id)}
                          onStatusUpdate={handleStatusUpdate}
                        />
                      ))}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}

// ==================== 漏洞项组件 ====================

interface FindingItemProps {
  finding: Vulnerability
  onJump: () => void
  onStatusUpdate: (
    findingId: string,
    status: 'fixed' | 'false_positive' | 'ignored' | 'verified'
  ) => Promise<void>
}

function FindingItem({ finding, onJump, onStatusUpdate }: FindingItemProps) {
  const [showActions, setShowActions] = useState(false)

  const severityColors = {
    critical: 'bg-red-500',
    high: 'bg-orange-500',
    medium: 'bg-yellow-500',
    low: 'bg-blue-500',
    info: 'bg-gray-500',
  }

  const statusIcons = {
    new: null,
    verified: <CheckCircle className="w-3 h-3 text-green-500" />,
    fixed: <CheckCircle className="w-3 h-3 text-gray-500" />,
    false_positive: <XCircle className="w-3 h-3 text-gray-500" />,
    ignored: <EyeOff className="w-3 h-3 text-gray-500" />,
  }

  return (
    <div
      className="flex items-start gap-2 px-3 py-2 hover:bg-[#2d2d2d] group transition-colors"
      onMouseEnter={() => setShowActions(true)}
      onMouseLeave={() => setShowActions(false)}
    >
      {/* 严重程度指示器 */}
      <div className={cn('w-1 rounded-full', severityColors[finding.severity])} />

      {/* 内容 */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <button
            onClick={onJump}
            className="text-sm text-white hover:text-[#007acc] truncate flex-1 text-left"
          >
            {finding.title || finding.vulnerability_type}
          </button>
          {statusIcons[finding.status || 'new']}
        </div>
        <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
          <span>行 {finding.line_number}</span>
          <span>·</span>
          <span className="truncate">{finding.vulnerability_type}</span>
        </div>
      </div>

      {/* 快速操作 */}
      {showActions && (
        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6 p-0"
            title="标记为已修复"
            onClick={() => onStatusUpdate(finding.id, 'fixed')}
          >
            <CheckCircle className="w-3.5 h-3.5 text-green-500" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6 p-0"
            title="标记为误报"
            onClick={() => onStatusUpdate(finding.id, 'false_positive')}
          >
            <XCircle className="w-3.5 h-3.5 text-gray-500" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6 p-0"
            title="忽略"
            onClick={() => onStatusUpdate(finding.id, 'ignored')}
          >
            <EyeOff className="w-3.5 h-3.5 text-gray-500" />
          </Button>
        </div>
      )}
    </div>
  )
}
