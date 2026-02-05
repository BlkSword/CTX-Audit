/**
 * ScanResultsPanel - 扫描结果面板
 *
 * VSCode 风格的扫描结果展示
 * 支持按严重程度、状态过滤
 * 显示项目级别的所有扫描发现
 */

import { useState, useEffect } from 'react'
import { AlertTriangle, CheckCircle, RefreshCw } from 'lucide-react'
import { useProjectStore } from '@/stores/projectStore'
import { useScanStore } from '@/stores/scanStore'
import { cn } from '@/lib/utils'
import type { Vulnerability } from '@/shared/types'

// ==================== 类型定义 ====================

type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low' | 'info'

// ==================== 辅助函数 ====================

function getSeverityColor(severity: string): string {
  const colors = {
    critical: 'text-[#f14c4c]',
    high: 'text-[#f14c4c]',
    medium: 'text-[var(--vscode-warningForeground)]',
    low: 'text-[#3794ff]',
    info: 'text-[var(--vscode-textLink-foreground)]',
  }
  return colors[severity as keyof typeof colors] || colors.info
}

function getSeverityBg(severity: string): string {
  const colors = {
    critical: 'bg-[#f14c4c15]',
    high: 'bg-[#f14c4c15]',
    medium: 'bg-[var(--vscode-warningForeground)]/15',
    low: 'bg-[#3794ff]/15',
    info: 'bg-[var(--vscode-textLink-foreground)]/15',
  }
  return colors[severity as keyof typeof colors] || colors.info
}

// ==================== 主组件 ====================

export function ScanResultsPanel() {
  const { currentProject } = useProjectStore()
  const { vulnerabilities: findings, loadFindings, isLoading } = useScanStore()

  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all')

  // 加载扫描结果
  useEffect(() => {
    if (currentProject) {
      loadFindings(currentProject.id)
    }
  }, [currentProject, loadFindings])

  // 过滤结果 - 只按严重程度过滤
  const filteredFindings = findings.filter((f: Vulnerability) => {
    return severityFilter === 'all' || f.severity === severityFilter
  })

  // 统计
  const stats = findings.reduce((acc, f) => {
    acc.total++
    acc.bySeverity[f.severity as keyof typeof acc.bySeverity]++
    return acc
  }, {
    total: 0,
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  })

  return (
    <div className="flex flex-col h-full bg-[var(--vscode-sideBar-background)]">
      {/* 头部 */}
      <div className="flex items-center justify-between px-3 py-2 border-b border-[var(--vscode-sideBar-border)]">
        <div className="flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-[var(--vscode-textLink-foreground)]" />
          <span className="text-sm font-medium text-[var(--vscode-foreground)]">扫描结果</span>
          <span className="text-xs text-[var(--vscode-descriptionForeground)]">
            ({filteredFindings.length}/{findings.length})
          </span>
        </div>
        <button
          onClick={() => currentProject && loadFindings(currentProject.id)}
          disabled={isLoading}
          className="h-6 w-6 flex items-center justify-center rounded text-[var(--vscode-activityBar-inactiveForeground)] hover:text-[var(--vscode-activityBar-foreground)] hover:bg-[var(--vscode-toolbar-hoverBackground)] disabled:opacity-50 transition-colors"
          title="刷新"
        >
          <RefreshCw className={cn("w-3.5 h-3.5", isLoading && "animate-spin")} />
        </button>
      </div>

      {/* 统计卡片 */}
      <div className="px-3 py-2 border-b border-[var(--vscode-sideBar-border)]">
        <div className="grid grid-cols-5 gap-1">
          {[
            { severity: 'critical', count: stats.bySeverity.critical, color: 'text-[#f14c4c]' },
            { severity: 'high', count: stats.bySeverity.high, color: 'text-[#f14c4c]' },
            { severity: 'medium', count: stats.bySeverity.medium, color: 'text-[var(--vscode-warningForeground)]' },
            { severity: 'low', count: stats.bySeverity.low, color: 'text-[#3794ff]' },
            { severity: 'info', count: stats.bySeverity.info, color: 'text-[var(--vscode-textLink-foreground)]' },
          ].map(({ severity, count, color }) => (
            <button
              key={severity}
              onClick={() => setSeverityFilter(severity === severityFilter ? 'all' : severity as SeverityFilter)}
              className={cn(
                "flex flex-col items-center justify-center p-1.5 rounded text-xs transition-colors",
                severityFilter === severity ? "bg-[var(--vscode-list-hoverBackground)]" : "hover:bg-[var(--vscode-toolbar-hoverBackground)]"
              )}
            >
              <span className={cn("text-lg font-semibold", color)}>{count}</span>
              <span className="text-[10px] text-[var(--vscode-descriptionForeground)] capitalize">{severity}</span>
            </button>
          ))}
        </div>
      </div>

      {/* 过滤器 - 移除状态过滤，Vulnerability 类型没有 status 字段 */}

      {/* 结果列表 */}
      <div className="flex-1 overflow-auto">
        {!currentProject ? (
          <div className="flex flex-col items-center justify-center h-full text-[var(--vscode-descriptionForeground)] p-4">
            <AlertTriangle className="w-8 h-8 mb-2 opacity-50" />
            <p className="text-xs text-center">请先打开一个项目</p>
          </div>
        ) : isLoading ? (
          <div className="flex items-center justify-center h-full">
            <RefreshCw className="w-6 h-6 animate-spin text-[var(--vscode-textLink-foreground)]" />
          </div>
        ) : filteredFindings.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-[var(--vscode-descriptionForeground)] p-4">
            <CheckCircle className="w-8 h-8 mb-2 opacity-50 text-[var(--vscode-testing-iconPassed)]" />
            <p className="text-xs text-center">未发现安全问题</p>
            <p className="text-[10px] mt-1">
              {findings.length === 0 ? '点击上方"扫描"按钮开始扫描' : '尝试调整过滤条件'}
            </p>
          </div>
        ) : (
          <div className="divide-y divide-[var(--vscode-sideBar-border)]/50">
            {filteredFindings.map((finding) => (
              <div
                key={finding.id}
                className="p-3 hover:bg-[var(--vscode-list-hoverBackground)] transition-colors"
              >
                {/* 头部 */}
                <div className="flex items-start justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2 flex-1 min-w-0">
                    {/* 严重程度标签 */}
                    <span className={cn(
                      "px-1.5 py-0.5 rounded text-xs font-semibold uppercase shrink-0",
                      getSeverityBg(finding.severity),
                      getSeverityColor(finding.severity)
                    )}>
                      {finding.severity}
                    </span>

                    {/* 检测器 */}
                    <span className="text-xs text-[var(--vscode-descriptionForeground)] truncate">
                      {finding.detector}
                    </span>

                    {/* 文件名 */}
                    <span className="text-xs text-[var(--vscode-descriptionForeground)] truncate">
                      {finding.file_path.split('/').pop()}
                    </span>

                    {/* 行号 */}
                    <span className="text-xs text-[var(--vscode-descriptionForeground)] shrink-0">
                      Ln {finding.line_start}
                    </span>
                  </div>

                  {/* 验证状态 - 如果有 verification 字段 */}
                  {finding.verification?.verified && (
                    <CheckCircle className="w-4 h-4 text-[var(--vscode-testing-iconPassed)]" />
                  )}
                </div>

                {/* 描述 */}
                <p className="text-xs text-[var(--vscode-foreground)] mb-2 line-clamp-2">
                  {finding.description}
                </p>

                {/* 代码片段 */}
                {finding.code_snippet && (
                  <pre className="text-xs bg-[var(--vscode-textBlockQuote-background)] text-[var(--vscode-textBlockQuote-foreground)] p-2 rounded mb-2 overflow-x-auto">
                    <code>{finding.code_snippet.slice(0, 200)}{finding.code_snippet.length > 200 ? '...' : ''}</code>
                  </pre>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
