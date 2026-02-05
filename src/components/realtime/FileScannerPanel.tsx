/**
 * FileScannerPanel - VSCode 风格文件扫描面板
 *
 * 提供单文件扫描、结果展示、漏洞状态管理功能
 */

import { useState, useEffect } from 'react'
import { Scan, CheckCircle, XCircle, AlertCircle, RefreshCw, FileCode, Filter } from 'lucide-react'
import { useRealtimeAuditStore } from '@/stores/realTimeAuditStore'
import { useEditorStore } from '@/stores/editorStore'
import { cn } from '@/lib/utils'

// ==================== 类型定义 ====================

type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low' | 'info'
type StatusFilter = 'all' | 'open' | 'resolved' | 'ignored'

interface FindingDisplay {
  id: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  status: 'open' | 'resolved' | 'ignored'
  detector: string
  description: string
  lineStart: number
  lineEnd?: number
  codeSnippet?: string
}

// ==================== 组件 ====================

export function FileScannerPanel() {
  const {
    autoMode,
    setAutoMode,
    scanQueue,
    triggerScan,
    updateFindingStatus,
    currentProjectId,
    projectStats,
    loadProjectStats,
  } = useRealtimeAuditStore()

  const { editorGroups } = useEditorStore()

  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all')
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all')
  const [isScanning, setIsScanning] = useState(false)

  // 获取当前活动的文件
  const activeFile = editorGroups[0]?.activeFile

  // 获取当前文件的扫描结果
  const currentScanResult = activeFile ? scanQueue.get(activeFile.path) : undefined

  // 过滤后的漏洞列表
  const filteredFindings = currentScanResult?.findings
    .filter(f => severityFilter === 'all' || f.severity === severityFilter)
    .filter(f => statusFilter === 'all' || f.status === statusFilter) || []

  // 加载项目统计
  useEffect(() => {
    if (currentProjectId) {
      loadProjectStats()
    }
  }, [currentProjectId, loadProjectStats])

  // 扫描当前文件
  const handleScanFile = async () => {
    if (!activeFile) return

    setIsScanning(true)
    try {
      await triggerScan(activeFile.path, activeFile.content)
    } finally {
      setIsScanning(false)
    }
  }

  // 更新漏洞状态
  const handleUpdateStatus = async (findingId: string, status: 'open' | 'resolved' | 'ignored') => {
    await updateFindingStatus(findingId, status)
  }

  // 获取严重程度颜色
  const getSeverityColor = (severity: string) => {
    const colors = {
      critical: 'text-[var(--vscode-errorForeground)]',
      high: 'text-[#f14c4c]',
      medium: 'text-[var(--vscode-warningForeground)]',
      low: 'text-[#3794ff]',
      info: 'text-[var(--vscode-textLink-foreground)]',
    }
    return colors[severity as keyof typeof colors] || colors.info
  }

  // 获取严重程度背景
  const getSeverityBg = (severity: string) => {
    const colors = {
      critical: 'bg-[#f14c4c15]',
      high: 'bg-[#f14c4c15]',
      medium: 'bg-[var(--vscode-warningForeground)]/15',
      low: 'bg-[#3794ff]/15',
      info: 'bg-[var(--vscode-textLink-foreground)]/15',
    }
    return colors[severity as keyof typeof colors] || colors.info
  }

  return (
    <div className="flex flex-col h-full bg-[var(--vscode-sideBar-background)]">
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2 border-b border-[var(--vscode-sideBar-border)]">
        <div className="flex items-center gap-2">
          <Scan className="w-4 h-4 text-[var(--vscode-textLink-foreground)]" />
          <span className="text-sm font-medium text-[var(--vscode-sideBar-foreground)]">
            文件扫描
          </span>
        </div>
        <div className="flex items-center gap-2">
          {/* 自动模式开关 */}
          <button
            onClick={() => setAutoMode(!autoMode)}
            className={cn(
              "flex items-center gap-1.5 px-2 py-1 rounded text-xs transition-all",
              autoMode
                ? "bg-[var(--vscode-button-background)] text-[var(--vscode-button-foreground)]"
                : "bg-[var(--vscode-button-secondaryBackground)] text-[var(--vscode-button-secondaryForeground)]"
            )}
          >
            <span className="relative flex h-3 w-4">
              <span className={cn(
                "animate-ping absolute inline-flex h-full w-full rounded-full opacity-75",
                autoMode ? "bg-green-400" : "bg-gray-400"
              )} />
              <span className={cn(
                "relative inline-flex rounded-full h-3 w-3",
                autoMode ? "bg-green-500" : "bg-gray-500"
              )} />
            </span>
            自动模式
          </button>
        </div>
      </div>

      {/* 文件信息 */}
      {activeFile && (
        <div className="px-3 py-2 border-b border-[var(--vscode-sideBar-border)] bg-[var(--vscode-editor-background)]">
          <div className="flex items-center gap-2 text-sm">
            <FileCode className="w-4 h-4 text-[var(--vscode-descriptionForeground)]" />
            <span className="text-[var(--vscode-sideBar-foreground)] font-medium">
              {activeFile.name}
            </span>
            <span className="text-[var(--vscode-descriptionForeground)] text-xs truncate">
              {activeFile.path}
            </span>
          </div>
        </div>
      )}

      {/* 操作栏 */}
      <div className="flex items-center gap-2 px-3 py-2 border-b border-[var(--vscode-sideBar-border)]">
        <button
          onClick={handleScanFile}
          disabled={!activeFile || isScanning}
          className="flex items-center gap-1 px-3 py-1 text-xs rounded bg-[var(--vscode-button-background)] text-[var(--vscode-button-foreground)] hover:bg-[var(--vscode-button-hoverBackground)] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {isScanning ? (
            <>
              <RefreshCw className="w-3 h-3 animate-spin" />
              扫描中...
            </>
          ) : (
            <>
              <Scan className="w-3 h-3" />
              扫描文件
            </>
          )}
        </button>

        {/* 严重程度过滤器 */}
        <div className="flex items-center gap-1 ml-auto">
          <Filter className="w-3 h-3 text-[var(--vscode-descriptionForeground)]" />
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value as SeverityFilter)}
            className="bg-[var(--vscode-input-background)] text-[var(--vscode-input-foreground)] text-xs px-2 py-1 rounded border border-[var(--vscode-input-border)] focus:outline-none focus:border-[var(--vscode-focusBorder)]"
          >
            <option value="all">全部严重程度</option>
            <option value="critical">严重</option>
            <option value="high">高</option>
            <option value="medium">中</option>
            <option value="low">低</option>
            <option value="info">信息</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as StatusFilter)}
            className="bg-[var(--vscode-input-background)] text-[var(--vscode-input-foreground)] text-xs px-2 py-1 rounded border border-[var(--vscode-input-border)] focus:outline-none focus:border-[var(--vscode-focusBorder)]"
          >
            <option value="all">全部状态</option>
            <option value="open">待处理</option>
            <option value="resolved">已修复</option>
            <option value="ignored">已忽略</option>
          </select>
        </div>
      </div>

      {/* 扫描状态 */}
      {currentScanResult && (
        <div className="px-3 py-2 border-b border-[var(--vscode-sideBar-border)]">
          <div className="flex items-center gap-2 text-xs">
            {currentScanResult.status === 'scanning' && (
              <>
                <RefreshCw className="w-3 h-3 animate-spin text-[var(--vscode-textLink-foreground)]" />
                <span className="text-[var(--vscode-sideBar-foreground)]">正在扫描...</span>
              </>
            )}
            {currentScanResult.status === 'completed' && (
              <>
                <CheckCircle className="w-3 h-3 text-[var(--vscode-testing-iconPassed)]" />
                <span className="text-[var(--vscode-sideBar-foreground)]">
                  扫描完成 - 发现 {filteredFindings.length} 个问题
                  {currentScanResult.cached && (
                    <span className="text-[var(--vscode-descriptionForeground)] ml-2">
                      (来自缓存)
                    </span>
                  )}
                </span>
              </>
            )}
            {currentScanResult.status === 'error' && (
              <>
                <XCircle className="w-3 h-3 text-[var(--vscode-errorForeground)]" />
                <span className="text-[var(--vscode-errorForeground)]">
                  扫描失败: {currentScanResult.error}
                </span>
              </>
            )}
            {currentScanResult.status === 'idle' && (
              <>
                <AlertCircle className="w-3 h-3 text-[var(--vscode-descriptionForeground)]" />
                <span className="text-[var(--vscode-descriptionForeground)]">
                  等待扫描...
                </span>
              </>
            )}
          </div>
        </div>
      )}

      {/* 漏洞列表 */}
      <div className="flex-1 overflow-auto">
        {!activeFile ? (
          <div className="flex flex-col items-center justify-center h-full text-[var(--vscode-descriptionForeground)]">
            <FileCode className="w-12 h-12 mb-3 opacity-50" />
            <p className="text-sm">请先打开一个文件</p>
          </div>
        ) : filteredFindings.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-[var(--vscode-descriptionForeground)]">
            <CheckCircle className="w-12 h-12 mb-3 opacity-50 text-[var(--vscode-testing-iconPassed)]" />
            <p className="text-sm">未发现安全问题</p>
            {currentScanResult && (
              <p className="text-xs mt-1">
                {currentScanResult.status === 'idle' ? '点击"扫描文件"开始' : '扫描已完成'}
              </p>
            )}
          </div>
        ) : (
          <div className="divide-y divide-[var(--vscode-sideBar-border)]">
            {filteredFindings.map((finding) => (
              <div
                key={finding.id}
                className={cn(
                  "p-3 hover:bg-[var(--vscode-list-hoverBackground)] transition-colors",
                  finding.status === 'resolved' && "opacity-50",
                  finding.status === 'ignored' && "opacity-30"
                )}
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

                    {/* 行号 */}
                    {finding.line_start && (
                      <span className="text-xs text-[var(--vscode-descriptionForeground)] shrink-0">
                        Ln {finding.line_start}
                        {finding.line_end && finding.line_end > finding.line_start && (
                          <>-{finding.line_end}</>
                        )}
                      </span>
                    )}
                  </div>

                  {/* 状态指示器 */}
                  {finding.status === 'open' && (
                    <AlertCircle className="w-4 h-4 text-[var(--vscode-warningForeground)] shrink-0" />
                  )}
                  {finding.status === 'resolved' && (
                    <CheckCircle className="w-4 h-4 text-[var(--vscode-testing-iconPassed)] shrink-0" />
                  )}
                  {finding.status === 'ignored' && (
                    <XCircle className="w-4 h-4 text-[var(--vscode-descriptionForeground)] shrink-0" />
                  )}
                </div>

                {/* 描述 */}
                <p className="text-sm text-[var(--vscode-sideBar-foreground)] mb-2">
                  {finding.description}
                </p>

                {/* 代码片段 */}
                {finding.code_snippet && (
                  <pre className="text-xs bg-[var(--vscode-textBlockQuote-background)] text-[var(--vscode-textBlockQuote-foreground)] p-2 rounded mb-2 overflow-x-auto">
                    <code>{finding.code_snippet}</code>
                  </pre>
                )}

                {/* 操作按钮 */}
                <div className="flex items-center gap-2">
                  {finding.status === 'open' ? (
                    <>
                      <button
                        onClick={() => handleUpdateStatus(finding.id, 'resolved')}
                        className="flex items-center gap-1 px-2 py-1 text-xs rounded border border-[var(--vscode-input-border)] bg-[var(--vscode-editor-background)] text-[var(--vscode-foreground)] hover:bg-[var(--vscode-toolbar-hoverBackground)] transition-colors"
                      >
                        <CheckCircle className="w-3 h-3" />
                        已修复
                      </button>
                      <button
                        onClick={() => handleUpdateStatus(finding.id, 'ignored')}
                        className="flex items-center gap-1 px-2 py-1 text-xs rounded bg-transparent text-[var(--vscode-foreground)] hover:bg-[var(--vscode-toolbar-hoverBackground)] transition-colors"
                      >
                        <XCircle className="w-3 h-3" />
                        忽略
                      </button>
                    </>
                  ) : (
                    <button
                      onClick={() => handleUpdateStatus(finding.id, 'open')}
                      className="flex items-center gap-1 px-2 py-1 text-xs rounded bg-transparent text-[var(--vscode-foreground)] hover:bg-[var(--vscode-toolbar-hoverBackground)] transition-colors"
                    >
                      <RefreshCw className="w-3 h-3" />
                      重新打开
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 项目统计 */}
      {projectStats && (
        <div className="border-t border-[var(--vscode-sideBar-border)] bg-[var(--vscode-editor-background)]">
          <div className="px-3 py-2">
            <div className="text-xs text-[var(--vscode-descriptionForeground)] mb-2">
              项目统计
            </div>
            <div className="grid grid-cols-5 gap-2 text-center">
              <div>
                <div className="text-lg font-semibold text-[var(--vscode-errorForeground)]">
                  {projectStats.by_severity.critical}
                </div>
                <div className="text-[10px] text-[var(--vscode-descriptionForeground)]">严重</div>
              </div>
              <div>
                <div className="text-lg font-semibold text-[#f14c4c]">
                  {projectStats.by_severity.high}
                </div>
                <div className="text-[10px] text-[var(--vscode-descriptionForeground)]">高</div>
              </div>
              <div>
                <div className="text-lg font-semibold text-[var(--vscode-warningForeground)]">
                  {projectStats.by_severity.medium}
                </div>
                <div className="text-[10px] text-[var(--vscode-descriptionForeground)]">中</div>
              </div>
              <div>
                <div className="text-lg font-semibold text-[#3794ff]">
                  {projectStats.by_severity.low}
                </div>
                <div className="text-[10px] text-[var(--vscode-descriptionForeground)]">低</div>
              </div>
              <div>
                <div className="text-lg font-semibold text-[var(--vscode-textLink-foreground)]">
                  {projectStats.by_severity.info}
                </div>
                <div className="text-[10px] text-[var(--vscode-descriptionForeground)]">信息</div>
              </div>
            </div>
            <div className="mt-2 pt-2 border-t border-[var(--vscode-sideBar-border)] flex justify-between text-xs text-[var(--vscode-descriptionForeground)]">
              <span>总计 {projectStats.total_files} 个文件</span>
              <span>{projectStats.total_findings} 个问题</span>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
