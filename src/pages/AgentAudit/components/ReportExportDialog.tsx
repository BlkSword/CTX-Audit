/**
 * 增强版报告导出对话框组件
 * 支持 Markdown、JSON、HTML 格式导出
 * 包含实时预览和搜索功能
 */

import { useState, useEffect, useCallback, useMemo } from "react"
import {
  Dialog,
  DialogContent,
  DialogTitle,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  FileText,
  FileJson,
  Code,
  Download,
  Loader2,
  Check,
  FileDown,
  Bug,
  Clock,
  Search,
  RefreshCw,
  Eye,
  EyeOff,
} from "lucide-react"
import { cn } from "@/lib/utils"
import type { AgentFinding } from "../types"

// ============ Types ============

type ReportFormat = "markdown" | "json" | "html"

interface ReportExportDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  auditId: string
  findings: AgentFinding[]
  task?: any
}

// ============ Constants ============

const FORMAT_CONFIG: Record<ReportFormat, {
  label: string
  description: string
  icon: React.ReactNode
  extension: string
  mime: string
  color: string
  bgColor: string
  borderColor: string
}> = {
  markdown: {
    label: "Markdown",
    description: "可编辑文档格式，便于版本控制",
    icon: <FileText className="w-5 h-5" />,
    extension: ".md",
    mime: "text/markdown",
    color: "text-sky-400",
    bgColor: "bg-sky-950/30",
    borderColor: "border-sky-500/30",
  },
  json: {
    label: "JSON",
    description: "结构化数据格式，适合程序处理",
    icon: <FileJson className="w-5 h-5" />,
    extension: ".json",
    mime: "application/json",
    color: "text-amber-400",
    bgColor: "bg-amber-950/30",
    borderColor: "border-amber-500/30",
  },
  html: {
    label: "HTML",
    description: "网页格式，可在浏览器中查看",
    icon: <Code className="w-5 h-5" />,
    extension: ".html",
    mime: "text/html",
    color: "text-emerald-400",
    bgColor: "bg-emerald-950/30",
    borderColor: "border-emerald-500/30",
  },
}

// ============ Helper Functions ============

function getSeverityColor(severity: string): string {
  const colors: Record<string, string> = {
    critical: "text-rose-400",
    high: "text-orange-400",
    medium: "text-amber-400",
    low: "text-sky-400",
    info: "text-slate-400",
  }
  return colors[severity.toLowerCase()] || colors.info
}

function getScoreColor(score: number): { text: string; bg: string } {
  if (score >= 80) return { text: "text-emerald-400", bg: "bg-emerald-500" }
  if (score >= 60) return { text: "text-amber-400", bg: "bg-amber-500" }
  if (score >= 40) return { text: "text-orange-400", bg: "bg-orange-500" }
  return { text: "text-rose-400", bg: "bg-rose-500" }
}

// 计算安全评分
function calculateScore(findings: AgentFinding[]): number {
  const criticalCount = findings.filter(f => f.severity === "critical").length
  const highCount = findings.filter(f => f.severity === "high").length
  const mediumCount = findings.filter(f => f.severity === "medium").length
  const lowCount = findings.filter(f => f.severity === "low").length

  const score = 100 - criticalCount * 25 - highCount * 10 - mediumCount * 5 - lowCount * 2
  return Math.max(0, score)
}

// ============ Sub Components ============

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
    <div className="flex items-center gap-3 p-3 rounded-lg bg-slate-900/50 border border-slate-800">
      <div className={cn("p-2 rounded-lg", bgColor)}>
        <Icon className={cn("w-4 h-4", color)} />
      </div>
      <div>
        <div className="text-xs text-slate-500 uppercase tracking-wide">{label}</div>
        <div className={cn("text-lg font-bold", color)}>{value}</div>
      </div>
    </div>
  )
}

// 格式选择器
function FormatSelector({
  activeFormat,
  onFormatChange,
}: {
  activeFormat: ReportFormat
  onFormatChange: (format: ReportFormat) => void
}) {
  return (
    <div className="grid grid-cols-3 gap-2">
      {(Object.keys(FORMAT_CONFIG) as ReportFormat[]).map((format) => {
        const config = FORMAT_CONFIG[format]
        const isActive = format === activeFormat

        return (
          <button
            key={format}
            onClick={() => onFormatChange(format)}
            className={cn(
              "relative p-3 rounded-lg border transition-all text-left",
              isActive
                ? `${config.bgColor} ${config.borderColor}`
                : "bg-slate-900/50 border-slate-800 hover:border-slate-700"
            )}
          >
            {isActive && (
              <div className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-emerald-500 flex items-center justify-center">
                <Check className="w-3 h-3 text-white" />
              </div>
            )}

            <div className={cn("mb-2", isActive ? config.color : "text-slate-500")}>
              {config.icon}
            </div>

            <div className={cn("text-xs font-semibold", isActive ? "text-slate-200" : "text-slate-400")}>
              {config.label}
            </div>
            <div className="text-[10px] text-slate-600 mt-0.5">
              {config.description}
            </div>
          </button>
        )
      })}
    </div>
  )
}

// Markdown 预览组件
function MarkdownPreview({
  content,
  searchQuery = "",
}: {
  content: string
  searchQuery?: string
}) {
  const highlightText = (text: string) => {
    if (!searchQuery) return text

    const regex = new RegExp(`(${searchQuery})`, 'gi')
    return text.replace(regex, '<mark class="bg-amber-500/50 text-slate-900 rounded px-0.5">$1</mark>')
  }

  const formatContent = useCallback((text: string) => {
    // 简单的 Markdown 格式化
    let formatted = text

    // 代码块
    formatted = formatted.replace(/```(\w*)\n([\s\S]*?)```/g, '<pre class="bg-slate-900 p-3 rounded-lg overflow-x-auto my-2"><code>$2</code></pre>')

    // 标题
    formatted = formatted.replace(/^### (.*$)/gm, '<h3 class="text-base font-bold text-slate-200 mt-4 mb-2">$1</h3>')
    formatted = formatted.replace(/^## (.*$)/gm, '<h2 class="text-lg font-bold text-slate-200 mt-6 mb-3">$1</h2>')
    formatted = formatted.replace(/^# (.*$)/gm, '<h1 class="text-xl font-bold text-slate-200 mt-6 mb-4">$1</h1>')

    // 粗体
    formatted = formatted.replace(/\*\*(.*?)\*\*/g, '<strong class="text-slate-200">$1</strong>')

    // 代码
    formatted = formatted.replace(/`([^`]+)`/g, '<code class="bg-slate-800 px-1.5 py-0.5 rounded text-amber-400 text-sm">$1</code>')

    // 分隔线
    formatted = formatted.replace(/^---$/gm, '<hr class="border-slate-800 my-4">')

    // 段落
    formatted = formatted.split('\n\n').map(para => {
      if (para.startsWith('<') || para.startsWith('#')) return para
      return `<p class="text-slate-400 my-2 leading-relaxed">${highlightText(para)}</p>`
    }).join('\n')

    return formatted
  }, [searchQuery])

  return (
    <div
      className="text-sm leading-relaxed prose prose-invert max-w-none"
      dangerouslySetInnerHTML={{ __html: formatContent(content) }}
    />
  )
}

// JSON 预览组件
function JsonPreview({
  content,
  searchQuery = "",
}: {
  content: string
  searchQuery?: string
}) {
  const [json, setJson] = useState<any>(null)
  const [error, setError] = useState<string>("")

  useEffect(() => {
    try {
      const parsed = JSON.parse(content)
      setJson(parsed)
      setError("")
    } catch (e) {
      setError("无效的 JSON 格式")
    }
  }, [content])

  if (error) {
    return <div className="text-rose-400 text-sm">{error}</div>
  }

  const highlightJson = (obj: any, indent = 0): string => {
    if (obj === null) return 'null'
    if (typeof obj === 'boolean') return obj ? 'true' : 'false'
    if (typeof obj === 'number') return obj.toString()
    if (typeof obj === 'string') {
      const highlighted = searchQuery && obj.toLowerCase().includes(searchQuery.toLowerCase())
        ? `<mark class="bg-amber-500/50 text-slate-900 rounded px-0.5">${obj}</mark>`
        : obj
      return `"${highlighted}"`
    }
    if (Array.isArray(obj)) {
      if (obj.length === 0) return '[]'
      const items = obj.map(item => '  '.repeat(indent + 1) + highlightJson(item, indent + 1))
      return `[\n${items.join(',\n')}\n${'  '.repeat(indent)}]`
    }
    if (typeof obj === 'object') {
      const keys = Object.keys(obj)
      if (keys.length === 0) return '{}'
      const items = keys.map(key => {
        const value = highlightJson(obj[key], indent + 1)
        return `${'  '.repeat(indent + 1)}"${key}": ${value}`
      })
      return `{\n${items.join(',\n')}\n${'  '.repeat(indent)}}`
    }
    return String(obj)
  }

  return (
    <pre
      className="text-xs bg-slate-900 p-4 rounded-lg overflow-x-auto"
      dangerouslySetInnerHTML={{ __html: highlightJson(json) }}
    />
  )
}

// HTML 预览组件
function HtmlPreview({
  content,
}: {
  content: string
}) {
  return (
    <div
      className="w-full h-full bg-white rounded-lg overflow-auto"
      dangerouslySetInnerHTML={{ __html: content }}
    />
  )
}

// ============ Main Component ============

export const ReportExportDialog = ({
  open,
  onOpenChange,
  auditId,
  findings,
  task: _task,
}: ReportExportDialogProps) => {
  const [activeFormat, setActiveFormat] = useState<ReportFormat>("markdown")
  const [downloading, setDownloading] = useState(false)
  const [downloadSuccess, setDownloadSuccess] = useState(false)
  const [previewContent, setPreviewContent] = useState<string>("")
  const [isLoadingPreview, setIsLoadingPreview] = useState(false)
  const [showPreview, setShowPreview] = useState(true)
  const [searchQuery, setSearchQuery] = useState("")

  // 计算统计数据
  const stats = useMemo(() => {
    const score = calculateScore(findings)
    const criticalCount = findings.filter(f => f.severity === "critical").length
    const highCount = findings.filter(f => f.severity === "high").length
    const mediumCount = findings.filter(f => f.severity === "medium").length
    const lowCount = findings.filter(f => f.severity === "low").length

    return { score, criticalCount, highCount, mediumCount, lowCount, total: findings.length }
  }, [findings])

  // 加载预览
  const loadPreview = useCallback(async (format: ReportFormat) => {
    setIsLoadingPreview(true)
    try {
      const API_BASE = import.meta.env.VITE_AGENT_SERVICE_URL || "http://localhost:8001"
      const url = `${API_BASE}/api/audit/${auditId}/report?format=${format}`

      const response = await fetch(url)
      if (!response.ok) {
        const errorText = await response.text()
        throw new Error(`HTTP ${response.status}: ${errorText || response.statusText}`)
      }

      if (format === "json") {
        const data = await response.json()
        setPreviewContent(JSON.stringify(data, null, 2))
      } else {
        const text = await response.text()
        setPreviewContent(text)
      }
    } catch (err) {
      console.error("Preview load failed:", err)
      const errorMessage = err instanceof Error ? err.message : "加载预览失败"
      setPreviewContent(`# 错误\n\n无法加载报告预览：\n\n\`\`\`\n${errorMessage}\n\`\`\`\n\n请检查：\n1. Agent 服务是否运行\n2. 审计 ID 是否正确\n3. 网络连接是否正常`)
    } finally {
      setIsLoadingPreview(false)
    }
  }, [auditId])

  // 当对话框打开或格式改变时加载预览
  useEffect(() => {
    if (open && showPreview) {
      loadPreview(activeFormat)
    }
  }, [open, activeFormat, showPreview, loadPreview])

  // 重置状态当对话框关闭时
  useEffect(() => {
    if (!open) {
      setDownloadSuccess(false)
      setPreviewContent("")
      setSearchQuery("")
    }
  }, [open])

  // 处理下载
  const handleDownload = async () => {
    setDownloading(true)
    try {
      const API_BASE = import.meta.env.VITE_AGENT_SERVICE_URL || "http://localhost:8001"
      const url = `${API_BASE}/api/audit/${auditId}/report?format=${activeFormat}`

      const response = await fetch(url)
      if (!response.ok) {
        const errorText = await response.text()
        throw new Error(`HTTP ${response.status}: ${errorText || response.statusText}`)
      }

      // 获取文件名
      const disposition = response.headers.get("Content-Disposition")
      let filename = `audit_report_${auditId}${FORMAT_CONFIG[activeFormat].extension}`
      if (disposition) {
        const match = disposition.match(/filename="?([^"]+)"?/)
        if (match) filename = match[1]
      }

      // 获取内容
      let blob: Blob
      if (activeFormat === "json") {
        const data = await response.json()
        blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" })
      } else {
        const text = await response.text()
        blob = new Blob([text], { type: FORMAT_CONFIG[activeFormat].mime })
      }

      // 触发下载
      const url2 = URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url2
      a.download = filename
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url2)

      setDownloadSuccess(true)
      setTimeout(() => {
        onOpenChange(false)
      }, 1500)
    } catch (err) {
      console.error("Download failed:", err)
      const errorMessage = err instanceof Error ? err.message : "导出报告失败，请重试"

      // 使用 toast 替代 alert
      if (window.navigator.clipboard) {
        // 尝试复制错误信息到剪贴板
        navigator.clipboard.writeText(errorMessage)
      }

      // 显示更友好的错误信息
      alert(`${errorMessage}\n\n请检查：\n1. Agent 服务是否运行\n2. 审计 ID 是否正确\n3. 网络连接是否正常\n\n错误信息已复制到剪贴板`)
    } finally {
      setDownloading(false)
    }
  }

  const scoreInfo = getScoreColor(stats.score)

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl h-[80vh] bg-slate-950 border-slate-800 flex flex-col p-0 gap-0">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 bg-slate-900/50 shrink-0">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="p-3 rounded-lg bg-rose-950/30 border border-rose-500/30">
                <FileDown className="w-6 h-6 text-rose-400" />
              </div>
              <div>
                <DialogTitle className="text-lg font-bold text-slate-200">导出审计报告</DialogTitle>
                <p className="text-xs text-slate-500 mt-1 flex items-center gap-2 font-mono">
                  <Clock className="w-3 h-3" />
                  {auditId}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setShowPreview(!showPreview)}
                className={cn(
                  "h-8",
                  showPreview ? "bg-amber-500/20 text-amber-400" : "text-slate-500"
                )}
              >
                {showPreview ? <Eye className="w-4 h-4" /> : <EyeOff className="w-4 h-4" />}
                <span className="ml-1.5">{showPreview ? "隐藏预览" : "显示预览"}</span>
              </Button>
            </div>
          </div>
        </div>

        {/* 内容区域 */}
        <div className={cn(
          "flex-1 flex overflow-hidden",
          !showPreview && "justify-center"
        )}>
          {/* 左侧：配置面板 */}
          <div className={cn(
            "flex flex-col p-6 space-y-5 overflow-y-auto",
            showPreview ? "w-80 border-r border-slate-800 shrink-0" : "w-full max-w-2xl"
          )}>
            {/* 统计概览 */}
            <div>
              <h3 className="text-sm font-semibold text-slate-300 mb-3">审计概览</h3>
              <div className="grid grid-cols-2 gap-2">
                <StatCard
                  icon={Bug}
                  label="漏洞总数"
                  value={stats.total}
                  color="text-rose-400"
                  bgColor="bg-rose-950/20"
                />
                <div className="flex items-center gap-3 p-3 rounded-lg bg-slate-900/50 border border-slate-800">
                  <div className={cn("p-2 rounded-lg", scoreInfo.bg)}>
                    <Bug className="w-4 h-4 text-white" />
                  </div>
                  <div>
                    <div className="text-xs text-slate-500 uppercase tracking-wide">安全评分</div>
                    <div className={cn("text-lg font-bold", scoreInfo.text)}>{stats.score}</div>
                  </div>
                </div>
              </div>

              {/* 严重程度分布 */}
              <div className="mt-3 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className={cn("font-medium", getSeverityColor("critical"))}>严重</span>
                  <span className="text-slate-400">{stats.criticalCount}</span>
                </div>
                <div className="flex items-center justify-between text-xs">
                  <span className={cn("font-medium", getSeverityColor("high"))}>高危</span>
                  <span className="text-slate-400">{stats.highCount}</span>
                </div>
                <div className="flex items-center justify-between text-xs">
                  <span className={cn("font-medium", getSeverityColor("medium"))}>中危</span>
                  <span className="text-slate-400">{stats.mediumCount}</span>
                </div>
                <div className="flex items-center justify-between text-xs">
                  <span className={cn("font-medium", getSeverityColor("low"))}>低危</span>
                  <span className="text-slate-400">{stats.lowCount}</span>
                </div>
              </div>
            </div>

            {/* 格式选择 */}
            <div>
              <h3 className="text-sm font-semibold text-slate-300 mb-3">选择格式</h3>
              <FormatSelector
                activeFormat={activeFormat}
                onFormatChange={setActiveFormat}
              />
            </div>

            {/* 格式说明 */}
            <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-800">
              <p className="text-xs text-slate-400">
                {activeFormat === "markdown" && "Markdown 格式便于编辑和版本控制，可用任何文本编辑器打开。"}
                {activeFormat === "json" && "JSON 格式包含完整的结构化数据，适合程序处理和数据分析。"}
                {activeFormat === "html" && "HTML 格式可在浏览器中直接查看，包含样式和交互功能。"}
              </p>
            </div>
          </div>

          {/* 右侧：预览面板 */}
          {showPreview && (
            <div className="flex-1 flex flex-col bg-slate-900/30 overflow-hidden">
              {/* 预览工具栏 */}
              <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between shrink-0">
                <div className="text-sm font-medium text-slate-300">
                  {FORMAT_CONFIG[activeFormat].label} 预览
                </div>
                <div className="flex items-center gap-2">
                  {/* 搜索框 */}
                  {activeFormat !== "html" && (
                    <div className="relative">
                      <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
                      <Input
                        type="text"
                        placeholder="搜索..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="h-7 pl-8 w-40 text-xs bg-slate-900/50 border-slate-700"
                      />
                    </div>
                  )}
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => loadPreview(activeFormat)}
                    disabled={isLoadingPreview}
                    className="h-7"
                  >
                    <RefreshCw className={cn("w-3.5 h-3.5", isLoadingPreview && "animate-spin")} />
                  </Button>
                </div>
              </div>

              {/* 预览内容 */}
              <div className="flex-1 p-4 overflow-auto">
                {isLoadingPreview ? (
                  <div className="flex items-center justify-center h-full">
                    <Loader2 className="w-8 h-8 text-slate-600 animate-spin" />
                  </div>
                ) : (
                  <>
                    {activeFormat === "json" && (
                      <JsonPreview content={previewContent} searchQuery={searchQuery} />
                    )}
                    {activeFormat === "markdown" && (
                      <MarkdownPreview content={previewContent} searchQuery={searchQuery} />
                    )}
                    {activeFormat === "html" && (
                      <HtmlPreview content={previewContent} />
                    )}
                  </>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-slate-800 bg-slate-900/50 shrink-0">
          <div className="flex items-center justify-end gap-3">
            <Button
              variant="ghost"
              onClick={() => onOpenChange(false)}
              disabled={downloading}
              className="text-slate-400 hover:text-slate-200"
            >
              取消
            </Button>

            <Button
              onClick={handleDownload}
              disabled={downloading}
              className={cn(
                "min-w-[140px]",
                downloadSuccess && "bg-emerald-600 hover:bg-emerald-700"
              )}
            >
              {downloading ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  导出中...
                </>
              ) : downloadSuccess ? (
                <>
                  <Check className="w-4 h-4 mr-2" />
                  导出成功
                </>
              ) : (
                <>
                  <Download className="w-4 h-4 mr-2" />
                  下载 {FORMAT_CONFIG[activeFormat].label}
                </>
              )}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}

export default ReportExportDialog
