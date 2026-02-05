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

// 统计数据类型
interface ReportStats {
  score: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  total: number
}

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

// 生成 Markdown 报告
function generateMarkdownReport(
  auditId: string,
  findings: AgentFinding[],
  task: any,
  stats: ReportStats
): string {
  const now = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })
  const severityEmoji: Record<string, string> = {
    critical: '🔴',
    high: '🟠',
    medium: '🟡',
    low: '🔵',
    info: '⚪'
  }

  let md = `# 代码安全审计报告

---

## 📊 审计概览

| 项目 | 详情 |
|------|------|
| **审计 ID** | \`${auditId}\` |
| **生成时间** | ${now} |
| **漏洞总数** | ${stats.total} |
| **安全评分** | ${stats.score}/100 |
| **严重** | ${stats.criticalCount} |
| **高危** | ${stats.highCount} |
| **中危** | ${stats.mediumCount} |
| **低危** | ${stats.lowCount} |

${task ? `
## 📋 任务信息

| 项目 | 详情 |
|------|------|
| **审计类型** | ${task.audit_type || 'N/A'} |
| **状态** | ${task.status || 'N/A'} |
| **总文件数** | ${task.total_files || 0} |
| **已分析文件** | ${task.analyzed_files || 0} |
| **创建时间** | ${task.created_at ? new Date(task.created_at).toLocaleString('zh-CN') : 'N/A'} |
` : ''}

---

## 🔍 漏洞详情

${findings.length === 0 ? `
### ✅ 未发现漏洞

未检测到任何安全问题。
` : findings.map((finding, index) => `
### ${severityEmoji[finding.severity]} ${index + 1}. ${finding.title}

| 属性 | 值 |
|------|------|
| **严重程度** | ${finding.severity.toUpperCase()} |
| **漏洞类型** | ${finding.vulnerability_type} |
| **文件** | \`${finding.file_path || 'N/A'}\` |
| **行号** | ${finding.line_start ? `${finding.line_start}${finding.line_end ? `-${finding.line_end}` : ''}` : 'N/A'} |
| **状态** | ${finding.status} |
| **置信度** | ${finding.confidence ? `${Math.round(finding.confidence * 100)}%` : 'N/A'} |

**描述:**

${finding.description}

${finding.code_snippet ? `
**代码片段:**

\`\`\`
${finding.code_snippet}
\`\`\`
` : ''}

${finding.recommendation ? `
**修复建议:**

${finding.recommendation}
` : ''}

${finding.references && finding.references.length > 0 ? `
**参考链接:**

${finding.references.map(ref => `- [${ref}](${ref})`).join('\n')}
` : ''}

---
`).join('')}

---

*本报告由 CTX-Audit 自动生成*
`

  return md
}

// 生成 JSON 报告
function generateJsonReport(
  auditId: string,
  findings: AgentFinding[],
  task: any,
  stats: ReportStats
): string {
  const report = {
    audit_id: auditId,
    generated_at: new Date().toISOString(),
    summary: {
      total_findings: stats.total,
      security_score: stats.score,
      severity_breakdown: {
        critical: stats.criticalCount,
        high: stats.highCount,
        medium: stats.mediumCount,
        low: stats.lowCount
      }
    },
    task: task ? {
      audit_type: task.audit_type,
      status: task.status,
      total_files: task.total_files,
      analyzed_files: task.analyzed_files,
      created_at: task.created_at,
      completed_at: task.completed_at
    } : null,
    findings: findings.map(f => ({
      id: f.id,
      task_id: f.task_id,
      vulnerability_type: f.vulnerability_type,
      severity: f.severity,
      title: f.title,
      description: f.description,
      file_path: f.file_path,
      line_start: f.line_start,
      line_end: f.line_end,
      code_snippet: f.code_snippet,
      recommendation: f.recommendation,
      references: f.references,
      status: f.status,
      is_verified: f.is_verified,
      confidence: f.confidence,
      created_at: f.created_at
    }))
  }

  return JSON.stringify(report, null, 2)
}

// 生成 HTML 报告
function generateHtmlReport(
  auditId: string,
  findings: AgentFinding[],
  task: any,
  stats: ReportStats
): string {
  const now = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })
  const severityColor: Record<string, string> = {
    critical: '#f43f5e',
    high: '#f97316',
    medium: '#f59e0b',
    low: '#0ea5e9',
    info: '#94a3b8'
  }
  const severityBgColor: Record<string, string> = {
    critical: '#fef2f2',
    high: '#fff7ed',
    medium: '#fffbeb',
    low: '#f0f9ff',
    info: '#f8fafc'
  }

  const findingsHtml = findings.length === 0
    ? '<div class="empty-state"><p>✅ 未发现漏洞</p></div>'
    : findings.map((finding, index) => `
      <div class="finding-card" style="border-left-color: ${severityColor[finding.severity]}">
        <div class="finding-header">
          <span class="finding-severity severity-${finding.severity}">${finding.severity.toUpperCase()}</span>
          <h3>${index + 1}. ${finding.title}</h3>
        </div>
        <table class="finding-meta">
          <tr><th>漏洞类型</th><td>${finding.vulnerability_type}</td></tr>
          <tr><th>文件</th><td><code>${finding.file_path || 'N/A'}</code></td></tr>
          <tr><th>行号</th><td>${finding.line_start ? `${finding.line_start}${finding.line_end ? `-${finding.line_end}` : ''}` : 'N/A'}</td></tr>
          <tr><th>状态</th><td>${finding.status}</td></tr>
          ${finding.confidence !== undefined ? `<tr><th>置信度</th><td>${Math.round(finding.confidence * 100)}%</td></tr>` : ''}
        </table>
        <div class="finding-section">
          <h4>描述</h4>
          <p>${finding.description.replace(/\n/g, '<br>')}</p>
        </div>
        ${finding.code_snippet ? `
        <div class="finding-section">
          <h4>代码片段</h4>
          <pre><code>${finding.code_snippet.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</code></pre>
        </div>
        ` : ''}
        ${finding.recommendation ? `
        <div class="finding-section">
          <h4>修复建议</h4>
          <p>${finding.recommendation.replace(/\n/g, '<br>')}</p>
        </div>
        ` : ''}
        ${finding.references && finding.references.length > 0 ? `
        <div class="finding-section">
          <h4>参考链接</h4>
          <ul>
            ${finding.references.map(ref => `<li><a href="${ref}" target="_blank">${ref}</a></li>`).join('')}
          </ul>
        </div>
        ` : ''}
      </div>
    `).join('')

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>代码安全审计报告 - ${auditId}</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      padding: 20px;
      line-height: 1.6;
    }
    .container {
      max-width: 1200px;
      margin: 0 auto;
      background: white;
      border-radius: 12px;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
      overflow: hidden;
    }
    .header {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      padding: 40px;
    }
    .header h1 {
      font-size: 32px;
      margin-bottom: 10px;
    }
    .header .meta {
      opacity: 0.9;
      font-size: 14px;
    }
    .summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      padding: 30px;
      background: #f8fafc;
    }
    .summary-card {
      background: white;
      padding: 20px;
      border-radius: 8px;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
      text-align: center;
    }
    .summary-card .value {
      font-size: 32px;
      font-weight: bold;
      margin-bottom: 5px;
    }
    .summary-card .label {
      color: #64748b;
      font-size: 14px;
    }
    .summary-card.score .value { color: ${stats.score >= 80 ? '#10b981' : stats.score >= 60 ? '#f59e0b' : '#ef4444'}; }
    .content {
      padding: 30px;
    }
    .section-title {
      font-size: 24px;
      margin-bottom: 20px;
      color: #1e293b;
    }
    .finding-card {
      background: white;
      border: 1px solid #e2e8f0;
      border-left: 4px solid;
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 20px;
    }
    .finding-header {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 15px;
    }
    .finding-severity {
      padding: 4px 12px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: bold;
      text-transform: uppercase;
    }
    .finding-severity.severity-critical { background: #fef2f2; color: #f43f5e; }
    .finding-severity.severity-high { background: #fff7ed; color: #f97316; }
    .finding-severity.severity-medium { background: #fffbeb; color: #f59e0b; }
    .finding-severity.severity-low { background: #f0f9ff; color: #0ea5e9; }
    .finding-severity.severity-info { background: #f8fafc; color: #94a3b8; }
    .finding-header h3 {
      font-size: 18px;
      color: #1e293b;
    }
    .finding-meta {
      width: 100%;
      margin-bottom: 15px;
      border-collapse: collapse;
    }
    .finding-meta th, .finding-meta td {
      padding: 8px;
      text-align: left;
      border-bottom: 1px solid #e2e8f0;
      font-size: 14px;
    }
    .finding-meta th {
      color: #64748b;
      font-weight: 600;
      width: 100px;
    }
    .finding-meta code {
      background: #f1f5f9;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 13px;
    }
    .finding-section {
      margin-top: 15px;
    }
    .finding-section h4 {
      font-size: 16px;
      color: #334155;
      margin-bottom: 8px;
    }
    .finding-section p {
      color: #475569;
      line-height: 1.7;
    }
    .finding-section pre {
      background: #1e293b;
      color: #e2e8f0;
      padding: 15px;
      border-radius: 6px;
      overflow-x: auto;
    }
    .finding-section ul {
      list-style: none;
      padding-left: 0;
    }
    .finding-section li {
      padding: 5px 0;
    }
    .finding-section a {
      color: #3b82f6;
      text-decoration: none;
    }
    .finding-section a:hover {
      text-decoration: underline;
    }
    .empty-state {
      text-align: center;
      padding: 60px 20px;
      color: #64748b;
    }
    .empty-state p {
      font-size: 18px;
    }
    .footer {
      text-align: center;
      padding: 20px;
      background: #f8fafc;
      color: #64748b;
      font-size: 14px;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🔒 代码安全审计报告</h1>
      <div class="meta">
        <span>审计 ID: <code>${auditId}</code></span> |
        <span>生成时间: ${now}</span>
      </div>
    </div>

    <div class="summary">
      <div class="summary-card">
        <div class="value" style="color: #ef4444">${stats.total}</div>
        <div class="label">漏洞总数</div>
      </div>
      <div class="summary-card score">
        <div class="value">${stats.score}</div>
        <div class="label">安全评分</div>
      </div>
      <div class="summary-card">
        <div class="value" style="color: #f43f5e">${stats.criticalCount}</div>
        <div class="label">严重</div>
      </div>
      <div class="summary-card">
        <div class="value" style="color: #f97316">${stats.highCount}</div>
        <div class="label">高危</div>
      </div>
      <div class="summary-card">
        <div class="value" style="color: #f59e0b">${stats.mediumCount}</div>
        <div class="label">中危</div>
      </div>
      <div class="summary-card">
        <div class="value" style="color: #0ea5e9">${stats.lowCount}</div>
        <div class="label">低危</div>
      </div>
    </div>

    <div class="content">
      <h2 class="section-title">🔍 漏洞详情</h2>
      ${findingsHtml}
    </div>

    <div class="footer">
      <p>本报告由 CTX-Audit 自动生成</p>
    </div>
  </div>
</body>
</html>`
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
  task,
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

  // 加载预览（客户端生成）
  const loadPreview = useCallback((format: ReportFormat) => {
    setIsLoadingPreview(true)
    try {
      let content = ""
      switch (format) {
        case "markdown":
          content = generateMarkdownReport(auditId, findings, task, stats)
          break
        case "json":
          content = generateJsonReport(auditId, findings, task, stats)
          break
        case "html":
          content = generateHtmlReport(auditId, findings, task, stats)
          break
      }
      setPreviewContent(content)
    } catch (err) {
      console.error("Preview generation failed:", err)
      const errorMessage = err instanceof Error ? err.message : "生成预览失败"
      setPreviewContent(`# 错误\n\n无法生成报告预览：\n\n\`\`\`\n${errorMessage}\n\`\`\``)
    } finally {
      setIsLoadingPreview(false)
    }
  }, [auditId, findings, task, stats])

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

  // 处理下载（客户端生成）
  const handleDownload = () => {
    setDownloading(true)
    try {
      let content = ""
      switch (activeFormat) {
        case "markdown":
          content = generateMarkdownReport(auditId, findings, task, stats)
          break
        case "json":
          content = generateJsonReport(auditId, findings, task, stats)
          break
        case "html":
          content = generateHtmlReport(auditId, findings, task, stats)
          break
      }

      // 生成文件名
      const timestamp = new Date().toISOString().slice(0, 10)
      const filename = `audit_report_${auditId.slice(0, 8)}_${timestamp}${FORMAT_CONFIG[activeFormat].extension}`

      // 创建 Blob 并触发下载
      const blob = new Blob([content], { type: FORMAT_CONFIG[activeFormat].mime })
      const url = URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = filename
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)

      setDownloadSuccess(true)
      setTimeout(() => {
        onOpenChange(false)
      }, 1500)
    } catch (err) {
      console.error("Download failed:", err)
      const errorMessage = err instanceof Error ? err.message : "导出报告失败，请重试"
      alert(`${errorMessage}\n\n如果问题持续存在，请尝试刷新页面重试。`)
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
