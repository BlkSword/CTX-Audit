/**
 * EditorDecorations - 编辑器装饰器系统
 *
 * 为 Monaco Editor 提供漏洞标记装饰器
 */

import * as monaco from 'monaco-editor'
import type { Vulnerability } from '@/shared/types/agent'

// ==================== 类型定义 ====================

export interface FindingDecoration {
  id: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  className: string
  glyphMarginClassName: string
  hoverMessage: monaco.IMarkdownString[]
  range: monaco.IRange
}

// ==================== 样式类名 ====================

const SEVERITY_CLASS_NAMES: Record<string, string> = {
  critical: 'finding-critical',
  high: 'finding-high',
  medium: 'finding-medium',
  low: 'finding-low',
  info: 'finding-info',
}

const GLYPH_CLASS_NAMES: Record<string, string> = {
  critical: 'glyph-critical',
  high: 'glyph-high',
  medium: 'glyph-medium',
  low: 'glyph-low',
  info: 'glyph-info',
}

// ==================== 工具函数 ====================

/**
 * 将漏洞转换为 Monaco 装饰器
 */
export function vulnerabilityToDecoration(
  vulnerability: Vulnerability
): FindingDecoration {
  const { id, severity, line_number, line_end, column_start, column_end } =
    vulnerability

  // 创建范围
  const startLine = line_number
  const endLine = line_end || line_number
  const startColumn = column_start || 1
  const endColumn = column_end || 100000

  const range: monaco.IRange = {
    startLineNumber: startLine,
    startColumn: startColumn,
    endLineNumber: endLine,
    endColumn: endColumn,
  }

  // 创建悬停消息
  const hoverMessage: monaco.IMarkdownString[] = [
    {
      value: createHoverMessage(vulnerability),
    },
  ]

  return {
    id,
    severity,
    className: SEVERITY_CLASS_NAMES[severity],
    glyphMarginClassName: GLYPH_CLASS_NAMES[severity],
    hoverMessage,
    range,
  }
}

/**
 * 创建悬停消息
 */
function createHoverMessage(vulnerability: Vulnerability): string {
  const { title, severity, description, code_snippet, remediation, vulnerability_type } =
    vulnerability

  const severityEmoji: Record<string, string> = {
    critical: '🚫',
    high: '⚠️',
    medium: '⚡',
    low: 'ℹ️',
    info: 'ℹ️',
  }
  const emoji = severityEmoji[severity] || '⚠️'

  return `**${emoji} ${title}**

**类型:** \`${vulnerability_type}\`
**严重程度:** \`${severity.toUpperCase()}\`

---

**描述**
${description}

---

**问题代码**
\`\`\`
${code_snippet.trim()}
\`\`\`

---

**修复建议**
${remediation}
`
}

/**
 * 获取严重程度对应的颜色
 */
function getSeverityColor(severity: FindingDecoration['severity']): string {
  const colors: Record<string, string> = {
    critical: '#ff4d4f',
    high: '#faad14',
    medium: '#fadb14',
    low: '#13c2c2',
    info: '#9CDCFE',
  }
  return colors[severity] || '#cccccc'
}

/**
 * 批量转换漏洞列表为装饰器列表（Monaco 格式）
 */
export function vulnerabilitiesToMonacoDecorations(
  vulnerabilities: Vulnerability[]
): monaco.editor.IModelDeltaDecoration[] {
  return vulnerabilities.map(vulnerabilityToDecoration).map((f) => ({
    range: f.range,
    options: {
      className: f.className,
      glyphMarginClassName: f.glyphMarginClassName,
      hoverMessage: f.hoverMessage,
      minimap: {
        color: getSeverityColor(f.severity),
        position: monaco.editor.MinimapPosition.Inline,
      },
    },
  }))
}

/**
 * 批量转换漏洞列表为装饰器列表
 */
export function vulnerabilitiesToDecorations(
  vulnerabilities: Vulnerability[]
): FindingDecoration[] {
  return vulnerabilities.map(vulnerabilityToDecoration)
}

/**
 * 根据严重程度过滤装饰器
 */
export function filterDecorationsBySeverity(
  decorations: FindingDecoration[],
  severities: ('critical' | 'high' | 'medium' | 'low' | 'info')[]
): FindingDecoration[] {
  return decorations.filter((d) => severities.includes(d.severity))
}

/**
 * 根据状态过滤装饰器
 */
export function filterDecorationsByStatus(
  vulnerabilities: Vulnerability[],
  excludeStatuses: ('fixed' | 'false_positive' | 'ignored')[]
): Vulnerability[] {
  return vulnerabilities.filter((v) => {
    if (!v.status) return true
    return !excludeStatuses.includes(v.status as any)
  })
}

// ==================== 样式注入 ====================

/**
 * 注入装饰器样式到页面
 */
export function injectDecorationStyles(): void {
  const styleId = 'finding-decoration-styles'

  // 检查是否已注入
  if (document.getElementById(styleId)) {
    return
  }

  const style = document.createElement('style')
  style.id = styleId
  style.textContent = `
    /* 漏洞高亮样式 */
    .finding-critical {
      background-color: rgba(255, 77, 79, 0.2);
      border-left: 3px solid #ff4d4f;
    }

    .finding-high {
      background-color: rgba(250, 173, 20, 0.2);
      border-left: 3px solid #faad14;
    }

    .finding-medium {
      background-color: rgba(250, 219, 20, 0.2);
      border-left: 3px solid #fadb14;
    }

    .finding-low {
      background-color: rgba(19, 194, 194, 0.2);
      border-left: 3px solid #13c2c2;
    }

    /* 字形边距图标 */
    .glyph-critical::before {
      content: '🚫';
      font-size: 14px;
    }

    .glyph-high::before {
      content: '⚠️';
      font-size: 14px;
    }

    .glyph-medium::before {
      content: '⚡';
      font-size: 14px;
    }

    .glyph-low::before {
      content: 'ℹ️';
      font-size: 14px;
    }

    /* Minimap 标记 */
    .minimap-critical {
      background-color: #ff4d4f;
    }

    .minimap-high {
      background-color: #faad14;
    }

    .minimap-medium {
      background-color: #fadb14;
    }

    .minimap-low {
      background-color: #13c2c2;
    }
  `

  document.head.appendChild(style)
}

// ==================== 装饰器管理 ====================

/**
 * 装饰器管理器
 */
export class DecorationManager {
  private decorations: Map<string, string[]> = new Map()

  /**
   * 更新装饰器
   */
  updateDecorations(
    editor: monaco.editor.IStandaloneCodeEditor,
    filePath: string,
    newDecorations: monaco.editor.IModelDeltaDecoration[]
  ): string[] {
    // 获取旧装饰器 ID
    const oldDecorations = this.decorations.get(filePath) || []

    // 应用新装饰器
    const decorationIds = editor.deltaDecorations(oldDecorations, newDecorations)

    // 保存装饰器 ID
    this.decorations.set(filePath, decorationIds)

    return decorationIds
  }

  /**
   * 清除装饰器
   */
  clearDecorations(
    editor: monaco.editor.IStandaloneCodeEditor,
    filePath: string
  ): void {
    const oldDecorations = this.decorations.get(filePath) || []
    editor.deltaDecorations(oldDecorations, [])
    this.decorations.delete(filePath)
  }

  /**
   * 清除所有装饰器
   */
  clearAllDecorations(editor: monaco.editor.IStandaloneCodeEditor): void {
    const allDecorations = Array.from(this.decorations.values()).flat()
    editor.deltaDecorations(allDecorations, [])
    this.decorations.clear()
  }
}
