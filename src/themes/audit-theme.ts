/**
 * Audit Theme - CTX-Audit 自定义 Monaco 主题
 *
 * 基于VSCode Dark+，针对代码审计场景优化
 */

import * as monaco from 'monaco-editor'

/**
 * 定义审计主题
 */
export const auditThemeData: monaco.editor.IStandaloneThemeData = {
  base: 'vs-dark',
  inherit: true,
  rules: [
    // 漏洞标记样式
    { token: 'finding-critical', background: '4a1010' },
    { token: 'finding-high', background: '4a2a10' },
    { token: 'finding-medium', background: '4a4a10' },
    { token: 'finding-low', background: '104a4a' },

    // 语法高亮（基于 VSCode Dark+）
    { token: 'comment', foreground: '6A9955' },
    { token: 'keyword', foreground: 'C586C0' },
    { token: 'string', foreground: 'CE9178' },
    { token: 'number', foreground: 'B5CEA8' },
    { token: 'type', foreground: '4EC9B0' },
    { token: 'function', foreground: 'DCDCAA' },
    { token: 'variable', foreground: '9CDCFE' },
    { token: 'operator', foreground: 'D4D4D4' },
    { token: 'tag', foreground: '569CD6' },
    { token: 'attribute.name', foreground: '9CDCFE' },
    { token: 'attribute.value', foreground: 'CE9178' },

    // 特殊标记
    { token: 'annotation', foreground: 'D7BA7D' },
    { token: 'modifier', foreground: 'C586C0' },

    // 安全相关关键字高亮
    { token: 'security.sensitive', foreground: 'F44747', fontStyle: 'bold' },
    { token: 'security.warning', foreground: 'FFD700' },
    { token: 'security.info', foreground: '4FC1FF' },

    // JavaScript/TypeScript
    { token: 'identifier.js', foreground: '9CDCFE' },
    { token: 'identifier.ts', foreground: '9CDCFE' },

    // Python
    { token: 'identifier.py', foreground: '9CDCFE' },

    // Rust
    { token: 'identifier.rs', foreground: '9CDCFE' },
  ],
  colors: {
    // 基础颜色
    'editor.background': '#1E1E1E',
    'editor.foreground': '#D4D4D4',
    'editor.inactiveSelectionBackground': '#3A3D41',

    // 光标
    'editorCursor.foreground': '#AEAFAD',

    // 行号
    'editorLineNumber.foreground': '#858585',
    'editorLineNumber.activeForeground': '#C6C6C6',

    // 选区
    'editor.selectionBackground': '#264F78',
    'editor.selectionHighlightBackground': '#ADD6FF80',

    // 当前行
    'editor.lineHighlightBackground': '#2A2D2E',
    'editor.lineHighlightBorder': '#00000000',

    // 搜索
    'editor.findMatchHighlightBackground': '#515C6A',
    'editor.findMatchBackground': '#613214',
    'editor.findMatchForeground': '#FFFFFF',

    // 滚动条
    'editor.scrollbar.background': '#1E1E1E',
    'editor.scrollbar.foreground': '#424242',
    'editor.scrollbarSlider.background': '#424242',
    'editor.scrollbarSlider.hoverBackground': '#4F4F4F',
    'editor.scrollbarSlider.activeBackground': '#5F5F5F',

    // Minimap
    'editor.minimap.background': '#1E1E1E',
    'editor.minimap.findMatchHighlight': '#613214',

    // 边距
    'editor overviewRuler.border': '#7f7f7f4d',

    // 错误/警告
    'editorError.foreground': '#F48771',
    'editorWarning.foreground': '#CCA700',
    'editorInfo.foreground': '#75BEFF',
    'editorHint.foreground': '#EEEEEE80',

    // 链接
    'textLink.foreground': '#4FC1FF',
    'textLink.activeForeground': '#4FC1FF',

    // 边框
    'editorIndentGuide.background': '#404040',
    'editorIndentGuide.activeBackground': '#707070',
    'editor.ruler.foreground': '#5A5A5A',

    // 代码镜头
    'editorCodeLens.foreground': '#999999',
    'editorCodeLens.background': '#1E1E1E00',

    // 括号匹配
    'editorBracketMatch.background': '#515C6A80',
    'editorBracketMatch.border': '#FFFFFF00',

    // 漏洞装饰器颜色
    'editorError.border': '#F48771',
    'editorWarning.border': '#CCA700',
    'editorInfo.border': '#75BEFF',

    // UI 元素
    'editorHoverWidget.background': '#252526',
    'editorHoverWidget.border': '#454545',
    'editorSuggestWidget.background': '#252526',
    'editorSuggestWidget.border': '#454545',
    'editorSuggestWidget.selectedBackground': '#094771',
  },
}

/**
 * 注册审计主题到 Monaco
 */
export function registerAuditTheme(monacoInstance: typeof monaco): void {
  monacoInstance.editor.defineTheme('audit-theme', auditThemeData)
}

/**
 * 漏洞严重程度对应的颜色
 */
export const severityColors = {
  critical: '#F44747',
  high: '#FF8C00',
  medium: '#FFD700',
  low: '#4FC1FF',
  info: '#9CDCFE',
}

/**
 * 获取严重程度对应的 Monaco 颜色 ID
 */
export function getSeverityColorId(severity: keyof typeof severityColors): string {
  return severityColors[severity]
}

/**
 * 漏洞装饰器样式配置
 */
export const findingDecorationStyles = {
  critical: {
    backgroundColor: 'rgba(244, 71, 71, 0.2)',
    borderLeft: '3px solid #F44747',
    overviewRulerColor: 'rgba(244, 71, 71, 1)',
    glyphMarginColor: '#F44747',
    minimapColor: '#F44747',
  },
  high: {
    backgroundColor: 'rgba(255, 140, 0, 0.2)',
    borderLeft: '3px solid #FF8C00',
    overviewRulerColor: 'rgba(255, 140, 0, 1)',
    glyphMarginColor: '#FF8C00',
    minimapColor: '#FF8C00',
  },
  medium: {
    backgroundColor: 'rgba(255, 215, 0, 0.2)',
    borderLeft: '3px solid #FFD700',
    overviewRulerColor: 'rgba(255, 215, 0, 1)',
    glyphMarginColor: '#FFD700',
    minimapColor: '#FFD700',
  },
  low: {
    backgroundColor: 'rgba(79, 193, 255, 0.2)',
    borderLeft: '3px solid #4FC1FF',
    overviewRulerColor: 'rgba(79, 193, 255, 1)',
    glyphMarginColor: '#4FC1FF',
    minimapColor: '#4FC1FF',
  },
  info: {
    backgroundColor: 'rgba(156, 220, 254, 0.2)',
    borderLeft: '3px solid #9CDCFE',
    overviewRulerColor: 'rgba(156, 220, 254, 1)',
    glyphMarginColor: '#9CDCFE',
    minimapColor: '#9CDCFE',
  },
}

/**
 * 创建漏洞装饰器选项
 */
export function createFindingDecorationOptions(
  severity: keyof typeof findingDecorationStyles
): monaco.editor.IModelDecorationOptions {
  const style = findingDecorationStyles[severity]

  return {
    className: `finding-${severity}`,
    glyphMarginClassName: `glyph-${severity}`,
    hoverMessage: { value: '' },
    minimap: {
      color: style.minimapColor,
      position: 1,
    },
  }
}
