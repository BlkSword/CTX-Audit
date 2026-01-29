/**
 * MonacoEditor - Monaco Editor 核心封装组件
 *
 * 提供代码编辑、语法高亮、自动补全等功能
 */

import { useEffect, useRef, useCallback } from 'react'
import Editor, { type OnMount, type OnChange } from '@monaco-editor/react'
import * as monaco from 'monaco-editor'
import { loader } from '@monaco-editor/react'
import editorWorker from 'monaco-editor/esm/vs/editor/editor.worker?worker'
import jsonWorker from 'monaco-editor/esm/vs/language/json/json.worker?worker'
import cssWorker from 'monaco-editor/esm/vs/language/css/css.worker?worker'
import htmlWorker from 'monaco-editor/esm/vs/language/html/html.worker?worker'
import tsWorker from 'monaco-editor/esm/vs/language/typescript/ts.worker?worker'

// ==================== Monaco Worker 配置 ====================
// 使用本地 worker 文件，避免 CDN 加载问题

self.MonacoEnvironment = {
  getWorker(_: string, label: string) {
    if (label === 'json') {
      return new jsonWorker()
    }
    if (label === 'css' || label === 'scss' || label === 'less') {
      return new cssWorker()
    }
    if (label === 'html' || label === 'handlebars' || label === 'razor') {
      return new htmlWorker()
    }
    if (label === 'typescript' || label === 'javascript') {
      return new tsWorker()
    }
    return new editorWorker()
  },
}

loader.config({ monaco })

// ==================== 类型定义 ====================

export interface MonacoEditorProps {
  filePath: string
  content: string
  language: string
  readOnly?: boolean
  theme?: string
  onContentChange?: (content: string) => void
  onCursorChange?: (position: { line: number; column: number }) => void
  onEditorMount?: (editor: monaco.editor.IStandaloneCodeEditor) => void
  findings?: FindingDecoration[]
}

export interface FindingDecoration {
  id: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  className: string
  glyphMarginClassName: string
  hoverMessage: monaco.IMarkdownString[]
  range: monaco.IRange
}

// ==================== 语言映射 ====================

const LANGUAGE_MAP: Record<string, string> = {
  ts: 'typescript',
  tsx: 'typescript',
  js: 'javascript',
  jsx: 'javascript',
  py: 'python',
  rs: 'rust',
  go: 'go',
  java: 'java',
  c: 'c',
  cpp: 'cpp',
  cs: 'csharp',
  json: 'json',
  yaml: 'yaml',
  yml: 'yaml',
  xml: 'xml',
  html: 'html',
  css: 'css',
  scss: 'scss',
  md: 'markdown',
  txt: 'plaintext',
}

/**
 * 根据文件扩展名获取语言
 */
export function getLanguageFromPath(filePath: string): string {
  const ext = filePath.split('.').pop()?.toLowerCase() || ''
  return LANGUAGE_MAP[ext] || 'plaintext'
}

// ==================== 组件 ====================

export function MonacoEditor({
  filePath: _filePath,
  content,
  language,
  readOnly = false,
  theme = 'vs-dark',
  onContentChange,
  onCursorChange,
  onEditorMount,
  findings = [],
}: MonacoEditorProps) {
  const editorRef = useRef<monaco.editor.IStandaloneCodeEditor | null>(null)
  const decorationsRef = useRef<string[]>([])

  // 编辑器挂载
  const handleMount: OnMount = (editor, _monaco) => {
    editorRef.current = editor

    // 配置编辑器选项
    editor.updateOptions({
      fontSize: 14,
      fontFamily: "'JetBrains Mono', 'Fira Code', 'Consolas', monospace",
      fontLigatures: true,
      lineNumbers: 'on',
      minimap: { enabled: true },
      scrollBeyondLastLine: false,
      renderWhitespace: 'selection',
      renderLineHighlight: 'all',
      cursorBlinking: 'smooth',
      cursorSmoothCaretAnimation: 'on',
      smoothScrolling: true,
      automaticLayout: true,
      wordWrap: 'off',
      readOnly,
      domReadOnly: readOnly,
      glyphMargin: true,
      lineDecorationsWidth: 10,
      lineNumbersMinChars: 3,
    })

    // 监听光标位置变化
    editor.onDidChangeCursorPosition((e) => {
      onCursorChange?.({
        line: e.position.lineNumber,
        column: e.position.column,
      })
    })

    // 通知父组件编辑器已挂载
    onEditorMount?.(editor)
  }

  // 内容变化
  const handleChange: OnChange = (value) => {
    if (value !== undefined) {
      onContentChange?.(value)
    }
  }

  // 更新装饰器
  const updateDecorations = useCallback(() => {
    if (!editorRef.current) return

    const editor = editorRef.current

    // 清除旧装饰器
    const oldDecorations = decorationsRef.current
    const newDecorations = findings.map((f) => ({
      id: f.id,
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

    decorationsRef.current = editor.deltaDecorations(
      oldDecorations,
      newDecorations
    )
  }, [findings])

  // 当 findings 变化时更新装饰器
  useEffect(() => {
    updateDecorations()
  }, [findings, updateDecorations])

  // 清理
  useEffect(() => {
    return () => {
      if (editorRef.current) {
        editorRef.current.dispose()
      }
    }
  }, [])

  return (
    <div className="h-full w-full">
      <Editor
        height="100%"
        width="100%"
        language={language}
        value={content}
        theme={theme}
        onMount={handleMount}
        onChange={handleChange}
        options={{
          readOnly,
          domReadOnly: readOnly,
        }}
        loading={
          <div className="flex items-center justify-center h-full text-muted-foreground">
            加载编辑器...
          </div>
        }
      />
    </div>
  )
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
 * 默认编辑器选项
 */
export const DEFAULT_EDITOR_OPTIONS: monaco.editor.IStandaloneEditorConstructionOptions =
  {
    fontSize: 14,
    fontFamily: "'JetBrains Mono', 'Fira Code', 'Consolas', monospace",
    fontLigatures: true,
    lineNumbers: 'on',
    minimap: { enabled: true },
    scrollBeyondLastLine: false,
    renderWhitespace: 'selection',
    renderLineHighlight: 'all',
    cursorBlinking: 'smooth',
    cursorSmoothCaretAnimation: 'on',
    smoothScrolling: true,
    automaticLayout: true,
    wordWrap: 'off',
    glyphMargin: true,
    lineDecorationsWidth: 10,
    lineNumbersMinChars: 3,
    folding: true,
    foldingStrategy: 'auto',
    showFoldingControls: 'always',
    matchBrackets: 'always',
    autoClosingBrackets: 'always',
    autoClosingQuotes: 'always',
    formatOnPaste: true,
    formatOnType: true,
    tabSize: 2,
    insertSpaces: true,
  }
