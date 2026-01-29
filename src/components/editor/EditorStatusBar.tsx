/**
 * EditorStatusBar - 编辑器状态栏
 *
 * 显示当前文件信息、光标位置、编码、漏洞统计等
 */

import { useMemo } from 'react'
import { useEditorStore } from '@/stores/editorStore'
import { useFindingMarkerStore } from '@/stores/findingMarkerStore'
import { useRealtimeAuditStore } from '@/stores/realTimeAuditStore'
import { AlertTriangle, CheckCircle, Scan, Zap } from 'lucide-react'
import { cn } from '@/lib/utils'

export interface EditorStatusBarProps {
  groupId: string
}

export function EditorStatusBar({ groupId }: EditorStatusBarProps) {
  const { editorGroups, activeGroupId } = useEditorStore()
  const { getFilteredFindingsForFile } = useFindingMarkerStore()
  const { autoMode, scanningFiles } = useRealtimeAuditStore()

  const group = editorGroups.find((g) => g.id === groupId)
  const isActive = activeGroupId === groupId

  const { activeFile } = group || {}

  // 获取当前文件的漏洞统计
  const findingStats = useMemo(() => {
    if (!activeFile) {
      return { critical: 0, high: 0, medium: 0, low: 0, total: 0 }
    }

    const findings = getFilteredFindingsForFile(activeFile.path)
    const stats = { critical: 0, high: 0, medium: 0, low: 0, total: 0 }

    findings.forEach((f) => {
      if (f.severity === 'critical') stats.critical++
      else if (f.severity === 'high') stats.high++
      else if (f.severity === 'medium') stats.medium++
      else if (f.severity === 'low') stats.low++
      stats.total++
    })

    return stats
  }, [activeFile, getFilteredFindingsForFile])

  // 文件是否正在扫描
  const isScanning = activeFile ? scanningFiles.has(activeFile.path) : false

  if (!activeFile) {
    return (
      <div
        className={cn(
          'h-6 bg-[#007acc] flex items-center justify-between px-3 text-[10px] text-white',
          !isActive && 'bg-[#0e639c]'
        )}
      >
        <div className="flex items-center gap-3">
          <span>未打开文件</span>
        </div>
      </div>
    )
  }

  const lineCount = activeFile.content.split('\n').length

  return (
    <div
      className={cn(
        'h-6 bg-[#007acc] flex items-center justify-between px-3 text-[10px] text-white',
        !isActive && 'bg-[#0e639c]'
      )}
    >
      {/* 左侧信息 */}
      <div className="flex items-center gap-3">
        {/* 文件信息 */}
        <span className="font-medium">{activeFile.name}</span>
        <span>{getLanguageDisplay(activeFile.name)}</span>
        <span>UTF-8</span>

        {/* 修改标记 */}
        {activeFile.isModified && <span className="text-yellow-300">● 已修改</span>}

        {/* 扫描状态 */}
        {isScanning && (
          <div className="flex items-center gap-1 text-white/80">
            <Scan className="w-3 h-3 animate-spin" />
            <span>扫描中...</span>
          </div>
        )}
      </div>

      {/* 右侧信息 */}
      <div className="flex items-center gap-3">
        {/* 漏洞统计 */}
        {findingStats.total > 0 && (
          <div
            className="flex items-center gap-2 cursor-pointer hover:bg-white/10 px-2 py-0.5 rounded transition-colors"
            title="点击查看问题详情"
          >
            {findingStats.critical > 0 && (
              <div className="flex items-center gap-1">
                <AlertTriangle className="w-3 h-3" />
                <span>{findingStats.critical}</span>
              </div>
            )}
            {findingStats.high > 0 && (
              <div className="flex items-center gap-1">
                <AlertTriangle className="w-3 h-3 text-orange-300" />
                <span>{findingStats.high}</span>
              </div>
            )}
            {findingStats.medium > 0 && (
              <div className="flex items-center gap-1">
                <Zap className="w-3 h-3 text-yellow-300" />
                <span>{findingStats.medium}</span>
              </div>
            )}
          </div>
        )}

        {/* 审计模式指示 */}
        <div
          className={cn(
            'flex items-center gap-1',
            autoMode ? 'text-green-300' : 'text-yellow-300'
          )}
          title={autoMode ? '自动审计模式' : '手动审计模式'}
        >
          {autoMode ? (
            <CheckCircle className="w-3 h-3" />
          ) : (
            <Zap className="w-3 h-3" />
          )}
        </div>

        {/* 光标位置 */}
        <span>Ln {lineCount}, Col 1</span>

        {/* 缩进 */}
        <span>Spaces: 2</span>
      </div>
    </div>
  )
}

/**
 * 获取语言显示名称
 */
function getLanguageDisplay(fileName: string): string {
  const ext = fileName.split('.').pop()?.toLowerCase()
  const languageMap: Record<string, string> = {
    ts: 'TypeScript',
    tsx: 'TypeScript JSX',
    js: 'JavaScript',
    jsx: 'JavaScript JSX',
    py: 'Python',
    rs: 'Rust',
    go: 'Go',
    java: 'Java',
    c: 'C',
    cpp: 'C++',
    cs: 'C#',
    json: 'JSON',
    yaml: 'YAML',
    yml: 'YAML',
    xml: 'XML',
    html: 'HTML',
    css: 'CSS',
    scss: 'SCSS',
    md: 'Markdown',
    txt: 'Plain Text',
  }
  return languageMap[ext || ''] || 'Plain Text'
}
