/**
 * EditorGroup - 单个编辑器组组件
 *
 * 管理单个编辑器组，支持文件标签页
 */

import type { FC } from 'react'
import { X, FileCode, SplitSquareVertical, SplitSquareHorizontal } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { useEditorStore } from '@/stores/editorStore'
import { MonacoEditor, getLanguageFromPath } from './MonacoEditor'
import { EditorStatusBar } from './EditorStatusBar'
import * as monaco from 'monaco-editor'

// ==================== 类型定义 ====================

export interface EditorGroupProps {
  groupId: string
  onSplit?: (orientation: 'horizontal' | 'vertical') => void
  onClose?: () => void
}

// ==================== 组件 ====================

export function EditorGroup({ groupId, onSplit, onClose }: EditorGroupProps) {
  const { editorGroups, activeGroupId, setActiveFile, closeFile, setEditorInstance } =
    useEditorStore()

  const group = editorGroups.find((g) => g.id === groupId)
  const isActive = activeGroupId === groupId

  if (!group) return null

  const { files, activeFile } = group

  // 处理内容变化
  const handleContentChange = (content: string) => {
    // TODO: 更新文件内容到 store
    console.log('Content changed:', content)
  }

  // 处理光标位置变化
  const handleCursorChange = (position: { line: number; column: number }) => {
    // TODO: 更新状态栏显示
    console.log('Cursor changed:', position)
  }

  // 处理编辑器挂载
  const handleEditorMount = (editor: monaco.editor.IStandaloneCodeEditor) => {
    setEditorInstance(groupId, editor)
  }

  return (
    <div className="flex flex-col h-full bg-[#1e1e1e]">
      {/* 文件标签栏 */}
      <div
        className={cn(
          'flex items-center h-9 border-b border-border/40 overflow-x-auto transition-colors',
          isActive ? 'bg-[#1e1e1e]' : 'bg-[#252526]'
        )}
      >
        {/* 拆分和关闭按钮 */}
        <div className="flex items-center gap-1 px-2 border-r border-border/40">
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6 p-0 text-muted-foreground hover:text-white hover:bg-white/10"
            title="垂直拆分"
            onClick={() => onSplit?.('vertical')}
          >
            <SplitSquareHorizontal className="w-3.5 h-3.5" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6 p-0 text-muted-foreground hover:text-white hover:bg-white/10"
            title="水平拆分"
            onClick={() => onSplit?.('horizontal')}
          >
            <SplitSquareVertical className="w-3.5 h-3.5" />
          </Button>
          {editorGroups.length > 1 && (
            <Button
              variant="ghost"
              size="icon"
              className="h-6 w-6 p-0 text-muted-foreground hover:text-white hover:bg-white/10"
              title="关闭编辑器组"
              onClick={onClose}
            >
              <X className="w-3.5 h-3.5" />
            </Button>
          )}
        </div>

        {/* 文件标签 */}
        {files.length === 0 ? (
          <div className="flex items-center gap-2 px-4 text-sm text-muted-foreground">
            <span>未打开文件</span>
          </div>
        ) : (
          files.map((file) => (
            <div
              key={file.path}
              className={cn(
                'flex items-center gap-2 px-3 h-full border-r border-border/40 cursor-pointer group min-w-[120px] max-w-[200px] transition-colors',
                file.isActive
                  ? 'bg-[#1e1e1e] text-white'
                  : 'bg-[#2d2d2d] text-muted-foreground hover:bg-[#1e1e1e] hover:text-white'
              )}
              onClick={() => setActiveFile(groupId, file.path)}
            >
              <FileCode className="w-3.5 h-3.5 shrink-0" />
              <span className="text-xs truncate flex-1">
                {file.name}
                {file.isModified && <span className="ml-1 text-white">●</span>}
              </span>
              <Button
                variant="ghost"
                size="icon"
                className="h-4 w-4 p-0 opacity-0 group-hover:opacity-100 hover:bg-white/10"
                onClick={(e) => {
                  e.stopPropagation()
                  closeFile(groupId, file.path)
                }}
              >
                <X className="w-3 h-3" />
              </Button>
            </div>
          ))
        )}
      </div>

      {/* 编辑器区域 */}
      <div className="flex-1 overflow-hidden">
        {!activeFile ? (
          // 空状态
          <div className="h-full flex flex-col items-center justify-center text-muted-foreground">
            <FileCode className="w-16 h-16 mb-4 opacity-20" />
            <p className="text-sm mb-2">未打开文件</p>
            <p className="text-xs opacity-60">从左侧资源管理器选择文件</p>
          </div>
        ) : (
          // Monaco Editor
          <MonacoEditor
            filePath={activeFile.path}
            content={activeFile.content}
            language={getLanguageFromPath(activeFile.path)}
            onContentChange={handleContentChange}
            onCursorChange={handleCursorChange}
            onEditorMount={handleEditorMount}
          />
        )}
      </div>

      {/* 底部状态栏 */}
      <EditorStatusBar groupId={groupId} />
    </div>
  )
}
