/**
 * CodeEditorPanel - 代码编辑器面板
 *
 * 显示代码编辑器，支持：
 * - 文件标签页
 * - 代码高亮（TODO: 集成 Monaco Editor 或 CodeMirror）
 * - 语法检测
 * - 文件切换
 */

import { useState, useEffect } from 'react'
import { X, FileCode, FolderOpen } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { useFileStore } from '@/stores/fileStore'
import { tauriApi } from '@/shared/api/tauri-client'

// 打开的文件标签
interface OpenFile {
  path: string
  name: string
  content: string
  isActive: boolean
}

export function CodeEditorPanel() {
  const { files } = useFileStore()
  const [openFiles, setOpenFiles] = useState<OpenFile[]>([])
  const [activeFile, setActiveFile] = useState<OpenFile | null>(null)

  // 加载文件内容
  const loadFileContent = async (filePath: string): Promise<string> => {
    try {
      return await tauriApi.readFile(filePath)
    } catch (error) {
      console.error('Failed to load file:', error)
      return '// Error loading file'
    }
  }

  // 打开文件
  const openFile = async (filePath: string) => {
    // 检查是否已经打开
    const existingFile = openFiles.find((f) => f.path === filePath)
    if (existingFile) {
      setActiveFile(existingFile)
      setOpenFiles((prev) =>
        prev.map((f) => ({ ...f, isActive: f.path === filePath }))
      )
      return
    }

    // 加载文件内容
    const content = await loadFileContent(filePath)
    const fileName = filePath.split('/').pop() || filePath

    const newFile: OpenFile = {
      path: filePath,
      name: fileName,
      content,
      isActive: true,
    }

    setOpenFiles((prev) => [
      ...prev.map((f) => ({ ...f, isActive: false })),
      newFile,
    ])
    setActiveFile(newFile)
  }

  // 关闭文件
  const closeFile = (filePath: string) => {
    const newOpenFiles = openFiles.filter((f) => f.path !== filePath)
    setOpenFiles(newOpenFiles)

    if (activeFile?.path === filePath) {
      // 如果关闭的是当前文件，切换到最后一个文件
      const lastFile = newOpenFiles[newOpenFiles.length - 1]
      if (lastFile) {
        setActiveFile(lastFile)
        setOpenFiles((prev) =>
          prev.map((f) => ({ ...f, isActive: f.path === lastFile.path }))
        )
      } else {
        setActiveFile(null)
      }
    }
  }

  // 获取文件语言
  const getLanguage = (fileName: string): string => {
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

  return (
    <div className="flex flex-col h-full bg-[#1e1e1e]">
      {/* 文件标签栏 */}
      <div className="flex items-center h-9 bg-[#252526] border-b border-border/40 overflow-x-auto">
        {openFiles.length === 0 ? (
          <div className="flex items-center gap-2 px-4 text-sm text-muted-foreground">
            <FolderOpen className="w-4 h-4" />
            <span>未打开文件</span>
          </div>
        ) : (
          openFiles.map((file) => (
            <div
              key={file.path}
              className={cn(
                'flex items-center gap-2 px-3 h-full border-r border-border/40 cursor-pointer group min-w-[120px] max-w-[200px]',
                file.isActive
                  ? 'bg-[#1e1e1e] text-white'
                  : 'bg-[#2d2d2d] text-muted-foreground hover:bg-[#1e1e1e] hover:text-white'
              )}
              onClick={() => {
                setActiveFile(file)
                setOpenFiles((prev) =>
                  prev.map((f) => ({ ...f, isActive: f.path === file.path }))
                )
              }}
            >
              <FileCode className="w-3.5 h-3.5 shrink-0" />
              <span className="text-xs truncate">{file.name}</span>
              <Button
                variant="ghost"
                size="icon"
                className="h-4 w-4 p-0 opacity-0 group-hover:opacity-100 hover:bg-white/10"
                onClick={(e) => {
                  e.stopPropagation()
                  closeFile(file.path)
                }}
              >
                <X className="w-3 h-3" />
              </Button>
            </div>
          ))
        )}
      </div>

      {/* 编辑器区域 */}
      <div className="flex-1 overflow-auto">
        {!activeFile ? (
          // 空状态
          <div className="h-full flex flex-col items-center justify-center text-muted-foreground">
            <FileCode className="w-16 h-16 mb-4 opacity-20" />
            <p className="text-sm mb-2">未打开文件</p>
            <p className="text-xs opacity-60">从左侧资源管理器选择文件</p>
          </div>
        ) : (
          // 代码内容（TODO: 替换为 Monaco Editor）
          <div className="h-full p-4 font-mono text-sm">
            {/* 文件信息 */}
            <div className="flex items-center justify-between mb-4 pb-2 border-b border-border/40">
              <div className="flex items-center gap-3">
                <span className="text-white font-medium">{activeFile.name}</span>
                <span className="text-xs text-muted-foreground">
                  {getLanguage(activeFile.name)}
                </span>
              </div>
              <span className="text-xs text-muted-foreground">
                {activeFile.content.split('\n').length} 行
              </span>
            </div>

            {/* 代码内容 */}
            <pre className="text-xs leading-relaxed overflow-x-auto">
              <code>{activeFile.content}</code>
            </pre>
          </div>
        )}
      </div>

      {/* 底部状态栏 */}
      <div className="h-6 bg-[#007acc] flex items-center justify-between px-3 text-[10px] text-white">
        <div className="flex items-center gap-3">
          {activeFile && (
            <>
              <span>{getLanguage(activeFile.name)}</span>
              <span>UTF-8</span>
            </>
          )}
        </div>
        <div className="flex items-center gap-3">
          {activeFile && <span>Ln {activeFile.content.split('\n').length}, Col 1</span>}
          <span>Spaces: 2</span>
        </div>
      </div>
    </div>
  )
}
