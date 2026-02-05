/**
 * FileSearchPanel - 文件搜索面板
 *
 * 支持文件名模糊搜索，快捷键 Ctrl+P
 */

import { useState, useCallback, useEffect, useMemo, useRef } from 'react'
import { Search, X } from 'lucide-react'
import { useFileStore } from '@/stores/fileStore'
import { useProjectStore } from '@/stores/projectStore'
import { useEditorStore } from '@/stores/editorStore'
import { cn } from '@/lib/utils'
import { getFileIcon } from '@/components/file-explorer/FileTree'
import { Input } from '@/components/ui/input'

interface FileSearchPanelProps {
  onClose?: () => void
}

interface FileMatch {
  path: string
  name: string
  type: 'file' | 'folder'
  score: number
  matchedRanges: [number, number][]
}

export function FileSearchPanel({ onClose }: FileSearchPanelProps) {
  const [query, setQuery] = useState('')
  const [selectedIndex, setSelectedIndex] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)

  const fileTree = useFileStore(state => state.fileTree)
  const selectFile = useFileStore(state => state.selectFile)
  const currentProject = useProjectStore(state => state.currentProject)
  const { editorGroups } = useEditorStore()

  // 自动聚焦输入框
  useEffect(() => {
    inputRef.current?.focus()
  }, [])

  // 扁平化文件树并进行搜索
  const searchResults = useMemo(() => {
    if (!query.trim()) {
      return []
    }

    const results: FileMatch[] = []
    const searchLower = query.toLowerCase()

    // 递归搜索文件树
    const searchInTree = (nodes: any[], depth = 0) => {
      for (const node of nodes) {
        const name = node.name.toLowerCase()
        const path = node.path

        // 计算匹配分数和范围
        let score = 0
        const matchedRanges: [number, number][] = []

        if (name.includes(searchLower)) {
          // 完全匹配优先级最高
          if (name === searchLower) {
            score = 100 - depth
          } else {
            score = 50 - depth
            // 记录匹配位置
            let start = name.indexOf(searchLower)
            matchedRanges.push([start, start + searchLower.length])
          }
        }

        // 只返回匹配的文件
        if (score > 0 && node.type === 'file') {
          results.push({
            path,
            name: node.name,
            type: node.type,
            score,
            matchedRanges
          })
        }

        // 递归搜索子目录
        if (node.children) {
          searchInTree(node.children, depth + 1)
        }
      }
    }

    searchInTree(fileTree)

    // 按分数排序
    return results.sort((a, b) => b.score - a.score)
  }, [query, fileTree])

  // 处理选择文件
  const handleSelectFile = useCallback((match: FileMatch) => {
    selectFile(match.path)
    onClose?.()
  }, [selectFile, onClose])

  // 键盘导航
  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault()
        setSelectedIndex(prev =>
          prev < searchResults.length - 1 ? prev + 1 : prev
        )
        break
      case 'ArrowUp':
        e.preventDefault()
        setSelectedIndex(prev => prev > 0 ? prev - 1 : 0)
        break
      case 'Enter':
        e.preventDefault()
        if (searchResults[selectedIndex]) {
          handleSelectFile(searchResults[selectedIndex])
        }
        break
      case 'Escape':
        e.preventDefault()
        onClose?.()
        break
    }
  }, [searchResults, selectedIndex, handleSelectFile, onClose])

  // 高亮匹配的文本
  const highlightMatch = (text: string, ranges: [number, number][]) => {
    if (ranges.length === 0) return text

    let lastIndex = 0
    const parts: React.ReactNode[] = []

    ranges.forEach(([start, end], i) => {
      // 添加匹配前的文本
      if (start > lastIndex) {
        parts.push(<span key={`before-${i}`}>{text.slice(lastIndex, start)}</span>)
      }
      // 添加高亮的匹配文本
      parts.push(
        <span key={`match-${i}`} className="bg-primary/30 text-white font-semibold">
          {text.slice(start, end)}
        </span>
      )
      lastIndex = end
    })

    // 添加剩余文本
    if (lastIndex < text.length) {
      parts.push(<span key="after">{text.slice(lastIndex)}</span>)
    }

    return parts
  }

  if (!currentProject) {
    return (
      <div className="p-4 text-sm text-muted-foreground text-center">
        请先打开项目
      </div>
    )
  }

  return (
    <div className="flex flex-col h-full">
      {/* 搜索输入框 */}
      <div className="p-2 border-b border-border/40">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            ref={inputRef}
            type="text"
            placeholder="搜索文件... (Ctrl+P)"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value)
              setSelectedIndex(0)
            }}
            onKeyDown={handleKeyDown}
            className="pl-10 pr-8 h-8 text-xs bg-[#3c3c3c] border-[#3c3c3c] focus:bg-[#4a4a4a]"
          />
          {query && (
            <button
              className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
              onClick={() => {
                setQuery('')
                setSelectedIndex(0)
                inputRef.current?.focus()
              }}
            >
              <X className="w-3 h-3" />
            </button>
          )}
        </div>
      </div>

      {/* 搜索结果 */}
      <div className="flex-1 overflow-y-auto">
        {!query.trim() ? (
          <div className="p-4 text-sm text-muted-foreground text-center">
            <Search className="w-8 h-8 mx-auto mb-2 opacity-30" />
            <p>输入文件名进行搜索</p>
            <p className="text-xs mt-1 opacity-60">支持模糊匹配</p>
          </div>
        ) : searchResults.length === 0 ? (
          <div className="p-4 text-sm text-muted-foreground text-center">
            未找到匹配的文件
          </div>
        ) : (
          <div className="p-1">
            <div className="text-xs text-muted-foreground px-2 py-1">
              找到 {searchResults.length} 个结果
            </div>
            {searchResults.map((match, index) => {
              const isSelected = index === selectedIndex
              const fileName = match.name
              const filePath = match.path
              const relativePath = filePath.replace(currentProject.path + '\\', '').replace(/\//g, '/')

              return (
                <button
                  key={match.path}
                  className={cn(
                    'w-full text-left px-2 py-1.5 rounded text-xs flex items-center gap-2 transition-colors',
                    isSelected
                      ? 'bg-primary/20 text-white'
                      : 'hover:bg-[#2a2a2a] text-muted-foreground hover:text-white'
                  )}
                  onClick={() => handleSelectFile(match)}
                  onMouseEnter={() => setSelectedIndex(index)}
                >
                  {getFileIcon(fileName)}
                  <div className="flex-1 min-w-0">
                    <div className="truncate">
                      {highlightMatch(fileName, match.matchedRanges)}
                    </div>
                    <div className="text-[10px] text-muted-foreground truncate mt-0.5">
                      {relativePath}
                    </div>
                  </div>
                </button>
              )
            })}
          </div>
        )}
      </div>

      {/* 底部提示 */}
      {searchResults.length > 0 && (
        <div className="p-2 border-t border-border/40 text-[10px] text-muted-foreground">
          <div className="flex justify-between">
            <span>↑↓ 选择</span>
            <span>Enter 打开</span>
            <span>Esc 关闭</span>
          </div>
        </div>
      )}
    </div>
  )
}
