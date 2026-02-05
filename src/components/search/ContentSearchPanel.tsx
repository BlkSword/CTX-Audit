/**
 * ContentSearchPanel - 内容搜索面板
 *
 * 支持跨文件内容搜索，快捷键 Ctrl+Shift+F
 */

import { useState, useCallback, useEffect, useMemo, useRef } from 'react'
import { Search, File, X, Loader2, ChevronDown, ChevronRight } from 'lucide-react'
import { useFileStore } from '@/stores/fileStore'
import { useProjectStore } from '@/stores/projectStore'
import { useEditorStore } from '@/stores/editorStore'
import { tauriApi } from '@/shared/api/tauri-client'
import { cn } from '@/lib/utils'
import { Input } from '@/components/ui/input'
import { Checkbox } from '@/components/ui/checkbox'

interface ContentSearchPanelProps {
  onClose?: () => void
}

interface SearchResult {
  path: string
  name: string
  line: number
  content: string
  matchedText: string
  lineStart: number
  lineEnd: number
}

interface ExpandedResults {
  [path: string]: boolean
}

export function ContentSearchPanel({ onClose }: ContentSearchPanelProps) {
  const [query, setQuery] = useState('')
  const [isSearching, setIsSearching] = useState(false)
  const [results, setResults] = useState<SearchResult[]>([])
  const [selectedIndex, setSelectedIndex] = useState(0)
  const [expandedResults, setExpandedResults] = useState<ExpandedResults>({})
  const [caseSensitive, setCaseSensitive] = useState(false)
  const [useRegex, setUseRegex] = useState(false)

  const inputRef = useRef<HTMLInputElement>(null)
  const currentProject = useProjectStore(state => state.currentProject)
  const selectFile = useFileStore(state => state.selectFile)
  const { editorGroups } = useEditorStore()

  // 自动聚焦输入框
  useEffect(() => {
    inputRef.current?.focus()
  }, [])

  // 获取所有文件路径
  const getAllFilePaths = useCallback((nodes: any[]): string[] => {
    const paths: string[] = []

    const traverse = (nodeList: any[]) => {
      for (const node of nodeList) {
        if (node.type === 'file') {
          paths.push(node.path)
        } else if (node.children) {
          traverse(node.children)
        }
      }
    }

    traverse(nodes)
    return paths
  }, [])

  // 执行搜索
  const performSearch = useCallback(async () => {
    const trimmedQuery = query.trim()
    if (!trimmedQuery || !currentProject) {
      setResults([])
      return
    }

    setIsSearching(true)
    setResults([])

    try {
      // 获取所有文件路径
      const fileTree = useFileStore.getState().fileTree
      const filePaths = getAllFilePaths(fileTree)

      const searchResults: SearchResult[] = []

      // 限制并发搜索的文件数
      const CHUNK_SIZE = 10
      for (let i = 0; i < filePaths.length; i += CHUNK_SIZE) {
        const chunk = filePaths.slice(i, i + CHUNK_SIZE)

        await Promise.all(
          chunk.map(async (filePath) => {
            try {
              const content = await tauriApi.readFile(filePath)
              const lines = content.split('\n')

              lines.forEach((line, lineIndex) => {
                const searchIn = caseSensitive ? line : line.toLowerCase()
                const searchQuery = caseSensitive ? trimmedQuery : trimmedQuery.toLowerCase()

                let matched = false
                let matchedText = ''

                if (useRegex) {
                  try {
                    const regex = new RegExp(trimmedQuery, caseSensitive ? 'g' : 'gi')
                    const matches = line.match(regex)
                    if (matches) {
                      matched = true
                      matchedText = matches[0]
                    }
                  } catch {
                    // 无效的正则表达式，忽略
                  }
                } else {
                  const index = searchIn.indexOf(searchQuery)
                  if (index !== -1) {
                    matched = true
                    matchedText = line.substring(index, index + trimmedQuery.length)
                  }
                }

                if (matched) {
                  // 计算该行在文件中的位置（字符位置）
                  const lineStart = content.split('\n').slice(0, lineIndex).join('\n').length
                  const lineEnd = lineStart + line.length

                  searchResults.push({
                    path: filePath,
                    name: filePath.split('\\').pop() || filePath,
                    line: lineIndex + 1,
                    content: line.trim(),
                    matchedText,
                    lineStart,
                    lineEnd
                  })
                }
              })
            } catch {
              // 忽略无法读取的文件
            }
          })
        )
      }

      setResults(searchResults)
      setSelectedIndex(0)

      // 自动展开第一个结果
      if (searchResults.length > 0) {
        setExpandedResults({ [searchResults[0].path]: true })
      }
    } catch (error) {
      console.error('Search failed:', error)
    } finally {
      setIsSearching(false)
    }
  }, [query, caseSensitive, useRegex, currentProject, getAllFilePaths])

  // 防抖搜索
  useEffect(() => {
    const timer = setTimeout(() => {
      if (query.trim()) {
        performSearch()
      }
    }, 300)

    return () => clearTimeout(timer)
  }, [query, performSearch])

  // 按文件分组结果
  const groupedResults = useMemo(() => {
    const groups: Record<string, SearchResult[]> = {}
    results.forEach(result => {
      if (!groups[result.path]) {
        groups[result.path] = []
      }
      groups[result.path].push(result)
    })
    return groups
  }, [results])

  // 切换展开/折叠
  const toggleExpand = (path: string) => {
    setExpandedResults(prev => ({
      ...prev,
      [path]: !prev[path]
    }))
  }

  // 处理选择结果
  const handleSelectResult = useCallback(async (result: SearchResult) => {
    try {
      // 先读取并选择文件
      await selectFile(result.path)

      // 跳转到指定行
      const { editorGroups } = useEditorStore.getState()
      const firstGroup = editorGroups[0]
      if (firstGroup?.editorInstance) {
        const editor = firstGroup.editorInstance
        editor.revealLineInCenter(result.line)
        editor.setPosition({ lineNumber: result.line, column: 1 })
        editor.focus()
      }

      onClose?.()
    } catch (error) {
      console.error('Failed to open file:', error)
    }
  }, [selectFile, onClose])

  // 键盘导航
  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault()
        setSelectedIndex(prev =>
          prev < results.length - 1 ? prev + 1 : prev
        )
        break
      case 'ArrowUp':
        e.preventDefault()
        setSelectedIndex(prev => prev > 0 ? prev - 1 : 0)
        break
      case 'Enter':
        e.preventDefault()
        if (results[selectedIndex]) {
          handleSelectResult(results[selectedIndex])
        }
        break
      case 'Escape':
        e.preventDefault()
        onClose?.()
        break
    }
  }, [results, selectedIndex, handleSelectResult, onClose])

  // 高亮匹配的文本
  const highlightMatch = (text: string, matched: string) => {
    const index = (caseSensitive ? text : text.toLowerCase()).indexOf(
      caseSensitive ? matched : matched.toLowerCase()
    )

    if (index === -1) return text

    return (
      <>
        <span>{text.substring(0, index)}</span>
        <span className="bg-primary/30 text-white font-semibold px-0.5 rounded">
          {text.substring(index, index + matched.length)}
        </span>
        <span>{text.substring(index + matched.length)}</span>
      </>
    )
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
        <div className="relative mb-2">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            ref={inputRef}
            type="text"
            placeholder="搜索内容... (Ctrl+Shift+F)"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            className="pl-10 pr-8 h-8 text-xs bg-[#3c3c3c] border-[#3c3c3c] focus:bg-[#4a4a4a]"
          />
          {query && (
            <button
              className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
              onClick={() => {
                setQuery('')
                setResults([])
                inputRef.current?.focus()
              }}
            >
              <X className="w-3 h-3" />
            </button>
          )}
        </div>

        {/* 搜索选项 */}
        <div className="flex items-center gap-4 px-2">
          <label className="flex items-center gap-1.5 text-xs text-muted-foreground cursor-pointer">
            <Checkbox
              checked={caseSensitive}
              onCheckedChange={(checked) => setCaseSensitive(checked === true)}
              className="w-3 h-3"
            />
            区分大小写
          </label>
          <label className="flex items-center gap-1.5 text-xs text-muted-foreground cursor-pointer">
            <Checkbox
              checked={useRegex}
              onCheckedChange={(checked) => setUseRegex(checked === true)}
              className="w-3 h-3"
            />
            正则表达式
          </label>
        </div>
      </div>

      {/* 搜索结果 */}
      <div className="flex-1 overflow-y-auto">
        {isSearching ? (
          <div className="flex items-center justify-center p-8">
            <Loader2 className="w-5 h-5 text-muted-foreground animate-spin mr-2" />
            <span className="text-sm text-muted-foreground">搜索中...</span>
          </div>
        ) : !query.trim() ? (
          <div className="p-4 text-sm text-muted-foreground text-center">
            <Search className="w-8 h-8 mx-auto mb-2 opacity-30" />
            <p>输入搜索内容</p>
            <p className="text-xs mt-1 opacity-60">支持文本和正则表达式</p>
          </div>
        ) : results.length === 0 ? (
          <div className="p-4 text-sm text-muted-foreground text-center">
            未找到匹配内容
          </div>
        ) : (
          <div className="p-1">
            <div className="text-xs text-muted-foreground px-2 py-1">
              找到 {results.length} 条结果
            </div>
            {Object.entries(groupedResults).map(([filePath, fileResults]) => {
              const isExpanded = expandedResults[filePath]
              const fileName = filePath.split('\\').pop() || filePath
              const relativePath = filePath.replace(currentProject.path + '\\', '').replace(/\//g, '/')

              return (
                <div key={filePath} className="mb-1">
                  {/* 文件标题 */}
                  <button
                    className={cn(
                      'w-full text-left px-2 py-1 rounded text-xs flex items-center gap-2 transition-colors',
                      'hover:bg-[#2a2a2a] text-muted-foreground hover:text-white'
                    )}
                    onClick={() => toggleExpand(filePath)}
                  >
                    {isExpanded ? (
                      <ChevronDown className="w-3 h-3" />
                    ) : (
                      <ChevronRight className="w-3 h-3" />
                    )}
                    <File className="w-3 h-3" />
                    <span className="flex-1 truncate">{fileName}</span>
                    <span className="text-[10px] opacity-60">({fileResults.length} 条)</span>
                  </button>

                  {/* 文件内容匹配 */}
                  {isExpanded && (
                    <div className="ml-4 border-l border-border/40 pl-1">
                      {fileResults.map((result, index) => {
                        const globalIndex = results.indexOf(result)
                        const isSelected = globalIndex === selectedIndex

                        return (
                          <button
                            key={`${result.path}-${result.line}`}
                            className={cn(
                              'w-full text-left px-2 py-1 rounded text-xs flex gap-2 transition-colors',
                              isSelected
                                ? 'bg-primary/20 text-white'
                                : 'hover:bg-[#2a2a2a] text-muted-foreground hover:text-white'
                            )}
                            onClick={() => handleSelectResult(result)}
                            onMouseEnter={() => setSelectedIndex(globalIndex)}
                          >
                            <span className="text-[10px] text-muted-foreground select-none min-w-[30px]">
                              {result.line}
                            </span>
                            <span className="flex-1 truncate font-mono">
                              {highlightMatch(result.content, result.matchedText)}
                            </span>
                          </button>
                        )
                      })}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* 底部提示 */}
      {results.length > 0 && (
        <div className="p-2 border-t border-border/40 text-[10px] text-muted-foreground">
          <div className="flex justify-between">
            <span>↑↓ 选择</span>
            <span>Enter 跳转</span>
            <span>Esc 关闭</span>
          </div>
        </div>
      )}
    </div>
  )
}
