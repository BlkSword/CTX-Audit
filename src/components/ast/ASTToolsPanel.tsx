/**
 * ASTToolsPanel - AST 分析工具面板
 *
 * 这是一个可展开的工具面板，包含以下功能：
 * - 符号搜索
 * - 代码大纲（当前文件的符号列表）
 * - 调用图分析
 * - 类型层次结构
 */

import { useState, useEffect } from 'react'
import { Search, GitGraph, Layers, ChevronRight, ChevronDown, FileCode, Loader2 } from 'lucide-react'
import { useEditorStore } from '@/stores/editorStore'
import { astService } from '@/shared/api/services/ast'
import { useProjectStore } from '@/stores/projectStore'
import { cn } from '@/lib/utils'
import type { GraphData } from '@/shared/types'

// ==================== 类型定义 ====================

type ToolTab = 'search' | 'outline' | 'callgraph' | 'hierarchy'

interface SymbolInfo {
  name: string
  kind: string
  file_path: string
  line: number
  column: number  // 必需字段
}

interface SearchResult {
  name: string
  kind: string
  file_path: string
  line: number
  definition: string
}

interface CallNode {
  name: string
  file_path: string
  line: number
  children: CallNode[]
}

// CallGraph 结果类型
type CallGraphResult = CallNode | GraphData

// ==================== 子组件 ====================

/**
 * 符号搜索工具
 */
function SymbolSearchTool({ onSymbolSelect }: { onSymbolSelect: (symbol: SymbolInfo) => void }) {
  const { currentProject } = useProjectStore()
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<SearchResult[]>([])
  const [isSearching, setIsSearching] = useState(false)

  const handleSearch = async () => {
    if (!query.trim() || !currentProject) return

    setIsSearching(true)
    try {
      const symbols = await astService.searchSymbol(query, currentProject.id)
      setResults(symbols.map(s => ({
        name: s.name,
        kind: s.kind,
        file_path: s.file_path,
        line: s.line,
        definition: '',
      })))
    } finally {
      setIsSearching(false)
    }
  }

  return (
    <div className="flex flex-col h-full">
      {/* 搜索输入框 */}
      <div className="flex gap-1 p-2 border-b border-[var(--vscode-sideBar-border)]">
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
          placeholder="搜索符号..."
          className="flex-1 bg-[var(--vscode-input-background)] text-[var(--vscode-input-foreground)] text-xs px-2 py-1.5 rounded border border-[var(--vscode-input-border)] focus:outline-none focus:border-[var(--vscode-focusBorder)]"
        />
        <button
          onClick={handleSearch}
          disabled={isSearching || !query.trim()}
          className="px-2 py-1 rounded bg-[var(--vscode-button-background)] text-[var(--vscode-button-foreground)] hover:bg-[var(--vscode-button-hoverBackground)] disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-xs"
        >
          {isSearching ? (
            <Loader2 className="w-3 h-3 animate-spin" />
          ) : (
            <Search className="w-3 h-3" />
          )}
        </button>
      </div>

      {/* 搜索结果 */}
      <div className="flex-1 overflow-auto">
        {results.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-[var(--vscode-descriptionForeground)] p-4">
            <Search className="w-8 h-8 mb-2 opacity-50" />
            <p className="text-xs text-center">
              {query ? '未找到匹配的符号' : '输入符号名称进行搜索'}
            </p>
          </div>
        ) : (
          <div className="divide-y divide-[var(--vscode-sideBar-border)]/50">
            {results.map((result, index) => (
              <div
                key={index}
                onClick={() => onSymbolSelect({
                  name: result.name,
                  kind: result.kind,
                  file_path: result.file_path,
                  line: result.line,
                  column: 0,
                })}
                className="flex items-start gap-2 p-2 hover:bg-[var(--vscode-list-hoverBackground)] cursor-pointer transition-colors"
              >
                <div className="mt-0.5">
                  <GitGraph className="w-3 h-3 text-[var(--vscode-textLink-foreground)]" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium text-[var(--vscode-foreground)] truncate">
                    {result.name}
                  </div>
                  <div className="flex items-center gap-2 mt-0.5 text-[10px] text-[var(--vscode-descriptionForeground)]">
                    <span className="capitalize">{result.kind}</span>
                    <span>:{result.line}</span>
                  </div>
                  <div className="text-[10px] text-[var(--vscode-descriptionForeground)] truncate mt-0.5">
                    {result.file_path}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

/**
 * 代码大纲工具
 */
function CodeOutlineTool({ symbols, onSymbolSelect }: { symbols: SymbolInfo[], onSymbolSelect: (symbol: SymbolInfo) => void }) {
  const [expandedKinds, setExpandedKinds] = useState<Set<string>>(new Set(['function', 'class', 'interface']))

  const toggleKind = (kind: string) => {
    setExpandedKinds(prev => {
      const newSet = new Set(prev)
      if (newSet.has(kind)) {
        newSet.delete(kind)
      } else {
        newSet.add(kind)
      }
      return newSet
    })
  }

  // 按类型分组符号
  const symbolsByKind = symbols.reduce((acc, symbol) => {
    if (!acc[symbol.kind]) {
      acc[symbol.kind] = []
    }
    acc[symbol.kind].push(symbol)
    return acc
  }, {} as Record<string, SymbolInfo[]>)

  const kindOrder = ['class', 'interface', 'function', 'variable', 'method']
  const kindIcons: Record<string, string> = {
    class: '📦',
    interface: '🔌',
    function: '⚡',
    variable: '📌',
    method: '⚙️',
  }

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b border-[var(--vscode-sideBar-border)]">
        <div className="text-xs font-medium text-[var(--vscode-foreground)]">代码大纲</div>
      </div>

      <div className="flex-1 overflow-auto">
        {symbols.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-[var(--vscode-descriptionForeground)] p-4">
            <FileCode className="w-8 h-8 mb-2 opacity-50" />
            <p className="text-xs text-center">当前文件没有符号信息</p>
          </div>
        ) : (
          <div>
            {kindOrder.map(kind => {
              const kindSymbols = symbolsByKind[kind]
              if (!kindSymbols || kindSymbols.length === 0) return null

              const isExpanded = expandedKinds.has(kind)

              return (
                <div key={kind}>
                  <button
                    onClick={() => toggleKind(kind)}
                    className="flex items-center gap-1 w-full px-2 py-1 text-xs text-[var(--vscode-foreground)] hover:bg-[var(--vscode-list-hoverBackground)] transition-colors"
                  >
                    {isExpanded ? (
                      <ChevronDown className="w-3 h-3" />
                    ) : (
                      <ChevronRight className="w-3 h-3" />
                    )}
                    <span>{kindIcons[kind] || '•'}</span>
                    <span className="capitalize">{kind}</span>
                    <span className="ml-auto text-[var(--vscode-descriptionForeground)]">
                      {kindSymbols.length}
                    </span>
                  </button>

                  {isExpanded && (
                    <div className="ml-4">
                      {kindSymbols.map((symbol, index) => (
                        <div
                          key={index}
                          onClick={() => onSymbolSelect(symbol)}
                          className="flex items-center gap-2 px-2 py-1 text-xs text-[var(--vscode-foreground)] hover:bg-[var(--vscode-list-hoverBackground)] cursor-pointer transition-colors"
                        >
                          <Layers className="w-3 h-3 text-[var(--vscode-descriptionForeground)]" />
                          <span className="flex-1 truncate">{symbol.name}</span>
                          <span className="text-[var(--vscode-descriptionForeground)]">:{symbol.line}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}

/**
 * 调用图工具
 */
function CallGraphTool() {
  const [entryFunction, setEntryFunction] = useState('')
  const [callGraph, setCallGraph] = useState<CallGraphResult | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const { currentProject } = useProjectStore()

  const handleBuildGraph = async () => {
    if (!entryFunction.trim() || !currentProject) return

    setIsLoading(true)
    try {
      const graph = await astService.getCallGraph(entryFunction, 3, currentProject.id)
      setCallGraph(graph)
    } finally {
      setIsLoading(false)
    }
  }

  // 判断结果是 CallNode 还是 GraphData
  const isCallNode = (result: CallGraphResult | null): result is CallNode => {
    return result !== null && 'children' in result
  }

  const renderCallNode = (node: CallNode, depth: number = 0) => (
    <div key={`${node.name}-${node.line}`} className="ml-2">
      <div
        className="flex items-center gap-1 px-2 py-1 text-xs hover:bg-[var(--vscode-list-hoverBackground)] cursor-pointer transition-colors rounded"
        style={{ marginLeft: `${depth * 8}px` }}
      >
        <GitGraph className="w-3 h-3 text-[var(--vscode-textLink-foreground)] shrink-0" />
        <span className="flex-1 truncate">{node.name}</span>
      </div>
      {node.children && node.children.map(child => renderCallNode(child, depth + 1))}
    </div>
  )

  return (
    <div className="flex flex-col h-full">
      <div className="flex gap-1 p-2 border-b border-[var(--vscode-sideBar-border)]">
        <input
          type="text"
          value={entryFunction}
          onChange={(e) => setEntryFunction(e.target.value)}
          placeholder="输入函数名..."
          className="flex-1 bg-[var(--vscode-input-background)] text-[var(--vscode-input-foreground)] text-xs px-2 py-1.5 rounded border border-[var(--vscode-input-border)] focus:outline-none focus:border-[var(--vscode-focusBorder)]"
        />
        <button
          onClick={handleBuildGraph}
          disabled={isLoading || !entryFunction.trim()}
          className="px-2 py-1 rounded bg-[var(--vscode-button-background)] text-[var(--vscode-button-foreground)] hover:bg-[var(--vscode-button-hoverBackground)] disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-xs"
        >
          {isLoading ? (
            <Loader2 className="w-3 h-3 animate-spin" />
          ) : (
            <GitGraph className="w-3 h-3" />
          )}
        </button>
      </div>

      <div className="flex-1 overflow-auto p-2">
        {!callGraph ? (
          <div className="flex flex-col items-center justify-center h-full text-[var(--vscode-descriptionForeground)]">
            <GitGraph className="w-8 h-8 mb-2 opacity-50" />
            <p className="text-xs text-center">输入函数名查看调用关系图</p>
          </div>
        ) : isCallNode(callGraph) ? (
          <div className="text-xs">
            {renderCallNode(callGraph)}
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center h-full text-[var(--vscode-descriptionForeground)]">
            <GitGraph className="w-8 h-8 mb-2 opacity-50" />
            <p className="text-xs text-center">图谱视图暂未实现</p>
          </div>
        )}
      </div>
    </div>
  )
}

// ==================== 主组件 ====================

interface ASTToolsPanelProps {
  onSymbolSelect?: (symbol: SymbolInfo) => void
}

export function ASTToolsPanel({ onSymbolSelect }: ASTToolsPanelProps) {
  const [activeTab, setActiveTab] = useState<ToolTab>('outline')
  const { editorGroups } = useEditorStore()
  const [symbols, setSymbols] = useState<SymbolInfo[]>([])

  // 获取当前活动文件
  const activeFile = editorGroups[0]?.activeFile

  // 加载文件符号
  useEffect(() => {
    if (activeFile) {
      astService.getCodeStructure(activeFile.path)
        .then((symbols) => {
          // 将 Symbol 转换为 SymbolInfo (确保 column 存在)
          setSymbols(symbols.map(s => ({
            ...s,
            column: s.column ?? 0  // 如果 column 不存在，使用默认值 0
          })))
        })
        .catch(() => setSymbols([]))
    } else {
      setSymbols([])
    }
  }, [activeFile])

  const tabs = [
    { id: 'search' as ToolTab, label: '符号搜索', icon: Search },
    { id: 'outline' as ToolTab, label: '代码大纲', icon: Layers },
    { id: 'callgraph' as ToolTab, label: '调用图', icon: GitGraph },
  ]

  return (
    <div className="flex flex-col h-full bg-[var(--vscode-sideBar-background)]">
      {/* 标签页 */}
      <div className="flex items-center border-b border-[var(--vscode-sideBar-border)]">
        {tabs.map((tab) => {
          const Icon = tab.icon
          const isActive = activeTab === tab.id

          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={cn(
                "flex items-center gap-1.5 px-3 py-2 text-xs font-medium transition-all flex-1",
                isActive
                  ? "bg-[var(--vscode-sideBar-background)] text-[var(--vscode-foreground)] border-b-2 border-b-[var(--vscode-activityBar-foreground)]"
                  : "text-[var(--vscode-activityBar-inactiveForeground)] hover:text-[var(--vscode-foreground)] hover:bg-[var(--vscode-toolbar-hoverBackground)]"
              )}
            >
              <Icon className="w-3.5 h-3.5" />
              {tab.label}
            </button>
          )
        })}
      </div>

      {/* 工具内容 */}
      <div className="flex-1 overflow-hidden">
        {activeTab === 'search' && (
          <SymbolSearchTool onSymbolSelect={(s) => onSymbolSelect?.(s)} />
        )}
        {activeTab === 'outline' && (
          <CodeOutlineTool symbols={symbols} onSymbolSelect={(s) => onSymbolSelect?.(s)} />
        )}
        {activeTab === 'callgraph' && <CallGraphTool />}
      </div>
    </div>
  )
}
