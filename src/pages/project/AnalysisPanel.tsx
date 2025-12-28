/**
 * AnalysisPanel - 分析工具面板
 */

import { useState } from 'react'
import { Database, Folder, Network, Search, Wrench, type LucideIcon } from 'lucide-react'
import { useProjectStore } from '@/stores/projectStore'
import { useFileStore } from '@/stores/fileStore'
import { useUIStore } from '@/stores/uiStore'
import { astService } from '@/shared/api/services'
import { api } from '@/shared/api/client'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'

interface Tool {
  name: string
  description: string
  icon: LucideIcon
  action: () => void | Promise<void>
  variant: 'default' | 'outline' | 'destructive' | 'secondary'
  disabled?: boolean
}

interface ToolSection {
  title: string
  tools: Tool[]
}

export function AnalysisPanel() {
  const { currentProject } = useProjectStore()
  const { selectedFile, fileTree } = useFileStore()
  const { addLog } = useUIStore()

  const [symbolSearchQuery, setSymbolSearchQuery] = useState('')
  const [isSearching, setIsSearching] = useState(false)
  const [searchResults, setSearchResults] = useState<any[]>([])

  const handleBuildIndex = async () => {
    if (!currentProject) return
    try {
      addLog('正在构建 AST 索引...', 'system')
      const result = await astService.buildIndex(currentProject.path)
      addLog(`AST 索引构建完成: ${result.message}`, 'system')
    } catch (err) {
      addLog(`构建索引失败: ${err}`, 'system')
    }
  }

  const handleListFiles = async () => {
    if (!currentProject) return
    try {
      addLog('正在列出文件...', 'system')
      const result = await api.listFiles(currentProject.path)
      addLog(`找到 ${Array.isArray(result) ? result.length : 0} 个文件`, 'system')
    } catch (err) {
      addLog(`列出文件失败: ${err}`, 'system')
    }
  }

  const handleGetCodeStructure = async () => {
    if (!selectedFile) {
      addLog('请先选择一个文件', 'system')
      return
    }
    try {
      addLog(`正在获取 ${selectedFile} 的代码结构...`, 'system')
      const result = await astService.getCodeStructure(selectedFile)
      addLog(`代码结构: ${JSON.stringify(result, null, 2)}`, 'system')
    } catch (err) {
      addLog(`获取代码结构失败: ${err}`, 'system')
    }
  }

  const handleSymbolSearch = async () => {
    if (!symbolSearchQuery.trim()) return
    setIsSearching(true)
    setSearchResults([])
    try {
      addLog(`搜索符号: ${symbolSearchQuery}`, 'system')
      const results = await astService.searchSymbol(symbolSearchQuery)
      setSearchResults(Array.isArray(results) ? results : [])
      addLog(`找到 ${Array.isArray(results) ? results.length : 0} 个结果`, 'system')
    } catch (err) {
      addLog(`搜索符号失败: ${err}`, 'system')
    } finally {
      setIsSearching(false)
    }
  }

  const toolSections: ToolSection[] = [
    {
      title: '项目分析',
      tools: [
        {
          name: '构建 AST 索引',
          description: '分析项目源代码，构建抽象语法树索引',
          icon: Database,
          action: handleBuildIndex,
          variant: 'default' as const,
        },
        {
          name: '列出所有文件',
          description: '获取项目中所有文件的列表',
          icon: Folder,
          action: handleListFiles,
          variant: 'outline' as const,
        },
      ],
    },
    {
      title: '当前文件',
      tools: [
        {
          name: '获取代码结构',
          description: selectedFile
            ? `分析 ${selectedFile.split(/[/\\]/).pop()} 的结构`
            : '请先选择一个文件',
          icon: Network,
          action: handleGetCodeStructure,
          variant: 'outline' as const,
          disabled: !selectedFile,
        },
      ],
    },
  ]

  return (
    <div className="h-full p-6 overflow-auto">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="mb-6">
          <h1 className="text-2xl font-bold">分析工具</h1>
          <p className="text-sm text-muted-foreground mt-1">
            使用 AST 分析和代码理解工具深入了解项目结构
          </p>
        </div>

        {/* Tools Grid */}
        <div className="space-y-6">
          {toolSections.map((section) => (
            <div key={section.title}>
              <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-3">
                {section.title}
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {section.tools.map((tool) => {
                  const Icon = tool.icon
                  return (
                    <Card
                      key={tool.name}
                      className="p-4 hover:shadow-md transition-shadow"
                    >
                      <div className="flex items-start gap-4">
                        <div className={`p-2 rounded-lg bg-muted ${
                          tool.disabled ? 'opacity-50' : ''
                        }`}>
                          <Icon className="w-5 h-5 text-primary" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <h3 className="font-medium text-sm mb-1">{tool.name}</h3>
                          <p className="text-xs text-muted-foreground mb-3">
                            {tool.description}
                          </p>
                          <Button
                            variant={tool.variant}
                            size="sm"
                            onClick={tool.action}
                            disabled={tool.disabled}
                            className="w-full"
                          >
                            <Wrench className="w-3.5 h-3.5 mr-2" />
                            执行
                          </Button>
                        </div>
                      </div>
                    </Card>
                  )
                })}
              </div>
            </div>
          ))}
        </div>

        {/* Symbol Search */}
        <div className="mt-8">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-3">
            符号搜索
          </h2>
          <Card className="p-4">
            <div className="flex gap-2 mb-4">
              <Input
                placeholder="输入符号名称（函数、类、变量等）..."
                value={symbolSearchQuery}
                onChange={(e) => setSymbolSearchQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSymbolSearch()}
                className="flex-1"
              />
              <Button
                onClick={handleSymbolSearch}
                disabled={isSearching || !symbolSearchQuery.trim()}
              >
                <Search className="w-4 h-4 mr-2" />
                搜索
              </Button>
            </div>

            {searchResults.length > 0 && (
              <ScrollArea className="h-[300px]">
                <div className="space-y-2">
                  {searchResults.map((result, index) => (
                    <div
                      key={index}
                      className="p-3 bg-muted/30 rounded-lg hover:bg-muted/50 cursor-pointer transition-colors"
                      onClick={() => {
                        if (result.file_path) {
                          addLog(`跳转到: ${result.file_path}:${result.line}`, 'system')
                        }
                      }}
                    >
                      <div className="flex items-center gap-2 mb-1">
                        <Badge variant="outline" className="text-[10px]">
                          {result.kind || 'unknown'}
                        </Badge>
                        <span className="text-sm font-medium">{result.name}</span>
                      </div>
                      <div className="text-xs text-muted-foreground font-mono">
                        {result.file_path}:{result.line}
                      </div>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            )}

            {isSearching && (
              <div className="text-center py-8 text-muted-foreground text-sm">
                搜索中...
              </div>
            )}

            {symbolSearchQuery && searchResults.length === 0 && !isSearching && (
              <div className="text-center py-8 text-muted-foreground text-sm">
                未找到匹配的符号
              </div>
            )}
          </Card>
        </div>

        {/* Project Info */}
        {currentProject && (
          <div className="mt-8">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-3">
              项目信息
            </h2>
            <Card className="p-4">
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-muted-foreground">项目名称:</span>
                  <span className="ml-2 font-medium">{currentProject.name}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">项目路径:</span>
                  <span className="ml-2 font-mono text-xs">{currentProject.path}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">创建时间:</span>
                  <span className="ml-2">{new Date(currentProject.created_at).toLocaleString()}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">文件数量:</span>
                  <span className="ml-2 font-medium">{fileTree.length}</span>
                </div>
              </div>
            </Card>
          </div>
        )}
      </div>
    </div>
  )
}
