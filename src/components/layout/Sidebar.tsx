/**
 * Sidebar - VSCode 风格侧边栏
 *
 * 根据活动栏显示不同的侧边栏内容：
 * - explorer: 文件资源管理器
 * - search: 搜索
 * - ast-tools: AST 工具
 * - scan-results: 扫描结果
 * - terminal: 终端
 */

import { useState, useCallback, memo } from 'react'
import { FileText, Search, GitGraph, BarChart3, Terminal, Folder, FileCode, Trash2 } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useLayoutStore, type ActivityId } from '@/stores/layoutStore'
import { FileTree } from '@/components/file-explorer/FileTree'
import { useFileStore } from '@/stores/fileStore'
import { useProjectStore } from '@/stores/projectStore'
import { cn } from '@/lib/utils'
import { confirmDialog } from '@/components/ui/confirm-dialog'
import { Button } from '@/components/ui/button'
import { FileSearchPanel, ContentSearchPanel } from '@/components/search'
import { ASTToolsPanel } from '@/components/ast/ASTToolsPanel'
import { ScanResultsPanel } from '@/components/scan/ScanResultsPanel'
import { TerminalPanel } from '@/components/terminal'

// 侧边栏标题映射
const sidebarTitles: Record<Exclude<ActivityId, null>, string> = {
  explorer: '资源管理器',
  search: '搜索',
  'ast-tools': 'AST 工具',
  'scan-results': '扫描结果',
  terminal: '终端',
}

const sidebarIcons: Record<Exclude<ActivityId, null>, React.ElementType> = {
  explorer: FileText,
  search: Search,
  'ast-tools': GitGraph,
  'scan-results': BarChart3,
  terminal: Terminal,
}

interface SidebarProps {
  className?: string
}

export function Sidebar({ className }: SidebarProps) {
  const { activeActivity } = useLayoutStore()

  // 如果没有活动项，不渲染侧边栏内容
  if (!activeActivity) {
    return null
  }

  const Icon = sidebarIcons[activeActivity]
  const title = sidebarTitles[activeActivity]

  return (
    <div className={cn(
      'bg-[var(--vscode-sideBar-background)] flex flex-col overflow-hidden h-full',
      className
    )}
    >
      {/* 侧边栏标题 */}
      <div className="h-9 flex items-center px-4 text-xs font-semibold text-[var(--vscode-sideBarSectionHeader-foreground)] uppercase tracking-wide select-none">
        <Icon className="w-4 h-4 mr-2" />
        {title}
      </div>

      {/* 侧边栏内容 */}
      <div className="flex-1 overflow-auto">
        {activeActivity === 'explorer' && <ExplorerContent />}
        {activeActivity === 'search' && <SearchContent />}
        {activeActivity === 'ast-tools' && <ASTToolsContent />}
        {activeActivity === 'scan-results' && <ScanResultsContent />}
        {activeActivity === 'terminal' && <TerminalContent />}
      </div>
    </div>
  )
}

// 资源管理器内容 - 使用 memo 避免不必要的重渲染
// 同时使用精确的 selector 来订阅 store，只在需要的状态变化时才重新渲染
const ExplorerContent = memo(function ExplorerContent() {
  const [selectedPath, setSelectedPath] = useState<string | null>(null)

  // 使用精确的 selector，只订阅需要的状态
  // 注意：不订阅 isLoading，因为文件加载状态不应该影响文件树的显示
  const fileTree = useFileStore(state => state.fileTree)
  const selectFile = useFileStore(state => state.selectFile)
  const currentProject = useProjectStore(state => state.currentProject)

  // 使用 useCallback 缓存函数，避免每次渲染都创建新函数
  // 注意：必须在所有 early return 之前调用，否则会违反 React Hooks 规则
  const handleFileSelect = useCallback(async (path: string | null) => {
    if (!path) {
      setSelectedPath(null)
      return
    }

    // 直接打开文件
    setSelectedPath(path)
    await selectFile(path)
  }, [selectFile])

  // 如果没有当前项目，显示项目列表
  if (!currentProject) {
    return <ProjectListContent />
  }

  // 使用 fileStore 中已经构建好的文件树
  // 注意：移除了 isLoading 检查，因为文件加载不应该隐藏文件树
  return (
    <div className="p-2">
      {fileTree.length > 0 ? (
        <FileTree
          nodes={fileTree}
          selectedPath={selectedPath}
          onSelect={handleFileSelect}
        />
      ) : (
        <div className="text-sm text-muted-foreground p-4 text-center">
          无文件
        </div>
      )}
    </div>
  )
})

// 搜索内容
function SearchContent() {
  const [searchType, setSearchType] = useState<'files' | 'content'>('files')

  return (
    <div className="flex flex-col h-full">
      {/* 搜索类型切换 */}
      <div className="flex border-b border-[var(--vscode-sideBar-border)]">
        <button
          className={cn(
            'flex-1 px-4 py-2 text-xs font-medium transition-colors',
            searchType === 'files'
              ? 'text-[var(--vscode-sideBar-foreground)] border-b-2 border-primary'
              : 'text-[var(--vscode-sideBar-foreground)] hover:text-[var(--vscode-sideBar-foreground)]'
          )}
          onClick={() => setSearchType('files')}
        >
          文件搜索
        </button>
        <button
          className={cn(
            'flex-1 px-4 py-2 text-xs font-medium transition-colors',
            searchType === 'content'
              ? 'text-[var(--vscode-sideBar-foreground)] border-b-2 border-primary'
              : 'text-[var(--vscode-sideBar-foreground)] hover:text-[var(--vscode-sideBar-foreground)]'
          )}
          onClick={() => setSearchType('content')}
        >
          内容搜索
        </button>
      </div>

      {/* 搜索面板 */}
      {searchType === 'files' ? <FileSearchPanel /> : <ContentSearchPanel />}
    </div>
  )
}

// 扫描结果内容 - 使用 ScanResultsPanel 组件
function ScanResultsContent() {
  return <ScanResultsPanel />
}

// AST 工具内容 - 使用 ASTToolsPanel 组件
function ASTToolsContent() {
  return <ASTToolsPanel />
}

// 终端内容
function TerminalContent() {
  return <TerminalPanel />
}

// 项目列表内容（显示在资源管理器中）
function ProjectListContent() {
  const navigate = useNavigate()
  const { projects, deleteProject, setCurrentProject } = useProjectStore()

  const handleOpenProject = (projectId: number) => {
    const project = projects.find(p => p.id === projectId)
    if (project) {
      setCurrentProject(project)
      navigate(`/editor/${projectId}`)
    }
  }

  const handleDeleteProject = async (id: number, name: string) => {
    const confirmed = await confirmDialog({
      title: '删除项目',
      description: `确定要删除项目 "${name}" 吗？此操作不可恢复。`,
      confirmText: '删除',
      cancelText: '取消',
      type: 'destructive',
    })
    if (!confirmed) return

    try {
      await deleteProject(id)
    } catch (err) {
      console.error('删除项目失败:', err)
    }
  }

  if (projects.length === 0) {
    return (
      <div className="p-4 text-sm text-muted-foreground text-center">
        <Folder className="w-12 h-12 mx-auto mb-2 opacity-30" />
        <p>暂无项目</p>
        <p className="text-xs mt-1">点击上方按钮创建新项目</p>
      </div>
    )
  }

  return (
    <div className="p-2">
      <div className="text-xs text-muted-foreground uppercase tracking-wide px-2 py-1">
        最近打开
      </div>
      {projects.map((project) => (
        <div
          key={project.id}
          className="group flex items-center gap-2 px-2 py-1.5 hover:bg-[var(--vscode-toolbar-hoverBackground)] rounded cursor-pointer transition-colors"
          onClick={() => handleOpenProject(project.id)}
        >
          <FileCode className="w-4 h-4 text-[var(--vscode-sideBar-foreground)] shrink-0" />
          <div className="flex-1 min-w-0">
            <div className="text-sm text-[var(--vscode-sideBar-foreground)] truncate">{project.name}</div>
            <div className="text-xs text-[var(--vscode-descriptionForeground)] truncate">{project.path}</div>
          </div>
          <Button
            size="sm"
            variant="ghost"
            className="h-6 w-6 p-0 text-muted-foreground hover:text-destructive hover:bg-destructive/10 opacity-0 group-hover:opacity-100 transition-opacity"
            onClick={(e) => {
              e.stopPropagation()
              handleDeleteProject(project.id, project.name)
            }}
          >
            <Trash2 className="w-3 h-3" />
          </Button>
        </div>
      ))}
    </div>
  )
}
