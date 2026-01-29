/**
 * Sidebar - VSCode 风格侧边栏
 *
 * 根据活动栏显示不同的侧边栏内容：
 * - explorer: 文件资源管理器
 * - search: 搜索
 * - findings: 扫描结果
 * - settings: 设置
 */

import { useState } from 'react'
import { FileText, Search, AlertTriangle, Settings, Folder, FileCode, Trash2 } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useLayoutStore } from '@/stores/layoutStore'
import type { ActivityBarItem } from '@/stores/layoutStore'
import { FileTree } from '@/components/file-explorer/FileTree'
import { useFileStore } from '@/stores/fileStore'
import { useProjectStore } from '@/stores/projectStore'
import { useScanStore } from '@/stores/scanStore'
import { cn } from '@/lib/utils'
import { confirmDialog } from '@/components/ui/confirm-dialog'
import { Button } from '@/components/ui/button'

// 侧边栏标题映射
const sidebarTitles: Record<ActivityBarItem, string> = {
  explorer: '资源管理器',
  search: '搜索',
  findings: '扫描结果',
  settings: '设置',
}

const sidebarIcons: Record<ActivityBarItem, React.ElementType> = {
  explorer: FileText,
  search: Search,
  findings: AlertTriangle,
  settings: Settings,
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
      'bg-[#252526] border-r border-border/40 flex flex-col overflow-hidden h-full',
      className
    )}
    >
      {/* 侧边栏标题 */}
      <div className="h-9 flex items-center px-4 text-xs font-semibold text-muted-foreground uppercase tracking-wide select-none">
        <Icon className="w-4 h-4 mr-2" />
        {title}
      </div>

      {/* 侧边栏内容 */}
      <div className="flex-1 overflow-auto">
        {activeActivity === 'explorer' && <ExplorerContent />}
        {activeActivity === 'search' && <SearchContent />}
        {activeActivity === 'findings' && <FindingsContent />}
        {activeActivity === 'settings' && <SettingsContent />}
      </div>
    </div>
  )
}

// 资源管理器内容
function ExplorerContent() {
  const [selectedPath, setSelectedPath] = useState<string | null>(null)
  const { fileTree, isLoading, selectFile } = useFileStore()
  const { currentProject } = useProjectStore()

  // 如果没有当前项目，显示项目列表
  if (!currentProject) {
    return <ProjectListContent />
  }

  // 加载中状态
  if (isLoading) {
    return (
      <div className="text-sm text-muted-foreground p-4 text-center">
        <div className="w-4 h-4 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-2" />
        加载中...
      </div>
    )
  }

  // 处理文件选择
  const handleFileSelect = async (path: string | null) => {
    if (!path) {
      setSelectedPath(null)
      return
    }

    // 检查是否是文件
    const findFile = (nodes: any[], targetPath: string): any => {
      for (const node of nodes) {
        if (node.path === targetPath) {
          return node
        }
        if (node.children) {
          const found = findFile(node.children, targetPath)
          if (found) return found
        }
      }
      return null
    }

    const fileNode = findFile(fileTree, path)
    if (fileNode && fileNode.type === 'file') {
      setSelectedPath(path)
      await selectFile(path)
    } else {
      // 文件夹点击：只设置选中状态，不加载内容
      setSelectedPath(path)
    }
  }

  // 使用 fileStore 中已经构建好的文件树
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
}

// 搜索内容
function SearchContent() {
  return (
    <div className="p-4 text-sm text-muted-foreground">
      <p>搜索功能</p>
      <p className="mt-2 text-xs">在项目中搜索文件和内容</p>
    </div>
  )
}

// 扫描结果内容
function FindingsContent() {
  const { vulnerabilities } = useScanStore()

  // 按严重程度分组
  const groupedFindings = {
    critical: vulnerabilities.filter((f: any) => f.severity === 'critical'),
    high: vulnerabilities.filter((f: any) => f.severity === 'high'),
    medium: vulnerabilities.filter((f: any) => f.severity === 'medium'),
    low: vulnerabilities.filter((f: any) => f.severity === 'low'),
    info: vulnerabilities.filter((f: any) => f.severity === 'info'),
  }

  const severityColors = {
    critical: 'text-red-400',
    high: 'text-orange-400',
    medium: 'text-yellow-400',
    low: 'text-blue-400',
    info: 'text-gray-400',
  }

  const severityLabels = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
    info: '信息',
  }

  return (
    <div className="p-2">
      {vulnerabilities.length === 0 ? (
        <div className="text-sm text-muted-foreground p-4 text-center">
          暂无扫描结果
        </div>
      ) : (
        <div className="space-y-1">
          {Object.entries(groupedFindings).map(([severity, items]) =>
            items.length > 0 ? (
              <div key={severity} className="mb-2">
                <div className={cn('text-xs font-semibold mb-1', severityColors[severity as keyof typeof severityColors])}>
                  {severityLabels[severity as keyof typeof severityLabels]} ({items.length})
                </div>
                {items.slice(0, 10).map((finding: any) => (
                  <div
                    key={finding.id}
                    className="text-xs p-2 rounded bg-[#1e1e1e] hover:bg-[#2a2a2a] cursor-pointer transition-colors"
                  >
                    <div className="font-medium text-white truncate">{finding.title || finding.vuln_type}</div>
                    <div className="text-muted-foreground truncate mt-1">{finding.file_path}</div>
                  </div>
                ))}
                {items.length > 10 && (
                  <div className="text-xs text-muted-foreground p-1 text-center">
                    还有 {items.length - 10} 条...
                  </div>
                )}
              </div>
            ) : null
          )}
        </div>
      )}
    </div>
  )
}

// 设置内容
function SettingsContent() {
  return (
    <div className="p-4 text-sm text-muted-foreground">
      <p>设置</p>
      <p className="mt-2 text-xs">配置应用程序设置</p>
    </div>
  )
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
          className="group flex items-center gap-2 px-2 py-1.5 hover:bg-[#2a2a2a] rounded cursor-pointer transition-colors"
          onClick={() => handleOpenProject(project.id)}
        >
          <FileCode className="w-4 h-4 text-muted-foreground shrink-0" />
          <div className="flex-1 min-w-0">
            <div className="text-sm text-white truncate">{project.name}</div>
            <div className="text-xs text-muted-foreground truncate">{project.path}</div>
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
