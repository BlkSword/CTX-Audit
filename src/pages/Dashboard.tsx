/**
 * Dashboard - VSCode 风格欢迎页面
 */

import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Plus, FolderOpen, FileCode, Loader2 } from 'lucide-react'
import { useProjectStore } from '@/stores/projectStore'
import { useUIStore } from '@/stores/uiStore'
import { useToast } from '@/hooks/use-toast'
import { useToastStore } from '@/stores/toastStore'
import { VSCodeLayout } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Label } from "@/components/ui/label"

export function Dashboard() {
  const navigate = useNavigate()
  const { projects, loadProjects, openDirectory, createProject, setCurrentProject, isLoading } = useProjectStore()
  const { addLog } = useUIStore()
  const toast = useToast()
  const { removeToast } = useToastStore()

  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false)
  const [newProjectName, setNewProjectName] = useState('')
  const [projectPath, setProjectPath] = useState('')
  const [isCreating, setIsCreating] = useState(false)

  useEffect(() => {
    loadProjects()
  }, [loadProjects])

  // 打开目录并自动创建/打开项目
  const handleOpenDirectory = async () => {
    try {
      const project = await openDirectory()
      toast.success(`已打开项目: ${project.name}`)
      addLog(`项目已打开: ${project.name}`, 'system')
      // 导航到编辑器页面
      navigate(`/editor/${project.id}`)
    } catch (err) {
      const message = err instanceof Error ? err.message : '打开目录失败'
      if (message !== 'No directory selected') {
        toast.error(message)
        addLog(`打开目录失败: ${err}`, 'system')
      }
    }
  }

  const handleCreateProject = async () => {
    if (!newProjectName.trim() || !projectPath) {
      toast.error('请填写项目名称并选择项目目录')
      return
    }

    // 检查路径是否已存在
    const existingProject = projects.find(p => p.path === projectPath)
    if (existingProject) {
      toast.error(`该路径已被项目 "${existingProject.name}" 使用，请选择其他路径或先删除现有项目`)
      return
    }

    setIsCreating(true)
    const loadingToast = toast.loading('正在创建项目...')

    try {
      const project = await createProject(newProjectName, projectPath)
      toast.success(`项目 "${project.name}" 创建成功！`)
      addLog(`项目创建成功: ${project.name}`, 'system')
      setIsCreateDialogOpen(false)
      setNewProjectName('')
      setProjectPath('')
    } catch (err) {
      const message = err instanceof Error ? err.message : '未知错误'
      // 检查是否是 UNIQUE 约束错误
      if (message.includes('UNIQUE constraint failed: projects.path')) {
        toast.error('该路径已被使用，请选择其他路径')
      } else {
        toast.error(`创建项目失败: ${message}`)
      }
      addLog(`创建项目失败: ${err}`, 'system')
    } finally {
      setIsCreating(false)
      if (loadingToast) removeToast(loadingToast)
    }
  }

  const handleOpenProject = (projectId: number) => {
    const project = projects.find(p => p.id === projectId)
    if (project) {
      setCurrentProject(project)
      navigate(`/editor/${projectId}`)
    }
  }

  // 自定义 Header - 简化版，移除右上角的新建项目按钮
  const header = (
    <header className="h-9 flex items-center justify-between px-3 bg-[var(--vscode-activityBar-background)] border-b border-[var(--vscode-sideBar-border)] select-none">
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2">
          <FileCode className="w-4 h-4 text-primary" />
          <span className="text-sm font-medium text-[var(--vscode-activityBar-foreground)]">CTX-Audit</span>
        </div>
        <Badge variant="outline" className="text-[10px] bg-transparent border-[var(--vscode-sideBar-border)] text-[var(--vscode-descriptionForeground)]">
          欢迎
        </Badge>
      </div>
    </header>
  )

  // 主内容区域 - VSCode 风格欢迎页面
  const mainContent = (
    <div className="h-full bg-[var(--vscode-editor-background)] overflow-auto">
      <div className="max-w-4xl mx-auto px-8 py-12">
        {/* 欢迎标题 */}
        <h1 className="text-3xl font-light text-[var(--vscode-editor-foreground)] mb-2">
          CTX-Audit
        </h1>
        <p className="text-sm text-[var(--vscode-descriptionForeground)] mb-8">
          AI 驱动的代码安全审计工具
        </p>

        {/* Start 区域 */}
        <div className="mb-10">
          <h2 className="text-sm font-semibold text-[var(--vscode-editor-foreground)] uppercase tracking-wide mb-3">
            Start
          </h2>
          <div className="space-y-1">
            <button
              onClick={() => setIsCreateDialogOpen(true)}
              className="w-full text-left px-4 py-3 bg-[var(--vscode-sideBar-background)] hover:bg-[var(--vscode-toolbar-hoverBackground)] border border-[var(--vscode-sideBar-border)] rounded transition-colors flex items-center gap-3 group"
            >
              <FileCode className="w-5 h-5 text-primary" />
              <div>
                <div className="text-sm text-[var(--vscode-editor-foreground)] group-hover:text-primary transition-colors">
                  新建项目
                </div>
                <div className="text-xs text-[var(--vscode-descriptionForeground)]">
                  创建一个新的代码审计项目
                </div>
              </div>
            </button>
            <button
              onClick={handleOpenDirectory}
              disabled={isLoading}
              className="w-full text-left px-4 py-3 bg-[var(--vscode-sideBar-background)] hover:bg-[var(--vscode-toolbar-hoverBackground)] border border-[var(--vscode-sideBar-border)] rounded transition-colors flex items-center gap-3 group disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoading ? (
                <Loader2 className="w-5 h-5 text-blue-400 animate-spin" />
              ) : (
                <FolderOpen className="w-5 h-5 text-blue-400" />
              )}
              <div>
                <div className="text-sm text-[var(--vscode-editor-foreground)] group-hover:text-blue-400 transition-colors">
                  打开项目目录
                </div>
                <div className="text-xs text-[var(--vscode-descriptionForeground)]">
                  从本地文件系统打开项目
                </div>
              </div>
            </button>
          </div>
        </div>

        {/* 创建项目 Dialog */}
        <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>创建新项目</DialogTitle>
              <DialogDescription>
                输入项目信息来创建一个新的审计项目
              </DialogDescription>
            </DialogHeader>
            <div className="grid gap-4 py-4">
              <div className="grid gap-2">
                <Label htmlFor="name">项目名称</Label>
                <Input
                  id="name"
                  placeholder="例如: my-project"
                  value={newProjectName}
                  onChange={(e) => setNewProjectName(e.target.value)}
                  disabled={isCreating}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="path">项目路径</Label>
                <Input
                  id="path"
                  placeholder="/path/to/project"
                  value={projectPath}
                  onChange={(e) => setProjectPath(e.target.value)}
                  disabled={isCreating}
                />
                <p className="text-xs text-muted-foreground">
                  提示：你也可以使用"打开项目目录"快速打开已有项目
                </p>
              </div>
            </div>
            <DialogFooter>
              <Button
                variant="outline"
                onClick={() => {
                  setIsCreateDialogOpen(false)
                  setNewProjectName('')
                  setProjectPath('')
                }}
                disabled={isCreating}
              >
                取消
              </Button>
              <Button
                onClick={handleCreateProject}
                disabled={isCreating || !newProjectName.trim() || !projectPath}
              >
                {isCreating ? '创建中...' : '创建项目'}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Recent 区域 */}
        <div className="mb-10">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-[var(--vscode-editor-foreground)] uppercase tracking-wide">
              Recent
            </h2>
            {projects.length > 0 && (
              <button
                onClick={() => loadProjects()}
                className="text-xs text-[var(--vscode-descriptionForeground)] hover:text-[var(--vscode-editor-foreground)] transition-colors"
              >
                刷新
              </button>
            )}
          </div>
          {projects.length === 0 ? (
            <div className="text-sm text-[var(--vscode-descriptionForeground)] p-4 text-center bg-[var(--vscode-sideBar-background)] border border-[var(--vscode-sideBar-border)] rounded">
              暂无最近项目
            </div>
          ) : (
            <div className="space-y-1">
              {projects.slice(0, 5).map((project) => (
                <button
                  key={project.id}
                  onClick={() => handleOpenProject(project.id)}
                  className="w-full text-left px-4 py-3 bg-[var(--vscode-sideBar-background)] hover:bg-[var(--vscode-toolbar-hoverBackground)] border border-[var(--vscode-sideBar-border)] rounded transition-colors flex items-center gap-3 group"
                >
                  <FileCode className="w-5 h-5 text-[var(--vscode-descriptionForeground)] group-hover:text-primary transition-colors" />
                  <div className="flex-1 min-w-0">
                    <div className="text-sm text-[var(--vscode-editor-foreground)] group-hover:text-primary transition-colors truncate">
                      {project.name}
                    </div>
                    <div className="text-xs text-[var(--vscode-descriptionForeground)] truncate">
                      {project.path}
                    </div>
                  </div>
                  <span className="text-xs text-[var(--vscode-descriptionForeground)] shrink-0">
                    {new Date(project.created_at).toLocaleDateString()}
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Help 区域 */}
        <div>
          <h2 className="text-sm font-semibold text-[var(--vscode-editor-foreground)] uppercase tracking-wide mb-3">
            Help
          </h2>
          <div className="space-y-1">
            <a
              href="https://github.com/ctx-audit/ctx-audit"
              target="_blank"
              rel="noopener noreferrer"
              className="block w-full text-left px-4 py-3 bg-[var(--vscode-sideBar-background)] hover:bg-[var(--vscode-toolbar-hoverBackground)] border border-[var(--vscode-sideBar-border)] rounded transition-colors"
            >
              <div className="text-sm text-[var(--vscode-editor-foreground)] hover:text-primary transition-colors">
                文档和指南
              </div>
              <div className="text-xs text-[var(--vscode-descriptionForeground)]">
                了解如何使用 CTX-Audit
              </div>
            </a>
            <button
              className="w-full text-left px-4 py-3 bg-[var(--vscode-sideBar-background)] hover:bg-[var(--vscode-toolbar-hoverBackground)] border border-[var(--vscode-sideBar-border)] rounded transition-colors"
            >
              <div className="text-sm text-[var(--vscode-editor-foreground)] hover:text-primary transition-colors">
                键盘快捷键
              </div>
              <div className="text-xs text-[var(--vscode-descriptionForeground)]">
                查看所有可用的快捷键
              </div>
            </button>
          </div>
        </div>
      </div>
    </div>
  )

  return (
    <VSCodeLayout
      header={header}
      editorContent={mainContent}
      showActivityBar={false}
    />
  )
}
