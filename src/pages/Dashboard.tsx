/**
 * Dashboard - VSCode 风格项目列表
 */

import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Plus, FolderOpen, Trash2, Folder, Settings, FileCode } from 'lucide-react'
import { useProjectStore } from '@/stores/projectStore'
import { useUIStore } from '@/stores/uiStore'
import { tauriApi } from '@/shared/api/tauri-client'
import { useToast } from '@/hooks/use-toast'
import { useToastStore } from '@/stores/toastStore'
import { VSCodeLayout } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
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
import { confirmDialog } from "@/components/ui/confirm-dialog"

export function Dashboard() {
  const navigate = useNavigate()
  const { projects, currentProject, isLoading, loadProjects, createProject, deleteProject, setCurrentProject } = useProjectStore()
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

  const handleSelectDirectory = async () => {
    try {
      const path = await tauriApi.selectDirectory()
      if (path) {
        setProjectPath(path)
      }
    } catch (err) {
      toast.error('选择目录失败')
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

  const handleDeleteProject = async (id: number, name: string) => {
    const confirmed = await confirmDialog({
      title: '删除项目',
      description: `确定要删除项目 "${name}" 吗？此操作不可恢复。`,
      confirmText: '删除',
      cancelText: '取消',
      type: 'destructive',
    })
    if (!confirmed) return

    const loadingToast = toast.loading(`正在删除项目 "${name}"...`)

    try {
      await deleteProject(id)
      toast.success(`项目 "${name}" 已删除`)
      addLog(`项目已删除: ${name}`, 'system')
    } catch (err) {
      const message = err instanceof Error ? err.message : '未知错误'
      toast.error(`删除项目失败: ${message}`)
      addLog(`删除项目失败: ${err}`, 'system')
    } finally {
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

  // 自定义 Header
  const header = (
    <header className="h-9 flex items-center justify-between px-3 bg-[#3c3c3c] border-b border-border/40 select-none">
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2">
          <FileCode className="w-4 h-4 text-primary" />
          <span className="text-sm font-medium text-white">CTX-Audit</span>
        </div>
        <Badge variant="outline" className="text-[10px] bg-transparent border-border/40 text-muted-foreground">
          项目管理
        </Badge>
      </div>
      <div className="flex items-center gap-2">
        <Button
          size="sm"
          variant="ghost"
          className="h-7 px-3 text-xs text-muted-foreground hover:text-white hover:bg-white/10"
          onClick={() => loadProjects()}
        >
          刷新
        </Button>
        <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
          <DialogTrigger asChild>
            <Button
              size="sm"
              className="h-7 px-3 text-xs bg-primary hover:bg-primary/90"
            >
              <Plus className="w-3 h-3 mr-1" />
              新建项目
            </Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>创建新项目</DialogTitle>
              <DialogDescription>
                选择本地项目目录来创建一个新的审计项目
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
                <Label>项目目录</Label>
                <div className="flex gap-2">
                  <Input
                    placeholder="选择项目目录..."
                    value={projectPath}
                    readOnly
                    disabled={isCreating}
                  />
                  <Button
                    type="button"
                    variant="outline"
                    onClick={handleSelectDirectory}
                    disabled={isCreating}
                  >
                    <Folder className="w-4 h-4 mr-2" />
                    浏览
                  </Button>
                </div>
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
      </div>
    </header>
  )

  // 主内容区域
  const mainContent = (
    <div className="h-full bg-[#1e1e1e] overflow-auto p-6">
      <div className="max-w-6xl mx-auto">
        {/* 统计卡片 */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <Card className="p-4 bg-[#252526] border-border/40">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground mb-1">总项目数</p>
                <p className="text-2xl font-bold text-white">{projects.length}</p>
              </div>
              <FolderOpen className="w-8 h-8 text-muted-foreground/50" />
            </div>
          </Card>
          <Card className="p-4 bg-[#252526] border-border/40">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground mb-1">当前项目</p>
                <p className="text-sm font-medium text-white truncate">
                  {currentProject?.name || '未选择'}
                </p>
              </div>
              <FileCode className="w-8 h-8 text-muted-foreground/50" />
            </div>
          </Card>
          <Card className="p-4 bg-[#252526] border-border/40">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground mb-1">状态</p>
                <p className="text-sm font-semibold text-green-400">就绪</p>
              </div>
              <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
            </div>
          </Card>
        </div>

        {/* 项目列表 */}
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-white uppercase tracking-wide">项目列表</h2>
          <span className="text-xs text-muted-foreground">{projects.length} 个项目</span>
        </div>

        {projects.length === 0 && !isLoading ? (
          <Card className="p-12 text-center bg-[#252526] border-border/40">
            <Folder className="w-16 h-16 mx-auto mb-4 text-muted-foreground/30" />
            <h3 className="text-lg font-semibold mb-2 text-white">没有项目</h3>
            <p className="text-sm text-muted-foreground mb-6 max-w-md mx-auto">
              选择本地项目目录，创建您的第一个审计项目
            </p>
          </Card>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {projects.map((project) => (
              <Card
                key={project.id}
                className="group bg-[#252526] border-border/40 hover:border-primary/50 transition-all cursor-pointer"
                onClick={() => handleOpenProject(project.id)}
              >
                <div className="p-4">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-2 flex-1 min-w-0">
                      <FileCode className="w-5 h-5 text-primary shrink-0" />
                      <h3 className="font-medium text-white truncate">{project.name}</h3>
                    </div>
                    <Badge variant="outline" className="text-[10px] bg-transparent border-border/40 text-muted-foreground shrink-0">
                      项目
                    </Badge>
                  </div>
                  <p className="text-xs text-muted-foreground mb-4 truncate font-mono">
                    {project.path}
                  </p>
                  <div className="flex items-center justify-between pt-3 border-t border-border/40">
                    <span className="text-[10px] text-muted-foreground">
                      {new Date(project.created_at).toLocaleDateString()}
                    </span>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-7 px-2 text-xs text-destructive hover:text-destructive hover:bg-destructive/10 opacity-0 group-hover:opacity-100 transition-opacity"
                      onClick={(e) => {
                        e.stopPropagation()
                        handleDeleteProject(project.id, project.name)
                      }}
                    >
                      <Trash2 className="w-3 h-3" />
                    </Button>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        )}
      </div>
    </div>
  )

  return (
    <VSCodeLayout
      header={header}
      editorContent={mainContent}
      showActivityBar={true}
    />
  )
}
