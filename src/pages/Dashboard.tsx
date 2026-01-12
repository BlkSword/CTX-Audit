/**
 * Dashboard - 项目列表和创建页面
 */

import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Plus, FolderOpen, Trash2, RefreshCw, ShieldAlert, FileArchive, Settings } from 'lucide-react'
import { useProjectStore } from '@/stores/projectStore'
import { useUIStore } from '@/stores/uiStore'
import { useToast } from '@/hooks/use-toast'
import { useToastStore } from '@/stores/toastStore'
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
import { FileUpload } from "@/components/ui/file-upload"

export function Dashboard() {
  const navigate = useNavigate()
  const { projects, currentProject, isLoading, error, loadProjects, createProject, deleteProject, setCurrentProject } = useProjectStore()
  const { addLog } = useUIStore()
  const toast = useToast()
  const { removeToast } = useToastStore()

  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false)
  const [newProjectName, setNewProjectName] = useState('')
  const [projectZip, setProjectZip] = useState<File | null>(null)
  const [isCreating, setIsCreating] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)

  useEffect(() => {
    loadProjects()
  }, [loadProjects])

  const handleCreateProject = async () => {
    if (!newProjectName.trim() || !projectZip) return

    setIsCreating(true)
    setUploadProgress(0)
    const loadingToast = toast.loading('正在上传并创建项目...')

    try {
      const project = await createProject(newProjectName, projectZip, (progress) => {
        setUploadProgress(progress)
      })
      toast.success(`项目 "${project.name}" 创建成功！`)
      addLog(`项目创建成功: ${project.name}`, 'system')
      setIsCreateDialogOpen(false)
      setNewProjectName('')
      setProjectZip(null)
      setUploadProgress(0)
    } catch (err) {
      const message = err instanceof Error ? err.message : '未知错误'
      toast.error(`创建项目失败: ${message}`)
      addLog(`创建项目失败: ${err}`, 'system')
    } finally {
      setIsCreating(false)
      setUploadProgress(0)
      // 移除加载提示
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
      // 移除加载提示
      if (loadingToast) removeToast(loadingToast)
    }
  }

  const handleOpenProject = (project: typeof projects[0]) => {
    setCurrentProject(project)
    navigate(`/project/${project.id}/agent`)
    addLog(`打开项目: ${project.name}`, 'system')
  }

  return (
    <div className="h-screen w-screen bg-background text-foreground flex flex-col overflow-hidden">
      {/* Header */}
      <header className="h-14 border-b border-border/40 px-6 flex items-center justify-between bg-muted/20 relative z-10">
        <div className="flex items-center gap-3">
          <ShieldAlert className="w-6 h-6 text-primary" />
          <h1 className="text-xl font-semibold tracking-tight">CTX-Audit</h1>
        </div>

        <div className="flex items-center gap-2 relative z-20">
          <Button
            variant="outline"
            size="sm"
            onClick={() => loadProjects()}
            disabled={isLoading}
          >
            <RefreshCw className={`w-4 h-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
            刷新
          </Button>

          <Button
            variant="outline"
            size="sm"
            onClick={() => navigate('/settings/llm')}
          >
            <Settings className="w-4 h-4 mr-2" />
            设置
          </Button>

          <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
            <DialogTrigger asChild>
              <Button size="sm">
                <Plus className="w-4 h-4 mr-2" />
                新建项目
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-md">
              <DialogHeader>
                <DialogTitle>创建新项目</DialogTitle>
                <DialogDescription>
                  上传项目 ZIP 文件来创建一个新的审计项目
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
                  />
                </div>
                <div className="grid gap-2">
                  <Label>项目文件 (ZIP)</Label>
                  <FileUpload
                    accept=".zip"
                    disabled={isCreating}
                    value={projectZip}
                    onChange={(file) => setProjectZip(file)}
                    maxSize={500}
                  />
                </div>

                {/* 上传进度 */}
                {isCreating && uploadProgress > 0 && (
                  <div className="space-y-2">
                    <div className="flex justify-between text-xs text-muted-foreground">
                      <span>上传中...</span>
                      <span>{uploadProgress}%</span>
                    </div>
                    <div className="h-2 bg-muted rounded-full overflow-hidden">
                      <div
                        className="h-full bg-primary transition-all duration-300"
                        style={{ width: `${uploadProgress}%` }}
                      />
                    </div>
                  </div>
                )}
              </div>
              <DialogFooter>
                <Button
                  variant="outline"
                  onClick={() => {
                    setIsCreateDialogOpen(false)
                    setUploadProgress(0)
                  }}
                  disabled={isCreating}
                >
                  取消
                </Button>
                <Button
                  onClick={handleCreateProject}
                  disabled={isCreating || !newProjectName.trim() || !projectZip}
                >
                  {isCreating ? '上传中...' : '上传并创建'}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 overflow-auto p-6 no-scrollbar">
        <div className="max-w-6xl mx-auto">
          {/* Stats */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
            <Card className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">总项目数</p>
                  <p className="text-2xl font-bold mt-1">{projects.length}</p>
                </div>
                <FolderOpen className="w-8 h-8 text-muted-foreground/50" />
              </div>
            </Card>
            <Card className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">当前项目</p>
                  <p className="text-lg font-semibold mt-1 truncate">
                    {currentProject?.name || '未选择'}
                  </p>
                </div>
                <ShieldAlert className="w-8 h-8 text-muted-foreground/50" />
              </div>
            </Card>
            <Card className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">状态</p>
                  <p className="text-lg font-semibold mt-1 text-green-500">就绪</p>
                </div>
                <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
              </div>
            </Card>
          </div>

          {/* Error */}
          {error && (
            <div className="mb-6 p-4 bg-destructive/10 border border-destructive/20 rounded-lg text-destructive text-sm">
              {error}
            </div>
          )}

          {/* Projects Grid */}
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold">项目列表</h2>
            <span className="text-sm text-muted-foreground">{projects.length} 个项目</span>
          </div>

          {projects.length === 0 && !isLoading ? (
            <Card className="p-12 text-center">
              <FileArchive className="w-16 h-16 mx-auto mb-4 text-muted-foreground/30" />
              <h3 className="text-lg font-semibold mb-2">没有项目</h3>
              <p className="text-sm text-muted-foreground mb-6 max-w-md mx-auto">
                上传项目 ZIP 文件，创建您的第一个审计项目
              </p>
            </Card>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {projects.map((project) => (
                <Card
                  key={project.id}
                  className="p-4 hover:shadow-md transition-all cursor-pointer group"
                  onClick={() => handleOpenProject(project)}
                >
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex-1 min-w-0">
                      <h3 className="font-semibold truncate group-hover:text-primary transition-colors">
                        {project.name}
                      </h3>
                      <p className="text-xs text-muted-foreground font-mono truncate mt-1">
                        {project.path}
                      </p>
                    </div>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="opacity-0 group-hover:opacity-100 transition-opacity"
                      onClick={(e) => {
                        e.stopPropagation()
                        handleDeleteProject(project.id, project.name)
                      }}
                    >
                      <Trash2 className="w-4 h-4 text-destructive" />
                    </Button>
                  </div>

                  <div className="flex items-center justify-between text-xs text-muted-foreground">
                    <span>创建于 {new Date(project.created_at).toLocaleDateString()}</span>
                    {currentProject?.id === project.id && (
                      <Badge variant="secondary" className="text-[10px]">当前</Badge>
                    )}
                  </div>

                  <div className="mt-4 pt-3 border-t border-border/40">
                    <Button
                      variant="outline"
                      size="sm"
                      className="w-full"
                      onClick={(e) => {
                        e.stopPropagation()
                        handleOpenProject(project)
                      }}
                    >
                      <FolderOpen className="w-3.5 h-3.5 mr-2" />
                      打开项目
                    </Button>
                  </div>
                </Card>
              ))}
            </div>
          )}

          {isLoading && (
            <div className="flex items-center justify-center py-12">
              <RefreshCw className="w-6 h-6 animate-spin text-muted-foreground" />
            </div>
          )}
        </div>
      </main>

      {/* Footer */}
      <footer className="h-8 border-t border-border/40 px-4 flex items-center justify-between text-[10px] text-muted-foreground select-none bg-muted/20">
        <span>CTX-Audit v1.0.0</span>
        <span>© 2026 Code Security Audit Platform</span>
      </footer>
    </div>
  )
}
