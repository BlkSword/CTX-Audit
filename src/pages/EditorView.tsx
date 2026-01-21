/**
 * EditorView - 代码审计编辑器页面
 *
 * 主编辑器视图，使用 EditorLayout
 * 包含：文件浏览器、代码编辑器、Agent 面板
 */

import { useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ShieldAlert, ArrowLeft, Home } from 'lucide-react'
import { useProjectStore } from '@/stores/projectStore'
import { useFileStore } from '@/stores/fileStore'
import { useScanStore } from '@/stores/scanStore'
import { EditorLayout } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

export function EditorView() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { currentProject, projects, setCurrentProject, isLoading: projectsLoading, isInitiallyLoaded, loadProjects } = useProjectStore()
  const { loadFiles } = useFileStore()
  const { loadFindings } = useScanStore()

  useEffect(() => {
    // 确保项目列表已加载
    loadProjects()
  }, [loadProjects])

  useEffect(() => {
    // 从 URL 参数加载项目
    const projectId = parseInt(id || '0')

    // 只有在初始加载完成后才进行判断
    if (isInitiallyLoaded && !projectsLoading) {
      const project = projects.find(p => p.id === projectId)

      if (project) {
        setCurrentProject(project)
        loadFiles(project.path)
        // 加载项目的扫描结果
        loadFindings(project.id)
      } else if (projectId !== 0) {
        // 只有当项目ID有效但找不到项目时才跳转
        navigate('/')
      }
    }
  }, [id, projects, projectsLoading, isInitiallyLoaded, navigate, setCurrentProject, loadFiles, loadFindings])

  if (!currentProject) {
    // 如果正在加载项目列表，显示加载状态
    if (projectsLoading || !isInitiallyLoaded) {
      return (
        <div className="h-screen w-screen flex items-center justify-center bg-[#1e1e1e]">
          <div className="text-center">
            <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4" />
            <p className="text-muted-foreground">加载项目...</p>
          </div>
        </div>
      )
    }
    // 如果项目列表已加载完成但找不到项目
    return (
      <div className="h-screen w-screen flex items-center justify-center bg-[#1e1e1e]">
        <div className="text-center">
          <p className="text-muted-foreground mb-4">项目不存在</p>
          <Button
            variant="outline"
            onClick={() => navigate('/')}
          >
            <Home className="w-4 h-4 mr-2" />
            返回仪表板
          </Button>
        </div>
      </div>
    )
  }

  // VSCode 风格的 Header
  const header = (
    <header className="h-9 flex items-center justify-between px-3 bg-[#3c3c3c] border-b border-border/40 select-none">
      <div className="flex items-center gap-3">
        <Button
          variant="ghost"
          size="icon"
          className="h-6 w-6 text-muted-foreground hover:text-white hover:bg-white/10"
          onClick={() => navigate('/')}
          title="返回仪表板"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
        </Button>
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-primary" />
          <span className="text-sm font-medium text-white">{currentProject.name}</span>
        </div>
        <Badge variant="outline" className="text-[10px] font-mono bg-transparent border-border/40 text-muted-foreground">
          {currentProject.path}
        </Badge>
      </div>

      <div className="flex items-center gap-2">
        {/* 可以添加其他控制按钮 */}
      </div>
    </header>
  )

  return (
    <EditorLayout
      header={header}
      showActivityBar={true}
    />
  )
}
