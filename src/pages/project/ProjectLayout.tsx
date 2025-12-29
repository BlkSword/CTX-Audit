/**
 * ProjectLayout - 项目页面布局
 */

import { useEffect } from 'react'
import { Outlet, useParams, useNavigate, useLocation, Link } from 'react-router-dom'
import { ShieldAlert, ArrowLeft, FileCode, Network, Activity, Scan, Bot, RefreshCw } from 'lucide-react'
import { useProjectStore } from '@/stores/projectStore'
import { useFileStore } from '@/stores/fileStore'
import { useScanStore } from '@/stores/scanStore'
import { useUIStore } from '@/stores/uiStore'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

export function ProjectLayout() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const location = useLocation()
  const { currentProject, projects, setCurrentProject, isLoading: projectsLoading, isInitiallyLoaded, loadProjects } = useProjectStore()
  const { loadFiles } = useFileStore()
  const { loadFindings } = useScanStore()
  const { bottomPanelVisible } = useUIStore()

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

  // 从 URL 获取当前激活的视图
  const currentView = location.pathname.split('/').pop() || 'editor'

  const views = [
    { id: 'editor' as const, label: '代码查看', icon: FileCode },
    { id: 'graph' as const, label: '代码图谱', icon: Network },
    { id: 'scan' as const, label: '安全扫描', icon: Scan },
    { id: 'analysis' as const, label: '分析工具', icon: Activity },
    { id: 'agent' as const, label: 'Agent 审计', icon: Bot },
  ]

  if (!currentProject) {
    // 如果正在加载项目列表，显示加载状态
    if (projectsLoading || !isInitiallyLoaded) {
      return (
        <div className="h-screen flex items-center justify-center">
          <div className="text-center">
            <RefreshCw className="w-8 h-8 animate-spin text-muted-foreground mx-auto mb-4" />
            <p className="text-muted-foreground">加载项目...</p>
          </div>
        </div>
      )
    }
    // 如果项目列表已加载完成但找不到项目
    return (
      <div className="h-screen flex items-center justify-center">
        <div className="text-center">
          <p className="text-muted-foreground">项目不存在</p>
        </div>
      </div>
    )
  }

  return (
    <div className="h-screen w-screen bg-background text-foreground flex flex-col overflow-hidden font-sans">
      {/* Header */}
      <header className="h-12 border-b border-border/40 px-4 flex items-center bg-muted/20 select-none relative">
        {/* Left Section */}
        <div className="flex items-center gap-4 w-1/3">
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7"
            onClick={() => navigate('/')}
            title="返回仪表板"
          >
            <ArrowLeft className="w-4 h-4" />
          </Button>

          <div className="flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-primary" />
            <span className="font-semibold text-sm">{currentProject.name}</span>
          </div>

          <Badge variant="outline" className="text-[10px] font-mono">
            {currentProject.path}
          </Badge>
        </div>

        {/* Center - View Tabs */}
        <div className="absolute left-1/2 -translate-x-1/2 flex items-center gap-1 bg-muted/30 rounded-lg p-1">
          {views.map((view) => {
            const Icon = view.icon
            const isActive = currentView === view.id
            return (
              <Link
                key={view.id}
                to={view.id}
                className={cn(
                  'flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all',
                  isActive
                    ? 'bg-background text-foreground shadow-sm'
                    : 'text-muted-foreground hover:text-foreground hover:bg-muted/50'
                )}
              >
                <Icon className="w-3.5 h-3.5" />
                {view.label}
              </Link>
            )
          })}
        </div>

        {/* Right Section - 空白，用于保持布局平衡 */}
        <div className="w-1/3"></div>
      </header>

      {/* Main Content */}
      <div className="flex-1 overflow-hidden">
        <Outlet />
      </div>
    </div>
  )
}
