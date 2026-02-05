/**
 * ProjectLayout - 项目页面布局 (VSCode 风格)
 */

import { useEffect } from 'react'
import { Outlet, useParams, useNavigate, useLocation, Link } from 'react-router-dom'
import { ShieldAlert, ArrowLeft, Network, Activity, Scan, Bot, RefreshCw, FileCode } from 'lucide-react'
import { useProjectStore } from '@/stores/projectStore'
import { useFileStore } from '@/stores/fileStore'
import { useScanStore } from '@/stores/scanStore'
import { VSCodeLayout } from '@/components/layout'
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

  const views = [
    { id: 'agent' as const, label: 'Agent 审计', icon: Bot },
    { id: 'graph' as const, label: '代码图谱', icon: Network },
    { id: 'scan' as const, label: '安全扫描', icon: Scan },
    { id: 'analysis' as const, label: '分析工具', icon: Activity },
  ]

  // 从 URL 获取当前激活的视图
  // 处理嵌套路由，如 /project/3/agent/audit_xxx 应该识别为 agent 视图
  const pathSegments = location.pathname.split('/').filter(Boolean)
  // 查找第一个匹配 views.id 的片段
  const currentView = pathSegments.find(segment =>
    views.some(view => view.id === segment)
  ) || 'agent'

  if (!currentProject) {
    // 如果正在加载项目列表，显示加载状态
    if (projectsLoading || !isInitiallyLoaded) {
      return (
        <div className="h-screen w-screen flex items-center justify-center bg-[var(--vscode-editor-background)]">
          <div className="text-center">
            <RefreshCw className="w-8 h-8 animate-spin text-[var(--vscode-descriptionForeground)] mx-auto mb-4" />
            <p className="text-[var(--vscode-descriptionForeground)]">加载项目...</p>
          </div>
        </div>
      )
    }
    // 如果项目列表已加载完成但找不到项目
    return (
      <div className="h-screen w-screen flex items-center justify-center bg-[var(--vscode-editor-background)]">
        <div className="text-center">
          <p className="text-[var(--vscode-descriptionForeground)]">项目不存在</p>
          <Button
            variant="outline"
            className="mt-4"
            onClick={() => navigate('/')}
          >
            返回仪表板
          </Button>
        </div>
      </div>
    )
  }

  // VSCode 风格的 Header
  const header = (
    <header className="h-9 flex items-center justify-between px-3 bg-[var(--vscode-activityBar-background)] border-b border-[var(--vscode-sideBar-border)] select-none">
      <div className="flex items-center gap-3">
        <Button
          variant="ghost"
          size="icon"
          className="h-6 w-6 text-[var(--vscode-activityBar-inactiveForeground)] hover:text-[var(--vscode-activityBar-foreground)] hover:bg-[var(--vscode-toolbar-hoverBackground)]"
          onClick={() => navigate('/')}
          title="返回仪表板"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
        </Button>
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-primary" />
          <span className="text-sm font-medium text-[var(--vscode-activityBar-foreground)]">{currentProject.name}</span>
        </div>
        <Badge variant="outline" className="text-[10px] font-mono bg-transparent border-[var(--vscode-sideBar-border)] text-[var(--vscode-descriptionForeground)]">
          {currentProject.path}
        </Badge>
      </div>

      {/* View Tabs */}
      <div className="flex items-center gap-1 bg-[var(--vscode-sideBar-background)] rounded p-0.5">
        {views.map((view) => {
          const Icon = view.icon
          const isActive = currentView === view.id
          return (
            <Link
              key={view.id}
              to={view.id}
              className={cn(
                'flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium transition-all',
                isActive
                  ? 'bg-[var(--vscode-editor-background)] text-[var(--vscode-editor-foreground)]'
                  : 'text-[var(--vscode-activityBar-inactiveForeground)] hover:text-[var(--vscode-activityBar-foreground)] hover:bg-[var(--vscode-toolbar-hoverBackground)]'
              )}
            >
              <Icon className="w-3 h-3" />
              {view.label}
            </Link>
          )
        })}
      </div>

      <div className="w-20"></div>
    </header>
  )

  return (
    <VSCodeLayout
      header={header}
      editorContent={<Outlet />}
      showActivityBar={true}
      showProjectTabs={true}
    />
  )
}
