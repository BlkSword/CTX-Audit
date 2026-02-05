/**
 * EditorView - 代码审计编辑器页面
 *
 * 主编辑器视图，使用 EditorLayout
 * 包含：文件浏览器、代码编辑器、Agent 面板
 */

import { useEffect } from 'react'
import { useParams, useNavigate, useSearchParams } from 'react-router-dom'
import { Home } from 'lucide-react'
import { useProjectStore } from '@/stores/projectStore'
import { useFileStore } from '@/stores/fileStore'
import { useScanStore } from '@/stores/scanStore'
import { useLayoutStore } from '@/stores/layoutStore'
import { EditorLayout } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { useEditorShortcuts } from '@/hooks/useKeyboard'

export function EditorView() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const { currentProject, projects, setCurrentProject, isLoading: projectsLoading, isInitiallyLoaded, loadProjects } = useProjectStore()
  const { loadFiles } = useFileStore()
  const { loadFindings } = useScanStore()
  const { setActiveActivity } = useLayoutStore()

  // 启用编辑器快捷键
  useEditorShortcuts()

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

        // 处理 panel 参数，设置对应的活动区域
        const panel = searchParams.get('panel')
        if (panel) {
          const activityMap: Record<string, 'explorer' | 'search' | 'ast-tools' | 'scan-results' | 'terminal'> = {
            'search': 'search',
            'ast': 'ast-tools',
            'scan': 'scan-results',
            'terminal': 'terminal',
          }
          setActiveActivity(activityMap[panel] || 'explorer')
        }
      } else if (projectId !== 0) {
        // 只有当项目ID有效但找不到项目时才跳转
        navigate('/')
      }
    }
  }, [id, projects, projectsLoading, isInitiallyLoaded, navigate, setCurrentProject, loadFiles, loadFindings, searchParams, setActiveActivity])

  if (!currentProject) {
    // 如果正在加载项目列表，显示加载状态
    if (projectsLoading || !isInitiallyLoaded) {
      return (
        <div className="h-screen w-screen flex items-center justify-center bg-[var(--vscode-editor-background)]">
          <div className="text-center">
            <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4" />
            <p className="text-[var(--vscode-descriptionForeground)]">加载项目...</p>
          </div>
        </div>
      )
    }
    // 如果项目列表已加载完成但找不到项目
    return (
      <div className="h-screen w-screen flex items-center justify-center bg-[var(--vscode-editor-background)]">
        <div className="text-center">
          <p className="text-[var(--vscode-descriptionForeground)] mb-4">项目不存在</p>
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

  return <EditorLayout showActivityBar={true} />
}
