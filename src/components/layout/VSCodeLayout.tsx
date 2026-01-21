/**
 * VSCodeLayout - VSCode 风格主布局
 *
 * 整合 ActivityBar、Sidebar、Editor Panel、BottomPanel、ProjectTabsBar
 * 提供可拖拽调整大小的面板布局，支持多项目并行审计
 */

import { type ReactNode } from 'react'
import { Outlet } from 'react-router-dom'
import { ActivityBar } from './ActivityBar'
import { Sidebar } from './Sidebar'
import { BottomPanel } from './BottomPanel'
import { ProjectTabsBar } from './ProjectTabsBar'
import { useLayoutStore } from '@/stores/layoutStore'
import { ResizablePanelGroup, ResizablePanel, ResizableHandle } from '@/components/ui/resizable'
import { cn } from '@/lib/utils'

interface VSCodeLayoutProps {
  /**
   * 顶部标题栏内容
   */
  header?: ReactNode

  /**
   * 编辑器区域内容（如果为空，则使用 Outlet 渲染子路由）
   */
  editorContent?: ReactNode

  /**
   * 底部面板内容（如果为空，则使用默认内容）
   */
  bottomPanelContent?: ReactNode

  /**
   * 自定义类名
   */
  className?: string

  /**
   * 是否显示活动栏
   */
  showActivityBar?: boolean

  /**
   * 是否显示项目标签栏（多项目模式）
   */
  showProjectTabs?: boolean
}

/**
 * VSCode 风格布局组件
 *
 * @example
 * ```tsx
 * <VSCodeLayout
 *   header={<CustomHeader />}
 *   editorContent={<CustomEditor />}
 *   showProjectTabs={true}
 * />
 * ```
 */
export function VSCodeLayout({
  header,
  editorContent,
  bottomPanelContent,
  className,
  showActivityBar = true,
  showProjectTabs = false,
}: VSCodeLayoutProps) {
  const { sidebarVisible, bottomPanelVisible } = useLayoutStore()

  return (
    <div className={cn('h-screen w-screen flex flex-col bg-background text-foreground overflow-hidden', className)}>
      {/* 顶部标题栏 */}
      {header && (
        <div className="shrink-0">
          {header}
        </div>
      )}

      {/* 项目标签栏（多项目模式） */}
      {showProjectTabs && (
        <div className="shrink-0">
          <ProjectTabsBar />
        </div>
      )}

      {/* 主内容区域 */}
      <div className="flex-1 flex overflow-hidden">
        {/* 活动栏 */}
        {showActivityBar && (
          <div className="shrink-0">
            <ActivityBar />
          </div>
        )}

        {/* 可调整大小的面板组 */}
        <ResizablePanelGroup
          direction="horizontal"
          className="flex-1"
        >
          {/* 侧边栏 */}
          {sidebarVisible && <Sidebar />}

          {/* 侧边栏和编辑器之间的分隔条 */}
          {sidebarVisible && <ResizableHandle withHandle />}

          {/* 编辑器和底部面板 - 作为可调整大小的面板 */}
          <ResizablePanel defaultSize={80} minSize={20}>
            <ResizablePanelGroup
              direction="vertical"
              className="h-full"
            >
              {/* 编辑器区域 */}
              <ResizablePanel
                defaultSize={bottomPanelVisible ? 75 : 100}
                minSize={20}
                className="bg-[#1e1e1e] overflow-auto"
              >
                {editorContent || <Outlet />}
              </ResizablePanel>

              {/* 底部面板 */}
              {bottomPanelVisible && (
                <>
                  <ResizableHandle withHandle />
                  <BottomPanel>
                    {bottomPanelContent}
                  </BottomPanel>
                </>
              )}
            </ResizablePanelGroup>
          </ResizablePanel>
        </ResizablePanelGroup>
      </div>
    </div>
  )
}

// 导出所有子组件
export { ActivityBar } from './ActivityBar'
export { Sidebar } from './Sidebar'
export { BottomPanel } from './BottomPanel'
export { ProjectTabsBar } from './ProjectTabsBar'

// 导出布局 store hooks
export { useLayoutStore, useActiveActivity, useSidebarVisible, useBottomPanelVisible, useActiveBottomTab } from '@/stores/layoutStore'
