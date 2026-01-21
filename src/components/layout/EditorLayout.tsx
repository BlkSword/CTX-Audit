/**
 * EditorLayout - 代码审计编辑器主布局
 *
 * VSCode 风格布局：
 * - 左侧：ActivityBar + Sidebar（文件浏览器/扫描结果/搜索/设置）
 * - 中间：代码编辑器
 * - 右侧：Agent 面板（可折叠）
 * - 底部：Terminal/Output 面板（可选）
 */

import { type ReactNode } from 'react'
import { Outlet } from 'react-router-dom'
import { ActivityBar } from './ActivityBar'
import { Sidebar } from './Sidebar'
import { BottomPanel } from './BottomPanel'
import { AgentPanel } from './AgentPanel'
import { CodeEditorPanel } from './CodeEditorPanel'
import { useLayoutStore } from '@/stores/layoutStore'
import { ResizablePanelGroup, ResizablePanel, ResizableHandle } from '@/components/ui/resizable'
import { cn } from '@/lib/utils'

export interface EditorLayoutProps {
  /**
   * 顶部标题栏内容（可选，默认使用项目头部）
   */
  header?: ReactNode

  /**
   * 编辑器区域内容（如果为空，则使用 Outlet 渲染子路由）
   */
  editorContent?: ReactNode

  /**
   * Agent 面板内容（如果为空，则使用默认 Agent 面板）
   */
  agentContent?: ReactNode

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
   * 是否显示底部面板
   */
  showBottomPanel?: boolean
}

/**
 * VSCode 风格编辑器布局组件
 *
 * 布局结构：
 * ```
 * +--------------+----------------------+--------------+
 * | ActivityBar | Sidebar              | Editor Area  | Agent Panel |
 * | (48px)      | (可拖拽调整)          | (弹性)       | (可折叠)    |
 * +--------------+----------------------+--------------+
 * | Bottom Panel (可折叠)                              |
 * +---------------------------------------------------+
 * ```
 */
export function EditorLayout({
  header,
  editorContent,
  agentContent,
  bottomPanelContent,
  className,
  showActivityBar = true,
  showBottomPanel = false,
}: EditorLayoutProps) {
  const {
    sidebarVisible,
    sidebarSize,
    agentPanelVisible,
    agentPanelSize,
    bottomPanelVisible,
    bottomPanelSize,
  } = useLayoutStore()

  return (
    <div className={cn('h-screen w-screen flex flex-col bg-[#1e1e1e] text-foreground overflow-hidden', className)}>
      {/* 顶部标题栏 */}
      {header && (
        <div className="shrink-0">
          {header}
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

          {/* 侧边栏分隔条 */}
          {sidebarVisible && <ResizableHandle withHandle />}

          {/* 编辑器 + Agent 面板 */}
          <ResizablePanel defaultSize={100} minSize={30}>
            <ResizablePanelGroup direction="horizontal" className="h-full">
              {/* 编辑器区域 */}
              <ResizablePanel
                defaultSize={agentPanelVisible ? 100 - agentPanelSize : 100}
                minSize={30}
                className="bg-[#1e1e1e] overflow-hidden"
              >
                <ResizablePanelGroup direction="vertical" className="h-full">
                  {/* 代码编辑器 */}
                  <ResizablePanel
                    defaultSize={bottomPanelVisible ? 100 - bottomPanelSize : 100}
                    minSize={20}
                    className="overflow-hidden"
                  >
                    {editorContent || <CodeEditorPanel />}
                  </ResizablePanel>

                  {/* 底部面板 */}
                  {(bottomPanelVisible || showBottomPanel) && (
                    <>
                      <ResizableHandle withHandle />
                      <BottomPanel>
                        {bottomPanelContent}
                      </BottomPanel>
                    </>
                  )}
                </ResizablePanelGroup>
              </ResizablePanel>

              {/* Agent 面板分隔条 */}
              {agentPanelVisible && <ResizableHandle withHandle />}

              {/* Agent 面板 */}
              {agentPanelVisible && (
                <ResizablePanel
                  defaultSize={agentPanelSize}
                  minSize={20}
                  maxSize={50}
                  className="bg-[#252526] border-l border-border/40 overflow-hidden"
                >
                  {agentContent || <AgentPanel />}
                </ResizablePanel>
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
export { AgentPanel } from './AgentPanel'
export { CodeEditorPanel } from './CodeEditorPanel'

// 导出布局 store hooks
export { useLayoutStore, useActiveActivity, useSidebarVisible, useAgentPanelVisible, useBottomPanelVisible, useActiveBottomTab } from '@/stores/layoutStore'
