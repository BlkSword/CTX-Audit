/**
 * VSCode 风格工作区布局
 * 全新的主布局系统，不依赖原有组件
 */

import { ReactNode, useRef, useState, useEffect, useCallback } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import { useVSCodeLayoutStore } from '@/stores/vscodeLayoutStore'
import { ActivityBar } from './ActivityBar'
import { Sidebar } from './Sidebar'
import { StatusBar } from './StatusBar'
import { WelcomePage } from './WelcomePage'

// ==================== 分隔条组件 ====================

interface ResizerProps {
  direction: 'horizontal' | 'vertical'
  onDrag: (delta: number) => void
  className?: string
}

function Resizer({ direction, onDrag, className = '' }: ResizerProps) {
  const [isDragging, setIsDragging] = useState(false)
  const startPosRef = useRef(0)

  const handleMouseDown = (e: React.MouseEvent) => {
    e.preventDefault()
    setIsDragging(true)
    startPosRef.current = direction === 'horizontal' ? e.clientX : e.clientY
  }

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!isDragging) return

      const currentPos = direction === 'horizontal' ? e.clientX : e.clientY
      const delta = currentPos - startPosRef.current
      startPosRef.current = currentPos

      onDrag(delta)
    }

    const handleMouseUp = () => {
      setIsDragging(false)
    }

    if (isDragging) {
      document.addEventListener('mousemove', handleMouseMove)
      document.addEventListener('mouseup', handleMouseUp)
      document.body.style.cursor = direction === 'horizontal' ? 'ew-resize' : 'ns-resize'
      document.body.style.userSelect = 'none'
    }

    return () => {
      document.removeEventListener('mousemove', handleMouseMove)
      document.removeEventListener('mouseup', handleMouseUp)
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }
  }, [isDragging, direction, onDrag])

  const isHorizontal = direction === 'horizontal'

  return (
    <div
      className={`
        ${isHorizontal ? 'w-1 cursor-ew-resize' : 'h-1 cursor-ns-resize'}
        bg-[var(--vscode-widget-border)]
        hover:bg-[var(--vscode-focusBorder)]
        transition-colors duration-150
        ${isDragging ? 'bg-[var(--vscode-focusBorder)]' : ''}
        ${className}
      `}
      onMouseDown={handleMouseDown}
    />
  )
}

// ==================== 主编辑器区域组件 ====================

interface MainContentProps {
  children?: ReactNode
}

function MainContent({ children }: MainContentProps) {
  const { bottomPanelVisible, bottomPanelHeight, setBottomPanelHeight, toggleBottomPanel } =
    useVSCodeLayoutStore()

  // 如果没有子内容，显示欢迎页面
  if (!children) {
    return <WelcomePage />
  }

  return (
    <div className="flex flex-col flex-1 h-full overflow-hidden">
      {/* 主内容区域 */}
      <div className="flex-1 overflow-hidden">
        {children}
      </div>

      {/* 底部面板 */}
      {bottomPanelVisible && (
        <>
          <Resizer
            direction="vertical"
            onDrag={(delta) => setBottomPanelHeight(bottomPanelHeight + delta)}
          />
          <div
            className="bg-[var(--vscode-editorGroupHeader-tabsBackground)] border-t border-[var(--vscode-panel-border)]"
            style={{ height: `${bottomPanelHeight}px` }}
          >
            <div className="flex items-center h-8 px-2 border-b border-[var(--vscode-panel-border)]">
              <div className="flex gap-1">
                <button className="px-3 py-1 text-xs text-[var(--vscode-tab-activeForeground)] bg-[var(--vscode-tab-activeBackground)] border-b-2 border-[var(--vscode-focusBorder)]">
                  输出
                </button>
                <button className="px-3 py-1 text-xs text-[var(--vscode-activityBar-inactiveForeground)] hover:text-[var(--vscode-activityBar-foreground)]">
                  终端
                </button>
                <button className="px-3 py-1 text-xs text-[var(--vscode-activityBar-inactiveForeground)] hover:text-[var(--vscode-activityBar-foreground)]">
                  问题
                </button>
              </div>
              <div className="flex-1" />
              <button
                className="p-1 hover:bg-[var(--vscode-toolbar-hoverBackground)] rounded"
                onClick={toggleBottomPanel}
              >
                <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                  <path d="M11 5L8 8 5 5 4 6l4 4 4-4-1-1z" />
                </svg>
              </button>
            </div>
            <div className="p-3 text-sm text-[var(--vscode-descriptionForeground)] font-mono">
              <div>[Info] 准备就绪</div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}

// ==================== VSCode 工作区布局组件 ====================

export function VSCodeWorkspaceLayout() {
  const { sidebarVisible, sidebarWidth, setSidebarWidth, statusBarVisible } =
    useVSCodeLayoutStore()
  const location = useLocation()

  // 判断是否在欢迎页面（根路径）
  const isWelcomePage = location.pathname === '/'

  return (
    <div className="flex flex-col h-screen bg-[var(--vscode-editor-background)] text-[var(--vscode-editor-foreground)] overflow-hidden">
      {/* 主工作区 */}
      <div className="flex flex-1 overflow-hidden">
        {/* 左侧活动栏 */}
        <ActivityBar />

        {/* 左侧边栏分隔条 */}
        {sidebarVisible && (
          <Resizer
            direction="horizontal"
            onDrag={(delta) => setSidebarWidth(sidebarWidth + delta)}
          />
        )}

        {/* 左侧边栏 */}
        <Sidebar />

        {/* 主内容区域 */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {isWelcomePage ? (
            <WelcomePage />
          ) : (
            <MainContent>
              <Outlet />
            </MainContent>
          )}
        </div>
      </div>

      {/* 底部状态栏 */}
      {statusBarVisible && <StatusBar />}
    </div>
  )
}

export default VSCodeWorkspaceLayout
