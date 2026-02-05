/**
 * SettingsLayout - 独立全屏设置页面
 *
 * 完全独立的界面，不依赖 VSCodeLayout
 * VSCode 风格设计
 */

import { Outlet, useNavigate, useLocation } from 'react-router-dom'
import { ArrowLeft, Settings, X } from 'lucide-react'
import { SETTINGS_NAV_ITEMS } from '@/config/navigation'
import { cn } from '@/lib/utils'

export function SettingsLayout() {
  const navigate = useNavigate()
  const location = useLocation()

  // 获取当前激活的设置标签
  const activeTabId = SETTINGS_NAV_ITEMS.find(item =>
    location.pathname === item.pathTemplate || location.pathname.startsWith(item.pathTemplate + '/')
  )?.id || SETTINGS_NAV_ITEMS[0].id

  // 获取当前标签的导航项
  const activeTab = SETTINGS_NAV_ITEMS.find(item => item.id === activeTabId)

  return (
    <div className="h-screen w-screen flex flex-col bg-[var(--vscode-editor-background)] text-[var(--vscode-editor-foreground)]">
      {/* 顶部导航栏 - VSCode 风格 */}
      <header className="h-9 flex items-center justify-between px-3 bg-[var(--vscode-activityBar-background)] border-b border-[var(--vscode-sideBar-border)] select-none shrink-0">
        {/* 左侧：返回按钮 + 标题 */}
        <div className="flex items-center gap-3">
          {/* 返回按钮 */}
          <button
            onClick={() => navigate('/')}
            className="h-7 w-7 flex items-center justify-center rounded text-[var(--vscode-activityBar-inactiveForeground)] hover:text-[var(--vscode-activityBar-foreground)] hover:bg-[var(--vscode-toolbar-hoverBackground)] transition-colors"
            title="返回主页"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>

          {/* 设置图标和标题 */}
          <div className="flex items-center gap-2">
            <Settings className="w-4 h-4 text-[var(--vscode-activityBar-foreground)]" />
            <span className="text-sm font-medium text-[var(--vscode-activityBar-foreground)]">设置</span>
          </div>
        </div>

        {/* 中间：设置子导航标签 */}
        <nav className="flex-1 flex items-center justify-center">
          <div className="flex items-center bg-[var(--vscode-editorGroupHeader-tabsBackground)] rounded px-1">
            {SETTINGS_NAV_ITEMS.map((item) => {
              const isActive = activeTabId === item.id
              const Icon = item.icon

              return (
                <button
                  key={item.id}
                  onClick={() => navigate(item.pathTemplate)}
                  className={cn(
                    "relative h-8 px-4 flex items-center gap-2 text-xs font-medium transition-colors border-r border-[var(--vscode-sideBar-border)]",
                    isActive
                      ? "bg-[var(--vscode-tab-activeBackground)] text-[var(--vscode-foreground)]"
                      : "text-[var(--vscode-activityBar-inactiveForeground)] hover:text-[var(--vscode-foreground)] hover:bg-[var(--vscode-toolbar-hoverBackground)]"
                  )}
                  title={item.description}
                >
                  <Icon className="w-3.5 h-3.5" />
                  {item.label}
                </button>
              )
            })}
          </div>
        </nav>

        {/* 右侧：关闭按钮 */}
        <button
          onClick={() => navigate('/')}
          className="h-7 w-7 flex items-center justify-center rounded text-[var(--vscode-activityBar-inactiveForeground)] hover:text-[var(--vscode-activityBar-foreground)] hover:bg-[var(--vscode-toolbar-hoverBackground)] transition-colors"
          title="关闭设置"
        >
          <X className="w-4 h-4" />
        </button>
      </header>

      {/* 页面标题栏（可选） */}
      {activeTab && (
        <div className="h-12 flex items-center px-6 border-b border-[var(--vscode-sideBar-background)] shrink-0">
          <div className="flex items-center gap-2">
            <activeTab.icon className="w-5 h-5 text-[var(--vscode-textLink-foreground)]" />
            <h1 className="text-base font-medium">{activeTab.label}</h1>
            <span className="text-xs text-[var(--vscode-descriptionForeground)] ml-2">
              {activeTab.description}
            </span>
          </div>
        </div>
      )}

      {/* 内容区域 */}
      <main className="flex-1 overflow-auto p-6">
        <Outlet />
      </main>
    </div>
  )
}
