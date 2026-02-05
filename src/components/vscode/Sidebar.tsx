/**
 * VSCode 风格侧边栏
 * 左侧面板，根据活动栏显示不同内容
 */

import { useVSCodeLayoutStore } from '@/stores/vscodeLayoutStore'
import { FileExplorer } from './FileExplorer'
import { VSCodeIcon } from './ActivityBar'

// ==================== 侧边栏面板组件 ====================

function ExplorerPanel() {
  return (
    <div className="h-full">
      <FileExplorer />
    </div>
  )
}

function SearchPanel() {
  return (
    <div className="flex flex-col h-full p-3">
      <input
        type="text"
        placeholder="搜索"
        className="w-full px-3 py-1.5 bg-[var(--vscode-input-background)] text-[var(--vscode-input-foreground)] border border-[var(--vscode-input-border)] text-sm rounded-sm focus:outline-none focus:border-[var(--vscode-focusBorder)]"
      />
      <div className="flex-1 flex items-center justify-center text-[var(--vscode-descriptionForeground)] text-sm">
        输入以搜索
      </div>
    </div>
  )
}

function GitPanel() {
  return (
    <div className="flex flex-col h-full p-3">
      <div className="text-sm text-[var(--vscode-sideBar-foreground)] mb-3">源代码管理</div>
      <div className="flex-1 flex items-center justify-center text-[var(--vscode-descriptionForeground)] text-sm">
        没有打开的存储库
      </div>
    </div>
  )
}

function DebugPanel() {
  return (
    <div className="flex flex-col h-full p-3">
      <div className="text-sm text-[var(--vscode-sideBar-foreground)] mb-3">运行和调试</div>
      <div className="flex-1 flex items-center justify-center text-[var(--vscode-descriptionForeground)] text-sm">
        尚未配置启动
      </div>
    </div>
  )
}

function ExtensionsPanel() {
  return (
    <div className="flex flex-col h-full p-3">
      <div className="text-sm text-[var(--vscode-sideBar-foreground)] mb-3">扩展</div>
      <div className="flex-1 flex items-center justify-center text-[var(--vscode-descriptionForeground)] text-sm">
        暂无扩展
      </div>
    </div>
  )
}

function AccountsPanel() {
  return (
    <div className="flex flex-col h-full p-3">
      <div className="text-sm text-[var(--vscode-sideBar-foreground)] mb-3">账户</div>
      <div className="flex-1 flex items-center justify-center text-[var(--vscode-descriptionForeground)] text-sm">
        已登录
      </div>
    </div>
  )
}

function SettingsPanel() {
  return (
    <div className="flex flex-col h-full p-3">
      <div className="text-sm text-[var(--vscode-sideBar-foreground)] mb-3">管理</div>
      <div className="space-y-1">
        <button className="w-full text-left px-3 py-2 text-sm text-[var(--vscode-sideBar-foreground)] hover:bg-[var(--vscode-list-hoverBackground)] rounded-sm">
          设置
        </button>
        <button className="w-full text-left px-3 py-2 text-sm text-[var(--vscode-sideBar-foreground)] hover:bg-[var(--vscode-list-hoverBackground)] rounded-sm">
          主题
        </button>
        <button className="w-full text-left px-3 py-2 text-sm text-[var(--vscode-sideBar-foreground)] hover:bg-[var(--vscode-list-hoverBackground)] rounded-sm">
          键盘快捷方式
        </button>
      </div>
    </div>
  )
}

// ==================== 侧边栏组件 ====================

export function Sidebar() {
  const { activeActivity, sidebarVisible, sidebarWidth } = useVSCodeLayoutStore()

  if (!sidebarVisible) {
    return null
  }

  const renderPanel = () => {
    switch (activeActivity) {
      case 'explorer':
        return <ExplorerPanel />
      case 'search':
        return <SearchPanel />
      case 'git':
        return <GitPanel />
      case 'debug':
        return <DebugPanel />
      case 'extensions':
        return <ExtensionsPanel />
      case 'accounts':
        return <AccountsPanel />
      case 'settings':
        return <SettingsPanel />
      default:
        return <ExplorerPanel />
    }
  }

  return (
    <div
      className="h-full bg-[var(--vscode-sideBar-background)] border-r border-[var(--vscode-sideBar-border)] overflow-hidden"
      style={{ width: `${sidebarWidth}px` }}
    >
      {renderPanel()}
    </div>
  )
}

export default Sidebar
