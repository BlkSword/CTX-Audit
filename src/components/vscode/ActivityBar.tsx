/**
 * VSCode 风格活动栏
 * 左侧垂直图标栏
 */

import { useVSCodeLayoutStore, ActivityId } from '@/stores/vscodeLayoutStore'

// ==================== 活动栏配置 ====================

interface ActivityBarItem {
  id: ActivityId
  icon: string
  label: string
  badge?: number | string
}

const TOP_ACTIVITIES: ActivityBarItem[] = [
  { id: 'explorer', icon: 'files', label: '资源管理器' },
  { id: 'search', icon: 'search', label: '搜索' },
  { id: 'git', icon: 'git-branch', label: '源代码管理' },
  { id: 'debug', icon: 'bug', label: '运行和调试' },
  { id: 'extensions', icon: 'extensions', label: '扩展' },
]

const BOTTOM_ACTIVITIES: ActivityBarItem[] = [
  { id: 'accounts', icon: 'account', label: '账户' },
  { id: 'settings', icon: 'settings-gear', label: '管理' },
]

// ==================== SVG 图标组件 ====================

interface IconProps {
  name: string
  className?: string
}

function VSCodeIcon({ name, className = '' }: IconProps) {
  const icons: Record<string, JSX.Element> = {
    // 文件相关
    files: (
      <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
        <path d="M20 6h-8l-2-2H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2zm0 12H4V8h16v10z" />
      </svg>
    ),
    'chevron-down': (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
        <path d="M11 5.5L8 8.5 5 5.5 4 6.5 8 10.5 12 6.5z" />
      </svg>
    ),
    'chevron-right': (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
        <path d="M6 4l4 4-4 4V4z" />
      </svg>
    ),
    search: (
      <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
        <path d="M15.25 0a8.25 8.25 0 0 0-6.18 13.72L1 22.88l1.12 1.12 8.05-9.12A8.251 8.251 0 1 0 15.25.01V0zm0 15a6.75 6.75 0 1 1 0-13.5 6.75 6.75 0 0 1 0 13.5z" />
      </svg>
    ),
    'git-branch': (
      <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
        <circle cx="6" cy="6" r="2" />
        <circle cx="6" cy="18" r="2" />
        <circle cx="18" cy="12" r="2" />
        <path d="M6 8v6" stroke="currentColor" strokeWidth="2" fill="none" />
        <path d="M8 12h10" stroke="currentColor" strokeWidth="2" fill="none" />
      </svg>
    ),
    bug: (
      <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
        <path d="M16 4h-2V2h-2v2h-2V2H8v2H6v2h10V4z" />
        <path d="M18 6H6v2h12V6z" />
        <path d="M19 10H5c-1.1 0-2 .9-2 2v6c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2v-6c0-1.1-.9-2-2-2zm0 8H5v-6h14v6z" />
      </svg>
    ),
    extensions: (
      <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
        <path d="M13.5 1.5L15 0h7.5L24 1.5V9l-1.5 1.5H15L13.5 9V1.5zm1.5 0V9h7.5V1.5H15zM0 15l1.5-1.5H9L10.5 15v7.5L9 24H1.5L0 22.5V15zm1.5 0v7.5H9V15H1.5z" />
        <path d="M13.5 15l1.5-1.5h7.5L24 15v7.5L22.5 24H15l-1.5-1.5V15zm1.5 0v7.5h7.5V15H15zM0 1.5L1.5 0H9l1.5 1.5V9L9 10.5H1.5L0 9V1.5zm1.5 0V9H9V1.5H1.5z" />
      </svg>
    ),
    account: (
      <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z" />
      </svg>
    ),
    'settings-gear': (
      <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
        <path d="M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58c.18-.14.23-.41.12-.61l-1.92-3.32c-.12-.22-.37-.29-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54c-.04-.24-.24-.41-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.09.63-.09.94s.02.64.07.94l-2.03 1.58c-.18.14-.23.41-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z" />
      </svg>
    ),
    'folder-open': (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
        <path d="M14 4H9.618l-1-2H2v12h12V4zm-1 9H3V6h10v7z" />
      </svg>
    ),
    'file-code': (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
        <path d="M4 2v12h8V2H4zm7 11H5V3h6v10z" />
        <path d="M6 5h4v1H6V5zm0 2h4v1H6V7zm0 2h3v1H6V9z" />
      </svg>
    ),
    close: (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
        <path d="M11.5 4.5L8 8l3.5 3.5L12 11l-2.5-2.5L12 6l-.5-.5zM8 8L4.5 4.5 4 5.5 6.5 8 4 10.5l.5.5L8 8z" />
      </svg>
    ),
    'chevron-up': (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
        <path d="M12 11L8 7 4 11l1 1.5L8 9.5l3 3z" />
      </svg>
    ),
    'horizontal-more': (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
        <circle cx="3" cy="8" r="1.5" />
        <circle cx="8" cy="8" r="1.5" />
        <circle cx="13" cy="8" r="1.5" />
      </svg>
    ),
    'bell': (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
        <path d="M8 2a4 4 0 0 0-4 4v3l-1 1v1h10v-1l-1-1V6a4 4 0 0 0-4-4zm0 10a2 2 0 0 1-2-2h4a2 2 0 0 1-2 2z" />
      </svg>
    ),
    'remote': (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
        <path d="M4 2v12h8V2H4zm7 11H5V3h6v10z" />
        <circle cx="8" cy="7.5" r="2" />
      </svg>
    ),
    'layout-sidebar-right': (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
        <path d="M1 3v10h14V3H1zm12 9H3V4h10v8z" />
        <path d="M10 5h2v7h-2V5z" />
      </svg>
    ),
  }

  return (
    <span className={`inline-flex items-center justify-center ${className}`}>
      {icons[name] || null}
    </span>
  )
}

// ==================== 活动栏组件 ====================

export function ActivityBar() {
  const { activeActivity, setActiveActivity, toggleSidebar, sidebarVisible } =
    useVSCodeLayoutStore()

  const handleClick = (id: ActivityId) => {
    if (activeActivity === id && sidebarVisible) {
      toggleSidebar()
    } else {
      setActiveActivity(id)
    }
  }

  return (
    <div
      className="flex flex-col items-center h-full bg-[var(--vscode-activityBar-background)]"
      style={{ width: '48px', minWidth: '48px' }}
    >
      {/* 顶部活动图标 */}
      <div className="flex flex-col items-center flex-1 py-1">
        {TOP_ACTIVITIES.map((activity) => {
          const isActive = activeActivity === activity.id
          return (
            <button
              key={activity.id}
              className={`
                relative flex items-center justify-center
                w-12 h-12 my-0.5
                text-[var(--vscode-activityBar-inactiveForeground)]
                transition-colors duration-150
                hover:text-[var(--vscode-activityBar-foreground)]
                ${isActive ? 'text-[var(--vscode-activityBar-foreground)]' : ''}
                before:content-[''] before:absolute before:left-0 before:top-2 before:bottom-2 before:w-0.5
                ${isActive ? 'before:bg-[var(--vscode-activityBar-foreground)]' : ''}
              `}
              onClick={() => handleClick(activity.id)}
              title={activity.label}
            >
              <VSCodeIcon name={activity.icon} className="w-6 h-6" />
              {activity.badge && (
                <span className="absolute top-1 right-1 flex items-center justify-center min-w-[16px] h-4 px-1 bg-[var(--vscode-badge-background)] text-[var(--vscode-badge-foreground)] text-xs font-bold rounded-sm">
                  {activity.badge}
                </span>
              )}
            </button>
          )
        })}
      </div>

      {/* 底部活动图标 */}
      <div className="flex flex-col items-center py-1 border-t border-[var(--vscode-sideBar-border)]">
        {BOTTOM_ACTIVITIES.map((activity) => {
          const isActive = activeActivity === activity.id
          return (
            <button
              key={activity.id}
              className={`
                relative flex items-center justify-center
                w-12 h-12 my-0.5
                text-[var(--vscode-activityBar-inactiveForeground)]
                transition-colors duration-150
                hover:text-[var(--vscode-activityBar-foreground)]
                ${isActive ? 'text-[var(--vscode-activityBar-foreground)]' : ''}
                before:content-[''] before:absolute before:left-0 before:top-2 before:bottom-2 before:w-0.5
                ${isActive ? 'before:bg-[var(--vscode-activityBar-foreground)]' : ''}
              `}
              onClick={() => handleClick(activity.id)}
              title={activity.label}
            >
              <VSCodeIcon name={activity.icon} className="w-6 h-6" />
            </button>
          )
        })}
      </div>
    </div>
  )
}

export default ActivityBar
