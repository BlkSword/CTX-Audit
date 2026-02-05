/**
 * VSCode 风格状态栏
 * 底部状态信息栏
 */

import { VSCodeIcon } from './ActivityBar'

// ==================== 状态栏配置 ====================

interface StatusItem {
  id: string
  label: string
  icon?: string
  badge?: string | number
  onClick?: () => void
}

const LEFT_ITEMS: StatusItem[] = [
  { id: 'outline', label: '大纲' },
  { id: 'timeline', label: '时间线' },
  { id: 'problems', label: '0 \u25b2 0', badge: '0' },
]

const RIGHT_ITEMS: StatusItem[] = [
  { id: 'remote', label: 'Go Live', icon: 'remote' },
  { id: 'notifications', label: '', icon: 'bell' },
  { id: 'settings', label: '', icon: 'settings-gear' },
]

// ==================== 状态栏组件 ====================

export function StatusBar() {
  return (
    <div
      className="flex items-center justify-between h-6 px-2 bg-[var(--vscode-statusBar-background)] text-[var(--vscode-statusBar-foreground)] text-xs"
      style={{
        backgroundColor: '#007acc',
        color: '#ffffff',
        height: '22px',
      }}
    >
      {/* 左侧状态项 */}
      <div className="flex items-center gap-1">
        {LEFT_ITEMS.map((item) => (
          <button
            key={item.id}
            className="flex items-center gap-1 px-2 py-0.5 hover:bg-[rgba(255,255,255,0.1)] transition-colors cursor-pointer text-white"
            onClick={item.onClick}
          >
            {item.icon && <VSCodeIcon name={item.icon} className="w-4 h-4" />}
            <span>{item.label}</span>
            {item.badge !== undefined && (
              <span className="ml-1 px-1.5 bg-[rgba(255,255,255,0.2)] rounded-sm text-xs font-semibold">
                {item.badge}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* 右侧状态项 */}
      <div className="flex items-center gap-0.5">
        {RIGHT_ITEMS.map((item) => (
          <button
            key={item.id}
            className="flex items-center gap-1 px-2 py-0.5 hover:bg-[rgba(255,255,255,0.1)] transition-colors cursor-pointer text-white"
            onClick={item.onClick}
          >
            {item.icon && <VSCodeIcon name={item.icon} className="w-4 h-4" />}
            {item.label && <span>{item.label}</span>}
          </button>
        ))}
      </div>
    </div>
  )
}

export default StatusBar
