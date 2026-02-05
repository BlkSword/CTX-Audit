/**
 * VSCode 风格欢迎页面
 * 类似截图中的欢迎界面
 */

import { useNavigate } from 'react-router-dom'

// ==================== 快捷键列表 ====================

const SHORTCUTS = [
  { keys: ['Ctrl', 'Shift', 'P'], label: '显示所有命令' },
  { keys: ['Ctrl', 'P'], label: '快速打开文件' },
  { keys: ['Ctrl', 'Shift', 'N'], label: '新建窗口' },
  { keys: ['Ctrl', ','], label: '打开用户设置' },
]

// ==================== 快捷键显示组件 ====================

function KeyShortcut({ keys }: { keys: string[] }) {
  return (
    <span className="inline-flex items-center gap-1">
      {keys.map((key, index) => (
        <span key={index} className="flex items-center">
          <kbd className="inline-flex items-center justify-center min-w-[20px] h-5 px-1.5 bg-[var(--vscode-keybindingLabel-background)] text-[var(--vscode-keybindingLabel-foreground)] text-xs border border-[var(--vscode-keybindingLabel-border)] rounded-sm">
            {key}
          </kbd>
          {index < keys.length - 1 && <span className="mx-1 text-[var(--vscode-descriptionForeground)]">+</span>}
        </span>
      ))}
    </span>
  )
}

// ==================== 欢迎页面组件 ====================

export function WelcomePage() {
  const navigate = useNavigate()

  const handleOpenFolder = async () => {
    // 使用 Tauri API 打开文件夹
    try {
      const { open } = await import('@tauri-apps/plugin-dialog')
      const selected = await open({
        directory: true,
        multiple: false,
        title: '选择项目目录',
      })
      if (selected) {
        // 导航到项目页面
        navigate(`/editor/${encodeURIComponent(selected as string)}`)
      }
    } catch (error) {
      console.error('打开文件夹失败:', error)
    }
  }

  const handleCloneRepository = () => {
    // TODO: 实现克隆仓库功能
    console.log('克隆仓库')
  }

  return (
    <div
      className="flex flex-col items-center justify-center h-full bg-[var(--vscode-editor-background)]"
      style={{
        background: 'linear-gradient(135deg, rgba(30,30,30,0.95) 0%, rgba(40,40,40,0.95) 100%)',
      }}
    >
      {/* 主内容区域 */}
      <div className="relative flex flex-col items-center justify-center max-w-2xl w-full px-8">
        {/* 装饰性背景 */}
        <div
          className="absolute inset-0 opacity-5 pointer-events-none"
          style={{
            backgroundImage: `url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='1'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E")`,
          }}
        />

        {/* 标题 */}
        <h1 className="relative text-4xl font-bold text-white mb-2">
          欢迎
        </h1>

        {/* 副标题 */}
        <p className="relative text-sm text-[var(--vscode-descriptionForeground)] mb-8">
          没有打开的文件夹
        </p>

        {/* 操作按钮 */}
        <div className="relative flex flex-col items-center gap-3 mb-8">
          <button
            className="inline-flex items-center justify-center px-6 py-2 bg-[var(--vscode-button-background)] text-[var(--vscode-button-foreground)] text-sm font-semibold rounded-sm hover:bg-[var(--vscode-button-hoverBackground)] transition-colors cursor-pointer"
            onClick={handleOpenFolder}
          >
            <span>打开文件夹</span>
          </button>

          <button
            className="inline-flex items-center justify-center px-6 py-2 bg-[var(--vscode-button-background)] text-[var(--vscode-button-foreground)] text-sm font-semibold rounded-sm hover:bg-[var(--vscode-button-hoverBackground)] transition-colors cursor-pointer"
            onClick={handleCloneRepository}
          >
            <span>克隆仓库</span>
          </button>
        </div>

        {/* 提示文本 */}
        <p className="relative text-sm text-[var(--vscode-descriptionForeground)] mb-8 text-center">
          可以在本地克隆仓库。
        </p>

        {/* 文档链接 */}
        <a
          href="#"
          className="relative text-sm text-[var(--vscode-textLink-foreground)] hover:text-[var(--vscode-textLink-activeForeground)] underline mb-12"
        >
          若要详细了解如何在 CTX-Audit 中使用代码审计功能，参阅我们的文档。
        </a>

        {/* 快捷键列表 */}
        <div className="relative self-end space-y-2">
          {SHORTCUTS.map((shortcut, index) => (
            <div key={index} className="flex items-center justify-between gap-8 text-sm">
              <span className="text-[var(--vscode-descriptionForeground)]">
                {shortcut.label}
              </span>
              <KeyShortcut keys={shortcut.keys} />
            </div>
          ))}
        </div>
      </div>

      {/* VSCode KeybindingLabel 颜色变量 (如果未定义) */}
      <style>{`
        :root {
          --vscode-keybindingLabel-background: #404040;
          --vscode-keybindingLabel-foreground: #cccccc;
          --vscode-keybindingLabel-border: #555555;
          --vscode-statusBar-background: #007acc;
          --vscode-statusBar-foreground: #ffffff;
        }
      `}</style>
    </div>
  )
}

export default WelcomePage
