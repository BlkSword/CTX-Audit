/**
 * 设置页面布局
 */

import { Outlet, useNavigate, useLocation } from 'react-router-dom'
import {
  ArrowLeft,
  Settings,
  Server,
  Sliders,
  FileText,
  Shield,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'

const settingsNavItems = [
  {
    id: 'llm',
    label: 'LLM 配置',
    icon: Server,
    path: '/settings/llm',
  },
  {
    id: 'system',
    label: '系统设置',
    icon: Sliders,
    path: '/settings/system',
  },
  {
    id: 'prompts',
    label: '提示词模板',
    icon: FileText,
    path: '/settings/prompts',
  },
  {
    id: 'rules',
    label: '安全规则',
    icon: Shield,
    path: '/settings/rules',
  },
]

export function SettingsLayout() {
  const navigate = useNavigate()
  const location = useLocation()

  return (
    <div className="h-screen w-screen bg-background text-foreground flex flex-col overflow-hidden font-sans">
      {/* Header */}
      <header className="h-14 border-b border-border/40 px-6 flex items-center gap-4 bg-muted/20">
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8"
          onClick={() => navigate('/')}
        >
          <ArrowLeft className="w-4 h-4" />
        </Button>

        <div className="flex items-center gap-3">
          <Settings className="w-5 h-5 text-primary" />
          <h1 className="text-lg font-semibold">设置</h1>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex-1 overflow-hidden flex">
        {/* Sidebar */}
        <div className="w-56 border-r border-border/40 p-4">
          <nav className="space-y-1">
            {settingsNavItems.map((item) => {
              const Icon = item.icon
              const isActive = location.pathname === item.path

              return (
                <button
                  key={item.id}
                  onClick={() => navigate(item.path)}
                  className={cn(
                    'w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors',
                    isActive
                      ? 'bg-primary text-primary-foreground'
                      : 'text-muted-foreground hover:bg-muted hover:text-foreground'
                  )}
                >
                  <Icon className="w-4 h-4" />
                  {item.label}
                </button>
              )
            })}
          </nav>
        </div>

        {/* Content Area */}
        <div className="flex-1 overflow-auto no-scrollbar">
          <Outlet />
        </div>
      </div>
    </div>
  )
}
