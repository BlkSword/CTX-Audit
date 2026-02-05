/**
 * TerminalPanel - 集成终端面板
 *
 * 使用 Tauri 的 Shell 命令执行系统命令
 * VSCode 风格设计
 */

import { useState, useEffect, useRef, useCallback } from 'react'
import { Terminal as TerminalIcon, Plus, X, Trash2, ChevronDown, ChevronRight } from 'lucide-react'
import { invoke } from '@tauri-apps/api/core'
import { cn } from '@/lib/utils'
import { useProjectStore } from '@/stores/projectStore'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'

// ==================== 类型定义 ====================

interface TerminalSession {
  id: string
  title: string
  shell: string
  cwd: string
  status: 'running' | 'stopped' | 'error'
}

interface TerminalOutput {
  id: string
  sessionId: string
  text: string
  timestamp: number
}

// ==================== 主组件 ====================

export function TerminalPanel() {
  const { currentProject } = useProjectStore()
  const [sessions, setSessions] = useState<TerminalSession[]>([])
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null)
  const [outputs, setOutputs] = useState<Record<string, TerminalOutput[]>>({})
  const [newSessionShell, setNewSessionShell] = useState('cmd')
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false)
  const terminalRefs = useRef<Record<string, HTMLDivElement>>({})

  // 当前活动的输出
  const activeOutputs = activeSessionId ? (outputs[activeSessionId] || []) : []

  // 创建新终端会话
  const createSession = useCallback(async (shell: string, cwd?: string) => {
    const sessionId = `term-${Date.now()}`
    const workingDir = cwd || currentProject?.path || '.'

    const newSession: TerminalSession = {
      id: sessionId,
      title: `${shell} · ${workingDir.split('/').pop() || workingDir}`,
      shell,
      cwd: workingDir,
      status: 'running',
    }

    setSessions(prev => [...prev, newSession])
    setActiveSessionId(sessionId)
    setOutputs(prev => ({ ...prev, [sessionId]: [] }))
    setIsCreateDialogOpen(false)

    // 发送初始欢迎消息
    addOutput(sessionId, `Welcome to CTX-Audit Terminal\r\nShell: ${shell}\r\nWorking directory: ${workingDir}\r\n\r\n$ `)
  }, [currentProject])

  // 添加输出
  const addOutput = useCallback((sessionId: string, text: string) => {
    setOutputs(prev => ({
      ...prev,
      [sessionId]: [
        ...(prev[sessionId] || []),
        {
          id: `out-${Date.now()}-${Math.random()}`,
          sessionId,
          text,
          timestamp: Date.now(),
        },
      ],
    }))
  }, [])

  // 执行命令
  const executeCommand = useCallback(async (sessionId: string, command: string) => {
    const session = sessions.find(s => s.id === sessionId)
    if (!session || session.status !== 'running') return

    // 添加命令到输出
    addOutput(sessionId, `$ ${command}\r\n`)

    try {
      // 使用 Tauri invoke 调用后端执行命令
      // 注意：这需要后端支持 execute_command 命令
      const result = await invoke<string>('execute_command', {
        sessionId,
        command,
        shell: session.shell,
        cwd: session.cwd,
      })

      addOutput(sessionId, `${result || ''}\r\n$ `)
    } catch (error) {
      addOutput(sessionId, `Error: ${error}\r\n$ `)
    }
  }, [sessions, addOutput])

  // 关闭会话
  const closeSession = useCallback((sessionId: string) => {
    setSessions(prev => prev.filter(s => s.id !== sessionId))
    if (activeSessionId === sessionId) {
      const remaining = sessions.filter(s => s.id !== sessionId)
      setActiveSessionId(remaining.length > 0 ? remaining[0].id : null)
    }
    setOutputs(prev => {
      const newOutputs = { ...prev }
      delete newOutputs[sessionId]
      return newOutputs
    })
  }, [activeSessionId, sessions])

  // 清空当前会话输出
  const clearCurrentOutput = useCallback(() => {
    if (activeSessionId) {
      setOutputs(prev => ({ ...prev, [activeSessionId]: [] }))
    }
  }, [activeSessionId])

  // 处理命令输入
  const [commandInput, setCommandInput] = useState('')
  const inputRef = useRef<HTMLInputElement>(null)

  const handleSubmitCommand = (e: React.FormEvent) => {
    e.preventDefault()
    if (!commandInput.trim() || !activeSessionId) return

    const cmd = commandInput.trim()
    setCommandInput('')
    executeCommand(activeSessionId, cmd)

    // 聚焦输入框
    setTimeout(() => inputRef.current?.focus(), 100)
  }

  // 自动滚动到底部
  useEffect(() => {
    if (activeSessionId && terminalRefs.current[activeSessionId]) {
      const container = terminalRefs.current[activeSessionId]
      container.scrollTop = container.scrollHeight
    }
  }, [activeOutputs, activeSessionId])

  return (
    <div className="h-full flex flex-col bg-[var(--vscode-sideBar-background)]">
      {/* 终端工具栏 */}
      <div className="flex items-center justify-between px-2 py-1 border-b border-[var(--vscode-sideBar-border)] shrink-0">
        <div className="flex items-center gap-1">
          {/* 新建终端按钮 */}
          <Button
            size="sm"
            variant="ghost"
            className="h-7 px-2"
            onClick={() => setIsCreateDialogOpen(true)}
            title="新建终端"
          >
            <Plus className="w-3.5 h-3.5" />
          </Button>

          {/* 会话选择器 */}
          {sessions.length > 0 && (
            <div className="flex items-center gap-1">
              <select
                value={activeSessionId || ''}
                onChange={(e) => setActiveSessionId(e.target.value || null)}
                className="h-7 bg-[var(--vscode-input-background)] text-[var(--vscode-input-foreground)] text-xs px-2 rounded border border-[var(--vscode-input-border)] focus:outline-none focus:border-[var(--vscode-focusBorder)]"
              >
                {sessions.map((session) => (
                  <option key={session.id} value={session.id}>
                    {session.title}
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>

        <div className="flex items-center gap-1">
          {/* 清空按钮 */}
          <Button
            size="sm"
            variant="ghost"
            className="h-7 w-7"
            onClick={clearCurrentOutput}
            disabled={!activeSessionId}
            title="清空终端"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </Button>

          {/* 关闭按钮 */}
          {sessions.length > 0 && activeSessionId && (
            <Button
              size="sm"
              variant="ghost"
              className="h-7 w-7"
              onClick={() => closeSession(activeSessionId)}
              title="关闭终端"
            >
              <X className="w-3.5 h-3.5" />
            </Button>
          )}
        </div>
      </div>

      {/* 终端会话区域 */}
      <div className="flex-1 overflow-auto">
        {!activeSessionId || sessions.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-[var(--vscode-descriptionForeground)] p-6">
            <TerminalIcon className="w-12 h-12 mb-4 opacity-30" />
            <p className="text-sm mb-4">没有打开的终端</p>
            <Button
              size="sm"
              onClick={() => setIsCreateDialogOpen(true)}
              className="gap-2"
            >
              <Plus className="w-4 h-4" />
              新建终端
            </Button>
          </div>
        ) : (
          <div className="h-full flex flex-col">
            {sessions.map((session) => (
              <div
                key={session.id}
                ref={el => { if (session.id === activeSessionId && el) terminalRefs.current[session.id] = el }}
                className={cn(
                  "flex-1 overflow-auto p-2 font-mono text-xs whitespace-pre-wrap break-words",
                  session.id === activeSessionId ? 'block' : 'hidden'
                )}
                style={{
                  fontFamily: 'Consolas, "Courier New", monospace',
                }}
              >
                {activeOutputs.map((output) => (
                  <div key={output.id} className="mb-0.5">
                    {output.text}
                  </div>
                ))}
              </div>
            ))}
          </div>
        )}

        {/* 命令输入框 */}
        {activeSessionId && sessions.length > 0 && (
          <div className="shrink-0 p-2 border-t border-[var(--vscode-sideBar-border)]">
            <form onSubmit={handleSubmitCommand} className="flex items-center gap-2">
              <span className="text-[var(--vscode-descriptionForeground)]">$</span>
              <Input
                ref={inputRef}
                type="text"
                value={commandInput}
                onChange={(e) => setCommandInput(e.target.value)}
                placeholder="输入命令..."
                className="flex-1 h-8 bg-[var(--vscode-input-background)] text-[var(--vscode-input-foreground)] text-xs px-2 py-1 rounded border border-[var(--vscode-input-border)] focus:outline-none focus:border-[var(--vscode-focusBorder)]"
                autoFocus
              />
              <Button
                type="submit"
                size="sm"
                variant="ghost"
                className="h-7 px-2"
                disabled={!commandInput.trim()}
              >
                执行
              </Button>
            </form>
          </div>
        )}
      </div>

      {/* 新建终端对话框 */}
      {isCreateDialogOpen && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-[var(--vscode-sideBar-background)] border border-[var(--vscode-sideBar-border)] rounded-lg p-6 w-[400px] shadow-[var(--vscode-widget-shadow)]">
            <h3 className="text-base font-semibold mb-4 text-[var(--vscode-foreground)]">新建终端</h3>

            <div className="space-y-4">
              {/* Shell 类型 */}
              <div className="space-y-2">
                <label className="text-xs text-[var(--vscode-foreground)]">Shell 类型</label>
                <select
                  value={newSessionShell}
                  onChange={(e) => setNewSessionShell(e.target.value)}
                  className="w-full h-8 bg-[var(--vscode-input-background)] text-[var(--vscode-input-foreground)] text-xs px-2 py-1 rounded border border-[var(--vscode-input-border)] focus:outline-none focus:border-[var(--vscode-focusBorder)]"
                >
                  <option value="cmd">CMD (Windows)</option>
                  <option value="powershell">PowerShell</option>
                  <option value="bash">Bash (WSL/Git Bash)</option>
                  <option value="zsh">Zsh</option>
                </select>
              </div>

              {/* 工作目录 */}
              <div className="space-y-2">
                <label className="text-xs text-[var(--vscode-foreground)]">工作目录</label>
                <Input
                  value={currentProject?.path || ''}
                  placeholder="工作目录"
                  className="text-xs"
                  disabled
                />
              </div>

              {/* 按钮组 */}
              <div className="flex items-center justify-end gap-2 pt-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setIsCreateDialogOpen(false)}
                >
                  取消
                </Button>
                <Button
                  size="sm"
                  onClick={() => createSession(newSessionShell)}
                  disabled={!currentProject}
                >
                  创建
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
