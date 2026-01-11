/**
 * EditorPanel - 代码编辑器面板
 * 三列布局：左侧文件树 - 中间编辑器 - 右侧终端
 */

import { useRef, useState, useMemo } from 'react'
import Editor from '@monaco-editor/react'
import { useFileStore } from '@/stores/fileStore'
import { useUIStore } from '@/stores/uiStore'
import { useAgentStore } from '@/stores/agentStore'
import { useAgentStream } from '@/hooks/useAgentStream'
import { ScrollArea } from '@/components/ui/scroll-area'
import { ResizableHandle, ResizablePanel, ResizablePanelGroup } from '@/components/ui/resizable'
import { X } from 'lucide-react'
import { FileTree } from '@/components/file-explorer/FileTree'
import { EnhancedLogPanel } from '@/components/audit/EnhancedLogPanel'
import type { LogItem } from '@/shared/types'

function getLanguageFromPath(path: string | null): string {
  if (!path) return 'plaintext'
  // 提取文件名，处理 Windows/Unix 路径分隔符
  const filename = path.split(/[/\\]/).pop() || ''
  const ext = filename.split('.').pop()?.toLowerCase()

  if (!ext || ext === filename) return 'plaintext'

  switch (ext) {
    case 'ts': return 'typescript'
    case 'tsx': return 'typescript'
    case 'js': return 'javascript'
    case 'jsx': return 'javascript'
    case 'rs': return 'rust'
    case 'py': return 'python'
    case 'java': return 'java'
    case 'go': return 'go'
    case 'c': return 'c'
    case 'cpp': return 'cpp'
    case 'h': return 'cpp'
    case 'hpp': return 'cpp'
    case 'cs': return 'csharp'
    case 'json': return 'json'
    case 'css': return 'css'
    case 'html': return 'html'
    case 'md': return 'markdown'
    case 'yaml': return 'yaml'
    case 'yml': return 'yaml'
    case 'xml': return 'xml'
    case 'sql': return 'sql'
    case 'sh': return 'shell'
    case 'bash': return 'shell'
    case 'zsh': return 'shell'
    case 'dockerfile': return 'dockerfile'
    case 'toml': return 'toml'
    case 'ini': return 'ini'
    case 'conf': return 'ini'
    case 'gradle': return 'groovy'
    case 'vue': return 'html' // Monaco doesn't have built-in vue, use html
    case 'svelte': return 'html'
    case 'php': return 'php'
    case 'rb': return 'ruby'
    case 'swift': return 'swift'
    case 'kt': return 'kotlin'
    case 'dart': return 'dart'
    case 'lua': return 'lua'
    case 'r': return 'r'
    case 'pl': return 'perl'
    case 'vb': return 'vb'
    case 'fs': return 'fsharp'
    case 'ex': return 'elixir'
    case 'exs': return 'elixir'
    case 'erl': return 'erlang'
    case 'clj': return 'clojure'
    case 'graphql': return 'graphql'
    case 'gql': return 'graphql'
    case 'txt': return 'plaintext'
    case 'log': return 'plaintext'
    case 'env': return 'ini'
    default: return 'plaintext'
  }
}

export function EditorPanel() {
  const { fileTree, openFiles, selectedFile, fileContent, selectFile, closeFile } = useFileStore()
  const { logs, bottomPanelVisible, setBottomPanelVisible, clearLogs } = useUIStore()
  const { currentAuditId } = useAgentStore()
  const editorRef = useRef<any>(null)

  // 获取 Agent 实时日志
  const { logs: agentLogs } = useAgentStream({
    auditId: currentAuditId || undefined,
    enabled: !!currentAuditId
  })

  // 日志展开状态
  const [expandedLogIds, setExpandedLogIds] = useState<Set<string>>(new Set())
  const handleToggleExpand = (id: string) => {
    const newSet = new Set(expandedLogIds)
    if (newSet.has(id)) {
      newSet.delete(id)
    } else {
      newSet.add(id)
    }
    setExpandedLogIds(newSet)
  }

  const handleEditorDidMount = (editor: any) => {
    editorRef.current = editor
  }

  // 合并并排序日志
  const allLogs = useMemo(() => {
    // 转换系统日志
    const systemLogItems: LogItem[] = logs
      .filter(l => l.source !== 'python')
      .map(l => ({
        id: l.id,
        type: 'system',
        agent_type: 'SYSTEM',
        // 尝试从 ID 提取时间戳（因为 ID 是 Date.now() + random）
        timestamp: parseInt(l.id.substring(0, 13)) || Date.now(),
        content: l.message
      }))

    // 合并
    return [...systemLogItems, ...agentLogs].sort((a, b) => a.timestamp - b.timestamp)
  }, [logs, agentLogs])

  return (
    <div className="h-full">
      <ResizablePanelGroup
        direction="horizontal"
        className="h-full items-stretch"
      >
        {/* 左侧文件树 */}
        <ResizablePanel defaultSize={20} minSize={5} id="left-panel">
          <div className="h-full flex flex-col border-r border-border/40 min-w-0">
            <div className="h-9 px-3 flex items-center border-b border-border/40 bg-muted/10 shrink-0">
              <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground truncate">
                资源管理器
              </span>
            </div>
            <ScrollArea className="flex-1">
              <div className="p-2">
                <FileTree
                  nodes={fileTree}
                  selectedPath={selectedFile}
                  onSelect={selectFile}
                />
              </div>
            </ScrollArea>
          </div>
        </ResizablePanel>

        {/* 左侧分隔条 */}
        <ResizableHandle withHandle={true} />

        {/* 中间编辑器区域 */}
        <ResizablePanel
          defaultSize={60}
          minSize={5}
          id="editor-panel"
        >
          <div className="h-full flex flex-col bg-[#1e1e1e] min-w-0">
            {/* Tabs */}
            <div className="h-9 flex items-end bg-[#18181b] border-b border-[#2b2b2b] shrink-0 overflow-hidden">
              {openFiles.length > 0 ? (
                openFiles.map(path => (
                  <div
                    key={path}
                    onClick={() => selectFile(path)}
                    className={`h-full px-3 min-w-[100px] max-w-[200px] flex items-center gap-2 border-t-2 text-xs cursor-pointer group select-none ${selectedFile === path
                      ? 'bg-[#1e1e1e] border-primary text-foreground/90'
                      : 'bg-[#2d2d2d] border-transparent text-muted-foreground hover:bg-[#252526]'
                      }`}
                  >
                    <span className="truncate flex-1">{path.split(/[/\\]/).pop()}</span>
                    <button
                      onClick={(e) => {
                        e.stopPropagation()
                        closeFile(path)
                      }}
                      className={`hover:bg-muted/50 rounded-sm p-0.5 shrink-0 ${selectedFile === path ? 'opacity-100' : 'opacity-0 group-hover:opacity-100'
                        }`}
                    >
                      <X className="w-3 h-3" />
                    </button>
                  </div>
                ))
              ) : (
                <div className="h-full px-3 flex items-center text-xs text-muted-foreground italic truncate">
                  未选择文件
                </div>
              )}
            </div>

            {/* Editor - 使用绝对定位防止撑开 */}
            <div className="flex-1 relative w-full h-full overflow-hidden">
              <div className="absolute inset-0">
                <Editor
                  height="100%"
                  width="100%"
                  onMount={handleEditorDidMount}
                  language={getLanguageFromPath(selectedFile)}
                  theme="vs-dark"
                  value={fileContent}
                  options={{
                    minimap: { enabled: true, scale: 0.5 },
                    fontSize: 13,
                    lineHeight: 20,
                    readOnly: true,
                    wordWrap: 'on',
                    wrappingStrategy: 'advanced',
                    fontFamily: "'JetBrains Mono', 'Fira Code', Consolas, monospace",
                    scrollBeyondLastLine: false,
                    smoothScrolling: true,
                    padding: { top: 10 },
                    automaticLayout: true,
                    formatOnPaste: true,
                    formatOnType: true,
                    renderWhitespace: 'selection',
                  }}
                />
              </div>
            </div>
          </div>
        </ResizablePanel>

        {/* 右侧终端面板 */}
        {bottomPanelVisible && (
          <>
            <ResizableHandle withHandle={true} />
            <ResizablePanel
              defaultSize={20}
              minSize={5}
              id="right-panel"
            >
              <div className="h-full flex flex-col border-l border-border/40 min-w-0">
                <div className="flex-1 overflow-hidden relative">
                  <div className="absolute inset-0">
                    <EnhancedLogPanel
                      logs={allLogs}
                      active={true}
                      expandedLogIds={expandedLogIds}
                      onToggleExpand={handleToggleExpand}
                      onToggle={() => setBottomPanelVisible(false)}
                      onClear={clearLogs}
                    />
                  </div>
                </div>
              </div>
            </ResizablePanel>
          </>
        )}
      </ResizablePanelGroup>
    </div>
  )

}
