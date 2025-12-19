import { useState, useEffect, useRef, useMemo } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import Editor from '@monaco-editor/react'
import ReactFlow, { Background, Controls } from 'reactflow'
import 'reactflow/dist/style.css'
import {
  FolderOpen,
  FileCode,
  ShieldAlert,
  Search,
  GitBranch,
  ChevronRight,
  ChevronDown,
  Folder,
  Network,
  Terminal,
  Loader2,
  Hammer,
  Database,
  FileDiff
} from 'lucide-react'

import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Input } from "@/components/ui/input"
import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { DiffViewer } from "@/components/diff/DiffViewer"

interface LogEntry {
  timestamp: string
  message: string
  source: 'rust' | 'python' | 'system'
}

interface SearchResult {
  file: string
  line: number
  content: string
}

interface Vulnerability {
  file: string
  line: number
  severity: 'high' | 'medium' | 'low'
  message: string
}

interface FileNode {
  name: string
  path: string
  type: 'file' | 'folder'
  children?: FileNode[]
}

const MCP_TOOL_DESCRIPTIONS: Record<string, string> = {
  build_ast_index: '构建/更新项目的 AST 索引，用于后续分析',
  run_security_scan: '使用自定义规则运行安全扫描',
  get_analysis_report: '读取最近一次分析生成的缓存报告',
  find_call_sites: '按被调用函数名查找调用点（基于 AST 索引）',
  get_call_graph: '从入口函数/方法名生成深度受限调用图（基于 AST 索引）',
  read_file: '通过 MCP 读取文件内容',
  list_files: '列出目录下的文件与子目录（非递归）',
  search_files: '在目录内按正则搜索文本（逐行匹配）',
  get_code_structure: '读取单文件的类/函数/方法结构（基于 AST）',
  search_symbol: '在项目范围内搜索类/函数等符号（基于 AST 索引）',
  get_class_hierarchy: '查看指定类的父类/子类层次（基于 AST 索引）',
}

function buildFileTree(paths: string[], rootPath: string): FileNode[] {
  const root: FileNode[] = []

  paths.forEach(path => {
    // Normalize path separators
    let relativePath = path;
    if (rootPath && path.startsWith(rootPath)) {
      relativePath = path.substring(rootPath.length).replace(/^[/\\]/, '');
    }

    const parts = relativePath.split(/[/\\]/)
    let currentLevel = root

    parts.forEach((part, index) => {
      // Skip empty parts
      if (!part) return

      const existingNode = currentLevel.find(node => node.name === part)
      const isFile = index === parts.length - 1

      if (existingNode) {
        if (existingNode.type === 'folder' && existingNode.children) {
          currentLevel = existingNode.children
        }
      } else {
        const newNode: FileNode = {
          name: part,
          path: isFile ? path : parts.slice(0, index + 1).join('/'),
          type: isFile ? 'file' : 'folder',
          children: isFile ? undefined : []
        }
        currentLevel.push(newNode)
        if (!isFile && newNode.children) {
          currentLevel = newNode.children
        }
      }
    })
  })

  // Sort: folders first, then files
  const sortNodes = (nodes: FileNode[]) => {
    nodes.sort((a, b) => {
      if (a.type === b.type) return a.name.localeCompare(b.name)
      return a.type === 'folder' ? -1 : 1
    })
    nodes.forEach(node => {
      if (node.children) sortNodes(node.children)
    })
  }
  sortNodes(root)

  return root
}

const FileTreeNode = ({ node, level, onSelect, selectedPath }: { node: FileNode, level: number, onSelect: (path: string) => void, selectedPath: string | null }) => {
  const [isOpen, setIsOpen] = useState(false)

  // Auto-expand if selected file is inside this folder
  useEffect(() => {
    if (selectedPath && selectedPath.startsWith(node.path) && node.type === 'folder') {
      setIsOpen(true)
    }
  }, [selectedPath, node.path, node.type])

  if (node.type === 'file') {
    return (
      <button
        onClick={() => onSelect(node.path)}
        className={`w-full text-left px-2 py-1 rounded-sm text-xs font-mono truncate transition-colors flex items-center gap-2 group ${selectedPath === node.path
          ? 'bg-primary/10 text-primary'
          : 'text-muted-foreground hover:bg-muted/50 hover:text-foreground'
          }`}
        style={{ paddingLeft: `${level * 12 + 8}px` }}
        title={node.path}
      >
        {/* Simple Icon Logic */}
        {node.name.endsWith('.rs') ? <span className="text-orange-500 w-3.5 text-center font-bold text-[10px]">Rs</span> :
          node.name.endsWith('.py') ? <span className="text-blue-400 w-3.5 text-center font-bold text-[10px]">Py</span> :
            node.name.endsWith('.tsx') || node.name.endsWith('.ts') ? <span className="text-blue-500 w-3.5 text-center font-bold text-[10px]">TS</span> :
              <FileCode className="w-3.5 h-3.5 opacity-70" />}

        <span className="truncate">{node.name}</span>
      </button>
    )
  }

  return (
    <Collapsible open={isOpen} onOpenChange={setIsOpen}>
      <CollapsibleTrigger className="w-full text-left px-2 py-1 rounded-sm text-xs font-mono truncate transition-colors flex items-center gap-1 text-muted-foreground hover:text-foreground hover:bg-muted/30"
        style={{ paddingLeft: `${level * 12 + 4}px` }}
      >
        {isOpen ? <ChevronDown className="w-3 h-3 opacity-70" /> : <ChevronRight className="w-3 h-3 opacity-70" />}
        <Folder className={`w-3.5 h-3.5 ${isOpen ? 'text-foreground' : 'text-muted-foreground/70'}`} />
        <span className="truncate">{node.name}</span>
      </CollapsibleTrigger>
      <CollapsibleContent>
        {node.children?.map(child => (
          <FileTreeNode key={child.path} node={child} level={level + 1} onSelect={onSelect} selectedPath={selectedPath} />
        ))}
      </CollapsibleContent>
    </Collapsible>
  )
}

function getLanguageFromPath(path: string | null): string {
  if (!path) return 'Plain Text';
  const ext = path.split('.').pop()?.toLowerCase();
  switch (ext) {
    case 'ts': return 'TypeScript';
    case 'tsx': return 'TypeScript React';
    case 'js': return 'JavaScript';
    case 'jsx': return 'JavaScript React';
    case 'rs': return 'Rust';
    case 'py': return 'Python';
    case 'json': return 'JSON';
    case 'css': return 'CSS';
    case 'html': return 'HTML';
    case 'md': return 'Markdown';
    case 'sql': return 'SQL';
    case 'toml': return 'TOML';
    case 'yaml':
    case 'yml': return 'YAML';
    case 'lock': return 'Lock File';
    case 'gitignore': return 'Git Ignore';
    default: return ext ? ext.toUpperCase() : 'Plain Text';
  }
}

function App() {
  const [projectPath, setProjectPath] = useState<string>('')
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [files, setFiles] = useState<string[]>([])
  const [fileTree, setFileTree] = useState<FileNode[]>([])
  const [selectedFile, setSelectedFile] = useState<string | null>(null)
  const [openFiles, setOpenFiles] = useState<string[]>([])
  const [fileContent, setFileContent] = useState<string>('// 请选择文件以查看内容')
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([])
  const logsEndRef = useRef<HTMLDivElement>(null)
  const logQueueRef = useRef<LogEntry[]>([])
  const logFlushTimerRef = useRef<number | null>(null)
  const pendingFilesRef = useRef<Set<string>>(new Set())
  const filesFlushTimerRef = useRef<number | null>(null)

  const [isOutputVisible, setIsOutputVisible] = useState(true)
  const [activeSidebarView, setActiveSidebarView] = useState<'explorer' | 'search' | 'graph' | 'tools'>('explorer')

  // Search State
  const [searchQuery, setSearchQuery] = useState('')
  const [isSearching, setIsSearching] = useState(false)
  const [searchResults, setSearchResults] = useState<SearchResult[]>([])
  const [activeSearchResult, setActiveSearchResult] = useState<SearchResult | null>(null)
  const [activeBottomTab, setActiveBottomTab] = useState<'output' | 'problems' | 'terminal' | 'mcp'>('output')
  const [replaceQuery, setReplaceQuery] = useState('')
  const [mcpStatus, setMcpStatus] = useState<'connected' | 'disconnected'>('disconnected')

  // Diff comparison state
  const [comparisonResult, setComparisonResult] = useState<any>(null)
  const [showComparisonView, setShowComparisonView] = useState(false)

  const groupedSearchResults = useMemo(() => {
    const groups: Record<string, SearchResult[]> = {}
    searchResults.forEach(result => {
      if (!groups[result.file]) {
        groups[result.file] = []
      }
      groups[result.file].push(result)
    })
    return groups
  }, [searchResults])

  const pythonLogs = useMemo(() => logs.filter(l => l.source === 'python'), [logs])
  const systemLogs = useMemo(() => logs.filter(l => l.source !== 'python'), [logs])

  // Menu State
  const [activeMenu, setActiveMenu] = useState<string | null>(null)

  // Editor Refs
  const editorRef = useRef<any>(null)
  const monacoRef = useRef<any>(null)
  const decorationsRef = useRef<string[]>([])

  // Graph Nodes (Dummy for now)
  const initialNodes = [
    { id: '1', position: { x: 0, y: 0 }, data: { label: 'Frontend (React)' } },
    { id: '2', position: { x: 0, y: 100 }, data: { label: 'Rust Host' } },
    { id: '3', position: { x: 200, y: 100 }, data: { label: 'Python Sidecar' } },
    { id: '4', position: { x: 0, y: 200 }, data: { label: 'SQLite DB' } },
  ];
  const initialEdges = [
    { id: 'e1-2', source: '1', target: '2', animated: true, label: 'Commands' },
    { id: 'e2-3', source: '2', target: '3', animated: true, label: 'MCP' },
    { id: 'e2-4', source: '2', target: '4', label: 'SQLx' },
  ];

  // Click outside to close menu
  useEffect(() => {
    const handleClickOutside = () => setActiveMenu(null)
    window.addEventListener('click', handleClickOutside)
    return () => window.removeEventListener('click', handleClickOutside)
  }, [])

  useEffect(() => {
    invoke<string>('get_mcp_status')
      .then((status) => {
        setMcpStatus(status === '运行中' ? 'connected' : 'disconnected')
      })
      .catch(() => {
        setMcpStatus('disconnected')
      })
  }, [])

  useEffect(() => {
    setFileTree(buildFileTree(files, projectPath))
  }, [files, projectPath])

  useEffect(() => {
    const unlistenPromise = listen<string>('mcp-message', (event) => {
      const msg = event.payload;

      // Parse Rust Scan messages to populate file tree
      if (msg.startsWith("Rust Scan")) {
        // Format: Rust Scan {path}: {details}
        const pathPart = msg.split(": ")[0].replace("Rust Scan ", "");
        pendingFilesRef.current.add(pathPart)
        if (filesFlushTimerRef.current === null) {
          filesFlushTimerRef.current = window.setTimeout(() => {
            const pending = pendingFilesRef.current
            pendingFilesRef.current = new Set()
            filesFlushTimerRef.current = null
            setFiles(prev => {
              const merged = new Set(prev)
              pending.forEach(p => merged.add(p))
              return Array.from(merged).sort()
            })
          }, 200)
        }
        // Disable Rust Scan logging to prevent frontend lag during large project scans
        // addLog(msg, 'rust');
      } else {
        addLog(msg, 'python');
      }
    })
    return () => {
      unlistenPromise.then((unlisten) => unlisten())
    }
  }, [])

  // Auto-scroll logs
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs, activeBottomTab])

  // Handle Search Result Highlighting
  useEffect(() => {
    if (!editorRef.current || !monacoRef.current) return

    const editor = editorRef.current
    const monaco = monacoRef.current

    // Clear previous decorations
    decorationsRef.current = editor.deltaDecorations(decorationsRef.current, [])

    if (activeSearchResult && selectedFile === activeSearchResult.file) {
      const { line } = activeSearchResult

      // Reveal line
      editor.revealLineInCenter(line)
      editor.setPosition({ lineNumber: line, column: 1 })
      editor.focus()

      // Add highlight decoration
      const newDecorations = editor.deltaDecorations([], [
        {
          range: new monaco.Range(line, 1, line, 1),
          options: {
            isWholeLine: true,
            className: 'bg-yellow-500/30 border-l-2 border-yellow-500', // Highlight style
            glyphMarginClassName: 'bg-yellow-500/50 w-2 h-2 rounded-full ml-1 mt-1' // Optional glyph
          }
        }
      ])
      decorationsRef.current = newDecorations
    }
  }, [selectedFile, fileContent, activeSearchResult])

  function handleEditorDidMount(editor: any, monaco: any) {
    editorRef.current = editor
    monacoRef.current = monaco
  }

  function addLog(message: string, source: LogEntry['source']) {
    logQueueRef.current.push({
      timestamp: new Date().toLocaleTimeString(),
      message,
      source
    })

    if (logFlushTimerRef.current !== null) return
    logFlushTimerRef.current = window.setTimeout(() => {
      const batch = logQueueRef.current
      logQueueRef.current = []
      logFlushTimerRef.current = null

      const MAX_LOGS = 2000
      setLogs(prev => {
        const merged = prev.concat(batch)
        if (merged.length <= MAX_LOGS) return merged
        return merged.slice(merged.length - MAX_LOGS)
      })
    }, 80)
  }

  async function callMcpTool(name: string, args: any) {
    const startedAt = performance.now()
    try {
      addLog(`正在调用工具: ${name}...`, 'system')
      const result = await invoke<string>('call_mcp_tool', { toolName: name, arguments: JSON.stringify(args) })

      let ok = true
      let errorMessage = ''
      try {
        const parsed = JSON.parse(result)
        if (parsed && typeof parsed === 'object') {
          if (typeof parsed.error === 'string' && parsed.error.trim()) {
            ok = false
            errorMessage = parsed.error
          } else if (typeof parsed.status === 'string' && parsed.status !== 'success') {
            ok = false
            errorMessage = parsed.status
          }
        }

        if (name === 'build_ast_index' && parsed.status === 'success') {
          if (parsed.summary) {
            addLog(parsed.summary, 'python')
          } else {
            addLog(`AST 索引构建成功`, 'python')
          }
        } else if (name === 'build_ast_index' && parsed.error) {
          addLog(`构建 AST 索引失败: ${parsed.error}`, 'python')
        } else if (name === 'run_security_scan' && parsed.status === 'success') {
          if (Array.isArray(parsed.findings)) {
            setVulnerabilities(parsed.findings)
            // Switch to problems tab to show results
            setActiveBottomTab('problems')
            setIsOutputVisible(true)
          }
          addLog(`安全扫描完成，发现 ${parsed.count || 0} 个问题`, 'python')
        } else if (name === 'run_security_scan' && parsed.error) {
          addLog(`安全扫描失败: ${parsed.error}`, 'python')
        } else if (name === 'get_analysis_report' && parsed.metadata) {
          const meta = parsed.metadata
          const nodeCount = typeof meta.node_count === 'number' ? meta.node_count : '未知'
          const buildTime = typeof meta.build_time === 'string' ? meta.build_time : ''
          addLog(`已读取缓存报告。节点数: ${nodeCount}${buildTime ? `，构建时间: ${buildTime}` : ''}`, 'python')
        } else {
          addLog(result, 'python')
        }
      } catch (e) {
        addLog(result, 'python')
        const text = String(result ?? '')
        const lower = text.toLowerCase()
        if (text.startsWith('错误') || lower.includes('"error"') || lower.includes('error:')) {
          ok = false
          errorMessage = text.length > 200 ? text.slice(0, 200) + '...' : text
        }
      }

      const costMs = Math.round(performance.now() - startedAt)
      addLog(
        `工具调用${ok ? '成功' : '失败'}: ${name}${ok ? '' : `，原因: ${errorMessage || '未知错误'}`}（${costMs}ms）`,
        'system'
      )
    } catch (e) {
      const costMs = Math.round(performance.now() - startedAt)
      addLog(`工具调用失败: ${name}，原因: ${e}（${costMs}ms）`, 'system')
    }
  }

  async function handleOpenProject() {
    try {
      const path = await invoke<string>('open_project')
      if (path) {
        setProjectPath(path)
        setFiles([]) // Reset files
        addLog(`已打开项目: ${path}`, 'system')

        if (mcpStatus !== 'connected') {
          addLog('正在启动 MCP 代理...', 'system')
          try {
            const msg = await invoke<string>('restart_mcp_server')
            addLog(msg, 'system')
            setMcpStatus('connected')
          } catch (e) {
            addLog(`启动 MCP 代理失败: ${e}`, 'system')
            return
          }
        }

        callMcpTool('build_ast_index', { directory: path })
      }
    } catch (e) {
      console.error(e)
      addLog(`打开项目出错: ${e}`, 'system')
    }
  }

  async function handleCompareProject() {
    if (!projectPath) {
      addLog('请先打开一个项目进行比较', 'system')
      return
    }

    try {
      addLog('请选择要比较的项目文件夹...', 'system')

      // 使用 Rust 的文件选择功能
      const selectedPath = await invoke<string>('open_project')

      if (selectedPath) {
        addLog(`开始比较项目: ${projectPath} vs ${selectedPath}`, 'system')

        // 调用 Rust 的比较函数
        const result = await invoke<string>('compare_files_or_directories', {
          sourceA: projectPath,
          sourceB: selectedPath,
          ignoreWhitespace: false,
          ignoreCase: false,
          viewMode: 'side-by-side',
          contextLines: 3,
          enableSyntaxHighlight: true,
          detectRenames: true,
          renameSimilarityThreshold: 0.8
        })

        setComparisonResult(JSON.parse(result))
        setShowComparisonView(true)
        addLog('比较完成！', 'system')
      } else {
        addLog('取消比较', 'system')
      }
    } catch (e) {
      console.error(e)
      addLog(`比较项目出错: ${e}`, 'system')
    }
  }

  async function handleFileSelect(path: string) {
    if (!openFiles.includes(path)) {
      setOpenFiles(prev => [...prev, path])
    }
    setSelectedFile(path)
    try {
      // Use custom Rust command to read file content to bypass frontend scope restrictions
      const text = await invoke<string>('read_file_content', { path });
      setFileContent(text);
      // If we are in search or graph view, maybe we want to switch back to explorer?
      // Or at least show the editor.
      if (activeSidebarView === 'graph') {
        // Optionally switch back, but user might want to see file while graph is active?
        // For now, if they select a file from search results, we stay in search view but update editor.
      }
    } catch (e) {
      addLog(`读取文件 ${path} 出错: ${e}`, 'system');
      setFileContent(`// 读取文件出错: ${e}`);
    }
  }

  function handleCloseFile(e: React.MouseEvent, path: string) {
    e.stopPropagation()
    const newOpenFiles = openFiles.filter(p => p !== path)
    setOpenFiles(newOpenFiles)

    if (selectedFile === path) {
      if (newOpenFiles.length > 0) {
        handleFileSelect(newOpenFiles[newOpenFiles.length - 1])
      } else {
        setSelectedFile(null)
      }
    }
  }

  function handleSearchResultClick(result: SearchResult) {
    setActiveSearchResult(result)
    if (selectedFile !== result.file) {
      handleFileSelect(result.file)
    }
  }

  async function handleSearchSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!searchQuery.trim() || !projectPath) return
    setIsSearching(true)
    setSearchResults([])
    setActiveSearchResult(null)
    try {
      const results = await invoke<SearchResult[]>('search_files', { query: searchQuery, path: projectPath })
      setSearchResults(results)
    } catch (e) {
      console.error(e)
      addLog(`搜索出错: ${e}`, 'system')
    } finally {
      setIsSearching(false)
    }
  }

  // MCP Menu
  // const [activeMcpMenu] = useState(false)

  async function handleMcpAction(action: string) {
    setActiveMenu(null)

    try {
      if (action === 'connect') {
        addLog("正在重启 MCP 代理...", "system")
        const msg = await invoke<string>('restart_mcp_server')
        addLog(msg, "system")
        setMcpStatus('connected')
      } else if (action === 'status') {
        const status = await invoke<string>('get_mcp_status')
        addLog(`MCP 服务器状态: ${status}`, "system")
        setMcpStatus(status === '运行中' ? 'connected' : 'disconnected')
      } else if (action === 'tools') {
        const tools = await invoke<string[]>('list_mcp_tools')
        addLog(
          `可用 MCP 工具:\n${tools
            .map(t => `- ${t}: ${MCP_TOOL_DESCRIPTIONS[t] ?? '（缺少描述）'}`)
            .join('\n')}`,
          "system"
        )
      }
    } catch (e) {
      console.error(e)
      addLog(`MCP 错误: ${e}`, 'system')
      setMcpStatus('disconnected')
    }
  }

  return (
    <div className="h-screen w-screen bg-background text-foreground flex flex-col overflow-hidden font-sans selection:bg-primary/20">
      {/* Header / Titlebar */}
      <header className="h-10 border-b border-border/40 px-3 flex items-center justify-between bg-muted/20 select-none z-50 relative">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-primary" />
            <span className="font-semibold text-sm tracking-tight hidden md:inline">DeepAudit Nexus</span>
          </div>

          {/* Menu Bar */}
          <div className="flex items-center gap-0.5">
            {/* File Menu */}
            <div className="relative">
              <button
                className={`px-3 py-1 text-xs rounded-sm hover:bg-muted transition-colors ${activeMenu === 'file' ? 'bg-muted text-foreground' : 'text-muted-foreground'}`}
                onClick={(e) => { e.stopPropagation(); setActiveMenu(activeMenu === 'file' ? null : 'file') }}
              >
                文件
              </button>
              {activeMenu === 'file' && (
                <div className="absolute top-full left-0 mt-1 w-48 bg-[#1e1e1e] border border-[#2b2b2b] rounded-md shadow-lg py-1 z-50">
                  <button
                    className="w-full text-left px-3 py-1.5 text-xs hover:bg-primary/20 hover:text-primary transition-colors flex items-center gap-2"
                    onClick={() => { handleOpenProject(); setActiveMenu(null) }}
                  >
                    <FolderOpen className="w-3.5 h-3.5" />
                    打开项目...
                  </button>
                  <button
                    className={`w-full text-left px-3 py-1.5 text-xs hover:bg-primary/20 hover:text-primary transition-colors flex items-center gap-2 ${!projectPath ? 'text-muted-foreground cursor-not-allowed' : ''}`}
                    onClick={() => {
                      if (projectPath) {
                        handleCompareProject();
                        setActiveMenu(null)
                      }
                    }}
                    disabled={!projectPath}
                  >
                    <FileDiff className="w-3.5 h-3.5" />
                    比较项目...
                  </button>
                  <div className="h-px bg-[#2b2b2b] my-1" />
                  <button
                    className="w-full text-left px-3 py-1.5 text-xs hover:bg-primary/20 hover:text-primary transition-colors flex items-center gap-2 text-destructive"
                    onClick={() => { setActiveMenu(null) }}
                  >
                    <span className="w-3.5" />
                    退出
                  </button>
                </div>
              )}
            </div>

            {/* Edit Menu */}
            <div className="relative">
              <button
                className={`px-3 py-1 text-xs rounded-sm hover:bg-muted transition-colors ${activeMenu === 'edit' ? 'bg-muted text-foreground' : 'text-muted-foreground'}`}
                onClick={(e) => { e.stopPropagation(); setActiveMenu(activeMenu === 'edit' ? null : 'edit') }}
              >
                编辑
              </button>
              {activeMenu === 'edit' && (
                <div className="absolute top-full left-0 mt-1 w-48 bg-[#1e1e1e] border border-[#2b2b2b] rounded-md shadow-lg py-1 z-50">
                  <button className="w-full text-left px-3 py-1.5 text-xs text-muted-foreground cursor-not-allowed">
                    撤销
                  </button>
                  <button className="w-full text-left px-3 py-1.5 text-xs text-muted-foreground cursor-not-allowed">
                    重做
                  </button>
                  <div className="h-px bg-[#2b2b2b] my-1" />
                  <button className="w-full text-left px-3 py-1.5 text-xs text-muted-foreground cursor-not-allowed">
                    剪切
                  </button>
                  <button className="w-full text-left px-3 py-1.5 text-xs text-muted-foreground cursor-not-allowed">
                    复制
                  </button>
                  <button className="w-full text-left px-3 py-1.5 text-xs text-muted-foreground cursor-not-allowed">
                    粘贴
                  </button>
                </div>
              )}
            </div>

            {/* View Menu */}
            <div className="relative">
              <button
                className={`px-3 py-1 text-xs rounded-sm hover:bg-muted transition-colors ${activeMenu === 'view' ? 'bg-muted text-foreground' : 'text-muted-foreground'}`}
                onClick={(e) => { e.stopPropagation(); setActiveMenu(activeMenu === 'view' ? null : 'view') }}
              >
                视图
              </button>
              {activeMenu === 'view' && (
                <div className="absolute top-full left-0 mt-1 w-48 bg-[#1e1e1e] border border-[#2b2b2b] rounded-md shadow-lg py-1 z-50">
                  <button
                    className="w-full text-left px-3 py-1.5 text-xs hover:bg-primary/20 hover:text-primary transition-colors flex items-center justify-between"
                    onClick={() => { setIsOutputVisible(!isOutputVisible); setActiveMenu(null) }}
                  >
                    <span>切换输出面板</span>
                    {isOutputVisible && <span className="text-[10px] text-primary">✓</span>}
                  </button>
                  <button
                    className="w-full text-left px-3 py-1.5 text-xs hover:bg-primary/20 hover:text-primary transition-colors flex items-center justify-between"
                    onClick={() => { setActiveSidebarView(activeSidebarView === 'explorer' ? 'search' : 'explorer'); setActiveMenu(null) }}
                  >
                    <span>切换资源管理器/搜索</span>
                  </button>
                </div>
              )}
            </div>

            {/* MCP Menu */}
            <div className="relative">
              <button
                className={`px-3 py-1 text-xs rounded-sm hover:bg-muted transition-colors ${activeMenu === 'mcp' ? 'bg-muted text-foreground' : 'text-muted-foreground'}`}
                onClick={(e) => { e.stopPropagation(); setActiveMenu(activeMenu === 'mcp' ? null : 'mcp') }}
              >
                MCP
              </button>
              {activeMenu === 'mcp' && (
                <div className="absolute top-full left-0 mt-1 w-48 bg-[#1e1e1e] border border-[#2b2b2b] rounded-md shadow-lg py-1 z-50">
                  <button
                    className="w-full text-left px-3 py-1.5 text-xs hover:bg-primary/20 hover:text-primary transition-colors"
                    onClick={() => handleMcpAction('status')}
                  >
                    服务器状态
                  </button>
                  <button
                    className="w-full text-left px-3 py-1.5 text-xs hover:bg-primary/20 hover:text-primary transition-colors"
                    onClick={() => handleMcpAction('connect')}
                  >
                    重启代理
                  </button>
                  <div className="h-px bg-[#2b2b2b] my-1" />
                  <button
                    className="w-full text-left px-3 py-1.5 text-xs hover:bg-primary/20 hover:text-primary transition-colors"
                    onClick={() => handleMcpAction('tools')}
                  >
                    列出可用工具
                  </button>
                </div>
              )}
            </div>

            {/* Help Menu */}
            <div className="relative">
              <button
                className={`px-3 py-1 text-xs rounded-sm hover:bg-muted transition-colors ${activeMenu === 'help' ? 'bg-muted text-foreground' : 'text-muted-foreground'}`}
                onClick={(e) => { e.stopPropagation(); setActiveMenu(activeMenu === 'help' ? null : 'help') }}
              >
                帮助
              </button>
              {activeMenu === 'help' && (
                <div className="absolute top-full left-0 mt-1 w-48 bg-[#1e1e1e] border border-[#2b2b2b] rounded-md shadow-lg py-1 z-50">
                  <button
                    className="w-full text-left px-3 py-1.5 text-xs hover:bg-primary/20 hover:text-primary transition-colors"
                    onClick={() => { addLog("DeepAudit Nexus v0.1.0 - 支持原生分析", 'system'); setActiveMenu(null) }}
                  >
                    关于
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {projectPath && (
            <span className="text-xs text-muted-foreground font-mono bg-muted/50 px-2 py-0.5 rounded">
              {projectPath}
            </span>
          )}
        </div>
      </header>

      {/* Main Workspace */}
      <div className="flex-1 overflow-hidden flex">

        {/* Activity Bar (Far Left) */}
        <div className="w-12 border-r border-border/40 flex flex-col items-center py-2 gap-2 bg-muted/10">
          <Button
            variant="ghost"
            size="icon"
            className={`w-8 h-8 rounded-md ${activeSidebarView === 'explorer' ? 'bg-accent text-accent-foreground' : 'text-muted-foreground hover:text-foreground'}`}
            onClick={() => setActiveSidebarView('explorer')}
            title="资源管理器"
          >
            <FileCode className="w-5 h-5" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className={`w-8 h-8 rounded-md ${activeSidebarView === 'search' ? 'bg-accent text-accent-foreground' : 'text-muted-foreground hover:text-foreground'}`}
            onClick={() => setActiveSidebarView('search')}
            title="搜索"
          >
            <Search className="w-5 h-5" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className={`w-8 h-8 rounded-md ${activeSidebarView === 'graph' ? 'bg-accent text-accent-foreground' : 'text-muted-foreground hover:text-foreground'}`}
            onClick={() => setActiveSidebarView('graph')}
            title="图谱视图"
          >
            <Network className="w-5 h-5" />
          </Button>

          <Button
            variant="ghost"
            size="icon"
            className={`w-8 h-8 rounded-md ${activeSidebarView === 'tools' ? 'bg-accent text-accent-foreground' : 'text-muted-foreground hover:text-foreground'}`}
            onClick={() => setActiveSidebarView('tools')}
            title="MCP 工具"
          >
            <Hammer className="w-5 h-5" />
          </Button>

          <div className="flex-1" />

          <Button
            variant="ghost"
            size="icon"
            className={`w-8 h-8 rounded-md ${isOutputVisible ? 'bg-accent text-accent-foreground' : 'text-muted-foreground hover:text-foreground'}`}
            onClick={() => setIsOutputVisible(!isOutputVisible)}
            title="切换输出"
          >
            <Terminal className="w-5 h-5" />
          </Button>
        </div>

        {/* Content Area */}
        <div className="flex-1 min-w-0">
          <ResizablePanelGroup direction="horizontal" className="h-full">

            {/* Sidebar: Explorer / Search / Graph Controls */}
            {activeSidebarView !== 'graph' && (
              <>
                <ResizablePanel defaultSize={20} collapsible={true} minSize={10} className="bg-background">
                  <div className="h-full flex flex-col border-r border-border/40">

                    {/* Explorer View */}
                    {activeSidebarView === 'explorer' && (
                      <>
                        <div className="h-8 px-3 flex items-center justify-between border-b border-border/40 bg-muted/5">
                          <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">资源管理器</span>
                          <Badge variant="secondary" className="h-4 px-1 text-[10px]">{files.length}</Badge>
                        </div>
                        <ScrollArea className="flex-1">
                          <div className="p-1 space-y-0.5">
                            {fileTree.length === 0 ? (
                              <div className="flex flex-col items-center justify-center py-10 text-muted-foreground opacity-50">
                                <FolderOpen className="w-8 h-8 mb-2 stroke-1" />
                                <span className="text-xs">未打开项目</span>
                              </div>
                            ) : (
                              fileTree.map((node) => (
                                <FileTreeNode
                                  key={node.path}
                                  node={node}
                                  level={0}
                                  onSelect={handleFileSelect}
                                  selectedPath={selectedFile}
                                />
                              ))
                            )}
                          </div>
                        </ScrollArea>
                      </>
                    )}

                    {/* Search View */}
                    {activeSidebarView === 'search' && (
                      <>
                        <div className="h-8 px-3 flex items-center justify-between border-b border-border/40 bg-muted/5">
                          <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">搜索</span>
                        </div>
                        <div className="p-2 border-b border-border/40 flex flex-col gap-2">
                          <form onSubmit={handleSearchSubmit}>
                            <div className="relative">
                              <Search className="absolute left-2 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
                              <Input
                                placeholder="搜索"
                                className="pl-8 h-8 text-xs"
                                value={searchQuery}
                                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSearchQuery(e.target.value)}
                              />
                            </div>
                          </form>
                          <div className="relative">
                            <div className="absolute left-2 top-2.5 h-3.5 w-3.5 text-muted-foreground flex items-center justify-center pointer-events-none select-none">
                              <span className="text-[10px] font-mono">AB</span>
                            </div>
                            <Input
                              placeholder="替换"
                              className="pl-8 h-8 text-xs"
                              value={replaceQuery}
                              onChange={(e: React.ChangeEvent<HTMLInputElement>) => setReplaceQuery(e.target.value)}
                            />
                          </div>
                        </div>

                        {searchResults.length > 0 && (
                          <div className="px-3 py-2 text-xs text-muted-foreground border-b border-border/40 flex justify-between">
                            <span>{Object.keys(groupedSearchResults).length} 个文件，{searchResults.length} 个结果</span>
                          </div>
                        )}

                        <ScrollArea className="flex-1">
                          {isSearching ? (
                            <div className="flex flex-col items-center justify-center py-10 text-muted-foreground">
                              <Loader2 className="w-6 h-6 animate-spin mb-2" />
                              <span className="text-xs">正在搜索...</span>
                            </div>
                          ) : searchResults.length === 0 ? (
                            <div className="flex flex-col items-center justify-center py-10 text-muted-foreground opacity-50">
                              <span className="text-xs">未找到结果</span>
                            </div>
                          ) : (
                            <div className="p-1 space-y-0.5">
                              {Object.entries(groupedSearchResults).map(([file, results]) => (
                                <Collapsible key={file} defaultOpen className="group/file">
                                  <CollapsibleTrigger className="w-full flex items-center gap-2 px-2 py-1.5 hover:bg-muted/50 text-xs font-medium text-foreground/80 select-none">
                                    <ChevronRight className="w-3.5 h-3.5 transition-transform group-data-[state=open]/file:rotate-90 text-muted-foreground" />
                                    <span className="truncate flex-1 text-left">{file.split(/[/\\]/).pop()}</span>
                                    <Badge variant="secondary" className="text-[10px] h-4 px-1">{results.length}</Badge>
                                  </CollapsibleTrigger>
                                  <CollapsibleContent>
                                    {results.map((result, i) => (
                                      <button
                                        key={i}
                                        onClick={() => handleSearchResultClick(result)}
                                        className={`w-full text-left pl-8 pr-2 py-1 text-xs hover:bg-muted/50 transition-colors flex gap-2 group/item ${activeSearchResult === result ? 'bg-muted text-accent-foreground' : 'text-muted-foreground'}`}
                                      >
                                        <span className="font-mono text-[10px] opacity-70 w-6 text-right shrink-0">{result.line}</span>
                                        <span className="truncate font-mono">{result.content}</span>
                                      </button>
                                    ))}
                                  </CollapsibleContent>
                                </Collapsible>
                              ))}
                            </div>
                          )}
                        </ScrollArea>
                      </>
                    )}

                    {/* Tools View */}
                    {activeSidebarView === 'tools' && (
                      <>
                        <div className="h-8 px-3 flex items-center justify-between border-b border-border/40 bg-muted/5">
                          <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">MCP 工具</span>
                        </div>
                        <ScrollArea className="flex-1">
                          <div className="p-3 space-y-4">
                            {/* Project Analysis */}
                            <div className="space-y-2">
                              <h3 className="text-xs font-semibold text-foreground/80">项目分析</h3>
                              <Button
                                variant="outline"
                                className="w-full justify-start text-xs h-8"
                                disabled={!projectPath}
                                onClick={() => callMcpTool('build_ast_index', { directory: projectPath })}
                              >
                                <Database className="w-3.5 h-3.5 mr-2 text-blue-500" />
                                构建 AST 索引
                              </Button>
                              <Button
                                variant="outline"
                                className="w-full justify-start text-xs h-8"
                                disabled={!projectPath}
                                onClick={() => callMcpTool('run_security_scan', { directory: projectPath })}
                              >
                                <ShieldAlert className="w-3.5 h-3.5 mr-2 text-orange-500" />
                                运行安全扫描
                              </Button>
                              <Button
                                variant="outline"
                                className="w-full justify-start text-xs h-8"
                                disabled={!projectPath}
                                onClick={() => callMcpTool('get_analysis_report', { directory: projectPath })}
                              >
                                <FileCode className="w-3.5 h-3.5 mr-2 text-zinc-500" />
                                读取缓存报告
                              </Button>
                              <Button
                                variant="outline"
                                className="w-full justify-start text-xs h-8"
                                disabled={!projectPath}
                                onClick={() => callMcpTool('list_files', { directory: projectPath })}
                              >
                                <Folder className="w-3.5 h-3.5 mr-2 text-blue-500" />
                                列出所有文件
                              </Button>
                            </div>

                            <div className="h-px bg-border/40" />

                            {/* File Analysis */}
                            <div className="space-y-2">
                              <h3 className="text-xs font-semibold text-foreground/80">当前文件</h3>
                              <div className="text-[10px] text-muted-foreground mb-2 px-1 truncate">
                                {selectedFile ? selectedFile.split(/[/\\]/).pop() : "未选择文件"}
                              </div>
                              <Button
                                variant="outline"
                                className="w-full justify-start text-xs h-8"
                                disabled={!selectedFile}
                                onClick={() => selectedFile && callMcpTool('get_code_structure', { file_path: selectedFile })}
                              >
                                <Network className="w-3.5 h-3.5 mr-2 text-green-500" />
                                获取代码结构
                              </Button>
                              <Button
                                variant="outline"
                                className="w-full justify-start text-xs h-8"
                                disabled={!selectedFile}
                                onClick={() => selectedFile && callMcpTool('read_file', { file_path: selectedFile })}
                              >
                                <FileCode className="w-3.5 h-3.5 mr-2 text-zinc-500" />
                                通过 MCP 读取
                              </Button>
                            </div>

                            <div className="h-px bg-border/40" />

                            {/* Symbol Search */}
                            <div className="space-y-2">
                              <h3 className="text-xs font-semibold text-foreground/80">符号搜索</h3>
                              <div className="flex gap-1">
                                <Input
                                  placeholder="符号名称..."
                                  className="h-7 text-xs"
                                  id="symbol-search-input"
                                />
                                <Button
                                  variant="secondary"
                                  size="icon"
                                  className="h-7 w-7"
                                  onClick={() => {
                                    const input = document.getElementById('symbol-search-input') as HTMLInputElement;
                                    if (input && input.value) {
                                      callMcpTool('search_symbol', { query: input.value });
                                    }
                                  }}
                                >
                                  <Search className="w-3.5 h-3.5" />
                                </Button>
                              </div>
                            </div>

                            <div className="h-px bg-border/40" />

                            {/* Class Hierarchy */}
                            <div className="space-y-2">
                              <h3 className="text-xs font-semibold text-foreground/80">类继承层次</h3>
                              <div className="flex gap-1">
                                <Input
                                  placeholder="类名..."
                                  className="h-7 text-xs"
                                  id="class-hierarchy-input"
                                />
                                <Button
                                  variant="secondary"
                                  size="icon"
                                  className="h-7 w-7"
                                  onClick={() => {
                                    const input = document.getElementById('class-hierarchy-input') as HTMLInputElement;
                                    if (input && input.value) {
                                      callMcpTool('get_class_hierarchy', { class_name: input.value });
                                    }
                                  }}
                                >
                                  <Network className="w-3.5 h-3.5" />
                                </Button>
                              </div>
                            </div>

                          </div>
                        </ScrollArea>
                      </>
                    )}

                  </div>
                </ResizablePanel>
                <ResizableHandle withHandle={true} className="w-[4px] bg-transparent hover:bg-primary/50 transition-colors data-[resize-handle-active]:bg-primary z-10 -mx-[2px]" />
              </>
            )}

            {/* Center: Editor / Graph & Bottom Panel */}
            <ResizablePanel defaultSize={60} minSize={30}>
              <ResizablePanelGroup direction="vertical">

                {/* Main View Area (Editor or Graph) */}
                <ResizablePanel defaultSize={70} minSize={20}>
                  <div className="h-full flex flex-col bg-[#1e1e1e] relative">

                    {activeSidebarView === 'graph' ? (
                      // Graph View
                      <div className="h-full w-full bg-background text-foreground">
                        <ReactFlow
                          nodes={initialNodes}
                          edges={initialEdges}
                          fitView
                        >
                          <Background />
                          <Controls />
                        </ReactFlow>
                      </div>
                    ) : (
                      // Editor View
                      <>
                        {/* Editor Tabs */}
                        <div className="h-9 flex items-end bg-[#18181b] border-b border-[#2b2b2b] overflow-x-auto no-scrollbar">
                          {openFiles.length > 0 ? (
                            openFiles.map(path => (
                              <div
                                key={path}
                                onClick={() => handleFileSelect(path)}
                                className={`h-full px-3 min-w-[120px] max-w-[200px] flex items-center gap-2 border-t-2 text-xs cursor-pointer group select-none ${selectedFile === path
                                  ? 'bg-[#1e1e1e] border-primary text-foreground/90'
                                  : 'bg-[#2d2d2d] border-transparent text-muted-foreground hover:bg-[#252526]'
                                  }`}
                              >
                                <span className="truncate">{path.split(/[/\\]/).pop()}</span>
                                <button
                                  onClick={(e) => handleCloseFile(e, path)}
                                  className={`ml-auto hover:bg-muted/50 rounded-sm p-0.5 ${selectedFile === path ? 'opacity-100' : 'opacity-0 group-hover:opacity-100'}`}
                                >
                                  <span className="sr-only">关闭</span>
                                  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18 6 6 18" /><path d="m6 6 12 12" /></svg>
                                </button>
                              </div>
                            ))
                          ) : (
                            <div className="h-full px-3 flex items-center text-xs text-muted-foreground italic">
                              未选择文件
                            </div>
                          )}
                        </div>

                        <div className="flex-1 relative">
                          {showComparisonView ? (
                            <DiffViewer
                              comparisonResult={comparisonResult}
                              onClose={() => setShowComparisonView(false)}
                            />
                          ) : (
                            <Editor
                              height="100%"
                              onMount={handleEditorDidMount}
                              defaultLanguage="typescript"
                              language={selectedFile?.endsWith('.py') ? 'python' : selectedFile?.endsWith('.rs') ? 'rust' : 'typescript'}
                              theme="vs-dark"
                              value={fileContent}
                              options={{
                                minimap: { enabled: true, scale: 0.5 },
                                fontSize: 13,
                                lineHeight: 20,
                                readOnly: true,
                                fontFamily: "'JetBrains Mono', 'Fira Code', Consolas, monospace",
                                scrollBeyondLastLine: false,
                                smoothScrolling: true,
                                padding: { top: 10 }
                              }}
                            />
                          )}
                        </div>
                      </>
                    )}

                  </div>
                </ResizablePanel>

                {/* Bottom Panel: Terminal/Logs/AI */}
                {isOutputVisible && (
                  <>
                    <ResizableHandle withHandle={true} className="h-[4px] bg-transparent hover:bg-primary/50 transition-colors data-[resize-handle-active]:bg-primary z-10 -my-[2px]" />
                    <ResizablePanel defaultSize={30} minSize={10} collapsible={true}>
                      <div className="h-full flex flex-col bg-card border-t border-border/40">
                        <div className="h-8 px-3 border-b border-border/40 flex items-center justify-between bg-muted/10">
                          <div className="flex items-center gap-4 h-full">
                            <button
                              onClick={() => setActiveBottomTab('output')}
                              className={`text-xs font-medium px-1 h-full flex items-center transition-colors ${activeBottomTab === 'output' ? 'border-b-2 border-primary text-foreground' : 'text-muted-foreground hover:text-foreground border-b-2 border-transparent'}`}
                            >
                              系统
                            </button>
                            <button
                              onClick={() => setActiveBottomTab('mcp')}
                              className={`text-xs font-medium px-1 h-full flex items-center transition-colors ${activeBottomTab === 'mcp' ? 'border-b-2 border-primary text-foreground' : 'text-muted-foreground hover:text-foreground border-b-2 border-transparent'}`}
                            >
                              MCP
                            </button>
                            <button
                              onClick={() => setActiveBottomTab('terminal')}
                              className={`text-xs font-medium px-1 h-full flex items-center transition-colors ${activeBottomTab === 'terminal' ? 'border-b-2 border-primary text-foreground' : 'text-muted-foreground hover:text-foreground border-b-2 border-transparent'}`}
                            >
                              终端
                            </button>
                          </div>
                          <div className="flex items-center gap-2">
                            <Button variant="ghost" size="icon" className="h-5 w-5" onClick={() => setLogs([])} title="清除日志">
                              <span className="sr-only">清除</span>
                              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 6h18" /><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6" /><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2" /></svg>
                            </Button>
                            <Button variant="ghost" size="icon" className="h-5 w-5" onClick={() => setIsOutputVisible(false)} title="关闭面板">
                              <span className="sr-only">关闭</span>
                              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18 6 6 18" /><path d="m6 6 12 12" /></svg>
                            </Button>
                          </div>
                        </div>

                        <div className="flex-1 overflow-hidden relative">
                          {activeBottomTab === 'output' && (
                            <ScrollArea className="h-full font-mono text-xs p-2 bg-black/95 text-zinc-300">
                              {systemLogs.map((log, i) => (
                                <div key={i} className="mb-0.5 flex gap-2 hover:bg-white/5 px-1 rounded-sm">
                                  <span className="text-zinc-600 shrink-0 select-none">[{log.timestamp}]</span>
                                  <span className={`shrink-0 w-16 text-right font-bold ${log.source === 'rust' ? 'text-orange-400' :
                                    log.source === 'python' ? 'text-blue-400' :
                                      'text-zinc-400'
                                    }`}>
                                    {log.source}
                                  </span>
                                  <span className="break-all whitespace-pre-wrap">{log.message}</span>
                                </div>
                              ))}
                              <div ref={logsEndRef} />
                            </ScrollArea>
                          )}

                          {activeBottomTab === 'mcp' && (
                            <ScrollArea className="h-full font-mono text-xs p-2 bg-black/95 text-zinc-300">
                              {pythonLogs.length === 0 ? (
                                <div className="h-full flex flex-col items-center justify-center text-muted-foreground opacity-50">
                                  <p>暂无 Python 日志。</p>
                                </div>
                              ) : (
                                pythonLogs.map((log, i) => (
                                  <div key={i} className="mb-0.5 flex gap-2 hover:bg-white/5 px-1 rounded-sm">
                                    <span className="text-zinc-600 shrink-0 select-none">[{log.timestamp}]</span>
                                    <span className="text-blue-400 shrink-0 w-16 text-right font-bold">
                                      python
                                    </span>
                                    <span className="break-all whitespace-pre-wrap">{log.message}</span>
                                  </div>
                                ))
                              )}
                              <div ref={logsEndRef} />
                            </ScrollArea>
                          )}

                          {activeBottomTab === 'problems' && (
                            <ScrollArea className="h-full p-3 bg-background">
                              {vulnerabilities.length === 0 ? (
                                <div className="flex flex-col gap-2 items-center justify-center py-10 text-muted-foreground opacity-60">
                                  <ShieldAlert className="w-10 h-10 stroke-1" />
                                  <p className="text-xs text-center max-w-[150px]">
                                    未检测到漏洞。请开始扫描以分析代码。
                                  </p>
                                </div>
                              ) : (
                                <div className="space-y-2">
                                  {vulnerabilities.map((v, i) => (
                                    <div key={i} onClick={() => handleSearchResultClick({ file: v.file, line: v.line, content: v.message })} className="flex items-start gap-3 p-2 rounded-md border border-border/40 bg-muted/5 hover:bg-muted/10 cursor-pointer transition-colors group">
                                      <div className="mt-0.5">
                                        <Badge variant={v.severity === 'high' ? 'destructive' : 'default'} className="text-[10px] h-4 px-1 rounded-sm uppercase">
                                          {v.severity}
                                        </Badge>
                                      </div>
                                      <div className="flex-1 min-w-0">
                                        <div className="flex items-center gap-2 mb-0.5">
                                          <span className="text-xs font-medium text-foreground">{v.file}</span>
                                          <span className="text-[10px] text-muted-foreground font-mono">:{v.line}</span>
                                        </div>
                                        <p className="text-xs text-muted-foreground leading-relaxed line-clamp-2 group-hover:text-foreground/80 transition-colors">
                                          {v.message}
                                        </p>
                                      </div>
                                      <div className="opacity-0 group-hover:opacity-100 transition-opacity">
                                        <Button variant="ghost" size="icon" className="h-6 w-6">
                                          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" /><polyline points="15 3 21 3 21 9" /><line x1="10" y1="14" x2="21" y2="3" /></svg>
                                        </Button>
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              )}
                            </ScrollArea>
                          )}

                          {activeBottomTab === 'terminal' && (
                            <div className="h-full flex items-center justify-center text-muted-foreground text-xs font-mono">
                              终端未连接
                            </div>
                          )}
                        </div>
                      </div>
                    </ResizablePanel>
                  </>
                )}
              </ResizablePanelGroup>
            </ResizablePanel>
          </ResizablePanelGroup>
        </div>
      </div>

      {/* Status Bar */}
      <footer className="h-6 border-t border-border/40 bg-primary text-primary-foreground px-3 flex items-center justify-between text-[10px] select-none">
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1"><GitBranch className="w-3 h-3" /> main*</span>
          <span className="opacity-50">|</span>
          <span>DeepAudit 就绪</span>
        </div>
        <div className="flex items-center gap-3">
          <span>行 {fileContent.split('\n').length}, 列 1</span>
          <span>UTF-8</span>
          <span>{getLanguageFromPath(selectedFile)}</span>
        </div>
      </footer>
    </div>
  )
}

export default App
