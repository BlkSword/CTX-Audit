/**
 * 共享类型定义
 */

// ==================== AST 相关 ====================

export interface Symbol {
  name: string
  kind: string
  file_path: string
  line: number
  column?: number
  end_line?: number
  end_column?: number
}

export interface CallNode {
  name: string
  file_path: string
  line: number
  children: CallNode[]
}

// ==================== 扫描相关 ====================

export interface Vulnerability {
  id: string
  file_path: string
  file?: string  // 兼容旧字段
  line_start: number
  line?: number  // 兼容旧字段
  line_end: number
  severity: 'high' | 'medium' | 'low' | 'critical'
  description: string
  message?: string  // 兼容旧字段
  detector: string
  vuln_type: string
  code?: string
  code_snippet?: string
  verification?: {
    verified: boolean
    confidence: number
    reasoning: string
  }
}

export interface ScanResult {
  findings: Vulnerability[]
  files_scanned: number
  scan_time: string
}

// ==================== 项目相关 ====================

export interface Project {
  id: number
  uuid: string
  name: string
  path: string
  created_at: string
}

// ==================== 规则相关 ====================

export interface Rule {
  id: string
  name: string
  description: string
  severity: string
  language: string
  pattern?: string
  query?: string
  category?: string
  cwe?: string
  enabled?: boolean
}

// ==================== 文件相关 ====================

export interface FileNode {
  name: string
  path: string
  type: 'file' | 'folder'
  children?: FileNode[]
  size?: number
  modified?: string
}

// ==================== 搜索相关 ====================

export interface SearchResult {
  file: string
  line: number
  content: string
  column?: number
  end_line?: number
  end_column?: number
  context?: string
}

// ==================== API 响应 ====================

export interface APIResponse<T = any> {
  success: boolean
  data?: T
  error?: string
  message?: string
}

// ==================== 差异相关 ====================

export interface DiffResult {
  old_content: string
  new_content: string
  hunks: DiffHunk[]
}

export interface DiffHunk {
  old_start: number
  old_lines: number
  new_start: number
  new_lines: number
  changes: DiffChange[]
}

export interface DiffChange {
  type: 'added' | 'removed' | 'context'
  old_line?: number
  new_line?: number
  content: string
}

// ==================== 图谱相关 ====================

export interface GraphNode {
  id: string
  label: string
  type: 'function' | 'class' | 'variable' | 'file'
  file_path?: string
  line?: number
  data?: Record<string, any>
}

export interface GraphEdge {
  id: string
  source: string
  target: string
  label?: string
  type: 'calls' | 'defines' | 'uses' | 'inherits'
  data?: Record<string, any>
}

export interface GraphData {
  nodes: GraphNode[]
  edges: GraphEdge[]
}

// ==================== 日志相关 ====================

export interface LogEntry {
  id: string
  timestamp: string
  level: 'info' | 'warning' | 'error' | 'debug'
  message: string
  source?: string
  data?: Record<string, any>
}

// ==================== MCP 工具相关 ====================

export interface MCPToolCall {
  name: string
  arguments: Record<string, any>
  result?: any
  error?: string
  duration?: number
}

export interface MCPToolDescription {
  name: string
  description: string
  parameters?: Record<string, { type: string; description: string; required?: boolean }>
}

export const MCP_TOOL_DESCRIPTIONS: Record<string, string> = {
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
  get_knowledge_graph: '获取项目的代码知识图谱（节点与关系）',
  verify_finding: '使用 LLM 验证安全漏洞的真实性',
  analyze_code_with_llm: '使用 LLM 分析代码片段的逻辑或缺陷',
}

// ==================== Agent 相关 ====================

export * from './agent'

// ==================== 设置相关 ====================

export * from './settings'
