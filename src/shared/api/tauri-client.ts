/**
 * Tauri API 客户端 - 桌面版专用
 *
 * 使用 Tauri 2.x invoke API 与 Rust 后端通信
 */

import { invoke } from '@tauri-apps/api/core'

// 类型定义
export interface Project {
  id: number
  uuid: string
  name: string
  path: string
  created_at: string
}

export interface FileInfo {
  name: string
  path: string
  is_dir: boolean
  size?: number
}

export interface Finding {
  id: string
  file_path: string
  line_start: number
  line_end: number
  detector: string
  vuln_type: string
  severity: string
  description: string
  code_snippet?: string
  status: string
  created_at: string
}

export interface ScanResult {
  id: number
  project_id: number
  status: string
  files_scanned: number
  findings_found: number
  findings: Finding[]
  started_at: string
  completed_at?: string
}

export interface AgentStatus {
  running: boolean
  port: number
  pid?: number
  uptime_secs?: number
}

export interface SymbolInfo {
  name: string
  kind: string  // "function", "class", "variable", etc.
  file_path: string
  line: number
  column: number
  parent?: string
  code_snippet?: string
  start_line: number
  end_line: number
}

export interface CallNode {
  name: string
  file_path: string
  line: number
  children: CallNode[]
}

export interface SymbolSearchResult {
  name: string
  kind: string
  file_path: string
  line: number
  definition: string
}

// ==================== LLM 相关 ====================

export interface LLMConfig {
  provider: string
  model: string
  apiKey: string
  apiEndpoint?: string
  temperature?: number
  maxTokens?: number
}

export interface TestResult {
  success: boolean
  message: string
  details?: TestDetails
}

export interface TestDetails {
  endpoint: string
  model: string
  response_time_ms?: number
  available_models?: string[]
}

/**
 * Tauri API 客户端
 */
export class TauriAPIClient {
  /**
   * 调用 Tauri Command
   */
  async invoke<T>(command: string, args?: Record<string, any>): Promise<T> {
    try {
      return await invoke<T>(command, args)
    } catch (error) {
      // 处理各种错误类型
      let message = 'Unknown error'
      if (error instanceof Error) {
        message = error.message
      } else if (typeof error === 'string') {
        message = error
      } else if (error && typeof error === 'object' && 'message' in error) {
        message = String(error.message)
      } else if (error) {
        message = JSON.stringify(error)
      }
      throw new Error(`Command ${command} failed: ${message}`)
    }
  }

  // ==================== 项目管理 ====================

  /** 列出所有项目 */
  async listProjects(): Promise<Project[]> {
    return this.invoke<Project[]>('list_projects')
  }

  /** 获取单个项目 */
  async getProjectById(id: number): Promise<Project> {
    return this.invoke<Project>('get_project_by_id', { id })
  }

  /** 通过路径获取项目 */
  async getProjectByPath(path: string): Promise<Project | null> {
    return this.invoke<Project | null>('get_project_by_path', { path })
  }

  /** 创建项目 */
  async createProject(name: string, path: string): Promise<Project> {
    return this.invoke<Project>('create_project', { name, path })
  }

  /** 打开目录（自动创建或获取现有项目） */
  async openDirectory(): Promise<Project> {
    return this.invoke<Project>('open_directory')
  }

  /** 删除项目 */
  async deleteProject(uuid: string): Promise<void> {
    return this.invoke<void>('delete_project', { uuid })
  }

  // ==================== 文件操作 ====================

  /** 读取文件内容 */
  async readFile(path: string): Promise<string> {
    return this.invoke<string>('read_file', { path })
  }

  /** 列出目录内容 */
  async listDirectory(path: string): Promise<FileInfo[]> {
    return this.invoke<FileInfo[]>('list_directory', { path })
  }

  /** 选择目录 */
  async selectDirectory(): Promise<string | null> {
    const result = await invoke<string | null>('select_directory')
    return result
  }

  // ==================== 扫描功能 ====================

  /** 运行扫描 */
  async runScan(projectPath: string, projectId?: number, rules?: string[]): Promise<ScanResult> {
    return this.invoke<ScanResult>('run_scan', {
      projectPath,
      projectId,
      rules,
    })
  }

  /** 获取扫描结果 */
  async getFindings(projectId: number): Promise<Finding[]> {
    return this.invoke<Finding[]>('get_findings', { projectId })
  }

  // ==================== Agent 审计（Rust 后端） ====================

  /** 启动审计 */
  async startAudit(request: {
    projectId: string
    auditType: string
    config?: Record<string, any>
  }): Promise<{ audit_id: string; status: string }> {
    return this.invoke('start_audit', request)
  }

  /** 获取审计状态 */
  async getAuditStatus(auditId: string): Promise<{
    audit_id: string
    status: string
    progress: Record<string, any>
    stats: Record<string, any>
  }> {
    return this.invoke('get_audit_status', { auditId })
  }

  /** 暂停审计 */
  async pauseAudit(auditId: string): Promise<void> {
    return this.invoke('pause_audit', { auditId })
  }

  /** 取消审计 */
  async cancelAudit(auditId: string): Promise<void> {
    return this.invoke('cancel_audit', { auditId })
  }

  /** 获取审计结果 */
  async getAuditResult(auditId: string): Promise<any[]> {
    return this.invoke('get_audit_result', { auditId })
  }

  /** 获取审计事件 */
  async getAuditEvents(auditId: string, afterSequence?: number, limit?: number): Promise<any[]> {
    return this.invoke('get_audit_events', { auditId, afterSequence, limit })
  }

  /** 获取 Agent 树 */
  async getAgentTree(auditId: string): Promise<{
    nodes: any[]
    edges: any[]
  }> {
    return this.invoke('get_agent_tree', { auditId })
  }

  // ==================== 索引器 ====================

  /** 索引项目中的所有文件 */
  async indexProject(projectPath: string): Promise<number> {
    return this.invoke<number>('index_project', { projectPath })
  }

  /** 获取文件中的符号 */
  async getFileSymbols(filePath: string): Promise<SymbolInfo[]> {
    return this.invoke<SymbolInfo[]>('get_file_symbols', { filePath })
  }

  /** 搜索符号 */
  async searchSymbol(symbolName: string, projectId: number): Promise<SymbolSearchResult[]> {
    return this.invoke<SymbolSearchResult[]>('search_symbol', { symbolName, projectId })
  }

  /** 获取调用图 */
  async getCallGraph(entryFunction: string, maxDepth: number, projectId: number): Promise<CallNode> {
    return this.invoke<CallNode>('get_call_graph', { entryFunction, maxDepth, projectId })
  }

  // ==================== LLM 测试 ====================

  /** 测试 LLM 连接 */
  async testLLMConnection(config: LLMConfig): Promise<TestResult> {
    return this.invoke<TestResult>('test_llm_connection', { config })
  }

  /** 测试已保存的 LLM 配置 */
  async testLLMConfig(id: string): Promise<TestResult> {
    return this.invoke<TestResult>('test_llm_config', { id })
  }
}

// 单例实例
let tauriClientInstance: TauriAPIClient | null = null

export function getTauriClient(): TauriAPIClient {
  if (!tauriClientInstance) {
    tauriClientInstance = new TauriAPIClient()
  }
  return tauriClientInstance
}

// 默认导出
export const tauriApi = getTauriClient()
