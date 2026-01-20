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
      if (error instanceof Error) {
        throw new Error(`Command ${command} failed: ${error.message}`)
      }
      throw error
    }
  }

  // ==================== 项目管理 ====================

  /** 列出所有项目 */
  async listProjects(): Promise<Project[]> {
    return this.invoke<Project[]>('list_projects')
  }

  /** 创建项目 */
  async createProject(name: string, path: string): Promise<Project> {
    return this.invoke<Project>('create_project', { name, path })
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

  // ==================== Agent 服务 ====================

  /** 启动 Agent 服务 */
  async startAgentService(): Promise<AgentStatus> {
    return this.invoke<AgentStatus>('start_agent_service')
  }

  /** 停止 Agent 服务 */
  async stopAgentService(): Promise<void> {
    return this.invoke<void>('stop_agent_service')
  }

  /** 获取 Agent 服务状态 */
  async getAgentStatus(): Promise<AgentStatus> {
    return this.invoke<AgentStatus>('get_agent_status')
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
