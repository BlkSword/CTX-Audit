/**
 * 实时审计服务 API
 *
 * 封装后端 realtime_audit.rs 命令
 */

import { invoke } from '@tauri-apps/api/core'

// ==================== 类型定义 ====================

export interface FileFinding {
  id: string
  file_path: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  detector: string
  description: string
  line_start: number
  line_end?: number
  vuln_type?: string
  code_snippet?: string
  status: 'open' | 'resolved' | 'ignored'
  confidence?: number
  created_at?: string
}

export interface ProjectStats {
  total_files: number
  total_findings: number
  by_severity: {
    critical: number
    high: number
    medium: number
    low: number
    info: number
  }
  recently_scanned: string[]
}

export interface ProjectFile {
  path: string
  name: string
  size: number
  is_binary: boolean
  language?: string
}

// ==================== 服务类 ====================

class RealtimeAuditService {
  /**
   * 获取文件的所有漏洞
   */
  async getFileFindings(projectId: number, filePath: string): Promise<FileFinding[]> {
    try {
      const findings = await invoke<FileFinding[]>('get_file_findings', {
        projectId,
        filePath,
      })
      return findings || []
    } catch (error) {
      console.error('Failed to get file findings:', error)
      return []
    }
  }

  /**
   * 更新漏洞状态
   */
  async updateFindingStatus(
    projectId: number,
    findingId: string,
    status: 'open' | 'resolved' | 'ignored'
  ): Promise<boolean> {
    try {
      await invoke('update_finding_status', {
        projectId,
        findingId,
        status,
      })
      return true
    } catch (error) {
      console.error('Failed to update finding status:', error)
      return false
    }
  }

  /**
   * 扫描单个文件（带缓存）
   */
  async scanFile(
    projectId: number,
    filePath: string,
    content: string
  ): Promise<{ findings: FileFinding[]; cached: boolean }> {
    try {
      const result = await invoke<{
        findings: FileFinding[]
        cached: boolean
      }>('scan_file', {
        projectId,
        filePath,
        content,
      })
      return result || { findings: [], cached: false }
    } catch (error) {
      console.error('Failed to scan file:', error)
      return { findings: [], cached: false }
    }
  }

  /**
   * 获取项目统计信息
   */
  async getProjectStats(projectId: number): Promise<ProjectStats | null> {
    try {
      const stats = await invoke<ProjectStats>('get_project_stats', {
        projectId,
      })
      return stats
    } catch (error) {
      console.error('Failed to get project stats:', error)
      return null
    }
  }

  /**
   * 获取项目文件列表
   */
  async getProjectFiles(
    projectId: number,
    includePatterns?: string[],
    excludePatterns?: string[]
  ): Promise<ProjectFile[]> {
    try {
      const files = await invoke<ProjectFile[]>('get_project_files', {
        projectId,
        includePatterns,
        excludePatterns,
      })
      return files || []
    } catch (error) {
      console.error('Failed to get project files:', error)
      return []
    }
  }

  /**
   * 批量更新漏洞状态
   */
  async batchUpdateFindingStatus(
    projectId: number,
    updates: Array<{ findingId: string; status: 'open' | 'resolved' | 'ignored' }>
  ): Promise<{ success: number; failed: number }> {
    let success = 0
    let failed = 0

    for (const update of updates) {
      const result = await this.updateFindingStatus(projectId, update.findingId, update.status)
      if (result) {
        success++
      } else {
        failed++
      }
    }

    return { success, failed }
  }

  /**
   * 按严重程度过滤漏洞
   */
  filterFindingsBySeverity(findings: FileFinding[], severities: string[]): FileFinding[] {
    if (severities.length === 0) return findings
    return findings.filter((f) => severities.includes(f.severity))
  }

  /**
   * 按状态过滤漏洞
   */
  filterFindingsByStatus(findings: FileFinding[], status: string[]): FileFinding[] {
    if (status.length === 0) return findings
    return findings.filter((f) => status.includes(f.status))
  }

  /**
   * 获取漏洞统计
   */
  getFindingStats(findings: FileFinding[]): {
    total: number
    by_severity: ProjectStats['by_severity']
    by_status: {
      open: number
      resolved: number
      ignored: number
    }
  } {
    const by_severity = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    }
    const by_status = {
      open: 0,
      resolved: 0,
      ignored: 0,
    }

    findings.forEach((f) => {
      by_severity[f.severity]++
      by_status[f.status]++
    })

    return {
      total: findings.length,
      by_severity,
      by_status,
    }
  }
}

// ==================== 导出单例 ====================

export const realtimeAuditService = new RealtimeAuditService()

// 同时导出类以供外部使用
export { RealtimeAuditService }
