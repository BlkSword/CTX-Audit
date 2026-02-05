/**
 * 扫描器服务 API
 */

import { tauriApi } from '../tauri-client'
import type { Vulnerability, ScanResult } from '@/shared/types'
import type { Finding as TauriFinding } from '../tauri-client'

// 将 Tauri Finding 转换为 Vulnerability 类型
function convertTauriFinding(finding: TauriFinding): Vulnerability {
  return {
    id: finding.id,
    file_path: finding.file_path,
    line_start: finding.line_start,
    line_end: finding.line_end || finding.line_start,
    severity: finding.severity as Vulnerability['severity'],
    description: finding.description,
    detector: finding.detector,
    vuln_type: finding.vuln_type,
    code_snippet: finding.code_snippet,
  }
}

export class ScannerService {
  /**
   * 运行扫描
   */
  async runScan(projectPath: string, projectId?: number, rules?: string[]): Promise<ScanResult> {
    const result = await tauriApi.runScan(projectPath, projectId, rules)
    return {
      findings: result.findings.map(convertTauriFinding),
      files_scanned: result.files_scanned,
      scan_time: result.completed_at || result.started_at || new Date().toISOString(),
    }
  }

  /**
   * 上传并扫描（Web 版 - Tauri 不支持）
   */
  async uploadAndScan(_files: FileList): Promise<ScanResult> {
    throw new Error('uploadAndScan is not supported in Tauri desktop app')
  }

  /**
   * 获取扫描结果
   */
  async getFindings(projectId: number): Promise<Vulnerability[]> {
    const findings = await tauriApi.getFindings(projectId)
    return findings.map(convertTauriFinding)
  }
}

export const scannerService = new ScannerService()
