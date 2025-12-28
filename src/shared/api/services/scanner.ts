/**
 * 扫描器服务 API
 */

import { api } from '../client'
import type { Vulnerability, ScanResult } from '@/shared/types'

export class ScannerService {
  /**
   * 运行扫描
   */
  async runScan(projectPath: string, rules?: string[]): Promise<ScanResult> {
    return api.invoke('run_scan', {
      project_path: projectPath,
      rules,
    })
  }

  /**
   * 上传并扫描（Web 版）
   */
  async uploadAndScan(files: FileList): Promise<ScanResult> {
    return api.uploadFiles(files)
  }

  /**
   * 获取扫描结果
   */
  async getFindings(projectId: number): Promise<Vulnerability[]> {
    return api.get<Vulnerability[]>(`/api/scanner/findings/${projectId}`)
  }
}

export const scannerService = new ScannerService()
