/**
 * 扫描器服务 API
 */

import { tauriApi } from '../tauri-client'
import type { Vulnerability, ScanResult } from '@/shared/types'

export class ScannerService {
  /**
   * 运行扫描
   */
  async runScan(projectPath: string, projectId?: number, rules?: string[]): Promise<ScanResult> {
    return tauriApi.runScan(projectPath, projectId, rules)
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
    return tauriApi.getFindings(projectId)
  }
}

export const scannerService = new ScannerService()
