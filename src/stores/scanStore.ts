/**
 * 扫描状态管理
 */

import { create } from 'zustand'
import { devtools } from 'zustand/middleware'
import type { Vulnerability, ScanResult } from '@/shared/types'
import { scannerService } from '@/shared/api/services'

interface ScanState {
  vulnerabilities: Vulnerability[]
  scanResults: ScanResult | null
  isScanning: boolean
  isLoading: boolean
  error: string | null

  // Actions
  runScan: (projectPath: string, projectId?: number, rules?: string[]) => Promise<ScanResult>
  loadFindings: (projectId: number) => Promise<void>
  verifyFinding: (id: string, vulnerability: Vulnerability) => Promise<void>
  clearFindings: () => void
  clearError: () => void
}

export const useScanStore = create<ScanState>()(
  devtools(
    (set) => ({
      vulnerabilities: [],
      scanResults: null,
      isScanning: false,
      isLoading: false,
      error: null,

      runScan: async (projectPath, projectId, rules) => {
        set({ isScanning: true, error: null })
        try {
          const result = await scannerService.runScan(projectPath, projectId, rules)
          set({
            scanResults: result,
            vulnerabilities: result.findings || [],
            isScanning: false
          })
          return result
        } catch (error) {
          const message = error instanceof Error ? error.message : '扫描失败'
          set({ error: message, isScanning: false })
          throw error
        }
      },

      loadFindings: async (projectId) => {
        set({ isLoading: true, error: null })
        try {
          const findings = await scannerService.getFindings(projectId)
          set({ vulnerabilities: findings, isLoading: false })
        } catch (error) {
          const message = error instanceof Error ? error.message : '加载扫描结果失败'
          set({ error: message, isLoading: false, vulnerabilities: [] })
        }
      },

      verifyFinding: async (id, _vulnerability) => {
        // TODO: 实现漏洞验证功能，需要后端API支持
        try {
          // 暂时使用模拟数据
          const mockResult = {
            verified: true,
            confidence: 0.85,
            reasoning: '待实现：需要通过MCP工具调用LLM进行验证'
          }

          set(state => ({
            vulnerabilities: state.vulnerabilities.map(v =>
              v.id === id ? { ...v, verification: mockResult } : v
            )
          }))
        } catch (error) {
          console.error('验证失败:', error)
        }
      },

      clearFindings: () => {
        set({
          vulnerabilities: [],
          scanResults: null
        })
      },

      clearError: () => {
        set({ error: null })
      },
    }),
    { name: 'scan-store' }
  )
)
