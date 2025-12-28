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
  runScan: (projectPath: string, rules?: string[]) => Promise<void>
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

      runScan: async (projectPath, rules) => {
        set({ isScanning: true, error: null })
        try {
          const result = await scannerService.runScan(projectPath, rules)
          set({
            scanResults: result,
            vulnerabilities: result.findings || [],
            isScanning: false
          })
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

      verifyFinding: async (id, vulnerability) => {
        try {
          const resultJson = await scannerService.callMCPTool('verify_finding', {
            file: vulnerability.file || vulnerability.file_path,
            line: vulnerability.line || vulnerability.line_start,
            description: vulnerability.message || vulnerability.description,
            vuln_type: vulnerability.vuln_type
          })

          let result
          if (typeof resultJson === 'string') {
            result = JSON.parse(resultJson)
          } else {
            result = resultJson
          }

          set(state => ({
            vulnerabilities: state.vulnerabilities.map(v =>
              v.id === id ? { ...v, verification: result } : v
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
