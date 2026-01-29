/**
 * FindingMarkerStore - 漏洞标记状态管理
 *
 * 管理漏洞装饰器、加载漏洞、更新装饰器状态
 */

import { create } from 'zustand'
import type { Vulnerability } from '@/shared/types/agent'
import {
  vulnerabilitiesToMonacoDecorations,
  filterDecorationsByStatus,
  DecorationManager,
} from '@/components/editor/EditorDecorations'
import { useEditorStore } from './editorStore'

// ==================== 类型定义 ====================

interface FindingMarkerState {
  // 文件路径 -> 漏洞列表
  findingsByFile: Map<string, Vulnerability[]>

  // 项目 ID -> 当前项目
  currentProjectId: string | null

  // Monaco 装饰器管理器
  decorationManager: DecorationManager

  // 过滤设置
  excludeStatuses: ('fixed' | 'false_positive' | 'ignored')[]

  // 操作
  setCurrentProject: (projectId: string) => void
  loadFindings: (filePath: string, projectId: string) => Promise<void>
  loadAllFindings: (projectId: string) => Promise<void>

  // 装饰器操作
  updateDecorations: (groupId: string, filePath: string) => void
  clearDecorations: (groupId: string, filePath: string) => void

  // 跳转操作
  jumpToFinding: (groupId: string, findingId: string) => void

  // 状态更新
  markAsFixed: (findingId: string) => Promise<void>
  markAsFalsePositive: (findingId: string) => Promise<void>
  markAsIgnored: (findingId: string) => Promise<void>
  markAsVerified: (findingId: string) => Promise<void>

  // 获取操作
  getFindingsForFile: (filePath: string) => Vulnerability[]
  getFilteredFindingsForFile: (filePath: string) => Vulnerability[]
  getAllFindings: () => Vulnerability[]
  getFilteredFindings: () => Vulnerability[]
}

// ==================== Store ====================

export const useFindingMarkerStore = create<FindingMarkerState>((set, get) => ({
  // 初始状态
  findingsByFile: new Map(),
  currentProjectId: null,
  decorationManager: new DecorationManager(),
  excludeStatuses: ['fixed', 'false_positive', 'ignored'],

  // 设置当前项目
  setCurrentProject: (projectId) => {
    set({ currentProjectId: projectId })
  },

  // 加载单个文件的漏洞
  loadFindings: async (filePath, projectId) => {
    try {
      // TODO: 调用后端 API 获取文件漏洞
      // const findings = await tauriApi.getFileFindings(filePath, projectId)
      // 暂时使用模拟数据
      const findings: Vulnerability[] = []

      set((state) => {
        const newFindingsByFile = new Map(state.findingsByFile)
        newFindingsByFile.set(filePath, findings)
        return { findingsByFile: newFindingsByFile }
      })
    } catch (error) {
      console.error('Failed to load findings:', error)
    }
  },

  // 加载项目的所有漏洞
  loadAllFindings: async (projectId) => {
    try {
      // TODO: 调用后端 API 获取项目所有漏洞
      // const allFindings = await tauriApi.getProjectFindings(projectId)
      // 暂时使用模拟数据
      const allFindings: Vulnerability[] = []

      // 按文件分组
      const findingsByFile = new Map<string, Vulnerability[]>()
      allFindings.forEach((finding) => {
        const filePath = finding.file_path
        if (!findingsByFile.has(filePath)) {
          findingsByFile.set(filePath, [])
        }
        findingsByFile.get(filePath)!.push(finding)
      })

      set({ findingsByFile, currentProjectId: projectId })
    } catch (error) {
      console.error('Failed to load all findings:', error)
    }
  },

  // 更新装饰器
  updateDecorations: (groupId, filePath) => {
    const { findingsByFile, decorationManager, excludeStatuses } = get()
    const { getEditorInstance } = useEditorStore.getState()

    const editor = getEditorInstance(groupId)
    if (!editor) return

    // 获取漏洞并过滤
    const findings = findingsByFile.get(filePath) || []
    const filteredFindings = filterDecorationsByStatus(findings, excludeStatuses)

    // 转换为装饰器
    const decorations = vulnerabilitiesToMonacoDecorations(filteredFindings)

    // 更新装饰器
    decorationManager.updateDecorations(editor, filePath, decorations)
  },

  // 清除装饰器
  clearDecorations: (groupId, filePath) => {
    const { decorationManager } = get()
    const { getEditorInstance } = useEditorStore.getState()

    const editor = getEditorInstance(groupId)
    if (!editor) return

    decorationManager.clearDecorations(editor, filePath)
  },

  // 跳转到漏洞位置
  jumpToFinding: (groupId, findingId) => {
    const { findingsByFile, decorationManager } = get()
    const { getEditorInstance } = useEditorStore.getState()

    const editor = getEditorInstance(groupId)
    if (!editor) return

    // 查找漏洞
    let targetFinding: Vulnerability | null = null
    let targetFilePath: string | null = null

    for (const [filePath, findings] of findingsByFile.entries()) {
      const finding = findings.find((f) => f.id === findingId)
      if (finding) {
        targetFinding = finding
        targetFilePath = filePath
        break
      }
    }

    if (!targetFinding || !targetFilePath) return

    // 跳转并高亮
    editor.revealLineInCenter(targetFinding.line_number)
    editor.setPosition({
      lineNumber: targetFinding.line_number,
      column: targetFinding.column_start || 1,
    })

    // 更新装饰器
    get().updateDecorations(groupId, targetFilePath)
  },

  // 标记为已修复
  markAsFixed: async (findingId) => {
    try {
      // TODO: 调用后端 API 更新状态
      // await tauriApi.updateFindingStatus(findingId, 'fixed')

      // 更新本地状态
      set((state) => {
        const newFindingsByFile = new Map(state.findingsByFile)

        for (const [filePath, findings] of newFindingsByFile.entries()) {
          const updatedFindings = findings.map((f) =>
            f.id === findingId ? { ...f, status: 'fixed' as const } : f
          )
          newFindingsByFile.set(filePath, updatedFindings)
        }

        return { findingsByFile: newFindingsByFile }
      })
    } catch (error) {
      console.error('Failed to mark as fixed:', error)
    }
  },

  // 标记为误报
  markAsFalsePositive: async (findingId) => {
    try {
      // TODO: 调用后端 API 更新状态
      // await tauriApi.updateFindingStatus(findingId, 'false_positive')

      // 更新本地状态
      set((state) => {
        const newFindingsByFile = new Map(state.findingsByFile)

        for (const [filePath, findings] of newFindingsByFile.entries()) {
          const updatedFindings = findings.map((f) =>
            f.id === findingId ? { ...f, status: 'false_positive' as const } : f
          )
          newFindingsByFile.set(filePath, updatedFindings)
        }

        return { findingsByFile: newFindingsByFile }
      })
    } catch (error) {
      console.error('Failed to mark as false positive:', error)
    }
  },

  // 标记为忽略
  markAsIgnored: async (findingId) => {
    try {
      // TODO: 调用后端 API 更新状态
      // await tauriApi.updateFindingStatus(findingId, 'ignored')

      // 更新本地状态
      set((state) => {
        const newFindingsByFile = new Map(state.findingsByFile)

        for (const [filePath, findings] of newFindingsByFile.entries()) {
          const updatedFindings = findings.map((f) =>
            f.id === findingId ? { ...f, status: 'ignored' as const } : f
          )
          newFindingsByFile.set(filePath, updatedFindings)
        }

        return { findingsByFile: newFindingsByFile }
      })
    } catch (error) {
      console.error('Failed to mark as ignored:', error)
    }
  },

  // 标记为已验证
  markAsVerified: async (findingId) => {
    try {
      // TODO: 调用后端 API 更新状态
      // await tauriApi.updateFindingStatus(findingId, 'verified')

      // 更新本地状态
      set((state) => {
        const newFindingsByFile = new Map(state.findingsByFile)

        for (const [filePath, findings] of newFindingsByFile.entries()) {
          const updatedFindings = findings.map((f) =>
            f.id === findingId ? { ...f, status: 'verified' as const } : f
          )
          newFindingsByFile.set(filePath, updatedFindings)
        }

        return { findingsByFile: newFindingsByFile }
      })
    } catch (error) {
      console.error('Failed to mark as verified:', error)
    }
  },

  // 获取文件的所有漏洞
  getFindingsForFile: (filePath) => {
    return get().findingsByFile.get(filePath) || []
  },

  // 获取文件过滤后的漏洞
  getFilteredFindingsForFile: (filePath) => {
    const { findingsByFile, excludeStatuses } = get()
    const findings = findingsByFile.get(filePath) || []
    return filterDecorationsByStatus(findings, excludeStatuses)
  },

  // 获取所有漏洞
  getAllFindings: () => {
    const { findingsByFile } = get()
    const allFindings: Vulnerability[] = []
    for (const findings of findingsByFile.values()) {
      allFindings.push(...findings)
    }
    return allFindings
  },

  // 获取过滤后的所有漏洞
  getFilteredFindings: () => {
    const { findingsByFile, excludeStatuses } = get()
    const allFindings: Vulnerability[] = []
    for (const findings of findingsByFile.values()) {
      allFindings.push(...filterDecorationsByStatus(findings, excludeStatuses))
    }
    return allFindings
  },
}))
