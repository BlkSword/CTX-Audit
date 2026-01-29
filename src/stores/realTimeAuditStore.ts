/**
 * RealtimeAuditStore - 实时审计状态管理
 *
 * 管理实时审计的模式、文件监听、扫描队列等
 */

import { create } from 'zustand'
import { invoke } from '@tauri-apps/api/core'

// ==================== 类型定义 ====================

export type ScanStatus = 'idle' | 'scanning' | 'completed' | 'error'

interface ScanQueueItem {
  filePath: string
  content: string
  status: ScanStatus
  error?: string
  findings: any[]
}

interface RealtimeAuditState {
  // 模式
  autoMode: boolean
  setAutoMode: (enabled: boolean) => void

  // 监听状态
  isWatching: boolean
  watchedFiles: Set<string>

  // 扫描队列
  pendingScans: string[]
  scanningFiles: Set<string>
  scanQueue: Map<string, ScanQueueItem>

  // 当前项目
  currentProjectId: string | null
  setCurrentProject: (projectId: string) => void

  // 扫描设置
  scanDebounceMs: number
  setScanDebounceMs: (ms: number) => void

  // 操作
  startWatching: (projectPath: string) => Promise<void>
  stopWatching: () => Promise<void>
  triggerScan: (filePath: string, content?: string) => Promise<void>
  addScanToQueue: (filePath: string, content: string) => void
  removeScanFromQueue: (filePath: string) => void
  clearScanQueue: () => void

  // 状态查询
  getScanStatus: (filePath: string) => ScanStatus
  getScanResult: (filePath: string) => ScanQueueItem | undefined
  isFileScanning: (filePath: string) => boolean
}

// ==================== Store ====================

export const useRealtimeAuditStore = create<RealtimeAuditState>((set, get) => ({
  // 初始状态
  autoMode: true,
  isWatching: false,
  watchedFiles: new Set(),
  pendingScans: [],
  scanningFiles: new Set(),
  scanQueue: new Map(),
  currentProjectId: null,
  scanDebounceMs: 500,

  // 设置自动模式
  setAutoMode: (enabled) => {
    set({ autoMode: enabled })
  },

  // 设置当前项目
  setCurrentProject: (projectId) => {
    set({ currentProjectId: projectId })
  },

  // 设置扫描防抖时间
  setScanDebounceMs: (ms) => {
    set({ scanDebounceMs: ms })
  },

  // 开始监听文件变化
  startWatching: async (projectPath) => {
    try {
      // TODO: 实现文件监听
      // 目前使用轮询或 Tauri 文件监听事件
      set({ isWatching: true })
    } catch (error) {
      console.error('Failed to start watching:', error)
    }
  },

  // 停止监听
  stopWatching: async () => {
    try {
      // TODO: 停止文件监听
      set({ isWatching: false, watchedFiles: new Set() })
    } catch (error) {
      console.error('Failed to stop watching:', error)
    }
  },

  // 触发扫描
  triggerScan: async (filePath, content) => {
    const { autoMode, currentProjectId, scanningFiles } = get()

    // 如果不是自动模式，不扫描
    if (!autoMode) return

    // 如果当前正在扫描，跳过
    if (scanningFiles.has(filePath)) return

    // 没有项目 ID，跳过
    if (!currentProjectId) return

    try {
      // 添加到正在扫描列表
      set((state) => ({
        scanningFiles: new Set(state.scanningFiles).add(filePath),
      }))

      // 调用后端扫描
      const result = await invoke('scan_file', {
        filePath,
        projectId: currentProjectId,
        content: content || '',
      })

      // 更新队列状态
      set((state) => {
        const newQueue = new Map(state.scanQueue)
        const existingItem = newQueue.get(filePath)

        newQueue.set(filePath, {
          filePath,
          content: content || existingItem?.content || '',
          status: 'completed',
          findings: (result as any).findings || [],
        })

        const newScanningFiles = new Set(state.scanningFiles)
        newScanningFiles.delete(filePath)

        return {
          scanQueue: newQueue,
          scanningFiles: newScanningFiles,
        }
      })

      // 更新漏洞标记 store
      const { useFindingMarkerStore } = await import('./findingMarkerStore')
      const findingMarkerStore = useFindingMarkerStore.getState()

      // 更新文件漏洞列表
      const findingsByFile = new Map(findingMarkerStore.findingsByFile)
      findingsByFile.set(filePath, (result as any).findings || [])

      findingMarkerStore.findingsByFile = findingsByFile

      // 更新装饰器
      // TODO: 触发装饰器更新
    } catch (error) {
      console.error('Failed to scan file:', error)

      // 标记为错误
      set((state) => {
        const newQueue = new Map(state.scanQueue)
        const existingItem = newQueue.get(filePath)

        newQueue.set(filePath, {
          filePath,
          content: content || existingItem?.content || '',
          status: 'error',
          error: String(error),
          findings: [],
        })

        const newScanningFiles = new Set(state.scanningFiles)
        newScanningFiles.delete(filePath)

        return {
          scanQueue: newQueue,
          scanningFiles: newScanningFiles,
        }
      })
    }
  },

  // 添加扫描到队列
  addScanToQueue: (filePath, content) => {
    set((state) => {
      const newQueue = new Map(state.scanQueue)
      newQueue.set(filePath, {
        filePath,
        content,
        status: 'idle',
        findings: [],
      })

      return {
        scanQueue: newQueue,
        pendingScans: [...state.pendingScans, filePath],
      }
    })
  },

  // 从队列移除
  removeScanFromQueue: (filePath) => {
    set((state) => {
      const newQueue = new Map(state.scanQueue)
      newQueue.delete(filePath)

      return {
        scanQueue: newQueue,
        pendingScans: state.pendingScans.filter((p) => p !== filePath),
      }
    })
  },

  // 清空队列
  clearScanQueue: () => {
    set({
      scanQueue: new Map(),
      pendingScans: [],
      scanningFiles: new Set(),
    })
  },

  // 获取扫描状态
  getScanStatus: (filePath) => {
    const item = get().scanQueue.get(filePath)
    return item?.status || 'idle'
  },

  // 获取扫描结果
  getScanResult: (filePath) => {
    return get().scanQueue.get(filePath)
  },

  // 判断文件是否正在扫描
  isFileScanning: (filePath) => {
    return get().scanningFiles.has(filePath)
  },
}))

// ==================== 防抖函数 ====================

let debounceTimer: ReturnType<typeof setTimeout> | null = null

export function debounceScan(
  filePath: string,
  content: string,
  delay: number = 500
): void {
  if (debounceTimer) {
    clearTimeout(debounceTimer)
  }

  debounceTimer = setTimeout(() => {
    useRealtimeAuditStore.getState().triggerScan(filePath, content)
  }, delay)
}
