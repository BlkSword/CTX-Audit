/**
 * 文件状态管理
 */

import { create } from 'zustand'
import { devtools } from 'zustand/middleware'
import type { FileNode } from '@/shared/types'
import { tauriApi } from '@/shared/api/tauri-client'

interface FileState {
  files: any[]  // 改为 any[] 因为 Tauri 返回的是 FileInfo[]
  fileTree: FileNode[]
  openFiles: string[]
  selectedFile: string | null
  fileContent: string
  isLoading: boolean
  error: string | null
  loadedPaths: Set<string>  // 已加载的路径缓存

  // Actions
  loadFiles: (projectPath: string) => Promise<void>
  selectFile: (filePath: string) => Promise<void>
  closeFile: (filePath: string) => void
  clearOpenFiles: () => void
  clearError: () => void
}

// 构建文件树（扁平结构）
function buildFileTree(files: any[]): FileNode[] {
  const root: FileNode[] = []

  files.forEach((file: any) => {
    const fileName = file.name
    const filePath = file.path
    const isDir = file.is_dir

    if (isDir) {
      // 文件夹节点
      const node: FileNode = {
        name: fileName,
        path: filePath,
        type: 'folder',
        children: [],
        loaded: false,
      }
      root.push(node)
    } else {
      // 文件节点
      const node: FileNode = {
        name: fileName,
        path: filePath,
        type: 'file',
      }
      root.push(node)
    }
  })

  // 排序：文件夹在前，然后按名称排序
  root.sort((a, b) => {
    if (a.type === 'folder' && b.type === 'folder') {
      return a.name.localeCompare(b.name)
    }
    if (a.type === 'folder') return -1
    if (b.type === 'folder') return 1
    return a.name.localeCompare(b.name)
  })

  return root
}

export const useFileStore = create<FileState>()(
  devtools(
    (set, get) => ({
      files: [],
      fileTree: [],
      openFiles: [],
      selectedFile: null,
      fileContent: '// 请选择文件以查看内容',
      isLoading: false,
      error: null,
      loadedPaths: new Set<string>(),

      loadFiles: async (projectPath) => {
        // 检查是否已加载过此路径
        const state = get()
        if (state.loadedPaths.has(projectPath)) {
          return
        }

        set({ isLoading: true, error: null })
        try {
          // 使用 Tauri API 列出目录
          const files = await tauriApi.listDirectory(projectPath)
          const fileTree = buildFileTree(files)

          // 更新缓存
          set(state => ({
            files,
            fileTree,
            isLoading: false,
            loadedPaths: new Set([...state.loadedPaths, projectPath])
          }))
        } catch (error) {
          const message = error instanceof Error ? error.message : '加载文件失败'
          console.error('loadFiles error:', message, error)
          set({ error: message, isLoading: false, files: [], fileTree: [] })
        }
      },

      selectFile: async (filePath) => {
        // 如果已经选中了同一个文件，不执行任何操作
        const state = get()
        if (state.selectedFile === filePath) {
          return
        }

        // 检查文件是否已经在打开的文件列表中（已缓存）
        // 注意：这里我们只检查是否在 openFiles 中，不进行实际的内容缓存
        // 如果需要更好的性能，可以添加一个 fileContents 缓存对象
        const isAlreadyOpen = state.openFiles.includes(filePath)

        set({ isLoading: true, error: null })
        try {
          // 使用 Tauri API 读取文件
          const content = await tauriApi.readFile(filePath)

          set(state => {
            const openFiles = state.openFiles.includes(filePath)
              ? state.openFiles
              : [...state.openFiles, filePath]

            return {
              selectedFile: filePath,
              openFiles,
              fileContent: content,
              isLoading: false,
              error: null
            }
          })
        } catch (error) {
          const message = error instanceof Error ? error.message : '读取文件失败'

          // 友好的错误消息
          let friendlyMessage = message
          if (message.includes('拒绝访问') || message.includes('权限不足')) {
            friendlyMessage = `无法访问文件: ${filePath}\n可能原因：文件是二进制文件、系统文件或没有访问权限`
          } else if (message.includes('不支持读取二进制文件')) {
            friendlyMessage = `不支持读取二进制文件: ${filePath}`
          } else if (message.includes('文件不存在')) {
            friendlyMessage = `文件不存在: ${filePath}`
          }

          console.error('selectFile error:', message, error)

          // 设置错误但不清空当前内容
          set({
            error: friendlyMessage,
            isLoading: false,
            fileContent: `// 无法加载文件\n// ${friendlyMessage}`
          })
        }
      },

      closeFile: (filePath) => {
        set(state => {
          const openFiles = state.openFiles.filter(f => f !== filePath)
          const selectedFile = state.selectedFile === filePath
            ? (openFiles.length > 0 ? openFiles[openFiles.length - 1] : null)
            : state.selectedFile

          return {
            openFiles,
            selectedFile,
            fileContent: selectedFile ? state.fileContent : '// 请选择文件以查看内容'
          }
        })
      },

      clearOpenFiles: () => {
        set({
          openFiles: [],
          selectedFile: null,
          fileContent: '// 请选择文件以查看内容'
        })
      },

      clearError: () => {
        set({ error: null })
      },
    }),
    { name: 'file-store' }
  )
)
