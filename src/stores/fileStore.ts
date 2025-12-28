/**
 * 文件状态管理
 */

import { create } from 'zustand'
import { devtools } from 'zustand/middleware'
import type { FileNode } from '@/shared/types'
import { api } from '@/shared/api/client'

interface FileState {
  files: string[]
  fileTree: FileNode[]
  openFiles: string[]
  selectedFile: string | null
  fileContent: string
  isLoading: boolean
  error: string | null

  // Actions
  loadFiles: (projectPath: string) => Promise<void>
  selectFile: (filePath: string) => Promise<void>
  closeFile: (filePath: string) => void
  clearOpenFiles: () => void
  clearError: () => void
}

// 构建文件树
function buildFileTree(paths: string[], rootPath: string): FileNode[] {
  const root: FileNode[] = []

  paths.forEach(path => {
    let relativePath = path
    if (rootPath && path.startsWith(rootPath)) {
      relativePath = path.substring(rootPath.length).replace(/^[/\\]/, '')
    }

    const parts = relativePath.split(/[/\\]/)
    let currentLevel = root

    parts.forEach((part, index) => {
      if (!part) return

      const existingNode = currentLevel.find(node => node.name === part)
      const isFile = index === parts.length - 1

      if (existingNode) {
        if (existingNode.type === 'folder' && existingNode.children) {
          currentLevel = existingNode.children
        }
      } else {
        const newNode: FileNode = {
          name: part,
          path: isFile ? path : parts.slice(0, index + 1).join('/'),
          type: isFile ? 'file' : 'folder',
          children: isFile ? undefined : []
        }
        currentLevel.push(newNode)
        if (!isFile && newNode.children) {
          currentLevel = newNode.children
        }
      }
    })
  })

  const sortNodes = (nodes: FileNode[]) => {
    nodes.sort((a, b) => {
      if (a.type === b.type) return a.name.localeCompare(b.name)
      return a.type === 'folder' ? -1 : 1
    })
    nodes.forEach(node => {
      if (node.children) sortNodes(node.children)
    })
  }
  sortNodes(root)

  return root
}

export const useFileStore = create<FileState>()(
  devtools(
    (set) => ({
      files: [],
      fileTree: [],
      openFiles: [],
      selectedFile: null,
      fileContent: '// 请选择文件以查看内容',
      isLoading: false,
      error: null,

      loadFiles: async (projectPath) => {
        set({ isLoading: true, error: null })
        try {
          const result = await api.listFiles(projectPath)
          const files = Array.isArray(result) ? result : []
          const fileTree = buildFileTree(files, projectPath)
          set({ files, fileTree, isLoading: false })
        } catch (error) {
          const message = error instanceof Error ? error.message : '加载文件失败'
          set({ error: message, isLoading: false, files: [], fileTree: [] })
        }
      },

      selectFile: async (filePath) => {
        set({ isLoading: true, error: null })
        try {
          const content = await api.readFile(filePath)

          set(state => {
            const openFiles = state.openFiles.includes(filePath)
              ? state.openFiles
              : [...state.openFiles, filePath]

            return {
              selectedFile: filePath,
              openFiles,
              fileContent: content,
              isLoading: false
            }
          })
        } catch (error) {
          const message = error instanceof Error ? error.message : '读取文件失败'
          set({ error: message, isLoading: false })
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
