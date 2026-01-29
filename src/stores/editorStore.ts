/**
 * EditorStore - 编辑器状态管理
 *
 * 管理多编辑器组、文件标签、编辑器实例等
 */

import { create } from 'zustand'
import { nanoid } from 'nanoid'
import type * as monaco from 'monaco-editor'

// ==================== 类型定义 ====================

export interface OpenFile {
  path: string
  name: string
  content: string
  language: string
  isModified: boolean
  isActive: boolean
}

export interface EditorGroup {
  id: string
  orientation: 'horizontal' | 'vertical'
  files: OpenFile[]
  activeFile: OpenFile | null
  editorInstance: monaco.editor.IStandaloneCodeEditor | null
}

interface EditorState {
  // 编辑器组
  editorGroups: EditorGroup[]
  activeGroupId: string | null

  // 操作
  createEditorGroup: (orientation: 'horizontal' | 'vertical') => string
  closeEditorGroup: (groupId: string) => void
  setActiveGroup: (groupId: string) => void

  // 文件操作
  openFileInGroup: (groupId: string, filePath: string, content: string, language: string) => void
  setActiveFile: (groupId: string, filePath: string) => void
  closeFile: (groupId: string, filePath: string) => void
  updateFileContent: (groupId: string, filePath: string, content: string) => void

  // 编辑器实例
  setEditorInstance: (
    groupId: string,
    editor: monaco.editor.IStandaloneCodeEditor | null
  ) => void
  getEditorInstance: (groupId: string) => monaco.editor.IStandaloneCodeEditor | null

  // 组操作
  splitGroup: (groupId: string, orientation: 'horizontal' | 'vertical') => string
}

// ==================== Store ====================

export const useEditorStore = create<EditorState>((set, get) => ({
  // 初始状态
  editorGroups: [
    {
      id: 'group-1',
      orientation: 'horizontal',
      files: [],
      activeFile: null,
      editorInstance: null,
    },
  ],
  activeGroupId: 'group-1',

  // 创建编辑器组
  createEditorGroup: (orientation) => {
    const newGroup: EditorGroup = {
      id: `group-${nanoid(8)}`,
      orientation,
      files: [],
      activeFile: null,
      editorInstance: null,
    }

    set((state) => ({
      editorGroups: [...state.editorGroups, newGroup],
      activeGroupId: newGroup.id,
    }))

    return newGroup.id
  },

  // 关闭编辑器组
  closeEditorGroup: (groupId) => {
    set((state) => {
      const groups = state.editorGroups.filter((g) => g.id !== groupId)

      // 如果关闭的是当前激活组，切换到第一个组
      let activeGroupId = state.activeGroupId
      if (activeGroupId === groupId && groups.length > 0) {
        activeGroupId = groups[0].id
      }

      return {
        editorGroups: groups,
        activeGroupId,
      }
    })
  },

  // 设置激活组
  setActiveGroup: (groupId) => {
    set({ activeGroupId: groupId })
  },

  // 在组中打开文件
  openFileInGroup: (groupId, filePath, content, language) => {
    set((state) => {
      const groups = state.editorGroups.map((group) => {
        if (group.id !== groupId) return group

        // 检查文件是否已经打开
        const existingFile = group.files.find((f) => f.path === filePath)

        if (existingFile) {
          // 文件已打开，设置为激活
          return {
            ...group,
            files: group.files.map((f) => ({
              ...f,
              isActive: f.path === filePath,
            })),
            activeFile: existingFile,
          }
        }

        // 创建新文件标签
        const fileName = filePath.split('/').pop() || filePath
        const newFile: OpenFile = {
          path: filePath,
          name: fileName,
          content,
          language,
          isModified: false,
          isActive: true,
        }

        return {
          ...group,
          files: [
            ...group.files.map((f) => ({ ...f, isActive: false })),
            newFile,
          ],
          activeFile: newFile,
        }
      })

      return { editorGroups: groups }
    })
  },

  // 设置激活文件
  setActiveFile: (groupId, filePath) => {
    set((state) => {
      const groups = state.editorGroups.map((group) => {
        if (group.id !== groupId) return group

        const activeFile = group.files.find((f) => f.path === filePath) || null

        return {
          ...group,
          files: group.files.map((f) => ({
            ...f,
            isActive: f.path === filePath,
          })),
          activeFile,
        }
      })

      return { editorGroups: groups }
    })
  },

  // 关闭文件
  closeFile: (groupId, filePath) => {
    set((state) => {
      const groups = state.editorGroups.map((group) => {
        if (group.id !== groupId) return group

        const files = group.files.filter((f) => f.path !== filePath)

        // 如果关闭的是当前激活文件，切换到最后一个文件
        let activeFile = group.activeFile
        if (group.activeFile?.path === filePath) {
          activeFile = files.length > 0 ? files[files.length - 1] : null
        }

        // 更新文件激活状态
        const updatedFiles = files.map((f, idx) => ({
          ...f,
          isActive: idx === files.length - 1,
        }))

        return {
          ...group,
          files: updatedFiles,
          activeFile,
        }
      })

      return { editorGroups: groups }
    })
  },

  // 更新文件内容
  updateFileContent: (groupId, filePath, content) => {
    set((state) => {
      const groups = state.editorGroups.map((group) => {
        if (group.id !== groupId) return group

        return {
          ...group,
          files: group.files.map((f) =>
            f.path === filePath ? { ...f, content, isModified: true } : f
          ),
          activeFile:
            group.activeFile?.path === filePath
              ? { ...group.activeFile, content, isModified: true }
              : group.activeFile,
        }
      })

      return { editorGroups: groups }
    })
  },

  // 设置编辑器实例
  setEditorInstance: (groupId, editor) => {
    set((state) => ({
      editorGroups: state.editorGroups.map((group) =>
        group.id === groupId ? { ...group, editorInstance: editor } : group
      ),
    }))
  },

  // 获取编辑器实例
  getEditorInstance: (groupId) => {
    const group = get().editorGroups.find((g) => g.id === groupId)
    return group?.editorInstance || null
  },

  // 拆分编辑器组
  splitGroup: (groupId, orientation) => {
    const state = get()
    const sourceGroup = state.editorGroups.find((g) => g.id === groupId)

    if (!sourceGroup) return state.activeGroupId || ''

    // 创建新组
    const newGroupId = get().createEditorGroup(orientation)

    // 复制当前文件到新组
    if (sourceGroup.activeFile) {
      get().openFileInGroup(
        newGroupId,
        sourceGroup.activeFile.path,
        sourceGroup.activeFile.content,
        sourceGroup.activeFile.language
      )
    }

    return newGroupId
  },
}))
