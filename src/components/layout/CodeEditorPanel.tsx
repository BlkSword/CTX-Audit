/**
 * CodeEditorPanel - 代码编辑器面板
 *
 * 显示代码编辑器，支持：
 * - Monaco Editor 集成
 * - 多编辑器组拆分
 * - 文件标签页
 * - 语法高亮
 * - 内联漏洞标记
 */

import { useEffect } from 'react'
import { useEditorStore } from '@/stores/editorStore'
import { EditorSplitContainer } from '@/components/editor/EditorSplitContainer'
import { useFileStore } from '@/stores/fileStore'
import { tauriApi } from '@/shared/api/tauri-client'
import { getLanguageFromPath } from '@/components/editor/MonacoEditor'

export function CodeEditorPanel() {
  const { selectedFile, fileContent } = useFileStore()
  const { editorGroups, openFileInGroup } = useEditorStore()

  // 当用户在文件浏览器中点击文件时，在第一个编辑器组中打开
  useEffect(() => {
    if (selectedFile && fileContent && fileContent !== '// 请选择文件以查看内容') {
      loadAndOpenFile(selectedFile, fileContent)
    }
  }, [selectedFile, fileContent])

  // 加载并打开文件
  const loadAndOpenFile = async (filePath: string, content: string) => {
    try {
      // const content = await tauriApi.readFile(filePath)
      const language = getLanguageFromPath(filePath)

      // 在第一个编辑器组中打开文件
      const firstGroup = editorGroups[0]
      if (firstGroup) {
        openFileInGroup(firstGroup.id, filePath, content, language)
      }
    } catch (error) {
      console.error('Failed to load file:', error)
    }
  }

  return (
    <div className="flex flex-col h-full bg-[#1e1e1e]">
      <EditorSplitContainer />
    </div>
  )
}
