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

import { useEffect, useRef } from 'react'
import { useEditorStore } from '@/stores/editorStore'
import { EditorSplitContainer } from '@/components/editor/EditorSplitContainer'
import { useFileStore } from '@/stores/fileStore'
import { getLanguageFromPath } from '@/components/editor/MonacoEditor'

export function CodeEditorPanel() {
  // 使用精确的 selector，只订阅需要的状态
  const selectedFile = useFileStore(state => state.selectedFile)
  const fileContent = useFileStore(state => state.fileContent)

  // 使用 ref 来跟踪上次打开的文件，避免重复打开
  const lastOpenedFileRef = useRef<string | null>(null)

  // 当用户在文件浏览器中点击文件时，在第一个编辑器组中打开
  useEffect(() => {
    if (!selectedFile) {
      lastOpenedFileRef.current = null
      return
    }

    // 避免重复打开同一个文件
    if (selectedFile === lastOpenedFileRef.current) {
      return
    }

    if (!fileContent) return

    // 排除初始占位符内容和错误消息
    if (fileContent.startsWith('// 无法加载文件') ||
        fileContent === '// 请选择文件以查看内容') {
      return
    }

    const { editorGroups, openFileInGroup } = useEditorStore.getState()
    const firstGroup = editorGroups[0]
    if (!firstGroup) return

    // 打开文件
    const language = getLanguageFromPath(selectedFile)
    openFileInGroup(firstGroup.id, selectedFile, fileContent, language)

    // 记录已打开的文件
    lastOpenedFileRef.current = selectedFile
  }, [selectedFile, fileContent])

  return (
    <div className="flex flex-col h-full bg-[#1e1e1e]">
      <EditorSplitContainer />
    </div>
  )
}
