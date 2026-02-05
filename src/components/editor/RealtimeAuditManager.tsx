/**
 * RealtimeAuditManager - 实时审计管理器
 *
 * 监听编辑器内容变化，触发实时扫描
 */

import { useEffect, useRef } from 'react'
import { useRealtimeAuditStore } from '@/stores/realTimeAuditStore'
import { useEditorStore } from '@/stores/editorStore'
import { useFindingMarkerStore } from '@/stores/findingMarkerStore'
import { injectDecorationStyles } from '@/components/editor/EditorDecorations'

export interface RealtimeAuditManagerProps {
  projectId: string
  projectPath: string
}

export function RealtimeAuditManager({
  projectId,
  projectPath,
}: RealtimeAuditManagerProps) {
  const { autoMode, setCurrentProject, startWatching, stopWatching } =
    useRealtimeAuditStore()
  const { editorGroups } = useEditorStore()
  const {
    updateDecorations,
    loadFindings,
  } = useFindingMarkerStore()

  const isInitialized = useRef(false)

  // 初始化
  useEffect(() => {
    if (!isInitialized.current) {
      // 将字符串 projectId 转换为数字
      const numericProjectId = parseInt(projectId, 10)
      setCurrentProject(isNaN(numericProjectId) ? null : numericProjectId)
      injectDecorationStyles()
      isInitialized.current = true

      // 如果是自动模式，开始监听
      if (autoMode) {
        startWatching(projectPath)
      }
    }

    // 清理
    return () => {
      stopWatching()
    }
  }, [projectId, projectPath, autoMode, setCurrentProject, startWatching, stopWatching])

  // 监听编辑器组变化，更新装饰器
  useEffect(() => {
    editorGroups.forEach((group) => {
      if (group.activeFile) {
        // 加载文件漏洞
        loadFindings(group.activeFile.path, String(projectId))

        // 更新装饰器
        updateDecorations(group.id, group.activeFile.path)
      }
    })
  }, [editorGroups, projectId, loadFindings, updateDecorations])

  // 监听自动模式变化
  useEffect(() => {
    if (autoMode) {
      startWatching(projectPath)
    } else {
      stopWatching()
    }
  }, [autoMode, projectPath, startWatching, stopWatching])

  return null // 这是一个管理组件，不渲染任何 UI
}
