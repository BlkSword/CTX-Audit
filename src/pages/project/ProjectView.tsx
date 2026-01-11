/**
 * ProjectView - 项目内部视图切换
 */

import { useUIStore } from '@/stores/uiStore'
import { EditorPanel } from './EditorPanel'
import { GraphPanel } from './GraphPanel'
import { ScanPanel } from './ScanPanel'
import { AnalysisPanel } from './AnalysisPanel'
import EnhancedAuditPage from '@/pages/AgentAudit/EnhancedAuditPage'

export function ProjectView() {
  const { activeView } = useUIStore()

  return (
    <div className="h-full">
      {activeView === 'editor' && <EditorPanel />}
      {activeView === 'graph' && <GraphPanel />}
      {activeView === 'scan' && <ScanPanel />}
      {activeView === 'analysis' && <AnalysisPanel />}
      {activeView === 'agent' && <EnhancedAuditPage />}
    </div>
  )
}
