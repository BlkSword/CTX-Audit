import { type ReactNode } from 'react'
import { ActivityBar } from './ActivityBar'
import { Sidebar } from './Sidebar'
import { BottomPanel } from './BottomPanel'
import { AgentPanel } from './AgentPanel'
import { CodeEditorPanel } from './CodeEditorPanel'
import { useLayoutStore, useSidebarVisible, useSidebarSize, useAgentPanelVisible, useAgentPanelSize } from '@/stores/layoutStore'
import { cn } from '@/lib/utils'
import {
  HorizontalGroup,
  VerticalGroup,
  HPanel,
  VPanel,
  FixedPanel,
  FlexPanel,
} from './FlexLayout'

export interface EditorLayoutProps {
  editorContent?: ReactNode
  agentContent?: ReactNode
  bottomPanelContent?: ReactNode
  className?: string
  showActivityBar?: boolean
  showBottomPanel?: boolean
}

export function EditorLayout({
  editorContent,
  agentContent,
  bottomPanelContent,
  className,
  showActivityBar = true,
  showBottomPanel = false,
}: EditorLayoutProps) {
  const sidebarVisible = useSidebarVisible()
  const sidebarSize = useSidebarSize()
  const agentPanelVisible = useAgentPanelVisible()
  const agentPanelSize = useAgentPanelSize()
  const bottomPanelVisible = useLayoutStore(state => state.bottomPanelVisible)
  const bottomPanelSize = useLayoutStore(state => state.bottomPanelSize)

  return (
    <div className={cn('h-screen w-screen flex flex-col bg-[#1e1e1e] text-foreground overflow-hidden', className)}>
      <div className="flex-1 flex overflow-hidden">
        {showActivityBar && (
          <FixedPanel basis="48px">
            <ActivityBar />
          </FixedPanel>
        )}

        <HorizontalGroup className="flex-1">
          {sidebarVisible && (
            <HPanel
              key="sidebar"
              defaultSize={sidebarSize}
              minSize={15}
              maxSize={50}
              className="bg-[#252526]"
            >
              <Sidebar />
            </HPanel>
          )}

          <FlexPanel>
            <VerticalGroup className="h-full">
              {bottomPanelVisible || showBottomPanel ? (
                <VPanel
                  defaultSize={bottomPanelVisible ? 75 : 100}
                  minSize={20}
                  showHandle={false}
                  className="bg-[#1e1e1e]"
                >
                  {editorContent || <CodeEditorPanel />}
                </VPanel>
              ) : (
                <div className="flex-1 min-h-0 bg-[#1e1e1e] overflow-hidden">
                  {editorContent || <CodeEditorPanel />}
                </div>
              )}

              {(bottomPanelVisible || showBottomPanel) && (
                <VPanel
                  key="bottom"
                  defaultSize={bottomPanelSize}
                  minSize={15}
                  maxSize={60}
                  showHandle={false}
                  className="bg-[#252526]"
                >
                  <BottomPanel>
                    {bottomPanelContent}
                  </BottomPanel>
                </VPanel>
              )}
            </VerticalGroup>
          </FlexPanel>

          {agentPanelVisible && (
            <HPanel
              key="agent"
              defaultSize={agentPanelSize}
              minSize={20}
              maxSize={50}
              className="bg-[#252526]"
            >
              {agentContent || <AgentPanel />}
            </HPanel>
          )}
        </HorizontalGroup>
      </div>
    </div>
  )
}

export { ActivityBar } from './ActivityBar'
export { Sidebar } from './Sidebar'
export { BottomPanel } from './BottomPanel'
export { AgentPanel } from './AgentPanel'
export { CodeEditorPanel } from './CodeEditorPanel'
export { useLayoutStore, useActiveActivity, useSidebarVisible, useAgentPanelVisible, useBottomPanelVisible, useActiveBottomTab } from '@/stores/layoutStore'
