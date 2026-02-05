import { type ReactNode } from 'react'
import { Outlet } from 'react-router-dom'
import { ActivityBar } from './ActivityBar'
import { Sidebar } from './Sidebar'
import { BottomPanel } from './BottomPanel'
import { ProjectTabsBar } from './ProjectTabsBar'
import { useLayoutStore, useSidebarVisible } from '@/stores/layoutStore'
import { cn } from '@/lib/utils'
import {
  HorizontalGroup,
  VerticalGroup,
  HPanel,
  VPanel,
  FixedPanel,
  FlexPanel,
} from './FlexLayout'

interface VSCodeLayoutProps {
  header?: ReactNode
  editorContent?: ReactNode
  bottomPanelContent?: ReactNode
  className?: string
  showActivityBar?: boolean
  showProjectTabs?: boolean
  forceHideSidebar?: boolean
}

export function VSCodeLayout({
  header,
  editorContent,
  bottomPanelContent,
  className,
  showActivityBar = true,
  showProjectTabs = false,
  forceHideSidebar = false,
}: VSCodeLayoutProps) {
  const sidebarVisible = useSidebarVisible()
  const bottomPanelVisible = useLayoutStore(state => state.bottomPanelVisible)
  const shouldShowSidebar = !forceHideSidebar && sidebarVisible && showActivityBar

  return (
    <div className={cn(
      'h-screen w-screen flex flex-col overflow-hidden',
      'bg-[var(--vscode-editor-background)]',
      'text-[var(--vscode-editor-foreground)]',
      className
    )}>
      {header && <div className="shrink-0">{header}</div>}

      {showProjectTabs && (
        <div className="shrink-0">
          <ProjectTabsBar />
        </div>
      )}

      <div className="flex-1 flex overflow-hidden">
        {showActivityBar && (
          <FixedPanel basis="48px">
            <ActivityBar />
          </FixedPanel>
        )}

        <HorizontalGroup className="flex-1">
          {shouldShowSidebar && (
            <HPanel
              key="sidebar"
              defaultSize={20}
              minSize={15}
              maxSize={50}
              className="bg-[var(--vscode-sideBar-background)]"
            >
              <Sidebar />
            </HPanel>
          )}

          <FlexPanel>
            <VerticalGroup className="h-full">
              {bottomPanelVisible ? (
                <VPanel
                  defaultSize={75}
                  minSize={20}
                  showHandle={false}
                  className="bg-[var(--vscode-editor-background)] overflow-auto"
                >
                  {editorContent || <Outlet />}
                </VPanel>
              ) : (
                <div className="flex-1 min-h-0 bg-[var(--vscode-editor-background)] overflow-auto">
                  {editorContent || <Outlet />}
                </div>
              )}

              {bottomPanelVisible && (
                <VPanel
                  key="bottom"
                  defaultSize={25}
                  minSize={15}
                  maxSize={50}
                  showHandle={false}
                  className="bg-[var(--vscode-sideBar-background)]"
                >
                  <BottomPanel>
                    {bottomPanelContent}
                  </BottomPanel>
                </VPanel>
              )}
            </VerticalGroup>
          </FlexPanel>
        </HorizontalGroup>
      </div>
    </div>
  )
}

export { ActivityBar } from './ActivityBar'
export { Sidebar } from './Sidebar'
export { BottomPanel } from './BottomPanel'
export { ProjectTabsBar } from './ProjectTabsBar'
export { useLayoutStore, useActiveActivity, useSidebarVisible, useBottomPanelVisible, useActiveBottomTab } from '@/stores/layoutStore'
