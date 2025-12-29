/**
 * CTX-Audit - 代码审计平台
 * 主应用入口 - 路由配置
 */

import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Dashboard } from '@/pages/Dashboard'
import { ProjectLayout } from '@/pages/project/ProjectLayout'
import { EditorPanel } from '@/pages/project/EditorPanel'
import { GraphPanel } from '@/pages/project/GraphPanel'
import { ScanPanel } from '@/pages/project/ScanPanel'
import { AnalysisPanel } from '@/pages/project/AnalysisPanel'
import AgentAuditPage from '@/pages/AgentAudit'
import { SettingsLayout } from '@/pages/settings/SettingsLayout'
import { LLMConfigPage } from '@/pages/settings/LLMConfigPage'
import { SystemSettingsPage } from '@/pages/settings/SystemSettingsPage'
import { PromptTemplatesPage } from '@/pages/settings/PromptTemplatesPage'
import { RulesPage } from '@/pages/settings/RulesPage'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import { Toaster } from '@/components/ui/toaster'

function App() {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <Routes>
          {/* Dashboard - 项目列表 */}
          <Route path="/" element={<Dashboard />} />

          {/* Project Routes */}
          <Route path="/project/:id" element={<ProjectLayout />}>
            {/* 默认重定向到编辑器 */}
            <Route index element={<Navigate to="editor" replace />} />
            {/* 各个栏目路由 */}
            <Route path="editor" element={<EditorPanel />} />
            <Route path="graph" element={<GraphPanel />} />
            <Route path="scan" element={<ScanPanel />} />
            <Route path="analysis" element={<AnalysisPanel />} />
            <Route path="agent" element={<AgentAuditPage />} />
          </Route>

          {/* Settings Routes */}
          <Route path="/settings" element={<SettingsLayout />}>
            <Route path="llm" element={<LLMConfigPage />} />
            <Route path="system" element={<SystemSettingsPage />} />
            <Route path="prompts" element={<PromptTemplatesPage />} />
            <Route path="rules" element={<RulesPage />} />
          </Route>

          {/* Catch all - redirect to dashboard */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
      {/* 全局 Toast 提示 */}
      <Toaster />
    </ErrorBoundary>
  )
}

export default App
