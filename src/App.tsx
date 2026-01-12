/**
 * CTX-Audit - 代码审计平台
 * 主应用入口 - 路由配置
 */

import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Dashboard } from '@/pages/Dashboard'
import { ProjectLayout } from '@/pages/project/ProjectLayout'
import { GraphPanel } from '@/pages/project/GraphPanel'
import { ScanPanel } from '@/pages/project/ScanPanel'
import { AnalysisPanel } from '@/pages/project/AnalysisPanel'
import EnhancedAuditPage from '@/pages/AgentAudit/EnhancedAuditPage'
import { SettingsLayout } from '@/pages/settings/SettingsLayout'
import { LLMConfigPage } from '@/pages/settings/LLMConfigPage'
import { SystemSettingsPage } from '@/pages/settings/SystemSettingsPage'
import { PromptTemplatesPage } from '@/pages/settings/PromptTemplatesPage'
import { RulesPage } from '@/pages/settings/RulesPage'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import { Toaster } from '@/components/ui/toaster'
import { ConfirmDialogComponent } from '@/components/ui/confirm-dialog'
import { AgentUIDemo } from '@/pages/Demo/AgentUIDemo'

function App() {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <Routes>
          {/* Dashboard - 项目列表 */}
          <Route path="/" element={<Dashboard />} />

          {/* Demo - UI组件演示页面（无需后端） */}
          <Route path="/demo" element={<AgentUIDemo />} />

          {/* Project Routes */}
          <Route path="/project/:id" element={<ProjectLayout />}>
            {/* 默认重定向到Agent审计 */}
            <Route index element={<Navigate to="agent" replace />} />
            {/* 各个栏目路由 */}
            <Route path="agent" element={<EnhancedAuditPage />} />
            <Route path="agent/:auditId" element={<EnhancedAuditPage />} />
            <Route path="graph" element={<GraphPanel />} />
            <Route path="scan" element={<ScanPanel />} />
            <Route path="analysis" element={<AnalysisPanel />} />
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
      {/* 全局确认对话框 */}
      <ConfirmDialogComponent />
    </ErrorBoundary>
  )
}

export default App
