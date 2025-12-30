
import { useEffect } from 'react'
import { AgentAuditPanel } from '@/components/audit/AgentAuditPanel'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { useAgentStore } from '@/stores/agentStore'
import { useProjectStore } from '@/stores/projectStore'
import { AlertTriangle, CheckCircle, Clock, Shield } from 'lucide-react'

export default function AgentAuditPage() {
  const { currentProject } = useProjectStore()
  const { auditStats, isConnected } = useAgentStore()

  if (!currentProject) {
    return (
      <div className="flex items-center justify-center h-full">
        <Card className="w-[400px]">
          <CardHeader>
            <CardTitle>未选择项目</CardTitle>
            <CardDescription>请先在项目管理页面选择一个项目进行审计。</CardDescription>
          </CardHeader>
        </Card>
      </div>
    )
  }

  return (
    <div className="container mx-auto p-6 h-[calc(100vh-4rem)] flex flex-col gap-6">
      {/* 统计概览 */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">发现漏洞</CardTitle>
            <AlertTriangle className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{auditStats.findings_detected}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">已验证</CardTitle>
            <CheckCircle className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{auditStats.verified_vulnerabilities}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">扫描文件</CardTitle>
            <Shield className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{auditStats.files_scanned}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Token 消耗</CardTitle>
            <Clock className="h-4 w-4 text-purple-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{auditStats.tokens_used || 0}</div>
          </CardContent>
        </Card>
      </div>

      {/* 主面板 */}
      <Card className="flex-1 overflow-hidden flex flex-col">
        <AgentAuditPanel />
      </Card>
    </div>
  )
}
