/**
 * ScanPanel - 安全扫描面板
 */

import { useState } from 'react'
import { ShieldAlert, Bug, AlertTriangle, CheckCircle, Search, RefreshCw } from 'lucide-react'
import { useScanStore } from '@/stores/scanStore'
import { useProjectStore } from '@/stores/projectStore'
import { useUIStore } from '@/stores/uiStore'
import { useFileStore } from '@/stores/fileStore'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card } from '@/components/ui/card'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Input } from '@/components/ui/input'

export function ScanPanel() {
  const { vulnerabilities, scanResults, isScanning, runScan, verifyFinding } = useScanStore()
  const { currentProject } = useProjectStore()
  const { addLog } = useUIStore()
  const { selectFile } = useFileStore()

  const [searchQuery, setSearchQuery] = useState('')
  const [severityFilter, setSeverityFilter] = useState<'all' | 'critical' | 'high' | 'medium' | 'low'>('all')

  const handleRunScan = async () => {
    if (!currentProject) return
    try {
      addLog('开始扫描...', 'system')
      await runScan(currentProject.path)
      addLog('扫描完成', 'system')
    } catch (err) {
      addLog(`扫描失败: ${err}`, 'system')
    }
  }

  const handleVerifyFinding = async (id: string, vuln: typeof vulnerabilities[0]) => {
    try {
      addLog(`验证漏洞: ${vuln.vuln_type}`, 'system')
      await verifyFinding(id, vuln)
    } catch (err) {
      addLog(`验证失败: ${err}`, 'system')
    }
  }

  const handleFindingClick = (vuln: typeof vulnerabilities[0]) => {
    const filePath = vuln.file || vuln.file_path
    if (filePath) {
      selectFile(filePath)
    }
  }

  const filteredVulnerabilities = vulnerabilities.filter(v => {
    const matchesSearch = searchQuery === '' ||
      v.message?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      v.vuln_type?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      v.file?.toLowerCase().includes(searchQuery.toLowerCase())

    const matchesSeverity = severityFilter === 'all' || v.severity === severityFilter

    return matchesSearch && matchesSeverity
  })

  const severityCount = {
    critical: vulnerabilities.filter(v => v.severity === 'critical').length,
    high: vulnerabilities.filter(v => v.severity === 'high').length,
    medium: vulnerabilities.filter(v => v.severity === 'medium').length,
    low: vulnerabilities.filter(v => v.severity === 'low').length,
  }

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
        return <AlertTriangle className="w-4 h-4 text-red-600" />
      case 'high':
        return <ShieldAlert className="w-4 h-4 text-orange-500" />
      case 'medium':
        return <Bug className="w-4 h-4 text-yellow-500" />
      case 'low':
        return <CheckCircle className="w-4 h-4 text-blue-500" />
      default:
        return <Bug className="w-4 h-4" />
    }
  }

  const getSeverityBadgeVariant = (severity: string): "destructive" | "default" | "secondary" | "outline" => {
    switch (severity) {
      case 'critical':
      case 'high':
        return 'destructive'
      case 'medium':
        return 'default'
      default:
        return 'secondary'
    }
  }

  return (
    <div className="h-full p-6 overflow-auto">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold">安全扫描</h1>
            <p className="text-sm text-muted-foreground mt-1">
              扫描代码中的安全漏洞和潜在问题
            </p>
          </div>

          <Button
            onClick={handleRunScan}
            disabled={isScanning || !currentProject}
            size="lg"
          >
            {isScanning ? (
              <>
                <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                扫描中...
              </>
            ) : (
              <>
                <Search className="w-4 h-4 mr-2" />
                开始扫描
              </>
            )}
          </Button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          <Card className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">严重</p>
                <p className="text-2xl font-bold text-red-600 mt-1">{severityCount.critical}</p>
              </div>
              <AlertTriangle className="w-8 h-8 text-red-600/20" />
            </div>
          </Card>

          <Card className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">高危</p>
                <p className="text-2xl font-bold text-orange-500 mt-1">{severityCount.high}</p>
              </div>
              <ShieldAlert className="w-8 h-8 text-orange-500/20" />
            </div>
          </Card>

          <Card className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">中危</p>
                <p className="text-2xl font-bold text-yellow-500 mt-1">{severityCount.medium}</p>
              </div>
              <Bug className="w-8 h-8 text-yellow-500/20" />
            </div>
          </Card>

          <Card className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">低危</p>
                <p className="text-2xl font-bold text-blue-500 mt-1">{severityCount.low}</p>
              </div>
              <CheckCircle className="w-8 h-8 text-blue-500/20" />
            </div>
          </Card>
        </div>

        {/* Filters */}
        <div className="flex items-center gap-4 mb-4">
          <div className="flex-1">
            <Input
              placeholder="搜索漏洞..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="max-w-md"
            />
          </div>

          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">严重级别:</span>
            {(['all', 'critical', 'high', 'medium', 'low'] as const).map((level) => (
              <Button
                key={level}
                variant={severityFilter === level ? 'default' : 'outline'}
                size="sm"
                onClick={() => setSeverityFilter(level)}
                className="text-xs"
              >
                {level === 'all' ? '全部' : level.charAt(0).toUpperCase() + level.slice(1)}
              </Button>
            ))}
          </div>
        </div>

        {/* Vulnerabilities List */}
        <Card className="p-0 overflow-hidden">
          {filteredVulnerabilities.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
              <ShieldAlert className="w-16 h-16 mb-4 opacity-20" />
              <p className="text-lg font-medium">未发现漏洞</p>
              <p className="text-sm mt-2">
                {vulnerabilities.length === 0
                  ? '点击"开始扫描"来检测安全问题'
                  : '尝试调整搜索或筛选条件'}
              </p>
            </div>
          ) : (
            <ScrollArea className="h-[calc(100vh-400px)]">
              <div className="divide-y divide-border/40">
                {filteredVulnerabilities.map((vuln, index) => (
                  <div
                    key={vuln.id || index}
                    onClick={() => handleFindingClick(vuln)}
                    className="p-4 hover:bg-muted/50 cursor-pointer transition-colors"
                  >
                    <div className="flex items-start gap-4">
                      <div className="mt-1">
                        {getSeverityIcon(vuln.severity)}
                      </div>

                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-2">
                          <Badge variant={getSeverityBadgeVariant(vuln.severity)} className="text-[10px] uppercase">
                            {vuln.severity}
                          </Badge>
                          <Badge variant="outline" className="text-[10px]">
                            {vuln.detector}
                          </Badge>
                          <span className="text-xs text-muted-foreground font-mono">
                            {vuln.file || vuln.file_path}:{vuln.line || vuln.line_start}
                          </span>
                        </div>

                        <h3 className="font-medium text-sm mb-1">
                          [{vuln.vuln_type}] {vuln.message || vuln.description}
                        </h3>

                        {vuln.code_snippet && (
                          <pre className="mt-2 p-2 bg-muted rounded text-xs font-mono overflow-x-auto">
                            <code>{vuln.code_snippet}</code>
                          </pre>
                        )}

                        {vuln.verification ? (
                          <div className="mt-2 flex items-center gap-2">
                            <Badge
                              variant={vuln.verification.verified ? "outline" : "destructive"}
                              className={`text-[10px] ${
                                vuln.verification.verified ? "text-green-500 border-green-500/30" : ""
                              }`}
                            >
                              {vuln.verification.verified ? "已确认" : "误报"} ({Math.round(vuln.verification.confidence * 100)}%)
                            </Badge>
                            <span className="text-xs text-muted-foreground" title={vuln.verification.reasoning}>
                              {vuln.verification.reasoning}
                            </span>
                          </div>
                        ) : (
                          <Button
                            variant="outline"
                            size="sm"
                            className="mt-2 text-xs h-7"
                            onClick={(e) => {
                              e.stopPropagation()
                              handleVerifyFinding(vuln.id, vuln)
                            }}
                          >
                            LLM 验证
                          </Button>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </ScrollArea>
          )}
        </Card>

        {/* Scan Info */}
        {scanResults && (
          <div className="mt-4 text-sm text-muted-foreground">
            扫描完成于 {new Date(scanResults.scan_time).toLocaleString()}，
            共扫描 {scanResults.files_scanned} 个文件，
            发现 {scanResults.findings.length} 个问题
          </div>
        )}
      </div>
    </div>
  )
}
