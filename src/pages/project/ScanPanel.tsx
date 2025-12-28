/**
 * ScanPanel - 安全扫描面板
 */

import { useState } from 'react'
import { ShieldAlert, Bug, AlertTriangle, CheckCircle, Search, RefreshCw } from 'lucide-react'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism'
import { useScanStore } from '@/stores/scanStore'
import { useProjectStore } from '@/stores/projectStore'
import { useUIStore } from '@/stores/uiStore'
import { useFileStore } from '@/stores/fileStore'
import { useToast } from '@/hooks/use-toast'
import { useToastStore } from '@/stores/toastStore'
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
  const toast = useToast()
  const { removeToast } = useToastStore()

  const [searchQuery, setSearchQuery] = useState('')
  const [severityFilter, setSeverityFilter] = useState<'all' | 'critical' | 'high' | 'medium' | 'low'>('all')

  const handleRunScan = async () => {
    if (!currentProject) {
      toast.warning('请先选择一个项目')
      return
    }

    const loadingToast = toast.loading('正在扫描代码安全问题...')

    try {
      addLog('开始扫描...', 'system')
      const result = await runScan(currentProject.path, currentProject.id)

      const findingsCount = result?.findings?.length || vulnerabilities.length
      toast.success(`扫描完成！发现 ${findingsCount} 个安全问题`)
      addLog(`扫描完成，发现 ${findingsCount} 个问题`, 'system')
    } catch (err) {
      const message = err instanceof Error ? err.message : '未知错误'
      toast.error(`扫描失败: ${message}`)
      addLog(`扫描失败: ${err}`, 'system')
    } finally {
      // 移除加载提示
      removeToast(loadingToast)
    }
  }

  const handleVerifyFinding = async (id: string, vuln: typeof vulnerabilities[0]) => {
    const loadingToast = toast.loading(`正在验证漏洞: ${vuln.vuln_type}...`)

    try {
      addLog(`验证漏洞: ${vuln.vuln_type}`, 'system')
      await verifyFinding(id, vuln)

      const verifiedVuln = vulnerabilities.find(v => v.id === id)
      if (verifiedVuln?.verification?.verified) {
        toast.success('漏洞已确认为真实问题')
      } else {
        toast.info('漏洞可能是误报')
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : '未知错误'
      toast.error(`验证失败: ${message}`)
      addLog(`验证失败: ${err}`, 'system')
    } finally {
      // 移除加载提示
      removeToast(loadingToast)
    }
  }

  const handleFindingClick = (vuln: typeof vulnerabilities[0]) => {
    const filePath = vuln.file_path
    if (filePath) {
      selectFile(filePath)
    }
  }

  const filteredVulnerabilities = vulnerabilities.filter(v => {
    const matchesSearch = searchQuery === '' ||
      v.description?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      v.vuln_type?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      v.file_path?.toLowerCase().includes(searchQuery.toLowerCase())

    const matchesSeverity = severityFilter === 'all' || v.severity === severityFilter

    return matchesSearch && matchesSeverity
  })

  // 计算当前筛选后的各严重级别数量（用于显示筛选结果）
  const filteredSeverityCount = {
    all: filteredVulnerabilities.length,
    critical: filteredVulnerabilities.filter(v => v.severity === 'critical').length,
    high: filteredVulnerabilities.filter(v => v.severity === 'high').length,
    medium: filteredVulnerabilities.filter(v => v.severity === 'medium').length,
    low: filteredVulnerabilities.filter(v => v.severity === 'low').length,
  }

  // 总数量（用于计数板显示）
  const totalCount = {
    critical: vulnerabilities.filter(v => v.severity === 'critical').length,
    high: vulnerabilities.filter(v => v.severity === 'high').length,
    medium: vulnerabilities.filter(v => v.severity === 'medium').length,
    low: vulnerabilities.filter(v => v.severity === 'low').length,
    all: vulnerabilities.length,
  }

  // 处理计数板点击，切换到对应级别的筛选
  const handleSeverityCardClick = (severity: 'all' | 'critical' | 'high' | 'medium' | 'low') => {
    if (severityFilter === severity) {
      // 如果已经选中该级别，则切换回全部
      setSeverityFilter('all')
    } else {
      setSeverityFilter(severity)
    }
  }

  // 检查计数板卡片是否处于激活状态
  const isCardActive = (severity: 'critical' | 'high' | 'medium' | 'low') => {
    return severityFilter === severity
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

  // 根据文件扩展名获取语言类型
  const getLanguageFromPath = (filePath: string): string => {
    if (!filePath) return 'text'
    const ext = filePath.split('.').pop()?.toLowerCase()
    switch (ext) {
      case 'ts': return 'typescript'
      case 'tsx': return 'typescript'
      case 'js': return 'javascript'
      case 'jsx': return 'javascript'
      case 'vue': return 'vue'
      case 'rs': return 'rust'
      case 'py': return 'python'
      case 'java': return 'java'
      case 'c': return 'c'
      case 'cpp': return 'cpp'
      case 'cc': return 'cpp'
      case 'h': return 'c'
      case 'hpp': return 'cpp'
      case 'cs': return 'csharp'
      case 'go': return 'go'
      case 'php': return 'php'
      case 'rb': return 'ruby'
      case 'sh': return 'bash'
      case 'json': return 'json'
      case 'xml': return 'xml'
      case 'yaml': return 'yaml'
      case 'yml': return 'yaml'
      case 'sql': return 'sql'
      case 'css': return 'css'
      case 'scss': return 'scss'
      case 'sass': return 'sass'
      case 'less': return 'less'
      case 'html': return 'html'
      case 'htm': return 'html'
      case 'md': return 'markdown'
      case 'mdx': return 'markdown'
      case 'toml': return 'toml'
      case 'ini': return 'ini'
      case 'conf': return 'ini'
      case 'dockerfile': return 'docker'
      case 'docker': return 'docker'
      case 'yaml': return 'yaml'
      case 'yml': return 'yaml'
      case 'txt': return 'text'
      default: return 'text'
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

        {/* Stats - 可点击的计数板 */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          <Card
            className={`p-4 cursor-pointer transition-all hover:shadow-md ${
              isCardActive('critical') ? 'ring-2 ring-red-500 bg-red-50 dark:bg-red-950/20' : ''
            }`}
            onClick={() => handleSeverityCardClick('critical')}
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">严重</p>
                <p className="text-2xl font-bold text-red-600 mt-1">{totalCount.critical}</p>
                {severityFilter === 'critical' && (
                  <p className="text-xs text-muted-foreground mt-1">已筛选</p>
                )}
              </div>
              <AlertTriangle className={`w-8 h-8 ${isCardActive('critical') ? 'text-red-600/40' : 'text-red-600/20'}`} />
            </div>
          </Card>

          <Card
            className={`p-4 cursor-pointer transition-all hover:shadow-md ${
              isCardActive('high') ? 'ring-2 ring-orange-500 bg-orange-50 dark:bg-orange-950/20' : ''
            }`}
            onClick={() => handleSeverityCardClick('high')}
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">高危</p>
                <p className="text-2xl font-bold text-orange-500 mt-1">{totalCount.high}</p>
                {severityFilter === 'high' && (
                  <p className="text-xs text-muted-foreground mt-1">已筛选</p>
                )}
              </div>
              <ShieldAlert className={`w-8 h-8 ${isCardActive('high') ? 'text-orange-500/40' : 'text-orange-500/20'}`} />
            </div>
          </Card>

          <Card
            className={`p-4 cursor-pointer transition-all hover:shadow-md ${
              isCardActive('medium') ? 'ring-2 ring-yellow-500 bg-yellow-50 dark:bg-yellow-950/20' : ''
            }`}
            onClick={() => handleSeverityCardClick('medium')}
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">中危</p>
                <p className="text-2xl font-bold text-yellow-500 mt-1">{totalCount.medium}</p>
                {severityFilter === 'medium' && (
                  <p className="text-xs text-muted-foreground mt-1">已筛选</p>
                )}
              </div>
              <Bug className={`w-8 h-8 ${isCardActive('medium') ? 'text-yellow-500/40' : 'text-yellow-500/20'}`} />
            </div>
          </Card>

          <Card
            className={`p-4 cursor-pointer transition-all hover:shadow-md ${
              isCardActive('low') ? 'ring-2 ring-blue-500 bg-blue-50 dark:bg-blue-950/20' : ''
            }`}
            onClick={() => handleSeverityCardClick('low')}
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">低危</p>
                <p className="text-2xl font-bold text-blue-500 mt-1">{totalCount.low}</p>
                {severityFilter === 'low' && (
                  <p className="text-xs text-muted-foreground mt-1">已筛选</p>
                )}
              </div>
              <CheckCircle className={`w-8 h-8 ${isCardActive('low') ? 'text-blue-500/40' : 'text-blue-500/20'}`} />
            </div>
          </Card>
        </div>

        {/* Filters */}
        <div className="flex items-center justify-between gap-4 mb-4">
          <div className="flex items-center gap-4 flex-1">
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
                  {level !== 'all' && (
                    <span className="ml-1 opacity-70">
                      ({filteredSeverityCount[level as keyof typeof filteredSeverityCount]})
                    </span>
                  )}
                </Button>
              ))}
            </div>
          </div>

          {/* 筛选结果计数 */}
          <div className="text-sm text-muted-foreground">
            显示 <span className="font-semibold text-foreground">{filteredVulnerabilities.length}</span> /
            <span className="font-semibold text-foreground"> {totalCount.all}</span> 个漏洞
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
                            {vuln.file_path}:{vuln.line_start}
                          </span>
                        </div>

                        <h3 className="font-medium text-sm mb-1">
                          [{vuln.vuln_type}] {vuln.description}
                        </h3>

                        {vuln.code_snippet && (
                          <div className="mt-2 rounded overflow-hidden text-xs">
                            <SyntaxHighlighter
                              language={getLanguageFromPath(vuln.file_path)}
                              style={vscDarkPlus}
                              customStyle={{
                                margin: 0,
                                borderRadius: '0.375rem',
                                fontSize: '0.75rem',
                                lineHeight: '1.4',
                                whiteSpace: 'pre-wrap',
                                wordBreak: 'break-word',
                              }}
                              wrapLongLines={true}
                            >
                              {vuln.code_snippet}
                            </SyntaxHighlighter>
                          </div>
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
