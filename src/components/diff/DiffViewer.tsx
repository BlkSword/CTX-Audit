import React from 'react'
import { FileDiff } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'

// 类型定义
interface DiffLine {
  left_line_number: number | null
  right_line_number: number | null
  diff_type: 'Equal' | 'Insert' | 'Delete' | 'Replace'
  content: string
  is_placeholder: boolean
}

interface FileStats {
  size: number
  line_count: number
  modified_time: number | null
}

interface DiffViewerProps {
  comparisonResult?: any
  onClose?: () => void
}

export const DiffViewer: React.FC<DiffViewerProps> = ({
  comparisonResult,
  onClose
}) => {
  const [selectedFileIndex, setSelectedFileIndex] = React.useState(0)

  const renderFileStats = (stats: FileStats) => (
    <div className="flex gap-4 text-xs text-muted-foreground">
      <span>大小: {formatFileSize(stats.size)}</span>
      <span>行数: {stats.line_count}</span>
      {stats.modified_time && (
        <span>修改: {new Date(stats.modified_time * 1000).toLocaleString()}</span>
      )}
    </div>
  )

  const renderDiffLine = (line: DiffLine, index: number) => {
    const getLineClass = () => {
      switch (line.diff_type) {
        case 'Equal': return 'bg-transparent'
        case 'Insert': return 'bg-green-500/10 border-l-2 border-l-green-500'
        case 'Delete': return 'bg-red-500/10 border-l-2 border-l-red-500'
        case 'Replace': return 'bg-yellow-500/10 border-l-2 border-l-yellow-500'
        default: return 'bg-transparent'
      }
    }

    const getLineNumberClass = () => {
      switch (line.diff_type) {
        case 'Insert': return 'bg-green-500/20 text-green-400'
        case 'Delete': return 'bg-red-500/20 text-red-400'
        case 'Replace': return 'bg-yellow-500/20 text-yellow-400'
        default: return 'bg-muted/50'
      }
    }

    // 使用并排视图
    return (
      <div key={index} className={`flex border-b border-border/30 ${getLineClass()}`}>
        {/* 左侧行号 */}
        <div className={`w-12 text-right px-2 text-xs font-mono ${getLineNumberClass()} border-r border-border/30`}>
          {line.left_line_number || ''}
        </div>
        {/* 右侧行号 */}
        <div className={`w-12 text-right px-2 text-xs font-mono ${getLineNumberClass()} border-r border-border/30`}>
          {line.right_line_number || ''}
        </div>
        {/* 内容 */}
        <div className="flex-1 font-mono text-sm py-0.5 px-2">
          {line.is_placeholder ? '' : line.content}
        </div>
      </div>
    )
  }

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
  }

  const getStatusBadge = (status: string) => {
    const variants: Record<string, { label: string; variant: 'default' | 'secondary' | 'destructive' | 'outline' }> = {
      'Added': { label: '新增', variant: 'default' },
      'Deleted': { label: '删除', variant: 'destructive' },
      'Modified': { label: '修改', variant: 'secondary' },
      'Renamed': { label: '重命名', variant: 'outline' },
      'Unchanged': { label: '未变更', variant: 'outline' }
    }

    const config = variants[status] || { label: status, variant: 'outline' as const }

    return (
      <Badge variant={config.variant} className="text-xs">
        {config.label}
      </Badge>
    )
  }

  return (
    <div className="h-full flex flex-col bg-background">
      {/* 顶部工具栏 */}
      <div className="border-b border-border/40 p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <FileDiff className="w-5 h-5" />
            <h2 className="text-lg font-semibold">代码差异比较</h2>
            <Badge variant="outline" className="ml-2">
              项目比较
            </Badge>
          </div>

          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={onClose}>
              关闭
            </Button>
          </div>
        </div>
      </div>

      {/* 结果显示区域 */}
      {comparisonResult && (
        <div className="flex-1 flex overflow-hidden">
          {/* 文件列表 */}
          <div className="w-80 border-r border-border/40 flex flex-col">
            <div className="p-3 border-b border-border/40">
              <h3 className="font-medium text-sm mb-2">比较摘要</h3>
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div className="flex items-center gap-1">
                  <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                  <span>新增: {comparisonResult.summary.files_added} 文件</span>
                </div>
                <div className="flex items-center gap-1">
                  <span className="w-2 h-2 bg-red-500 rounded-full"></span>
                  <span>删除: {comparisonResult.summary.files_deleted} 文件</span>
                </div>
                <div className="flex items-center gap-1">
                  <span className="w-2 h-2 bg-yellow-500 rounded-full"></span>
                  <span>修改: {comparisonResult.summary.files_modified} 文件</span>
                </div>
                <div className="flex items-center gap-1">
                  <span className="w-2 h-2 bg-blue-500 rounded-full"></span>
                  <span>重命名: {comparisonResult.summary.files_renamed} 文件</span>
                </div>
                <div className="col-span-2">
                  <span>+{comparisonResult.summary.lines_added}/-{comparisonResult.summary.lines_deleted} 行</span>
                </div>
              </div>
            </div>

            <div className="p-3 border-b border-border/40 flex-1 flex flex-col">
              <h3 className="font-medium text-sm mb-2">文件列表</h3>
              <ScrollArea className="flex-1">
                <div className="space-y-1">
                  {comparisonResult.file_diffs.map((file: any, index: number) => (
                    <div
                      key={index}
                      onClick={() => setSelectedFileIndex(index)}
                      className={`p-2 rounded cursor-pointer text-xs flex items-center justify-between ${
                        selectedFileIndex === index ? 'bg-primary/10 border border-primary/30' : 'hover:bg-muted/50'
                      }`}
                    >
                      <div className="flex items-center gap-2 flex-1 min-w-0">
                        {getStatusBadge(file.status)}
                        <span className="truncate" title={file.path}>
                          {file.path}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </div>
          </div>

          {/* 差异显示 */}
          <div className="flex-1 flex flex-col overflow-hidden">
            {comparisonResult.file_diffs[selectedFileIndex] && (
              <>
                <div className="p-3 border-b border-border/40 bg-muted/10">
                  <div className="flex items-center justify-between mb-2">
                    <h3 className="font-medium text-sm truncate">
                      {comparisonResult.file_diffs[selectedFileIndex].path}
                    </h3>
                    {getStatusBadge(comparisonResult.file_diffs[selectedFileIndex].status)}
                  </div>

                  <div className="flex justify-between text-xs text-muted-foreground">
                    <div>左侧:</div>
                    <div>{renderFileStats(comparisonResult.file_diffs[selectedFileIndex].left_stats)}</div>
                    <div>右侧:</div>
                    <div>{renderFileStats(comparisonResult.file_diffs[selectedFileIndex].right_stats)}</div>
                  </div>
                </div>

                <ScrollArea className="flex-1">
                  <div className="font-mono text-sm">
                    {comparisonResult.file_diffs[selectedFileIndex].lines.map((line: any, index: number) =>
                      renderDiffLine(line, index)
                    )}
                  </div>
                </ScrollArea>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  )
}