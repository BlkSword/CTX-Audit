/**
 * AuditModeToggle - 审计模式切换组件
 *
 * 切换自动/手动审计模式，显示当前审计状态
 */

import { useRealtimeAuditStore } from '@/stores/realTimeAuditStore'
import { Switch } from '@/components/ui/switch'
import { Label } from '@/components/ui/label'
import { Scan, CheckCircle, AlertCircle } from 'lucide-react'

export function AuditModeToggle() {
  const { autoMode, setAutoMode, scanningFiles, scanQueue } = useRealtimeAuditStore()

  const scanningCount = scanningFiles.size
  const queueCount = scanQueue.size

  return (
    <div className="flex items-center gap-3 px-3 py-2 bg-[#252526] border-b border-border/40">
      {/* 模式切换 */}
      <div className="flex items-center gap-2">
        <Switch
          id="audit-mode"
          checked={autoMode}
          onCheckedChange={setAutoMode}
          className="data-[state=checked]:bg-[#007acc]"
        />
        <Label
          htmlFor="audit-mode"
          className="text-xs text-muted-foreground cursor-pointer"
        >
          {autoMode ? '自动审计' : '手动审计'}
        </Label>
      </div>

      {/* 状态指示 */}
      <div className="flex items-center gap-2 ml-auto">
        {scanningCount > 0 ? (
          <div className="flex items-center gap-1.5 text-xs text-[#007acc]">
            <Scan className="w-3.5 h-3.5 animate-spin" />
            <span>扫描中 ({scanningCount})</span>
          </div>
        ) : queueCount > 0 ? (
          <div className="flex items-center gap-1.5 text-xs text-yellow-500">
            <AlertCircle className="w-3.5 h-3.5" />
            <span>队列中 ({queueCount})</span>
          </div>
        ) : (
          <div className="flex items-center gap-1.5 text-xs text-green-500">
            <CheckCircle className="w-3.5 h-3.5" />
            <span>就绪</span>
          </div>
        )}
      </div>
    </div>
  )
}
