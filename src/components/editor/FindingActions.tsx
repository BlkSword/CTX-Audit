/**
 * FindingActions - 漏洞操作菜单
 *
 * 提供右键菜单显示漏洞操作选项
 */

import type { Vulnerability } from '@/shared/types/agent'
import {
  CheckCircle,
  XCircle,
  EyeOff,
  ShieldCheck,
  Copy,
  Trash2,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'

export interface FindingActionsProps {
  finding: Vulnerability
  onMarkAsFixed: (findingId: string) => Promise<void>
  onMarkAsFalsePositive: (findingId: string) => Promise<void>
  onMarkAsIgnored: (findingId: string) => Promise<void>
  onMarkAsVerified: (findingId: string) => Promise<void>
  onCopy?: (finding: Vulnerability) => void
  onDelete?: (findingId: string) => Promise<void>
  trigger?: React.ReactNode
}

export function FindingActions({
  finding,
  onMarkAsFixed,
  onMarkAsFalsePositive,
  onMarkAsIgnored,
  onMarkAsVerified,
  onCopy,
  onDelete,
  trigger,
}: FindingActionsProps) {
  const statusLabels = {
    new: '新发现',
    verified: '已验证',
    fixed: '已修复',
    false_positive: '误报',
    ignored: '已忽略',
  }

  const statusIcons = {
    new: null,
    verified: <ShieldCheck className="w-4 h-4 text-green-500" />,
    fixed: <CheckCircle className="w-4 h-4 text-gray-500" />,
    false_positive: <XCircle className="w-4 h-4 text-gray-500" />,
    ignored: <EyeOff className="w-4 h-4 text-gray-500" />,
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        {trigger || (
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6 p-0"
          >
            <svg
              className="w-4 h-4"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <circle cx="12" cy="12" r="1" />
              <circle cx="12" cy="5" r="1" />
              <circle cx="12" cy="19" r="1" />
            </svg>
          </Button>
        )}
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-48">
        {/* 当前状态 */}
        <div className="flex items-center gap-2 px-2 py-1.5 border-b border-border/40">
          {statusIcons[finding.status || 'new']}
          <span className="text-sm">{statusLabels[finding.status || 'new']}</span>
        </div>

        {/* 状态操作 */}
        <DropdownMenuSub>
          <DropdownMenuSubTrigger>
            <ShieldCheck className="w-4 h-4 mr-2" />
            <span>标记状态</span>
          </DropdownMenuSubTrigger>
          <DropdownMenuSubContent>
            <DropdownMenuItem
              onClick={() => onMarkAsVerified(finding.id)}
              disabled={finding.status === 'verified'}
            >
              <CheckCircle className="w-4 h-4 mr-2 text-green-500" />
              <span>已验证</span>
            </DropdownMenuItem>
            <DropdownMenuItem
              onClick={() => onMarkAsFixed(finding.id)}
              disabled={finding.status === 'fixed'}
            >
              <CheckCircle className="w-4 h-4 mr-2 text-blue-500" />
              <span>已修复</span>
            </DropdownMenuItem>
            <DropdownMenuItem
              onClick={() => onMarkAsFalsePositive(finding.id)}
              disabled={finding.status === 'false_positive'}
            >
              <XCircle className="w-4 h-4 mr-2 text-orange-500" />
              <span>误报</span>
            </DropdownMenuItem>
            <DropdownMenuItem
              onClick={() => onMarkAsIgnored(finding.id)}
              disabled={finding.status === 'ignored'}
            >
              <EyeOff className="w-4 h-4 mr-2 text-gray-500" />
              <span>忽略</span>
            </DropdownMenuItem>
          </DropdownMenuSubContent>
        </DropdownMenuSub>

        <DropdownMenuSeparator />

        {/* 快速操作 */}
        <DropdownMenuItem onClick={() => onCopy?.(finding)}>
          <Copy className="w-4 h-4 mr-2" />
          <span>复制漏洞信息</span>
        </DropdownMenuItem>

        {onDelete && (
          <DropdownMenuItem
            onClick={() => onDelete(finding.id)}
            className="text-red-500 focus:text-red-500"
          >
            <Trash2 className="w-4 h-4 mr-2" />
            <span>删除</span>
          </DropdownMenuItem>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

/**
 * FindingContextMenu - 右键上下文菜单版本
 */
export interface FindingContextMenuProps extends Omit<FindingActionsProps, 'trigger'> {
  children: React.ReactNode
}

export function FindingContextMenu({
  children,
  ...props
}: FindingContextMenuProps) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>{children}</DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-48">
        <FindingActionsContent {...props} />
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

/**
 * FindingActionsContent - 菜单内容（可复用）
 */
function FindingActionsContent({
  finding,
  onMarkAsFixed,
  onMarkAsFalsePositive,
  onMarkAsIgnored,
  onMarkAsVerified,
  onCopy,
  onDelete,
}: Omit<FindingActionsProps, 'trigger'>) {
  return (
    <>
      {/* 状态操作 */}
      <DropdownMenuSub>
        <DropdownMenuSubTrigger>
          <ShieldCheck className="w-4 h-4 mr-2" />
          <span>标记状态</span>
        </DropdownMenuSubTrigger>
        <DropdownMenuSubContent>
          <DropdownMenuItem onClick={() => onMarkAsVerified(finding.id)}>
            <CheckCircle className="w-4 h-4 mr-2 text-green-500" />
            <span>已验证</span>
          </DropdownMenuItem>
          <DropdownMenuItem onClick={() => onMarkAsFixed(finding.id)}>
            <CheckCircle className="w-4 h-4 mr-2 text-blue-500" />
            <span>已修复</span>
          </DropdownMenuItem>
          <DropdownMenuItem onClick={() => onMarkAsFalsePositive(finding.id)}>
            <XCircle className="w-4 h-4 mr-2 text-orange-500" />
            <span>误报</span>
          </DropdownMenuItem>
          <DropdownMenuItem onClick={() => onMarkAsIgnored(finding.id)}>
            <EyeOff className="w-4 h-4 mr-2 text-gray-500" />
            <span>忽略</span>
          </DropdownMenuItem>
        </DropdownMenuSubContent>
      </DropdownMenuSub>

      <DropdownMenuSeparator />

      {/* 快速操作 */}
      <DropdownMenuItem onClick={() => onCopy?.(finding)}>
        <Copy className="w-4 h-4 mr-2" />
        <span>复制漏洞信息</span>
      </DropdownMenuItem>

      {onDelete && (
        <DropdownMenuItem
          onClick={() => onDelete(finding.id)}
          className="text-red-500 focus:text-red-500"
        >
          <Trash2 className="w-4 h-4 mr-2" />
          <span>删除</span>
        </DropdownMenuItem>
      )}
    </>
  )
}
