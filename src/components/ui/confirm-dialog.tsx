/**
 * 统一的确认对话框组件
 * 替代原生 confirm() 和 alert()
 */

import { useState, useCallback } from 'react'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { AlertCircle, Info, CheckCircle, XCircle, AlertTriangle } from 'lucide-react'
import { cn } from '@/lib/utils'

export type ConfirmDialogType = 'default' | 'destructive' | 'warning' | 'info' | 'success'

export interface ConfirmDialogOptions {
  title: string
  description?: string
  confirmText?: string
  cancelText?: string
  type?: ConfirmDialogType
}

const typeConfig = {
  default: {
    icon: AlertCircle,
    iconColor: 'text-primary',
    buttonVariant: 'default' as const,
  },
  destructive: {
    icon: XCircle,
    iconColor: 'text-destructive',
    buttonVariant: 'destructive' as const,
  },
  warning: {
    icon: AlertTriangle,
    iconColor: 'text-amber-500',
    buttonVariant: 'default' as const,
  },
  info: {
    icon: Info,
    iconColor: 'text-blue-500',
    buttonVariant: 'default' as const,
  },
  success: {
    icon: CheckCircle,
    iconColor: 'text-emerald-500',
    buttonVariant: 'default' as const,
  },
}

let currentResolve: ((value: boolean) => void) | null = null

export function ConfirmDialogComponent() {
  const [isOpen, setIsOpen] = useState(false)
  const [options, setOptions] = useState<ConfirmDialogOptions>({
    title: '',
    description: '',
    type: 'default',
  })

  const closeDialog = useCallback(() => {
    setIsOpen(false)
    if (currentResolve) {
      currentResolve(false)
      currentResolve = null
    }
  }, [])

  const confirm = useCallback(() => {
    setIsOpen(false)
    if (currentResolve) {
      currentResolve(true)
      currentResolve = null
    }
  }, [])

  // 全局监听
  useState(() => {
    ;(window as any).confirmDialog = (opts: ConfirmDialogOptions) => {
      return new Promise<boolean>((resolve) => {
        setOptions(opts)
        setIsOpen(true)
        currentResolve = resolve
      })
    }

    ;(window as any).alertDialog = (opts: ConfirmDialogOptions) => {
      return new Promise<boolean>((resolve) => {
        setOptions({ ...opts, type: 'info' })
        setIsOpen(true)
        currentResolve = () => {
          resolve(true)
          currentResolve = null
        }
      })
    }
  })

  const config = typeConfig[options.type || 'default']
  const Icon = config.icon

  return (
    <AlertDialog open={isOpen} onOpenChange={setIsOpen}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <div className="flex items-center gap-3">
            <div className={cn('p-2 rounded-lg bg-muted', config.iconColor)}>
              <Icon className="w-5 h-5" />
            </div>
            <AlertDialogTitle>{options.title}</AlertDialogTitle>
          </div>
          {options.description && (
            <AlertDialogDescription className="mt-2 ml-11">
              {options.description}
            </AlertDialogDescription>
          )}
        </AlertDialogHeader>
        <AlertDialogFooter className="ml-11">
          <AlertDialogCancel onClick={closeDialog}>
            {options.cancelText || '取消'}
          </AlertDialogCancel>
          <AlertDialogAction
            onClick={confirm}
            className={cn(
              options.type === 'destructive' && 'bg-destructive text-destructive-foreground hover:bg-destructive/90'
            )}
          >
            {options.confirmText || '确定'}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}

// 导出便捷函数
export const confirmDialog = (options: ConfirmDialogOptions): Promise<boolean> => {
  return (window as any).confirmDialog(options)
}

export const alertDialog = (options: ConfirmDialogOptions): Promise<boolean> => {
  return (window as any).alertDialog(options)
}

// 使用示例:
// import { confirmDialog } from '@/components/ui/confirm-dialog'
//
// const result = await confirmDialog({
//   title: '删除项目',
//   description: '确定要删除此项目吗？此操作不可恢复。',
//   confirmText: '删除',
//   cancelText: '取消',
//   type: 'destructive'
// })
