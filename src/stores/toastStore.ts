/**
 * Toast 状态管理
 */

import { create } from 'zustand'
import { devtools } from 'zustand/middleware'

export type ToastType = 'success' | 'error' | 'info' | 'warning' | 'loading'

export interface Toast {
  id: string
  title?: string
  description: string
  type?: ToastType
  duration?: number
  action?: {
    label: string
    onClick: () => void
  }
}

interface ToastState {
  toasts: Toast[]
  addToast: (toast: Omit<Toast, 'id'>) => string
  removeToast: (id: string) => void
  clearAll: () => void
}

// 生成唯一 ID
let toastId = 0
function generateId(): string {
  return `toast-${++toastId}`
}

export const useToastStore = create<ToastState>()(
  devtools(
    (set, get) => ({
      toasts: [],

      addToast: (toast) => {
        const id = generateId()
        const newToast: Toast = {
          id,
          type: toast.type || 'info',
          title: toast.title,
          description: toast.description,
          action: toast.action,
          duration: toast.duration ?? 3000, // 使用 ?? 而不是默认值展开
        }

        set((state) => ({
          toasts: [...state.toasts, newToast],
        }))

        // 自动移除 toast（loading 类型除外）
        if (newToast.type !== 'loading' && newToast.duration && newToast.duration > 0) {
          setTimeout(() => {
            get().removeToast(id)
          }, newToast.duration)
        }

        return id
      },

      removeToast: (id) => {
        set((state) => ({
          toasts: state.toasts.filter((t) => t.id !== id),
        }))
      },

      clearAll: () => {
        set({ toasts: [] })
      },
    }),
    { name: 'toast-store' }
  )
)
