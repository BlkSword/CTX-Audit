/**
 * useToast Hook - 便捷的 Toast 调用接口
 */

import { useToastStore } from '@/stores/toastStore'

export function useToast() {
  const { addToast, removeToast, clearAll } = useToastStore()

  return {
    /** 显示成功提示 */
    success: (description: string, options?: { title?: string; duration?: number }) => {
      return addToast({
        type: 'success',
        title: options?.title || '成功',
        description,
        duration: options?.duration,
      })
    },

    /** 显示错误提示 */
    error: (description: string, options?: { title?: string; duration?: number }) => {
      return addToast({
        type: 'error',
        title: options?.title || '错误',
        description,
        duration: options?.duration || 5000,
      })
    },

    /** 显示信息提示 */
    info: (description: string, options?: { title?: string; duration?: number }) => {
      return addToast({
        type: 'info',
        title: options?.title || '提示',
        description,
        duration: options?.duration,
      })
    },

    /** 显示警告提示 */
    warning: (description: string, options?: { title?: string; duration?: number }) => {
      return addToast({
        type: 'warning',
        title: options?.title || '警告',
        description,
        duration: options?.duration,
      })
    },

    /** 显示加载提示 */
    loading: (description: string, options?: { title?: string }) => {
      return addToast({
        type: 'loading',
        title: options?.title,
        description,
        duration: 0, // loading 类型的 toast 不会自动消失
      })
    },

    /** 显示带操作的提示 */
    promise: <T,>(
      promise: Promise<T>,
      {
        loading,
        success,
        error,
      }: {
        loading: string
        success: string | ((data: T) => string)
        error: string | ((err: unknown) => string)
      }
    ) => {
      const id = addToast({
        type: 'loading',
        description: loading,
      })

      promise
        .then((data) => {
          removeToast(id)
          addToast({
            type: 'success',
            description: typeof success === 'function' ? success(data) : success,
          })
        })
        .catch((err) => {
          removeToast(id)
          addToast({
            type: 'error',
            description: typeof error === 'function' ? error(err) : error,
          })
        })

      return id
    },

    /** 手动移除指定的 toast */
    dismiss: (id: string) => {
      removeToast(id)
    },

    /** 清空所有 toast */
    clear: () => {
      clearAll()
    },
  }
}
