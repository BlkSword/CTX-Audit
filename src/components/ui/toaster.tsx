/**
 * Toaster - 全局 Toast 容器组件
 */

import { useEffect } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import { useToastStore } from '@/stores/toastStore'
import { Toast } from '@/components/ui/toast'

export function Toaster() {
  const { toasts, removeToast } = useToastStore()

  // 监听 toasts 变化，自动滚动到顶部
  useEffect(() => {
    if (toasts.length > 0) {
      // 可以在这里添加滚动逻辑
    }
  }, [toasts])

  return (
    <div className="fixed top-4 right-4 z-[9999] flex max-h-screen w-full flex-col-reverse gap-2 p-4 sm:max-w-[420px]">
      <AnimatePresence mode="popLayout">
        {toasts.map((toast) => (
          <motion.div
            key={toast.id}
            initial={{ opacity: 0, x: 100, scale: 0.9 }}
            animate={{ opacity: 1, x: 0, scale: 1 }}
            exit={{ opacity: 0, x: 100, scale: 0.9 }}
            transition={{
              type: 'spring',
              stiffness: 300,
              damping: 30,
            }}
            layout
          >
            <Toast
              type={toast.type}
              title={toast.title}
              description={toast.description}
              action={toast.action}
              onClose={() => removeToast(toast.id)}
            />
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  )
}
