/**
 * Toaster - 全局 Toast 容器组件
 */

import { memo } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import { useToastStore } from '@/stores/toastStore'
import { Toast } from '@/components/ui/toast'

const ToastItem = memo(({ toast, onRemove }: { toast: Parameters<typeof Toast>[0] & { id: string }, onRemove: (id: string) => void }) => (
  <motion.div
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
      onClose={() => onRemove(toast.id)}
    />
  </motion.div>
))
ToastItem.displayName = 'ToastItem'

export function Toaster() {
  const { toasts, removeToast } = useToastStore()

  return (
    <div className="fixed top-32 right-4 z-[9999] flex max-h-screen w-full flex-col-reverse gap-2 p-4 sm:max-w-[420px]">
      <AnimatePresence mode="popLayout">
        {toasts.map((toast) => (
          <ToastItem
            key={toast.id}
            toast={toast}
            onRemove={removeToast}
          />
        ))}
      </AnimatePresence>
    </div>
  )
}
