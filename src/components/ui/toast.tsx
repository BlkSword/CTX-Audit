import * as React from "react"
import { cva } from "class-variance-authority"
import { X } from "lucide-react"
import { cn } from "@/lib/utils"
import { type ToastType } from "@/stores/toastStore"

const toastVariants = cva(
  "group pointer-events-auto relative flex w-full items-center justify-between space-x-4 overflow-hidden rounded-md border p-4 pr-8 shadow-lg transition-all data-[swipe=cancel]:translate-x-0 data-[swipe=end]:translate-x-[var(--radix-toast-swipe-end-x)] data-[swipe=move]:translate-x-[var(--radix-toast-swipe-move-x)] data-[swipe=move]:transition-none data-[state=open]:animate-in data-[state=closed]:animate-out data-[swipe=end]:animate-out data-[state=closed]:fade-out-80 data-[state=closed]:slide-out-to-right-full data-[state=open]:slide-in-from-top-full data-[state=open]:sm:slide-in-from-bottom-full",
  {
    variants: {
      variant: {
        success: "border-green-200 bg-green-50 text-green-900 dark:border-green-900 dark:bg-green-950 dark:text-green-50",
        error: "border-red-200 bg-red-50 text-red-900 dark:border-red-900 dark:bg-red-950 dark:text-red-50",
        warning: "border-yellow-200 bg-yellow-50 text-yellow-900 dark:border-yellow-900 dark:bg-yellow-950 dark:text-yellow-50",
        info: "border-blue-200 bg-blue-50 text-blue-900 dark:border-blue-900 dark:bg-blue-950 dark:text-blue-50",
        loading: "border-gray-200 bg-gray-50 text-gray-900 dark:border-gray-900 dark:bg-gray-950 dark:text-gray-50",
      },
    },
    defaultVariants: {
      variant: "info",
    },
  }
)

export interface ToastProps extends React.HTMLAttributes<HTMLDivElement> {
  type?: ToastType
  title?: string
  description: string
  onClose?: () => void
  action?: {
    label: string
    onClick: () => void
  }
}

const Toast = React.forwardRef<HTMLDivElement, ToastProps>(
  ({ className, type = "info", title, description, onClose, action, ...props }, ref) => {
    // 获取对应的图标
    const getIcon = () => {
      switch (type) {
        case 'success':
          return (
            <svg className="h-5 w-5 text-green-600 dark:text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
            </svg>
          )
        case 'error':
          return (
            <svg className="h-5 w-5 text-red-600 dark:text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          )
        case 'warning':
          return (
            <svg className="h-5 w-5 text-yellow-600 dark:text-yellow-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          )
        case 'loading':
          return (
            <svg className="h-5 w-5 animate-spin text-gray-600 dark:text-gray-400" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
          )
        default:
          return (
            <svg className="h-5 w-5 text-blue-600 dark:text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          )
      }
    }

    return (
      <div
        ref={ref}
        className={cn(toastVariants({ variant: type }), className)}
        {...props}
      >
        <div className="flex gap-3">
          <div className="flex-shrink-0">{getIcon()}</div>
          <div className="flex-1 space-y-1">
            {title && <p className="text-sm font-semibold">{title}</p>}
            <p className="text-sm opacity-90">{description}</p>
            {action && (
              <button
                onClick={action.onClick}
                className="mt-2 text-sm font-medium underline underline-offset-2 hover:no-underline"
              >
                {action.label}
              </button>
            )}
          </div>
        </div>
        {onClose && (
          <button
            onClick={onClose}
            className="absolute right-2 top-2 rounded-md p-1 text-foreground/50 opacity-0 transition-opacity hover:text-foreground focus:opacity-100 focus:outline-none group-hover:opacity-100"
          >
            <X className="h-4 w-4" />
          </button>
        )}
      </div>
    )
  }
)
Toast.displayName = "Toast"

export { Toast, toastVariants }
