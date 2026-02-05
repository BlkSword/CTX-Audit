import * as React from "react"
import { cn } from "@/lib/utils"

export interface VSInputProps
  extends React.InputHTMLAttributes<HTMLInputElement> {}

const VSInput = React.forwardRef<HTMLInputElement, VSInputProps>(
  ({ className, type, ...props }, ref) => {
    return (
      <input
        type={type}
        className={cn(
          "flex w-full h-8 px-3 py-1.5",
          "bg-[var(--vscode-input-background)]",
          "text-[var(--vscode-input-foreground)]",
          "border border-[var(--vscode-input-border)]",
          "rounded-vs-sm",
          "text-vs-text-sm",
          "placeholder:text-[var(--vscode-input-placeholderForeground)]",
          "focus-visible:outline-none focus-visible:border-[var(--vscode-focusBorder)]",
          "disabled:cursor-not-allowed disabled:opacity-50",
          "vs-transition",
          className
        )}
        ref={ref}
        {...props}
      />
    )
  }
)
VSInput.displayName = "VSInput"

export { VSInput }
