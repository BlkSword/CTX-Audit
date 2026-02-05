import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const vsButtonVariants = cva(
  cn(
    "inline-flex items-center justify-center whitespace-nowrap",
    "transition-colors duration-150",
    "focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[var(--vscode-focusBorder)]",
    "disabled:pointer-events-none disabled:opacity-50",
    "rounded-vs-sm",
    "text-vs-text-sm",
    "vs-font-semibold"
  ),
  {
    variants: {
      variant: {
        primary: cn(
          "bg-[var(--vscode-button-background)]",
          "text-[var(--vscode-button-foreground)]",
          "hover:bg-[var(--vscode-button-hoverBackground)]",
          "border border-transparent"
        ),
        secondary: cn(
          "bg-[var(--vscode-button-secondaryBackground)]",
          "text-[var(--vscode-button-secondaryForeground)]",
          "hover:bg-[var(--vscode-button-secondaryHoverBackground)]",
          "border border-transparent"
        ),
        outline: cn(
          "border border-[var(--vscode-input-border)]",
          "bg-[var(--vscode-editor-background)]",
          "text-[var(--vscode-editor-foreground)]",
          "hover:bg-[var(--vscode-toolbar-hoverBackground)]"
        ),
        ghost: cn(
          "bg-transparent",
          "text-[var(--vscode-editor-foreground)]",
          "hover:bg-[var(--vscode-toolbar-hoverBackground)]",
          "border border-transparent"
        ),
        link: cn(
          "bg-transparent",
          "text-[var(--vscode-textLink-foreground)]",
          "hover:underline",
          "border-0",
          "p-0 h-auto"
        ),
        destructive: cn(
          "bg-[var(--vscode-errorBackground)]",
          "text-[var(--vscode-errorForeground)]",
          "hover:bg-[var(--vscode-errorForeground)] hover:text-[var(--vscode-editor-background)]",
          "border border-transparent"
        ),
      },
      size: {
        sm: cn("h-6 px-2", "text-vs-text-xs"),
        md: cn("h-8 px-3", "text-vs-text-sm"),
        lg: cn("h-10 px-4", "text-vs-text-base"),
        icon: cn("h-8 w-8 p-0"),
      },
    },
    defaultVariants: { variant: "primary", size: "md" },
  }
)

export interface VSButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof vsButtonVariants> {
  asChild?: boolean
}

const VSButton = React.forwardRef<HTMLButtonElement, VSButtonProps>(
  ({ className, variant, size, ...props }, ref) => {
    return (
      <button
        className={cn(vsButtonVariants({ variant, size, className }))}
        ref={ref}
        {...props}
      />
    )
  }
)
VSButton.displayName = "VSButton"

export { VSButton, vsButtonVariants }
