import * as React from "react"
import { cn } from "@/lib/utils"

const VSCard = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => (
  <div
    ref={ref}
    className={cn(
      "rounded-vs-md border border-[var(--vscode-widget-border)]",
      "bg-[var(--vscode-editor-background)]",
      "text-[var(--vscode-editor-foreground)]",
      "shadow-[0_2px_8px_var(--vscode-widget-shadow)]",
      className
    )}
    {...props}
  />
))
VSCard.displayName = "VSCard"

const VSCardHeader = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => (
  <div
    ref={ref}
    className={cn("flex flex-col space-y-1.5 p-vs-lg", className)}
    {...props}
  />
))
VSCardHeader.displayName = "VSCardHeader"

const VSCardTitle = React.forwardRef<
  HTMLHeadingElement,
  React.HTMLAttributes<HTMLHeadingElement>
>(({ className, ...props }, ref) => (
  <h3
    ref={ref}
    className={cn(
      "text-vs-text-lg vs-font-semibold leading-none",
      "text-[var(--vscode-editor-foreground)]",
      className
    )}
    {...props}
  />
))
VSCardTitle.displayName = "VSCardTitle"

const VSCardDescription = React.forwardRef<
  HTMLParagraphElement,
  React.HTMLAttributes<HTMLParagraphElement>
>(({ className, ...props }, ref) => (
  <p
    ref={ref}
    className={cn(
      "text-vs-text-sm",
      "text-[var(--vscode-descriptionForeground)]",
      className
    )}
    {...props}
  />
))
VSCardDescription.displayName = "VSCardDescription"

const VSCardContent = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => (
  <div ref={ref} className={cn("p-vs-lg pt-0", className)} {...props} />
))
VSCardContent.displayName = "VSCardContent"

const VSCardFooter = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => (
  <div
    ref={ref}
    className={cn("flex items-center p-vs-lg pt-0", className)}
    {...props}
  />
))
VSCardFooter.displayName = "VSCardFooter"

export { VSCard, VSCardHeader, VSCardTitle, VSCardDescription, VSCardContent, VSCardFooter }
