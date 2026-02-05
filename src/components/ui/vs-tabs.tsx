import * as React from 'react'
import * as TabsPrimitives from '@radix-ui/react-tabs'
import { cn } from '@/lib/utils'

const VSTabs = TabsPrimitives.Root

const VSTabsList = React.forwardRef<
  React.ElementRef<typeof TabsPrimitives.List>,
  React.ComponentPropsWithoutRef<typeof TabsPrimitives.List>
>(({ className, ...props }, ref) => (
  <TabsPrimitives.List
    ref={ref}
    className={cn(
      "inline-flex items-center h-[35px]",
      "bg-[var(--vscode-editorGroupHeader-tabsBackground)]",
      "border-b border-[var(--vscode-editorGroup-border)]",
      className
    )}
    {...props}
  />
))
VSTabsList.displayName = TabsPrimitives.List.displayName

const VSTabsTrigger = React.forwardRef<
  React.ElementRef<typeof TabsPrimitives.Trigger>,
  React.ComponentPropsWithoutRef<typeof TabsPrimitives.Trigger>
>(({ className, ...props }, ref) => (
  <TabsPrimitives.Trigger
    ref={ref}
    className={cn(
      "inline-flex items-center justify-center whitespace-nowrap",
      "px-3 h-full vs-transition",
      "text-vs-text-sm vs-font-semibold",
      "text-[var(--vscode-activityBar-inactiveForeground)]",
      "hover:text-[var(--vscode-editor-foreground)]",
      "hover:bg-[var(--vscode-toolbar-hoverBackground)]",
      "border-r border-[var(--vscode-sideBar-border)]",
      "data-[state=active]:bg-[var(--vscode-tab-activeBackground)]",
      "data-[state=active]:text-[var(--vscode-editor-foreground)]",
      "focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[var(--vscode-focusBorder)]",
      "disabled:pointer-events-none disabled:opacity-50",
      className
    )}
    {...props}
  />
))
VSTabsTrigger.displayName = TabsPrimitives.Trigger.displayName

const VSTabsContent = React.forwardRef<
  React.ElementRef<typeof TabsPrimitives.Content>,
  React.ComponentPropsWithoutRef<typeof TabsPrimitives.Content>
>(({ className, ...props }, ref) => (
  <TabsPrimitives.Content
    ref={ref}
    className={cn(
      "mt-0 focus-visible:outline-none",
      "bg-[var(--vscode-editor-background)]",
      "text-[var(--vscode-editor-foreground)]",
      className
    )}
    {...props}
  />
))
VSTabsContent.displayName = TabsPrimitives.Content.displayName

export { VSTabs, VSTabsList, VSTabsTrigger, VSTabsContent }
