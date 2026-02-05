/**
 * Tauri 全局类型声明
 */

declare global {
  interface Window {
    __TAURI__?: unknown
  }
}

export {}
