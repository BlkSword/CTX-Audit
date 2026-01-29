import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './index.css'
import { ErrorBoundary } from './components/ErrorBoundary'

document.documentElement.classList.add('dark');

// 清除旧的布局状态（迁移到新的 FlexLayout 系统）
const oldLayoutKeys = [
  'ctx-audit-layout',
  'ctx-audit-layout-persist',
  'ctx-audit-layout-v2',
  'ctx-audit-layout-v3',
]
oldLayoutKeys.forEach(key => {
  try {
    localStorage.removeItem(key)
  } catch (e) {
    console.warn('Failed to remove old layout key:', key, e)
  }
})

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
    <React.StrictMode>
        <ErrorBoundary>
            <App />
        </ErrorBoundary>
    </React.StrictMode>,
)
