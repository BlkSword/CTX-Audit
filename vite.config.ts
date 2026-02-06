import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => ({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  // Worker 配置，支持 Monaco Editor
  worker: {
    format: 'es',
  },
  base: '/',
  clearScreen: false,
  server: {
    port: 3002,
    strictPort: false,
    host: '127.0.0.1',
  },
  envPrefix: ['VITE_'],
  build: {
    outDir: 'dist',
    sourcemap: mode === 'development',
    minify: 'esbuild',
    target: 'esnext',
    rollupOptions: {
      output: {
        manualChunks: (id) => {
          // Vendor chunks
          if (id.includes('node_modules')) {
            // React core
            if (id.includes('react') || id.includes('react-dom')) {
              return 'react-core'
            }
            // Radix UI
            if (id.includes('@radix-ui')) {
              return 'ui'
            }
            // Router
            if (id.includes('react-router')) {
              return 'router'
            }
            // Editor
            if (id.includes('monaco-editor')) {
              return 'editor'
            }
            // Graph
            if (id.includes('reactflow')) {
              return 'graph'
            }
            // State management
            if (id.includes('zustand')) {
              return 'state'
            }
            // Other vendor
            return 'vendor'
          }
        },
        // 资源文件命名
        chunkFileNames: 'assets/js/[name]-[hash].js',
        entryFileNames: 'assets/js/[name]-[hash].js',
        assetFileNames: 'assets/[ext]/[name]-[hash].[ext]',
      },
    },
    // 优化配置
    chunkSizeWarningLimit: 1000,
    // CSS 代码分割
    cssCodeSplit: true,
  },
  // 优化依赖预构建
  optimizeDeps: {
    include: [
      'react',
      'react-dom',
      'react-router-dom',
      'zustand',
      '@radix-ui/react-dialog',
      '@radix-ui/react-select',
      '@radix-ui/react-tabs',
    ],
  },
}))
