import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The console is served by `server/index.mjs` in production; during development
// Vite proxies the API to that server so the SPA and the API share an origin.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 4318,
    proxy: {
      '/api': 'http://127.0.0.1:4317',
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    chunkSizeWarningLimit: 1200,
  },
})
