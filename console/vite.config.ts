import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The console is served by `server/index.mjs` standalone (root) and by the DSH
// host plugin under `/console`. A relative base keeps asset URLs working under
// both mounts; the API base is derived at runtime in src/api.ts.
export default defineConfig({
  base: './',
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
