import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { viteSingleFile } from 'vite-plugin-singlefile'
import path from 'path'

export default defineConfig({
  plugins: [react(), tailwindcss(), viteSingleFile()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    // Proxy /api/* to zgrnetd during development.
    // Requires zgrnetd to be running (sudo zgrnetd -c default).
    proxy: {
      '/api': {
        target: 'http://100.64.0.1',
        changeOrigin: true,
      },
      '/internal': {
        target: 'http://100.64.0.1',
        changeOrigin: true,
      },
    },
  },
})
