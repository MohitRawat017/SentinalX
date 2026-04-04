import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const browserGlobal = 'globalThis'

export default defineConfig({
  define: {
    global: browserGlobal,
  },
  plugins: [react()],
  resolve: {
    alias: {
      buffer: 'buffer/',
    },
  },
  optimizeDeps: {
    include: ['@perawallet/connect', 'buffer'],
    esbuildOptions: {
      define: {
        global: browserGlobal,
      },
    },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes('node_modules')) {
            return;
          }

          if (id.includes('react-router')) {
            return 'router';
          }

          if (id.includes('recharts') || id.includes('d3-')) {
            return 'charts';
          }

          if (id.includes('leaflet')) {
            return 'maps';
          }

          if (id.includes('react-markdown') || id.includes('remark-') || id.includes('micromark')) {
            return 'markdown';
          }

          if (id.includes('react') || id.includes('scheduler')) {
            return 'react-vendor';
          }
        },
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
})
