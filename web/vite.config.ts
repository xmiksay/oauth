/// <reference types="vitest/config" />
import { fileURLToPath, URL } from 'node:url'
import { defineConfig, type ProxyOptions } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'
import { PROXY_PATTERNS } from './dev-proxy.ts'

const backend: ProxyOptions = { target: 'http://localhost:8080', changeOrigin: false }

export default defineConfig({
  plugins: [vue(), tailwindcss()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  server: {
    proxy: Object.fromEntries(PROXY_PATTERNS.map((p) => [p, backend])),
  },
  build: { outDir: 'dist' },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.ts', '*.test.ts'],
  },
})
