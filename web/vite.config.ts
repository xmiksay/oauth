/// <reference types="vitest/config" />
import { fileURLToPath, URL } from 'node:url'
import { defineConfig, loadEnv, type ProxyOptions } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'
import { BACKEND_PROXY_PATTERN } from './dev-proxy.ts'

// `changeOrigin: false` forwards the browser's Host (`acme.localhost:5173`) untouched: the
// backend resolves the tenant from it, so dev needs PUBLIC_URL=http://localhost:5173.
const backend: ProxyOptions = { target: 'http://localhost:8080', changeOrigin: false }

export default defineConfig(({ mode }) => ({
  plugins: [vue(), tailwindcss()],
  // Only the dev apex (`localhost:5173`, served by Vite) needs the system tenant's slug, to send
  // the browser to its admin center as the server's apex does; read from the backend's `.env`.
  define: {
    __SYSTEM_TENANT_SLUG__: JSON.stringify(
      loadEnv(mode, fileURLToPath(new URL('..', import.meta.url)), 'SYSTEM_TENANT_SLUG')
        .SYSTEM_TENANT_SLUG || 'system',
    ),
  },
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  server: {
    // Tenants are subdomains (`system.localhost:5173`); `*.localhost` resolves to loopback in
    // browsers and Vite allows those hosts by default. The port must match PUBLIC_URL.
    port: 5173,
    strictPort: true,
    proxy: { [BACKEND_PROXY_PATTERN]: backend },
  },
  build: { outDir: 'dist' },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.ts', '*.test.ts'],
  },
}))
