/// <reference types="vitest/config" />
import { fileURLToPath, URL } from 'node:url'
import { defineConfig, loadEnv, type ProxyOptions } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'
import { BACKEND_PROXY_PATTERN } from './dev-proxy.ts'
import { tenantDefines } from './tenant-defines.ts'

// `changeOrigin: false` forwards the browser's Host (`acme.localhost:5173`) untouched: the
// backend resolves the tenant from it, so dev needs PUBLIC_URL=http://localhost:5173.
const backend: ProxyOptions = { target: 'http://localhost:8080', changeOrigin: false }

export default defineConfig(({ command, mode }) => ({
  plugins: [vue(), tailwindcss()],
  // The backend's `.env` reaches only the dev server; builds and vitest (whose command is also
  // `serve`) get fixed values, so a developer's `.env` can't change test results or break a build.
  define: tenantDefines(command === 'serve' && !process.env.VITEST, (key) => {
    const root = fileURLToPath(new URL('..', import.meta.url))
    return loadEnv(mode, root, key)[key]
  }),
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
