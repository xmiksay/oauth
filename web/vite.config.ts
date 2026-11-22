/// <reference types="vitest/config" />
import { fileURLToPath, URL } from 'node:url'
import { defineConfig, loadEnv, type ProxyOptions } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'
import { BACKEND_PROXY_PATTERN } from './dev-proxy.ts'

// `changeOrigin: false` forwards the browser's Host (`acme.localhost:5173`) untouched: the
// backend resolves the tenant from it, so dev needs PUBLIC_URL=http://localhost:5173.
const backend: ProxyOptions = { target: 'http://localhost:8080', changeOrigin: false }

// Only the dev apex (`localhost:5173`, served by Vite, so without the server's tenant `<meta>`)
// needs these: the system tenant's slug, to send the browser to its admin center as the
// server's apex does, or the `APEX_TENANT` it serves instead. Read from the backend's `.env`,
// trimmed like the server does. A malformed slug, or an `APEX_TENANT` naming the system tenant,
// fails here too, loudly; whether the tenant exists, is enabled or reserved only the server knows.
function tenantSlug(mode: string, key: string, fallback: string): string {
  const env = loadEnv(mode, fileURLToPath(new URL('..', import.meta.url)), key)
  const slug = (env[key] ?? '').trim() || fallback
  if (slug && !/^[a-z0-9][a-z0-9-]{1,62}$/.test(slug)) {
    throw new Error(`${key} \`${slug}\` is not a valid tenant slug`)
  }
  return slug
}

function tenantDefines(mode: string): Record<string, string> {
  const system = tenantSlug(mode, 'SYSTEM_TENANT_SLUG', 'system')
  const apex = tenantSlug(mode, 'APEX_TENANT', '')
  if (apex === system) {
    throw new Error(`APEX_TENANT \`${apex}\` is the system tenant, which the apex cannot serve`)
  }
  return { __SYSTEM_TENANT_SLUG__: JSON.stringify(system), __APEX_TENANT__: JSON.stringify(apex) }
}

export default defineConfig(({ mode }) => ({
  plugins: [vue(), tailwindcss()],
  define: tenantDefines(mode),
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
