import { describe, expect, it } from 'vitest'
import { isProxied } from './dev-proxy.ts'

describe('dev proxy matcher', () => {
  it.each([
    '/api/v1/x',
    '/api',
    '/api/authn/tx/x/password',
    '/oauth2/token',
    '/.well-known/openid-configuration',
    '/discovery/keys',
  ])('proxies %s', (path) => {
    expect(isProxied(path)).toBe(true)
  })

  it.each([
    '/src/api/client.ts',
    '/node_modules/foo/api/x.js',
    '/@fs/home/x/api/y.ts',
    '/@id/api/x',
    '/@vite/client',
    '/apix',
    '/admin/users',
    '/login',
    '/contoso/oauth2/token',
  ])('does not proxy %s', (path) => {
    expect(isProxied(path)).toBe(false)
  })
})
