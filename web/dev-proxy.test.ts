import { describe, expect, it } from 'vitest'
import { isProxied } from './dev-proxy.ts'

describe('dev proxy matcher', () => {
  it.each([
    '/api/v1/x',
    '/api',
    '/contoso/api/authn',
    '/contoso/oauth2/token',
    '/contoso/.well-known/openid-configuration',
    '/contoso/discovery/keys',
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
    '/contoso/admin/users',
    '/contoso/apix',
  ])('does not proxy %s', (path) => {
    expect(isProxied(path)).toBe(false)
  })
})
