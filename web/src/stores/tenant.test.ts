import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { systemAdminUrl, tenantFromHostname, tenantOrigin, useTenantStore } from './tenant'

describe('tenantFromHostname', () => {
  it('takes the first label of a tenant host', () => {
    expect(tenantFromHostname('contoso.id.example.com')).toBe('contoso')
    expect(tenantFromHostname('acme.localhost')).toBe('acme')
    expect(tenantFromHostname('Contoso.ID.example.com')).toBe('contoso')
  })

  it('has no tenant on a single-label or malformed host', () => {
    expect(tenantFromHostname('localhost')).toBeNull()
    expect(tenantFromHostname('')).toBeNull()
    expect(tenantFromHostname('.localhost')).toBeNull()
    expect(tenantFromHostname('acme..localhost')).toBeNull()
  })
})

describe('tenantOrigin', () => {
  it('swaps the first label and keeps protocol and port', () => {
    const dev = { protocol: 'http:', host: 'system.localhost:5173' }
    expect(tenantOrigin('acme', dev)).toBe('http://acme.localhost:5173')
    const prod = { protocol: 'https:', host: 'system.id.example.com' }
    expect(tenantOrigin('fabrikam', prod)).toBe('https://fabrikam.id.example.com')
  })
})

describe('systemAdminUrl', () => {
  it('prefixes the dev apex with the system label', () => {
    expect(systemAdminUrl({ protocol: 'http:', host: 'localhost:5173' })).toBe(
      'http://system.localhost:5173/admin',
    )
  })
})

describe('useTenantStore', () => {
  beforeEach(() => setActivePinia(createPinia()))
  afterEach(() => vi.unstubAllGlobals())

  it('reads the tenant from the current hostname', () => {
    vi.stubGlobal('location', { ...window.location, hostname: 'acme.localhost' })
    expect(useTenantStore().slug).toBe('acme')
  })

  it('has no tenant on the dev apex', () => {
    vi.stubGlobal('location', { ...window.location, hostname: 'localhost' })
    expect(useTenantStore().slug).toBeNull()
  })
})
