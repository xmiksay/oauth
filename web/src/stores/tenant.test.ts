import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import {
  currentTenant,
  systemAdminUrl,
  tenantFromHostname,
  tenantFromMeta,
  tenantOrigin,
  useTenantStore,
} from './tenant'

/** A document whose head holds `html`. */
function docWith(html: string): Document {
  const doc = document.implementation.createHTMLDocument('t')
  doc.head.innerHTML = html
  return doc
}

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

describe('tenantFromMeta', () => {
  it('reads the server-provided tenant', () => {
    expect(tenantFromMeta(docWith('<meta name="oauth-tenant" content="prod">'))).toBe('prod')
  })

  it('is null without one', () => {
    expect(tenantFromMeta(docWith(''))).toBeNull()
    expect(tenantFromMeta(docWith('<meta name="oauth-tenant" content="">'))).toBeNull()
  })
})

describe('currentTenant', () => {
  const meta = docWith('<meta name="oauth-tenant" content="prod">')
  const none = docWith('')

  it('believes the server over the host name (the apex serving APEX_TENANT)', () => {
    expect(currentTenant(meta, 'id.example.com', '')).toBe('prod')
    expect(currentTenant(meta, 'acme.localhost', 'other')).toBe('prod')
  })

  it('falls back to the first label under the dev server', () => {
    expect(currentTenant(none, 'acme.localhost', 'prod')).toBe('acme')
  })

  it("takes the dev apex's APEX_TENANT, if any", () => {
    expect(currentTenant(none, 'localhost', 'prod')).toBe('prod')
    expect(currentTenant(none, 'localhost', '')).toBeNull()
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
    expect(systemAdminUrl({ protocol: 'http:', host: 'localhost:5173' }, 'system')).toBe(
      'http://system.localhost:5173/admin',
    )
    expect(systemAdminUrl({ protocol: 'http:', host: 'localhost:5173' }, 'config')).toBe(
      'http://config.localhost:5173/admin',
    )
  })

  it('defaults to the configured system slug', () => {
    expect(systemAdminUrl({ protocol: 'http:', host: 'localhost:5173' })).toBe(
      `http://${__SYSTEM_TENANT_SLUG__}.localhost:5173/admin`,
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
    expect(useTenantStore().slug).toBe(__APEX_TENANT__ || null)
  })

  it("prefers the server's meta", () => {
    vi.stubGlobal('location', { ...window.location, hostname: 'id.example.com' })
    const tag = document.createElement('meta')
    tag.name = 'oauth-tenant'
    tag.content = 'prod'
    document.head.append(tag)
    try {
      expect(useTenantStore().slug).toBe('prod')
    } finally {
      tag.remove()
    }
  })
})
