import { beforeEach, describe, expect, it } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { useTenantStore } from './tenant'

describe('useTenantStore', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('starts without a tenant', () => {
    expect(useTenantStore().slug).toBeNull()
  })

  it('stores a string route param', () => {
    const store = useTenantStore()
    store.setFromParam('contoso')
    expect(store.slug).toBe('contoso')
  })

  it('clears on missing, empty or array params', () => {
    const store = useTenantStore()
    store.setFromParam('contoso')
    store.setFromParam(undefined)
    expect(store.slug).toBeNull()
    store.setFromParam('')
    expect(store.slug).toBeNull()
    store.setFromParam(['a', 'b'])
    expect(store.slug).toBeNull()
  })
})
