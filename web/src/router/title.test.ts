import { describe, expect, it } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { pageTitle, router } from './index'

setActivePinia(createPinia())

describe('pageTitle', () => {
  it('names the page, the area and the tenant', () => {
    const title = (path: string) => pageTitle(router.resolve(path), 'contoso')
    expect(title('/admin/users')).toBe('Users · Admin center · contoso')
    expect(title('/myaccount/security')).toBe('Security info · My Account · contoso')
    expect(title('/admin/app-registrations/x/secrets')).toBe(
      'App registration · Admin center · contoso',
    )
    expect(title('/login')).toBe('Sign in · contoso')
    expect(pageTitle(router.resolve('/nowhere'), null)).toBe('Page not found')
  })
})
