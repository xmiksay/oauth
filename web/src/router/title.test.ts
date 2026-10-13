import { describe, expect, it } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { pageTitle, router } from './index'

setActivePinia(createPinia())

describe('pageTitle', () => {
  it('names the page, the area and the tenant', () => {
    expect(pageTitle(router.resolve('/contoso/admin/users'))).toBe('Users · Admin center · contoso')
    expect(pageTitle(router.resolve('/contoso/myaccount/security'))).toBe(
      'Security info · My Account · contoso',
    )
    expect(pageTitle(router.resolve('/contoso/admin/app-registrations/x/secrets'))).toBe(
      'App registration · Admin center · contoso',
    )
    expect(pageTitle(router.resolve('/contoso/login'))).toBe('Sign in · contoso')
  })
})
