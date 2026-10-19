import { describe, expect, it } from 'vitest'
import { router } from './index'

describe('email-link routes', () => {
  it.each([
    ['/login/reset#token=t', 'password-reset'],
    ['/login/invite#token=t', 'invite'],
    ['/myaccount/verify-email#token=t', 'verify-email'],
  ])('%s is public (no area, so the guard never starts a sign-in)', (url, name) => {
    const to = router.resolve(url)
    expect(to.name).toBe(name)
    expect(to.meta.area).toBeUndefined()
  })

  it('keeps the rest of My Account signed in', () => {
    expect(router.resolve('/myaccount/notifications').meta.area).toBe('myaccount')
  })

  it('signs in to the portal at / with the My Account client', () => {
    const to = router.resolve('/')
    expect(to.name).toBe('portal')
    expect(to.meta.area).toBe('myaccount')
  })
})
