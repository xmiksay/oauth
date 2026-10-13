import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { FakeManager, fakeUser, mockFetch } from '@/test/helpers'
import { ApiError } from '@/api/client'

vi.mock('@/auth/oidc', () => ({
  createUserManager: (t: string, a: string) => new FakeManager(t, a),
}))

const { useAuthStore, SignInRequired } = await import('./auth')
const { authed, tenantPath } = await import('@/api/management')

function manager(area = 'admin'): FakeManager {
  const m = FakeManager.instances.filter((i) => i.area === area).at(-1)
  if (!m) throw new Error('no manager')
  return m
}

beforeEach(() => {
  setActivePinia(createPinia())
  FakeManager.instances = []
  sessionStorage.clear()
})
afterEach(() => vi.unstubAllGlobals())

describe('auth store', () => {
  it('starts the sign-in redirect when nothing is stored', async () => {
    const auth = useAuthStore()
    expect(await auth.ensureSignedIn('contoso', 'admin', '/contoso/admin/users')).toBe(false)
    expect(manager().signinRedirect).toHaveBeenCalledWith({
      state: { returnTo: '/contoso/admin/users' },
    })
  })

  it('accepts a stored user, even an expired one that can refresh', async () => {
    const auth = useAuthStore()
    await auth.ensureSignedIn('contoso', 'admin', '/')
    manager().stored = fakeUser({ expired: true })
    expect(await auth.ensureSignedIn('contoso', 'admin', '/')).toBe(true)
    expect(manager().signinRedirect).toHaveBeenCalledTimes(1)
  })

  it('keeps one manager per tenant and area', async () => {
    const auth = useAuthStore()
    await auth.ensureSignedIn('contoso', 'admin', '/')
    await auth.ensureSignedIn('contoso', 'admin', '/')
    await auth.ensureSignedIn('contoso', 'myaccount', '/')
    expect(FakeManager.instances.map((m) => m.area)).toEqual(['admin', 'myaccount'])
  })

  it('returns to a same-origin path after the callback, never elsewhere', async () => {
    const auth = useAuthStore()
    await auth.ensureSignedIn('contoso', 'admin', '/')
    const m = manager()
    m.signinRedirectCallback.mockResolvedValueOnce(
      fakeUser({ state: { returnTo: '/contoso/admin/groups' } }),
    )
    expect(await auth.completeSignIn('contoso', 'admin')).toBe('/contoso/admin/groups')
    m.signinRedirectCallback.mockResolvedValueOnce(
      fakeUser({ state: { returnTo: '//evil.example/x' } }),
    )
    expect(await auth.completeSignIn('contoso', 'admin')).toBe('/contoso/admin')
  })

  it('refreshes an expired token silently', async () => {
    const auth = useAuthStore()
    await auth.ensureSignedIn('contoso', 'admin', '/')
    const m = manager()
    m.stored = fakeUser({ expired: true })
    m.signinSilent.mockResolvedValueOnce(fakeUser({ access_token: 'fresh' }))
    expect(await auth.accessToken()).toBe('fresh')
  })

  it('shares one refresh between parallel callers (rotating refresh tokens)', async () => {
    const auth = useAuthStore()
    await auth.ensureSignedIn('contoso', 'admin', '/')
    const m = manager()
    m.stored = fakeUser({ expired: true })
    let release: (u: ReturnType<typeof fakeUser>) => void = () => {}
    m.signinSilent.mockReturnValueOnce(new Promise((r) => (release = r)))
    const tokens = Promise.all([auth.accessToken(), auth.accessToken(), auth.accessToken()])
    await Promise.resolve()
    release(fakeUser({ access_token: 'fresh' }))
    expect(await tokens).toEqual(['fresh', 'fresh', 'fresh'])
    expect(m.signinSilent).toHaveBeenCalledTimes(1)
  })

  it('refreshes shortly before expiry, not only after', async () => {
    const auth = useAuthStore()
    await auth.ensureSignedIn('contoso', 'admin', '/')
    const m = manager()
    m.stored = fakeUser({ expires_in: 10 })
    m.signinSilent.mockResolvedValueOnce(fakeUser({ access_token: 'early' }))
    expect(await auth.accessToken()).toBe('early')
  })

  it('reuses one manager per tenant and area when switching back and forth', async () => {
    const auth = useAuthStore()
    for (let i = 0; i < 5; i++) {
      await auth.ensureSignedIn('contoso', 'admin', '/')
      await auth.ensureSignedIn('contoso', 'myaccount', '/')
    }
    expect(FakeManager.instances.map((m) => m.area)).toEqual(['admin', 'myaccount'])
  })

  it('re-authenticates when refresh fails', async () => {
    const auth = useAuthStore()
    await auth.ensureSignedIn('contoso', 'admin', '/')
    const m = manager()
    m.stored = fakeUser({ expired: true })
    await expect(auth.accessToken()).rejects.toBeInstanceOf(SignInRequired)
    expect(m.removeUser).toHaveBeenCalled()
    expect(m.signinRedirect).toHaveBeenCalledTimes(2)
  })

  it('parallel callers share one re-auth redirect and report no false loop', async () => {
    const auth = useAuthStore()
    await auth.ensureSignedIn('contoso', 'admin', '/')
    const m = manager()
    m.stored = fakeUser({ expired: true })
    m.signinSilent.mockRejectedValueOnce(new Error('refresh failed'))
    const results = await Promise.allSettled([auth.accessToken(), auth.accessToken()])
    expect(results.map((r) => r.status)).toEqual(['rejected', 'rejected'])
    expect(auth.fatal).toBeNull()
    expect(m.removeUser).toHaveBeenCalledTimes(1)
    expect(m.signinRedirect).toHaveBeenCalledTimes(2) // initial sign-in + one re-auth
  })

  it('retries a refresh that failed earlier instead of reusing the failure', async () => {
    const auth = useAuthStore()
    await auth.ensureSignedIn('contoso', 'admin', '/')
    const m = manager()
    m.stored = fakeUser({ expired: true })
    m.signinSilent.mockRejectedValueOnce(new Error('network down'))
    await expect(auth.accessToken()).rejects.toBeInstanceOf(SignInRequired)
    m.stored = fakeUser({ expired: true })
    m.signinSilent.mockResolvedValueOnce(fakeUser({ access_token: 'second-try' }))
    expect(await auth.accessToken()).toBe('second-try')
    expect(m.signinSilent).toHaveBeenCalledTimes(2)
  })

  it('stops a re-auth loop: a second 401 right after a re-auth shows an error', async () => {
    const auth = useAuthStore()
    await auth.ensureSignedIn('contoso', 'admin', '/')
    await auth.reauthenticate()
    await auth.reauthenticate()
    expect(manager().signinRedirect).toHaveBeenCalledTimes(2) // initial + first re-auth
    expect(auth.fatal).toMatch(/rejected/)
    await auth.reauthenticate(true)
    expect(manager().signinRedirect).toHaveBeenCalledTimes(3)
  })

  it('sign-out ends the session and drops the other area tokens too', async () => {
    const auth = useAuthStore()
    await auth.ensureSignedIn('contoso', 'myaccount', '/')
    await auth.signOut()
    expect(manager('myaccount').signoutRedirect).toHaveBeenCalled()
    expect(manager('admin').removeUser).toHaveBeenCalled()
  })

  it('derives write permissions from directory roles', () => {
    const auth = useAuthStore()
    const base = {
      id: 'u',
      email: 'e',
      display_name: 'n',
      user_type: 'member' as const,
      email_verified: false,
      disabled: false,
      must_change_password: false,
      has_password: true,
      created_at: '',
      updated_at: '',
      mfa: { totp: false, totp_pending: false, recovery_codes_remaining: 0 },
    }
    auth.setMe({ ...base, directory_roles: ['UserAdmin'] })
    expect([auth.isAdmin, auth.canWriteUsers, auth.canWriteApps, auth.isGlobalAdmin]).toEqual([
      true,
      true,
      false,
      false,
    ])
    auth.setMe({ ...base, directory_roles: [] })
    expect(auth.isAdmin).toBe(false)
  })
})

describe('authed management requests', () => {
  async function signedIn() {
    const auth = useAuthStore()
    await auth.ensureSignedIn('contoso', 'admin', '/')
    manager().stored = fakeUser({ access_token: 'tok' })
    await auth.ensureSignedIn('contoso', 'admin', '/')
    return auth
  }

  it('injects the bearer token and builds tenant paths', async () => {
    await signedIn()
    const calls = mockFetch({ body: { ok: 1 } })
    await authed(tenantPath('users'))
    expect(calls[0]?.url).toBe('/api/v1/tenants/contoso/users')
    expect(calls[0]?.headers.Authorization).toBe('Bearer tok')
  })

  it('re-authenticates on 401 and still throws', async () => {
    await signedIn()
    mockFetch({ status: 401, body: { error: 'invalid_token' } })
    const err = await authed(tenantPath('me')).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(manager().removeUser).toHaveBeenCalled()
    expect(manager().signinRedirect).toHaveBeenCalledTimes(2)
  })

  it('does not re-authenticate on 403', async () => {
    await signedIn()
    mockFetch({ status: 403, body: { error: 'forbidden' } })
    await expect(authed(tenantPath('users'))).rejects.toMatchObject({ status: 403 })
    expect(manager().removeUser).not.toHaveBeenCalled()
  })
})
