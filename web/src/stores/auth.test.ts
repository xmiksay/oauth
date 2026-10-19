import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { FakeManager, fakeMe, fakeUser, mockFetch } from '@/test/helpers'
import { ApiError } from '@/api/client'

vi.mock('@/auth/oidc', () => ({
  createUserManager: (a: string) => new FakeManager(a),
}))

const { useAuthStore, SignInRequired } = await import('./auth')
const { authed, apiPath } = await import('@/api/management')

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
    expect(await auth.ensureSignedIn('admin', '/admin/users')).toBe(false)
    expect(manager().signinRedirect).toHaveBeenCalledWith({
      state: { returnTo: '/admin/users' },
    })
  })

  it('accepts a stored user, even an expired one that can refresh', async () => {
    const auth = useAuthStore()
    await auth.ensureSignedIn('admin', '/')
    manager().stored = fakeUser({ expired: true })
    expect(await auth.ensureSignedIn('admin', '/')).toBe(true)
    expect(manager().signinRedirect).toHaveBeenCalledTimes(1)
  })

  it('keeps one manager per area', async () => {
    const auth = useAuthStore()
    await auth.ensureSignedIn('admin', '/')
    await auth.ensureSignedIn('admin', '/')
    await auth.ensureSignedIn('myaccount', '/')
    expect(FakeManager.instances.map((m) => m.area)).toEqual(['admin', 'myaccount'])
  })

  it('returns to a same-origin path after the callback, never elsewhere', async () => {
    const auth = useAuthStore()
    await auth.ensureSignedIn('admin', '/')
    const m = manager()
    m.signinRedirectCallback.mockResolvedValueOnce(
      fakeUser({ state: { returnTo: '/admin/groups' } }),
    )
    expect(await auth.completeSignIn('admin')).toBe('/admin/groups')
    m.signinRedirectCallback.mockResolvedValueOnce(
      fakeUser({ state: { returnTo: '//evil.example/x' } }),
    )
    expect(await auth.completeSignIn('admin')).toBe('/admin')
  })

  it('returns the portal (/) to / after the My Account callback', async () => {
    const auth = useAuthStore()
    await auth.ensureSignedIn('myaccount', '/')
    manager('myaccount').signinRedirectCallback.mockResolvedValueOnce(
      fakeUser({ state: { returnTo: '/' } }),
    )
    expect(await auth.completeSignIn('myaccount')).toBe('/')
  })

  it("drops the previous area's me (and roles) when switching areas", async () => {
    const auth = useAuthStore()
    await auth.ensureSignedIn('myaccount', '/')
    auth.setMe(fakeMe({ directory_roles: ['GlobalAdmin'] }))
    expect(auth.isAdmin).toBe(true)
    await auth.ensureSignedIn('admin', '/admin')
    // The admin layout reloads `me` with the admin token; nothing stale shows meanwhile.
    expect(auth.me).toBeNull()
    expect(auth.isAdmin).toBe(false)
  })

  it('refreshes an expired token silently', async () => {
    const auth = useAuthStore()
    await auth.ensureSignedIn('admin', '/')
    const m = manager()
    m.stored = fakeUser({ expired: true })
    m.signinSilent.mockResolvedValueOnce(fakeUser({ access_token: 'fresh' }))
    expect(await auth.accessToken()).toBe('fresh')
  })

  it('shares one refresh between parallel callers (rotating refresh tokens)', async () => {
    const auth = useAuthStore()
    await auth.ensureSignedIn('admin', '/')
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
    await auth.ensureSignedIn('admin', '/')
    const m = manager()
    m.stored = fakeUser({ expires_in: 10 })
    m.signinSilent.mockResolvedValueOnce(fakeUser({ access_token: 'early' }))
    expect(await auth.accessToken()).toBe('early')
  })

  it('reuses one manager per area when switching back and forth', async () => {
    const auth = useAuthStore()
    for (let i = 0; i < 5; i++) {
      await auth.ensureSignedIn('admin', '/')
      await auth.ensureSignedIn('myaccount', '/')
    }
    expect(FakeManager.instances.map((m) => m.area)).toEqual(['admin', 'myaccount'])
  })

  it('re-authenticates when refresh fails', async () => {
    const auth = useAuthStore()
    await auth.ensureSignedIn('admin', '/')
    const m = manager()
    m.stored = fakeUser({ expired: true })
    await expect(auth.accessToken()).rejects.toBeInstanceOf(SignInRequired)
    expect(m.removeUser).toHaveBeenCalled()
    expect(m.signinRedirect).toHaveBeenCalledTimes(2)
  })

  it('parallel callers share one re-auth redirect and report no false loop', async () => {
    const auth = useAuthStore()
    await auth.ensureSignedIn('admin', '/')
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
    await auth.ensureSignedIn('admin', '/')
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
    await auth.ensureSignedIn('admin', '/')
    await auth.reauthenticate()
    await auth.reauthenticate()
    expect(manager().signinRedirect).toHaveBeenCalledTimes(2) // initial + first re-auth
    expect(auth.fatal).toMatch(/rejected/)
    await auth.reauthenticate(true)
    expect(manager().signinRedirect).toHaveBeenCalledTimes(3)
    expect(auth.fatal).toBeNull()
  })

  it('a forced re-auth joining a guarded one still redirects', async () => {
    const auth = useAuthStore()
    await auth.ensureSignedIn('admin', '/')
    await auth.reauthenticate() // writes the loop guard
    expect(manager().signinRedirect).toHaveBeenCalledTimes(2)
    // A plain 401 (stopped by the guard) is in flight when "sign out everywhere" forces one.
    const plain = auth.reauthenticate()
    const forced = auth.reauthenticate(true)
    await Promise.all([plain, forced])
    expect(auth.fatal).toBeNull() // set by the guarded call, cleared by the forced one
    expect(manager().signinRedirect).toHaveBeenCalledTimes(3)
  })

  it('a forced re-auth joining one that redirects does not redirect twice', async () => {
    const auth = useAuthStore()
    await auth.ensureSignedIn('admin', '/')
    await Promise.all([auth.reauthenticate(), auth.reauthenticate(true)])
    expect(manager().removeUser).toHaveBeenCalledTimes(1)
    expect(manager().signinRedirect).toHaveBeenCalledTimes(2) // initial + one re-auth
  })

  it('a failed re-auth does not block the next one', async () => {
    const auth = useAuthStore()
    await auth.ensureSignedIn('admin', '/')
    const m = manager()
    m.removeUser.mockRejectedValueOnce(new Error('storage'))
    await expect(auth.reauthenticate(true)).rejects.toThrow('storage')
    m.signinRedirect.mockRejectedValueOnce(new Error('discovery'))
    await expect(auth.reauthenticate(true)).rejects.toThrow('discovery')
    await auth.reauthenticate(true)
    expect(m.signinRedirect).toHaveBeenCalledTimes(3) // initial + the two that got that far
  })

  it('sign-out ends the session and drops the other area tokens too', async () => {
    const auth = useAuthStore()
    await auth.ensureSignedIn('myaccount', '/')
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
      mfa: { totp: false, totp_pending: false, recovery_codes_remaining: 0, passkeys: 0, telegram: false },
      features: { email: false, telegram: false },
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
    await auth.ensureSignedIn('admin', '/')
    manager().stored = fakeUser({ access_token: 'tok' })
    await auth.ensureSignedIn('admin', '/')
    return auth
  }

  it('injects the bearer token and builds tenant-host paths', async () => {
    await signedIn()
    const calls = mockFetch({ body: { ok: 1 } })
    await authed(apiPath('users'))
    expect(calls[0]?.url).toBe('/api/v1/users')
    expect(calls[0]?.headers.Authorization).toBe('Bearer tok')
  })

  it('re-authenticates on 401 and still throws', async () => {
    await signedIn()
    mockFetch({ status: 401, body: { error: 'invalid_token' } })
    const err = await authed(apiPath('me')).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(manager().removeUser).toHaveBeenCalled()
    expect(manager().signinRedirect).toHaveBeenCalledTimes(2)
  })

  it('does not re-authenticate on 403', async () => {
    await signedIn()
    mockFetch({ status: 403, body: { error: 'forbidden' } })
    await expect(authed(apiPath('users'))).rejects.toMatchObject({ status: 403 })
    expect(manager().removeUser).not.toHaveBeenCalled()
  })
})
