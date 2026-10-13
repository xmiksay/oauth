import { defineStore } from 'pinia'
import { computed, ref, shallowRef } from 'vue'
import type { User, UserManager } from 'oidc-client-ts'
import { createUserManager, type SpaArea } from '@/auth/oidc'
import type { DirectoryRole, UserDetail } from '@/api/types'

interface ReturnState {
  returnTo?: string
}

/** A second 401 this soon after a re-auth redirect means re-auth won't help; stops a loop. */
const REAUTH_GUARD_MS = 60_000
/** Refresh this long before expiry so a token doesn't lapse while a request is in flight. */
const REFRESH_EARLY_SECS = 30

export class SignInRequired extends Error {
  constructor() {
    super('sign-in required')
    this.name = 'SignInRequired'
  }
}

export const useAuthStore = defineStore('auth', () => {
  const tenant = ref<string | null>(null)
  const area = ref<SpaArea | null>(null)
  const user = shallowRef<User | null>(null)
  const me = ref<UserDetail | null>(null)
  /** Set when re-authentication can't fix a 401 (shown instead of looping). */
  const fatal = ref<string | null>(null)
  let manager: UserManager | null = null
  // One manager per tenant + area for the page's lifetime, so switching areas never leaves a
  // second instance acting on the same stored user.
  const managers = new Map<string, UserManager>()
  // Refresh tokens rotate and the server revokes the whole grant on reuse, so concurrent
  // callers must share one refresh instead of each redeeming the same token.
  const refreshing = new Map<UserManager, Promise<User | null>>()

  const roles = computed<DirectoryRole[]>(() => me.value?.directory_roles ?? [])
  const hasRole = (...wanted: DirectoryRole[]) => roles.value.some((r) => wanted.includes(r))
  const isAdmin = computed(() => roles.value.length > 0)
  const isGlobalAdmin = computed(() => hasRole('GlobalAdmin'))
  const canWriteUsers = computed(() => hasRole('GlobalAdmin', 'UserAdmin'))
  const canWriteApps = computed(() => hasRole('GlobalAdmin', 'ApplicationAdmin'))

  function managerFor(t: string, a: SpaArea): UserManager {
    const key = `${t}:${a}`
    let m = managers.get(key)
    if (!m) {
      m = createUserManager(t, a)
      managers.set(key, m)
    }
    return m
  }

  function use(t: string, a: SpaArea): UserManager {
    if (manager && tenant.value === t && area.value === a) return manager
    manager = managerFor(t, a)
    tenant.value = t
    area.value = a
    user.value = null
    me.value = null
    fatal.value = null
    return manager
  }

  function refresh(m: UserManager): Promise<User | null> {
    let pending = refreshing.get(m)
    if (!pending) {
      pending = m
        .signinSilent()
        .catch(() => null)
        .finally(() => refreshing.delete(m))
      refreshing.set(m, pending)
    }
    return pending
  }

  function current(): UserManager {
    if (!manager) throw new SignInRequired()
    return manager
  }

  /** True when a usable user is stored; otherwise starts the sign-in redirect and returns false. */
  async function ensureSignedIn(t: string, a: SpaArea, returnTo: string): Promise<boolean> {
    const m = use(t, a)
    const stored = await m.getUser()
    if (stored && (!stored.expired || stored.refresh_token)) {
      user.value = stored
      return true
    }
    await m.signinRedirect({ state: { returnTo } satisfies ReturnState })
    return false
  }

  /** Finishes the code flow on the callback route; returns where to go next. */
  async function completeSignIn(t: string, a: SpaArea): Promise<string> {
    const signedIn = await use(t, a).signinRedirectCallback()
    user.value = signedIn
    const state = signedIn.state as ReturnState | undefined
    const back = state?.returnTo
    return back && back.startsWith('/') && !back.startsWith('//') ? back : `/${t}/${a}`
  }

  /** The current access token, refreshed (once, shared by all callers) when near expiry. */
  async function accessToken(): Promise<string> {
    const m = current()
    let u = user.value ?? (await m.getUser())
    const stale = u && (u.expired || (u.expires_in ?? Infinity) < REFRESH_EARLY_SECS)
    if (u && stale && u.refresh_token) {
      u = await refresh(m)
    }
    if (!u || u.expired) {
      if (m === manager) await reauthenticate()
      throw new SignInRequired()
    }
    if (m === manager) user.value = u
    return u.access_token
  }

  let reauthing: Promise<void> | null = null

  /**
   * Called on a 401 from the API (the token or its session is gone) — sign in again. `force`
   * skips the loop guard when the caller knows why the session ended (sign out everywhere).
   * Single-flight: pages fire several requests at once, and a second caller arriving after the
   * first wrote the loop-guard timestamp must join that redirect, not report a loop.
   */
  function reauthenticate(force = false): Promise<void> {
    reauthing ??= doReauth(force).finally(() => (reauthing = null))
    return reauthing
  }

  async function doReauth(force: boolean): Promise<void> {
    const m = current()
    const last = Number(sessionStorage.getItem(guardKey()) ?? 0)
    if (!force && Date.now() - last < REAUTH_GUARD_MS) {
      fatal.value =
        'Your sign-in was accepted, but the management API rejected the new token. Try again later or contact your administrator.'
      return
    }
    sessionStorage.setItem(guardKey(), String(Date.now()))
    await m.removeUser()
    const returnTo = window.location.pathname + window.location.search
    await m.signinRedirect({ state: { returnTo } satisfies ReturnState })
  }

  async function signOut(): Promise<void> {
    const m = current()
    me.value = null
    // Both areas ride on the same browser session, so the other area's tokens die with it.
    if (tenant.value && area.value) {
      await managerFor(tenant.value, area.value === 'admin' ? 'myaccount' : 'admin').removeUser()
    }
    // With id_token_hint the server ends the session and returns to the area root.
    await m.signoutRedirect()
  }

  function guardKey(): string {
    return `oauth.reauth:${tenant.value}:${area.value}`
  }

  function setMe(detail: UserDetail | null) {
    me.value = detail
  }

  return {
    tenant,
    area,
    user,
    me,
    fatal,
    roles,
    isAdmin,
    isGlobalAdmin,
    canWriteUsers,
    canWriteApps,
    ensureSignedIn,
    completeSignIn,
    accessToken,
    reauthenticate,
    signOut,
    setMe,
  }
})
