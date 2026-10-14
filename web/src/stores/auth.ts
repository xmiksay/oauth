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
  // The tenant is the page's host (`stores/tenant`), fixed for the page's lifetime.
  const area = ref<SpaArea | null>(null)
  const user = shallowRef<User | null>(null)
  const me = ref<UserDetail | null>(null)
  /** Set when re-authentication can't fix a 401 (shown instead of looping). */
  const fatal = ref<string | null>(null)
  let manager: UserManager | null = null
  // One manager per area for the page's lifetime, so switching areas never leaves a second
  // instance acting on the same stored user.
  const managers = new Map<SpaArea, UserManager>()
  // Refresh tokens rotate and the server revokes the whole grant on reuse, so concurrent
  // callers must share one refresh instead of each redeeming the same token.
  const refreshing = new Map<UserManager, Promise<User | null>>()

  const roles = computed<DirectoryRole[]>(() => me.value?.directory_roles ?? [])
  const hasRole = (...wanted: DirectoryRole[]) => roles.value.some((r) => wanted.includes(r))
  const isAdmin = computed(() => roles.value.length > 0)
  const isGlobalAdmin = computed(() => hasRole('GlobalAdmin'))
  const canWriteUsers = computed(() => hasRole('GlobalAdmin', 'UserAdmin'))
  const canWriteApps = computed(() => hasRole('GlobalAdmin', 'ApplicationAdmin'))

  function managerFor(a: SpaArea): UserManager {
    let m = managers.get(a)
    if (!m) {
      m = createUserManager(a)
      managers.set(a, m)
    }
    return m
  }

  function use(a: SpaArea): UserManager {
    if (manager && area.value === a) return manager
    manager = managerFor(a)
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
  async function ensureSignedIn(a: SpaArea, returnTo: string): Promise<boolean> {
    const m = use(a)
    const stored = await m.getUser()
    if (stored && (!stored.expired || stored.refresh_token)) {
      user.value = stored
      return true
    }
    await m.signinRedirect({ state: { returnTo } satisfies ReturnState })
    return false
  }

  /** Finishes the code flow on the callback route; returns where to go next. */
  async function completeSignIn(a: SpaArea): Promise<string> {
    const signedIn = await use(a).signinRedirectCallback()
    user.value = signedIn
    const state = signedIn.state as ReturnState | undefined
    const back = state?.returnTo
    return back && back.startsWith('/') && !back.startsWith('//') ? back : `/${a}`
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

  /** The in-flight re-auth (resolves to whether it redirected) and whether it was forced. */
  let reauthing: { done: Promise<boolean>; forced: boolean } | null = null

  /**
   * Called on a 401 from the API (the token or its session is gone) — sign in again. `force`
   * skips the loop guard when the caller knows why the session ended (sign out everywhere).
   * Single-flight: pages fire several requests at once, and a second caller arriving after the
   * first wrote the loop-guard timestamp must join that redirect, not report a loop.
   */
  function reauthenticate(force = false): Promise<void> {
    if (!reauthing) {
      reauthing = track(doReauth(force), force)
    } else if (force && !reauthing.forced) {
      // The call in flight may stop at the loop guard (or fail); a forced caller still needs
      // its redirect, so it runs after it unless that one already redirected.
      const retry = () => doReauth(true)
      reauthing = track(
        reauthing.done.then((redirected) => redirected || retry(), retry),
        true,
      )
    }
    return reauthing.done.then(() => undefined)
  }

  function track(done: Promise<boolean>, forced: boolean) {
    const entry = {
      done: done.finally(() => {
        if (reauthing === entry) reauthing = null
      }),
      forced,
    }
    return entry
  }

  async function doReauth(force: boolean): Promise<boolean> {
    const m = current()
    const last = Number(sessionStorage.getItem(guardKey()) ?? 0)
    if (!force && Date.now() - last < REAUTH_GUARD_MS) {
      fatal.value =
        'Your sign-in was accepted, but the management API rejected the new token. Try again later or contact your administrator.'
      return false
    }
    sessionStorage.setItem(guardKey(), String(Date.now()))
    // A forced re-auth proceeding past a guard hit retires that hit's banner.
    fatal.value = null
    await m.removeUser()
    const returnTo = window.location.pathname + window.location.search
    await m.signinRedirect({ state: { returnTo } satisfies ReturnState })
    return true
  }

  async function signOut(): Promise<void> {
    const m = current()
    me.value = null
    // Both areas ride on the same browser session, so the other area's tokens die with it.
    if (area.value) {
      await managerFor(area.value === 'admin' ? 'myaccount' : 'admin').removeUser()
    }
    // With id_token_hint the server ends the session and returns to the area root.
    await m.signoutRedirect()
  }

  function guardKey(): string {
    return `oauth.reauth:${area.value}`
  }

  function setMe(detail: UserDetail | null) {
    me.value = detail
  }

  return {
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
