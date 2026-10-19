import { computed, ref, shallowRef } from 'vue'
import { ApiError } from '@/api/client'
import { authn, isRedirect, type StepResult, type TxView } from '@/api/authn'
import type { IdpRef } from '@/api/types'
import { isWebUrl, navigateTo } from '@/lib/navigate'
import { PasskeyCancelled, conditionalMediationAvailable, getPasskey } from '@/webauthn'
import {
  ALREADY_LINKED,
  LINK_UNAVAILABLE,
  UPSTREAM_FAILED,
  discoverable,
  upstreamErrorMessage,
} from './federation'

/**
 * `missing`: no tx in the URL; `expired`: unknown / expired / finished transaction;
 * `error`: the transaction couldn't be loaded (network / server) — retry with `load`.
 */
export type Phase = 'loading' | 'step' | 'redirecting' | 'expired' | 'missing' | 'error'

export interface LoginDeps {
  api: typeof authn
  navigate: (url: string) => void
  passkeys: { conditional: () => Promise<boolean>; get: typeof getPasskey }
}

const defaultDeps: LoginDeps = {
  api: authn,
  navigate: navigateTo,
  passkeys: { conditional: conditionalMediationAvailable, get: getPasskey },
}

export const PASSKEY_FAILED = "That passkey couldn't be verified. Try again or use another method."
export const PASSKEY_CANCELLED = 'Passkey sign-in was cancelled.'
export const TELEGRAM_FAILED = 'Wrong or expired code. Request a new code if needed.'
export const TELEGRAM_UNAVAILABLE =
  'Telegram sign-in is unavailable on this server. Use another method or contact your administrator.'

function messageFor(err: ApiError): string {
  switch (err.code) {
    case 'invalid_credentials':
      return 'Your email or password is incorrect.'
    case 'invalid_code':
      return "That code didn't work. Check it and try again."
    case 'delivery_failed':
      return "Couldn't send the code via Telegram. Try again."
    case 'telegram_unavailable':
      return TELEGRAM_UNAVAILABLE
    case 'account_disabled':
      return 'Your account has been disabled. Contact your administrator.'
    case 'csrf_rejected':
      return 'The request was blocked for security reasons. Reload the page and try again.'
    case 'invalid_request':
      return err.description ?? 'The request was not valid.'
    case 'upstream_failed':
      return UPSTREAM_FAILED
  }
  return 'Something went wrong on our side. Please try again.'
}

/**
 * Drives one login transaction through its steps (docs/api/authn.md). `upstreamError`: the
 * `error` the federation callback put in the URL — shown at the password step, and it turns
 * off the `idp_hint` auto-redirect (which would otherwise loop back to the same failure).
 */
export function useLoginFlow(
  tx: string | null,
  deps: LoginDeps = defaultDeps,
  upstreamError: string | null = null,
) {
  const phase = ref<Phase>(tx ? 'loading' : 'missing')
  const view = shallowRef<TxView | null>(null)
  const error = ref<string | null>(null)
  /** A soft note (a dismissed passkey dialog, a sent code), not an error. */
  const notice = ref<string | null>(null)
  const busy = ref(false)
  const retryIn = ref(0)
  /** A Telegram code was sent during this MFA step, so its input can be shown. */
  const telegramSent = ref(false)
  /** The identity provider a federated sign-in is being started with. */
  const federating = ref<IdpRef | null>(null)
  /** The provider the typed email's domain belongs to (email-domain discovery). */
  const suggestion = ref<IdpRef | null>(null)
  let timer: ReturnType<typeof setInterval> | null = null
  let firstView = true
  let autoRedirected = false

  const locked = computed(() => busy.value || retryIn.value > 0)
  const rateLimited = computed(() => retryIn.value > 0)

  function stopTimer() {
    if (timer !== null) clearInterval(timer)
    timer = null
  }

  function startCountdown(secs: number) {
    stopTimer()
    retryIn.value = Math.max(1, secs)
    timer = setInterval(() => {
      retryIn.value -= 1
      if (retryIn.value <= 0) {
        retryIn.value = 0
        stopTimer()
      }
    }, 1000)
  }

  function apply(result: StepResult) {
    if (isRedirect(result)) {
      // Defence in depth: the server only redirects to registered URIs, but never follow a
      // javascript:/data: URL whatever it sends.
      if (!isWebUrl(result.redirect)) {
        phase.value = 'error'
        error.value = 'The sign-in returned an invalid address. Contact your administrator.'
        return
      }
      phase.value = 'redirecting'
      deps.navigate(result.redirect)
      return
    }
    if (result.step !== 'mfa') telegramSent.value = false
    view.value = result
    phase.value = 'step'
  }

  async function handleError(err: unknown, failed?: string) {
    if (err instanceof PasskeyCancelled) {
      notice.value = PASSKEY_CANCELLED
      return
    }
    if (typeof err === 'string') {
      error.value = err
      return
    }
    if (!(err instanceof ApiError)) {
      error.value = 'Could not reach the server. Check your connection and try again.'
      return
    }
    if (err.status === 404) {
      phase.value = 'expired'
      view.value = null
    } else if (err.status === 409 && err.code === 'already_linked') {
      error.value = ALREADY_LINKED
    } else if (err.status === 409 && err.code === 'link_unavailable') {
      // The parked link is gone; the reloaded view is the plain password step.
      await load()
      notice.value = LINK_UNAVAILABLE
    } else if (err.status === 409) {
      // Another tab (or a double submit) advanced the transaction: show where it is now.
      await load()
    } else if (err.status === 429) {
      startCountdown(err.retryAfter ?? 30)
    } else {
      const rejected = err.code === 'invalid_credentials' || err.code === 'invalid_code'
      error.value = failed && rejected ? failed : messageFor(err)
    }
  }

  async function load() {
    if (!tx) return
    phase.value = 'loading'
    error.value = null
    try {
      const v = await deps.api.get(tx)
      apply(v)
      const first = firstView
      firstView = false
      if (v.step !== 'password') return
      if (v.notice === 'link_unavailable') notice.value = LINK_UNAVAILABLE
      if (upstreamError) {
        if (first) error.value = upstreamErrorMessage(upstreamError)
      } else if (v.idp_hint && !autoRedirected) {
        // Once per page: a failed attempt reloads the view, which must not start another.
        autoRedirected = true
        await federate(v.idp_hint)
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        phase.value = 'expired'
        view.value = null
      } else {
        phase.value = 'error'
        error.value =
          err instanceof ApiError
            ? messageFor(err)
            : 'Could not reach the server. Check your connection and try again.'
      }
    }
  }

  /** One request at a time; `failed`: the step's own rejection (`invalid_credentials` / `invalid_code`) message. */
  async function guarded(call: (tx: string) => Promise<void>, failed?: string) {
    if (!tx || locked.value) return
    busy.value = true
    error.value = null
    notice.value = null
    try {
      await call(tx)
    } catch (err) {
      await handleError(err, failed)
    } finally {
      busy.value = false
    }
  }

  const run = (call: (tx: string) => Promise<StepResult>, failed?: string) =>
    guarded(async (id) => apply(await call(id)), failed)

  const a = deps.api

  /** Starts a sign-in at `idp`: the server answers with its authorize URL (another origin). */
  async function federate(idp: IdpRef) {
    stopConditional()
    federating.value = idp
    await run((id) => a.federation(id, idp.id))
    if (phase.value !== 'redirecting') federating.value = null
  }

  let discovered: string | null = null
  let discoverSeq = 0

  /**
   * Looks up the provider of the email's domain, once per distinct address. Never blocks or
   * fails the form: any error (a 429 included) just means no suggestion.
   */
  async function discover(email: string) {
    const value = email.trim()
    const v = view.value
    if (!tx || !v?.features.federation || v.step !== 'password') return
    if (!discoverable(value) || value === discovered) return
    discovered = value
    const mine = ++discoverSeq
    try {
      const res = await a.discover(tx, value)
      if (mine === discoverSeq) suggestion.value = res.idp ?? null
    } catch {
      if (mine === discoverSeq) suggestion.value = null
    }
  }

  /** Not a step POST: it answers `{ sent, expires_in }` and the MFA step stays. */
  const sendTelegram = () =>
    guarded(async (id) => {
      const { expires_in } = await a.sendTelegramCode(id)
      telegramSent.value = true
      const minutes = Math.max(1, Math.round(expires_in / 60))
      notice.value = `We sent a code to your Telegram. It's valid for ${minutes} minutes.`
    })

  // The pending autofill (conditional mediation) request, if any.
  let conditional: AbortController | null = null

  function stopConditional() {
    conditional?.abort()
    conditional = null
  }

  /**
   * Offers passkeys in the email field's autofill. Silent on any failure: it's a shortcut
   * beside the form and the passkey button, which both keep working.
   */
  async function startConditional() {
    if (!tx || conditional || !view.value?.factors.includes('passkey')) return
    const ctl = new AbortController()
    conditional = ctl
    try {
      if (!(await deps.passkeys.conditional()) || ctl.signal.aborted) return
      const options = await a.passkeyOptions(tx)
      if (ctl.signal.aborted) return
      const assertion = await deps.passkeys.get(options, {
        mediation: 'conditional',
        signal: ctl.signal,
      })
      if (ctl.signal.aborted) return
      conditional = null
      await run((id) => a.passkey(id, assertion), PASSKEY_FAILED)
    } catch {
      // Aborted, dismissed or unavailable: nothing to tell the user.
    } finally {
      if (conditional === ctl) conditional = null
    }
  }

  /** Modal passkey sign-in, with fresh options: they replace the autofill's challenge. */
  async function passkey() {
    stopConditional()
    await run(
      async (id) => a.passkey(id, await deps.passkeys.get(await a.passkeyOptions(id))),
      PASSKEY_FAILED,
    )
  }

  return {
    phase,
    view,
    error,
    notice,
    busy,
    retryIn,
    locked,
    rateLimited,
    telegramSent,
    federating,
    suggestion,
    load,
    federate,
    discover,
    password: (email: string, password: string) =>
      run((id) => a.password(id, email, password)),
    totp: (code: string) => run((id) => a.totp(id, code.replace(/\s/g, ''))),
    recovery: (code: string) => run((id) => a.recovery(id, code)),
    sendTelegram,
    telegram: (code: string) =>
      run((id) => a.submitTelegram(id, code.replace(/\s/g, '')), TELEGRAM_FAILED),
    passkey,
    startConditional,
    stopConditional,
    changePassword: (next: string) => run((id) => a.changePassword(id, next)),
    consent: (approve: boolean) =>
      run((id) =>
        a.consent(id, approve, view.value?.consent?.scopes.map((s) => s.value) ?? []),
      ),
    dispose: () => {
      stopTimer()
      stopConditional()
    },
  }
}

export type LoginFlow = ReturnType<typeof useLoginFlow>
