import { computed, ref, shallowRef } from 'vue'
import { ApiError } from '@/api/client'
import { authn, isRedirect, type StepResult, type TxView } from '@/api/authn'
import { PasskeyCancelled, conditionalMediationAvailable, getPasskey } from '@/webauthn'

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
  navigate: (url) => window.location.assign(url),
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
  }
  return 'Something went wrong on our side. Please try again.'
}

function isWebUrl(raw: string): boolean {
  try {
    const { protocol } = new URL(raw)
    return protocol === 'https:' || protocol === 'http:'
  } catch {
    return false
  }
}

/** Drives one login transaction through its steps (docs/api/authn.md). */
export function useLoginFlow(tx: string | null, deps: LoginDeps = defaultDeps) {
  const phase = ref<Phase>(tx ? 'loading' : 'missing')
  const view = shallowRef<TxView | null>(null)
  const error = ref<string | null>(null)
  /** A soft note (a dismissed passkey dialog, a sent code), not an error. */
  const notice = ref<string | null>(null)
  const busy = ref(false)
  const retryIn = ref(0)
  /** A Telegram code was sent during this MFA step, so its input can be shown. */
  const telegramSent = ref(false)
  let timer: ReturnType<typeof setInterval> | null = null

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
      apply(await deps.api.get(tx))
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
    load,
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
