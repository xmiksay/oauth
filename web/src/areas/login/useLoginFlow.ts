import { computed, ref, shallowRef } from 'vue'
import { ApiError } from '@/api/client'
import { authn, isRedirect, type StepResult, type TxView } from '@/api/authn'

/**
 * `missing`: no tx in the URL; `expired`: unknown / expired / finished transaction;
 * `error`: the transaction couldn't be loaded (network / server) — retry with `load`.
 */
export type Phase = 'loading' | 'step' | 'redirecting' | 'expired' | 'missing' | 'error'

export interface LoginDeps {
  api: typeof authn
  navigate: (url: string) => void
}

const defaultDeps: LoginDeps = {
  api: authn,
  navigate: (url) => window.location.assign(url),
}

function messageFor(err: ApiError): string {
  switch (err.code) {
    case 'invalid_credentials':
      return 'Your email or password is incorrect.'
    case 'invalid_code':
      return "That code didn't work. Check it and try again."
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
  const busy = ref(false)
  const retryIn = ref(0)
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
    view.value = result
    phase.value = 'step'
  }

  async function handleError(err: unknown) {
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
      error.value = messageFor(err)
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

  async function run(call: (tx: string) => Promise<StepResult>) {
    if (!tx || locked.value) return
    busy.value = true
    error.value = null
    try {
      apply(await call(tx))
    } catch (err) {
      await handleError(err)
    } finally {
      busy.value = false
    }
  }

  const a = deps.api
  return {
    phase,
    view,
    error,
    busy,
    retryIn,
    locked,
    rateLimited,
    load,
    password: (email: string, password: string) =>
      run((id) => a.password(id, email, password)),
    totp: (code: string) => run((id) => a.totp(id, code.replace(/\s/g, ''))),
    recovery: (code: string) => run((id) => a.recovery(id, code)),
    changePassword: (next: string) => run((id) => a.changePassword(id, next)),
    consent: (approve: boolean) =>
      run((id) =>
        a.consent(id, approve, view.value?.consent?.scopes.map((s) => s.value) ?? []),
      ),
    dispose: stopTimer,
  }
}

export type LoginFlow = ReturnType<typeof useLoginFlow>
