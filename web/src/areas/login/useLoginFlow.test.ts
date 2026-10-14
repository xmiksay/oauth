import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/api/client'
import type { LoginStep, TxView } from '@/api/authn'
import { PasskeyCancelled } from '@/webauthn'
import { ASSERTION_JSON, REQUEST_OPTIONS, domError } from '@/test/helpers'
import {
  PASSKEY_CANCELLED,
  PASSKEY_FAILED,
  useLoginFlow,
  type LoginDeps,
} from './useLoginFlow'

function view(step: LoginStep, extra: Partial<TxView> = {}): TxView {
  return {
    tx: 'tx-1',
    step,
    factors: step === 'password' ? ['password'] : step === 'mfa' ? ['totp', 'recovery'] : [],
    tenant: { slug: 'contoso', display_name: 'Contoso' },
    client: { client_id: 'shop', display_name: 'Shop' },
    user: step === 'password' ? null : { email: 'ann@example.com', display_name: 'Ann' },
    consent: null,
    features: { password_reset: false },
    ...extra,
  }
}

const err = (status: number, error: string, retryAfter: number | null = null) =>
  new ApiError(status, { error, error_description: `${error} detail` }, retryAfter)

function deps() {
  const api = {
    get: vi.fn(),
    password: vi.fn(),
    totp: vi.fn(),
    recovery: vi.fn(),
    changePassword: vi.fn(),
    consent: vi.fn(),
    signOut: vi.fn(),
    passkeyOptions: vi.fn(),
    passkey: vi.fn(),
  }
  const navigate = vi.fn()
  const passkeys = { conditional: vi.fn(async () => false), get: vi.fn() }
  return { api, navigate, passkeys, deps: { api, navigate, passkeys } as unknown as LoginDeps }
}

const passkeyView = () => view('password', { factors: ['password', 'passkey'] })

/** A `get` that stays pending until its signal aborts (like a conditional request). */
function pendingUntilAborted(...args: unknown[]) {
  const signal = (args[1] as { signal?: AbortSignal } | undefined)?.signal
  return new Promise((_, reject) =>
    signal?.addEventListener('abort', () => reject(domError('AbortError'))),
  )
}

describe('useLoginFlow passkeys', () => {
  it('signs in with a passkey: fresh options, assertion, step POST', async () => {
    const d = deps()
    d.api.get.mockResolvedValue(passkeyView())
    d.api.passkeyOptions.mockResolvedValue(REQUEST_OPTIONS)
    d.passkeys.get.mockResolvedValue(ASSERTION_JSON)
    d.api.passkey.mockResolvedValue({ redirect: 'https://shop/cb?code=c' })
    const flow = useLoginFlow('tx-1', d.deps)
    await flow.load()
    await flow.passkey()
    expect(d.api.passkeyOptions).toHaveBeenCalledWith('tx-1')
    expect(d.passkeys.get).toHaveBeenCalledWith(REQUEST_OPTIONS)
    expect(d.api.passkey).toHaveBeenCalledWith('tx-1', ASSERTION_JSON)
    expect(d.navigate).toHaveBeenCalledWith('https://shop/cb?code=c')
  })

  it('says the passkey (not the password) failed on invalid_credentials', async () => {
    const d = deps()
    d.api.get.mockResolvedValue(view('mfa', { factors: ['passkey'] }))
    d.api.passkeyOptions.mockResolvedValue(REQUEST_OPTIONS)
    d.passkeys.get.mockResolvedValue(ASSERTION_JSON)
    d.api.passkey.mockRejectedValue(err(401, 'invalid_credentials'))
    const flow = useLoginFlow('tx-1', d.deps)
    await flow.load()
    await flow.passkey()
    expect(flow.error.value).toBe(PASSKEY_FAILED)
  })

  it('shows a soft note, not an error, when the dialog is dismissed', async () => {
    const d = deps()
    d.api.get.mockResolvedValue(passkeyView())
    d.api.passkeyOptions.mockResolvedValue(REQUEST_OPTIONS)
    d.passkeys.get.mockRejectedValue(new PasskeyCancelled())
    const flow = useLoginFlow('tx-1', d.deps)
    await flow.load()
    await flow.passkey()
    expect([flow.error.value, flow.notice.value]).toEqual([null, PASSKEY_CANCELLED])
    expect(d.api.passkey).not.toHaveBeenCalled()
  })

  it('submits a passkey picked from the autofill', async () => {
    const d = deps()
    d.api.get.mockResolvedValue(passkeyView())
    d.passkeys.conditional.mockResolvedValue(true)
    d.api.passkeyOptions.mockResolvedValue(REQUEST_OPTIONS)
    d.passkeys.get.mockResolvedValue(ASSERTION_JSON)
    d.api.passkey.mockResolvedValue({ redirect: 'https://shop/cb' })
    const flow = useLoginFlow('tx-1', d.deps)
    await flow.load()
    await flow.startConditional()
    expect(d.passkeys.get).toHaveBeenCalledWith(REQUEST_OPTIONS, {
      mediation: 'conditional',
      signal: expect.any(AbortSignal),
    })
    expect(d.api.passkey).toHaveBeenCalledWith('tx-1', ASSERTION_JSON)
  })

  it('aborts the autofill request before the modal one and refetches options', async () => {
    const d = deps()
    d.api.get.mockResolvedValue(passkeyView())
    d.passkeys.conditional.mockResolvedValue(true)
    d.api.passkeyOptions.mockResolvedValue(REQUEST_OPTIONS)
    d.passkeys.get.mockImplementationOnce(pendingUntilAborted).mockResolvedValueOnce(ASSERTION_JSON)
    d.api.passkey.mockResolvedValue(view('consent'))
    const flow = useLoginFlow('tx-1', d.deps)
    await flow.load()
    const autofill = flow.startConditional()
    await vi.waitFor(() => expect(d.passkeys.get).toHaveBeenCalledTimes(1))
    const signal = d.passkeys.get.mock.calls[0]?.[1]?.signal as AbortSignal
    await flow.passkey()
    await autofill
    expect(signal.aborted).toBe(true)
    expect(d.api.passkeyOptions).toHaveBeenCalledTimes(2)
    expect(d.api.passkey).toHaveBeenCalledTimes(1)
    expect([flow.error.value, flow.notice.value, flow.view.value?.step]).toEqual([
      null,
      null,
      'consent',
    ])
  })

  it('offers no autofill without the passkey factor or browser support', async () => {
    const d = deps()
    d.api.get.mockResolvedValue(view('password'))
    const flow = useLoginFlow('tx-1', d.deps)
    await flow.load()
    await flow.startConditional()
    expect(d.passkeys.conditional).not.toHaveBeenCalled()

    d.api.get.mockResolvedValue(passkeyView())
    await flow.load()
    await flow.startConditional()
    expect(d.passkeys.conditional).toHaveBeenCalled()
    expect(d.api.passkeyOptions).not.toHaveBeenCalled()
  })

  it('stays quiet when the autofill options cannot be fetched', async () => {
    const d = deps()
    d.api.get.mockResolvedValue(passkeyView())
    d.passkeys.conditional.mockResolvedValue(true)
    d.api.passkeyOptions.mockRejectedValue(err(429, 'rate_limited', 5))
    const flow = useLoginFlow('tx-1', d.deps)
    await flow.load()
    await flow.startConditional()
    expect([flow.error.value, flow.retryIn.value]).toEqual([null, 0])
  })
})

beforeEach(() => vi.useFakeTimers())
afterEach(() => vi.useRealTimers())

describe('useLoginFlow', () => {
  it('without a tx shows the "start from the app" state and calls nothing', async () => {
    const d = deps()
    const flow = useLoginFlow(null, d.deps)
    await flow.load()
    expect(flow.phase.value).toBe('missing')
    expect(d.api.get).not.toHaveBeenCalled()
  })

  it('walks password → mfa → change_password → consent → redirect', async () => {
    const d = deps()
    const consent = {
      resource: { display_name: 'Orders', audience: 'api://orders' },
      scopes: [
        { value: 'Orders.Read', description: 'Read' },
        { value: 'Orders.Write', description: 'Write' },
      ],
    }
    d.api.get.mockResolvedValue(view('password'))
    d.api.password.mockResolvedValue(view('mfa'))
    d.api.totp.mockResolvedValue(view('change_password'))
    d.api.changePassword.mockResolvedValue(view('consent', { consent }))
    d.api.consent.mockResolvedValue({ redirect: 'https://shop/cb?code=c' })
    const flow = useLoginFlow('tx-1', d.deps)

    await flow.load()
    expect([flow.phase.value, flow.view.value?.step]).toEqual(['step', 'password'])
    await flow.password('ann@example.com', 'pw')
    expect(d.api.password).toHaveBeenCalledWith('tx-1', 'ann@example.com', 'pw')
    expect(flow.view.value?.step).toBe('mfa')
    await flow.totp('123 456')
    expect(d.api.totp).toHaveBeenCalledWith('tx-1', '123456')
    await flow.changePassword('a-new-password!')
    expect(flow.view.value?.step).toBe('consent')
    await flow.consent(true)
    expect(d.api.consent).toHaveBeenCalledWith('tx-1', true, [
      'Orders.Read',
      'Orders.Write',
    ])
    expect(flow.phase.value).toBe('redirecting')
    expect(d.navigate).toHaveBeenCalledWith('https://shop/cb?code=c')
  })

  it('uses the recovery endpoint for recovery codes', async () => {
    const d = deps()
    d.api.get.mockResolvedValue(view('mfa'))
    d.api.recovery.mockResolvedValue({ redirect: 'https://x' })
    const flow = useLoginFlow('tx-1', d.deps)
    await flow.load()
    await flow.recovery('abcd-efgh-ijkl')
    expect(d.api.recovery).toHaveBeenCalledWith('tx-1', 'abcd-efgh-ijkl')
  })

  it('shows one generic message for wrong credentials and stays on the step', async () => {
    const d = deps()
    d.api.get.mockResolvedValue(view('password'))
    d.api.password.mockRejectedValue(err(401, 'invalid_credentials'))
    const flow = useLoginFlow('tx-1', d.deps)
    await flow.load()
    await flow.password('x@y.z', 'bad')
    expect(flow.error.value).toBe('Your email or password is incorrect.')
    expect(flow.view.value?.step).toBe('password')
    expect(flow.busy.value).toBe(false)
  })

  it.each([
    ['invalid_code', 401, /didn't work/],
    ['account_disabled', 403, /disabled/],
    ['csrf_rejected', 403, /blocked/],
    ['invalid_request', 400, /invalid_request detail/],
    ['server_error', 500, /went wrong/],
  ])('maps %s to a message', async (code, status, message) => {
    const d = deps()
    d.api.get.mockResolvedValue(view('mfa'))
    d.api.totp.mockRejectedValue(err(status, code))
    const flow = useLoginFlow('tx-1', d.deps)
    await flow.load()
    await flow.totp('000000')
    expect(flow.error.value).toMatch(message)
  })

  it('treats an unknown or expired transaction as expired', async () => {
    const d = deps()
    d.api.get.mockRejectedValue(err(404, 'not_found'))
    const flow = useLoginFlow('tx-1', d.deps)
    await flow.load()
    expect(flow.phase.value).toBe('expired')
  })

  it('expires when a step answers 404 (finished elsewhere)', async () => {
    const d = deps()
    d.api.get.mockResolvedValue(view('password'))
    d.api.password.mockRejectedValue(err(404, 'not_found'))
    const flow = useLoginFlow('tx-1', d.deps)
    await flow.load()
    await flow.password('a@b.c', 'pw')
    expect([flow.phase.value, flow.view.value]).toEqual(['expired', null])
  })

  it('reloads the view on wrong_step', async () => {
    const d = deps()
    d.api.get.mockResolvedValueOnce(view('password')).mockResolvedValueOnce(view('mfa'))
    d.api.password.mockRejectedValue(err(409, 'wrong_step'))
    const flow = useLoginFlow('tx-1', d.deps)
    await flow.load()
    await flow.password('a@b.c', 'pw')
    expect(d.api.get).toHaveBeenCalledTimes(2)
    expect(flow.view.value?.step).toBe('mfa')
  })

  it('locks the form during a 429 countdown from Retry-After', async () => {
    const d = deps()
    d.api.get.mockResolvedValue(view('password'))
    d.api.password.mockRejectedValue(err(429, 'rate_limited', 3))
    const flow = useLoginFlow('tx-1', d.deps)
    await flow.load()
    await flow.password('a@b.c', 'pw')
    expect(flow.retryIn.value).toBe(3)
    expect(flow.locked.value).toBe(true)
    expect(flow.rateLimited.value).toBe(true)

    await flow.password('a@b.c', 'pw') // ignored while locked
    expect(d.api.password).toHaveBeenCalledTimes(1)

    vi.advanceTimersByTime(2000)
    expect(flow.retryIn.value).toBe(1)
    vi.advanceTimersByTime(1000)
    expect([flow.retryIn.value, flow.locked.value, flow.rateLimited.value]).toEqual([
      0,
      false,
      false,
    ])
  })

  it('shows a retryable error when the first load fails, and retries', async () => {
    const d = deps()
    d.api.get
      .mockRejectedValueOnce(new TypeError('Failed to fetch'))
      .mockRejectedValueOnce(err(500, 'server_error'))
      .mockResolvedValueOnce(view('password'))
    const flow = useLoginFlow('tx-1', d.deps)
    await flow.load()
    expect([flow.phase.value, flow.error.value]).toEqual([
      'error',
      'Could not reach the server. Check your connection and try again.',
    ])
    await flow.load()
    expect(flow.phase.value).toBe('error')
    expect(flow.error.value).toMatch(/went wrong/)
    await flow.load()
    expect([flow.phase.value, flow.error.value, flow.view.value?.step]).toEqual([
      'step',
      null,
      'password',
    ])
  })

  it('never navigates to a non-http(s) redirect', async () => {
    const d = deps()
    d.api.get.mockResolvedValue(view('password'))
    d.api.password.mockResolvedValue({ redirect: 'javascript:alert(1)' })
    const flow = useLoginFlow('tx-1', d.deps)
    await flow.load()
    await flow.password('a@b.c', 'pw')
    expect(d.navigate).not.toHaveBeenCalled()
    expect(flow.phase.value).toBe('error')
  })

  it('reports network failures', async () => {
    const d = deps()
    d.api.get.mockResolvedValue(view('password'))
    d.api.password.mockRejectedValue(new TypeError('Failed to fetch'))
    const flow = useLoginFlow('tx-1', d.deps)
    await flow.load()
    await flow.password('a@b.c', 'pw')
    expect(flow.error.value).toMatch(/reach the server/)
  })
})
