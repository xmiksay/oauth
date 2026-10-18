// Test fixtures for `useLoginFlow` (shared by its test files).
import { vi } from 'vitest'
import { ApiError } from '@/api/client'
import type { LoginStep, TxView } from '@/api/authn'
import type { LoginDeps } from './useLoginFlow'

export function view(step: LoginStep, extra: Partial<TxView> = {}): TxView {
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

export const err = (status: number, error: string, retryAfter: number | null = null) =>
  new ApiError(status, { error, error_description: `${error} detail` }, retryAfter)

/** Mocked login API, navigation and WebAuthn, plus them bundled as `LoginDeps`. */
export function deps() {
  const api = {
    get: vi.fn(),
    password: vi.fn(),
    totp: vi.fn(),
    recovery: vi.fn(),
    sendTelegramCode: vi.fn(),
    submitTelegram: vi.fn(),
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
