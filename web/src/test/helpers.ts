import { vi } from 'vitest'
import type { Me, Passkey } from '@/api/types'

export interface Call {
  url: string
  method: string
  headers: Record<string, string>
  body: unknown
}

/** Replies served in order by the stubbed `fetch`; each call is recorded. */
export function mockFetch(
  ...replies: { status?: number; body?: unknown; headers?: Record<string, string> }[]
) {
  const calls: Call[] = []
  const fn = vi.fn(async (url: string, init: RequestInit = {}) => {
    calls.push({
      url,
      method: init.method ?? 'GET',
      headers: (init.headers ?? {}) as Record<string, string>,
      body: typeof init.body === 'string' ? JSON.parse(init.body) : undefined,
    })
    const reply = replies.shift() ?? { status: 204 }
    const status = reply.status ?? 200
    const text = reply.body === undefined ? null : JSON.stringify(reply.body)
    return new Response(text, {
      status,
      headers: { 'content-type': 'application/json', ...reply.headers },
    })
  })
  vi.stubGlobal('fetch', fn)
  return calls
}

export function fakeUser(over: Partial<FakeUser> = {}): FakeUser {
  return {
    access_token: 'at-1',
    refresh_token: 'rt-1',
    expired: false,
    expires_in: 3600,
    state: undefined,
    ...over,
  }
}

export interface FakeUser {
  access_token: string
  refresh_token?: string
  expired: boolean
  expires_in: number
  state: unknown
}

/** Stand-in for oidc-client-ts' UserManager; one per area. */
export class FakeManager {
  static instances: FakeManager[] = []
  stored: FakeUser | null = null
  signinRedirect = vi.fn(async () => {})
  signinSilent = vi.fn(async (): Promise<FakeUser | null> => null)
  signinRedirectCallback = vi.fn(async (): Promise<FakeUser> => fakeUser())
  signoutRedirect = vi.fn(async () => {})
  removeUser = vi.fn(async () => {
    this.stored = null
  })

  constructor(readonly area: string) {
    FakeManager.instances.push(this)
  }

  async getUser() {
    return this.stored
  }
}

/** `GET me` for a member with a password and no second factor. */
export function fakeMe(over: Partial<Me> = {}): Me {
  return {
    id: 'u',
    email: 'ann@example.com',
    display_name: 'Ann',
    user_type: 'member',
    email_verified: true,
    disabled: false,
    must_change_password: false,
    has_password: true,
    created_at: '',
    updated_at: '',
    directory_roles: [],
    mfa: { totp: false, totp_pending: false, recovery_codes_remaining: 0, passkeys: 0 },
    features: { email: true },
    ...over,
  }
}

/** A registered passkey. */
export function fakePasskey(over: Partial<Passkey> = {}): Passkey {
  return {
    id: 'pk1',
    name: 'Laptop',
    created_at: '2026-10-01T10:00:00Z',
    last_used_at: null,
    backup_eligible: true,
    backup_state: true,
    transports: ['internal'],
    aaguid: '00000000-0000-0000-0000-000000000000',
    ...over,
  }
}

const bytes = (...b: number[]) => new Uint8Array(b).buffer

/** A credential as `navigator.credentials.create` returns it (fixed bytes). */
export function fakeAttestation() {
  return {
    id: 'AQI',
    rawId: bytes(1, 2),
    type: 'public-key',
    response: {
      clientDataJSON: bytes(3),
      attestationObject: bytes(4),
      getTransports: () => ['internal'],
    },
  }
}

/** A credential as `navigator.credentials.get` returns it (fixed bytes). */
export function fakeAssertion(userHandle: ArrayBuffer | null = bytes(9)) {
  return {
    id: 'AQI',
    rawId: bytes(1, 2),
    type: 'public-key',
    response: {
      clientDataJSON: bytes(3),
      authenticatorData: bytes(5),
      signature: bytes(6),
      userHandle,
    },
  }
}

/** The JSON `fakeAssertion()` serializes to. */
export const ASSERTION_JSON = {
  id: 'AQI',
  rawId: 'AQI',
  type: 'public-key' as const,
  response: { clientDataJSON: 'Aw', authenticatorData: 'BQ', signature: 'Bg', userHandle: 'CQ' },
}

/** The JSON `fakeAttestation()` serializes to. */
export const REGISTRATION_JSON = {
  id: 'AQI',
  rawId: 'AQI',
  type: 'public-key' as const,
  response: { clientDataJSON: 'Aw', attestationObject: 'BA', transports: ['internal'] },
}

/** Request options as the server sends them (challenge = bytes 1, 2, 3). */
export const REQUEST_OPTIONS = {
  publicKey: { challenge: 'AQID', rpId: 'contoso.example', userVerification: 'required' as const },
}

/** Creation options as the server sends them. */
export const CREATION_OPTIONS = {
  publicKey: {
    challenge: 'AQID',
    rp: { id: 'contoso.example', name: 'Contoso' },
    user: { id: 'BAU', name: 'ann@example.com', displayName: 'Ann' },
    pubKeyCredParams: [{ type: 'public-key' as const, alg: -7 }],
  },
}

/**
 * Installs `PublicKeyCredential` and `navigator.credentials` mocks (jsdom has neither);
 * `vi.unstubAllGlobals()` makes passkeys unsupported again.
 */
export function stubWebAuthn(conditional = false) {
  const create = vi.fn<(o?: CredentialCreationOptions) => Promise<unknown>>(async () =>
    fakeAttestation(),
  )
  const get = vi.fn<(o?: CredentialRequestOptions) => Promise<unknown>>(async () =>
    fakeAssertion(),
  )
  vi.stubGlobal(
    'PublicKeyCredential',
    Object.assign(function PublicKeyCredential() {}, {
      isConditionalMediationAvailable: async () => conditional,
    }),
  )
  Object.defineProperty(navigator, 'credentials', { value: { create, get }, configurable: true })
  return { create, get }
}

/** A `DOMException`-like browser failure (`NotAllowedError`, …). */
export function domError(name: string): Error {
  const err = new Error(name)
  err.name = name
  return err
}
