import { vi } from 'vitest'

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

/** Stand-in for oidc-client-ts' UserManager; one per (tenant, area). */
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

  constructor(
    readonly tenant: string,
    readonly area: string,
  ) {
    FakeManager.instances.push(this)
  }

  async getUser() {
    return this.stored
  }
}
