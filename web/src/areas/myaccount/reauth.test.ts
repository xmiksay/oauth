import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/api/client'
import { ASSERTION_JSON, REQUEST_OPTIONS, stubWebAuthn } from '@/test/helpers'

const api = { reauthOptions: vi.fn() }
vi.mock('@/api/me', () => ({ me: api }))

const { passkeyReauth, reauthError } = await import('./reauth')

afterEach(() => vi.unstubAllGlobals())

describe('reauthError', () => {
  it('turns a 403 into "wrong password" or "passkey not verified"', () => {
    const denied = new ApiError(403, { error: 'forbidden' })
    expect(reauthError(denied, 'password')).toBe('Your current password is incorrect.')
    expect(reauthError(denied, 'passkey')).toMatch(/passkey couldn't be verified/)
  })

  it('passes other errors through unchanged', () => {
    const limited = new ApiError(429, { error: 'rate_limited' }, 60)
    const network = new TypeError('Failed to fetch')
    expect(reauthError(limited, 'password')).toBe(limited)
    expect(reauthError(network, 'passkey')).toBe(network)
  })
})

describe('passkeyReauth', () => {
  it('signs the re-auth challenge and wraps the assertion', async () => {
    const { get } = stubWebAuthn()
    api.reauthOptions.mockResolvedValue(REQUEST_OPTIONS)
    expect(await passkeyReauth()).toEqual({ passkey: ASSERTION_JSON })
    expect(get).toHaveBeenCalledTimes(1)
  })
})
