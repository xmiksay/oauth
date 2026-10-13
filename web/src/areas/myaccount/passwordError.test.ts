import { describe, expect, it } from 'vitest'
import { ApiError } from '@/api/client'
import { passwordError } from './passwordError'

describe('passwordError', () => {
  it('turns a 403 from a me/… security endpoint into "wrong password"', () => {
    expect(passwordError(new ApiError(403, { error: 'forbidden' }))).toBe(
      'Your current password is incorrect.',
    )
  })

  it('passes other errors through unchanged', () => {
    const limited = new ApiError(429, { error: 'rate_limited' }, 60)
    const network = new TypeError('Failed to fetch')
    expect(passwordError(limited)).toBe(limited)
    expect(passwordError(network)).toBe(network)
  })
})
