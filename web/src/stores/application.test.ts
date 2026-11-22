import { describe, expect, it } from 'vitest'
import { changedFields } from './application'
import { fakeApp } from '@/test/helpers'

const app = fakeApp({ display_name: 'Shop', redirect_uris: ['https://shop/cb'] })

describe('changedFields', () => {
  it('keeps only fields that differ (arrays compared by value)', () => {
    expect(
      changedFields(app, {
        display_name: 'Shop',
        redirect_uris: ['https://shop/cb'],
        access_token_ttl_secs: 1800,
        identifier_uri: 'api://shop',
        device_code_enabled: true,
      }),
    ).toEqual({
      access_token_ttl_secs: 1800,
      identifier_uri: 'api://shop',
      device_code_enabled: true,
    })
  })

  it('is empty when nothing changed', () => {
    expect(
      changedFields(app, {
        access_token_format: 'jwt',
        post_logout_redirect_uris: [],
        device_code_enabled: false,
      }),
    ).toEqual({})
  })
})
