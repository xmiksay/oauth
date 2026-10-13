import { describe, expect, it } from 'vitest'
import { changedFields } from './application'
import type { Application } from '@/api/types'

const app: Application = {
  id: 'a1',
  client_id: 'shop',
  display_name: 'Shop',
  client_type: 'public',
  builtin: false,
  redirect_uris: ['https://shop/cb'],
  post_logout_redirect_uris: [],
  identifier_uri: null,
  audience: 'api://shop',
  access_token_format: 'jwt',
  signing_alg: 'RS256',
  access_token_ttl_secs: 3600,
  refresh_token_ttl_secs: 86400,
  created_at: '',
  updated_at: '',
}

describe('changedFields', () => {
  it('keeps only fields that differ (arrays compared by value)', () => {
    expect(
      changedFields(app, {
        display_name: 'Shop',
        redirect_uris: ['https://shop/cb'],
        access_token_ttl_secs: 1800,
        identifier_uri: 'api://shop',
      }),
    ).toEqual({ access_token_ttl_secs: 1800, identifier_uri: 'api://shop' })
  })

  it('is empty when nothing changed', () => {
    expect(changedFields(app, { access_token_format: 'jwt', post_logout_redirect_uris: [] })).toEqual(
      {},
    )
  })
})
